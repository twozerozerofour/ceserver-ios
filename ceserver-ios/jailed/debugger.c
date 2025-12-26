#include "debugger.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <time.h>

#include <mach/exception_types.h>
#include <mach/exc.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/ndr.h>
#include <mach/thread_act.h>
#include <mach/thread_status.h>

#include "api.h"


#define S_USER ((uint32_t)(2u << 1))
#define WCR_ENABLE ((uint32_t)(1u))
#define WCR_LOAD ((uint32_t)(1u << 3))
#define WCR_STORE ((uint32_t)(1u << 4))

#ifndef EXC_ARM_DA_DEBUG
#define EXC_ARM_DA_DEBUG 0x102
#endif

typedef struct DebugEventQueueElement
{
  DebugEvent de;
  struct DebugEventQueueElement *next;
} DebugEventQueueElement;

typedef struct WatchpointSpec
{
  uint64_t aligned_start;
  uint64_t aligned_size;
  uint64_t requested_start;
  uint64_t requested_size;
} WatchpointSpec;

typedef struct DebuggerBreakpoint
{
  uint64_t address;
  int debugreg;
  int size;
  int bptype;
  thread_t tid;
  int hw_count;
  int hw_index[2];
  WatchpointSpec wp[2];
  struct DebuggerBreakpoint *next;
} DebuggerBreakpoint;

typedef struct PendingException
{
  thread_t thread;
  mach_port_t reply_port;
  mach_msg_id_t msg_id;
  struct PendingException *next;
} PendingException;

typedef struct DebuggerData
{
  mach_port_t exception_port;
  exception_mask_t exception_mask;
  exception_mask_t saved_masks[EXC_TYPES_COUNT];
  mach_port_t saved_ports[EXC_TYPES_COUNT];
  exception_behavior_t saved_behaviors[EXC_TYPES_COUNT];
  thread_state_flavor_t saved_flavors[EXC_TYPES_COUNT];
  mach_msg_type_number_t saved_count;
  task_t task;

  pthread_t exception_thread;
  int exception_thread_running;
  int exception_thread_started;
  thread_t exception_thread_port;

  pthread_mutex_t queue_mutex;
  pthread_cond_t queue_cond;
  DebugEventQueueElement *queue_head;
  DebugEventQueueElement *queue_tail;

  pthread_mutex_t breakpoint_mutex;
  DebuggerBreakpoint *breakpoints;

  thread_t *threads;
  mach_msg_type_number_t thread_count;

  thread_t single_step_thread;

  PendingException *pending_head;
  PendingException *pending_tail;
} DebuggerData;

static pthread_mutex_t g_debugger_lock = PTHREAD_MUTEX_INITIALIZER;
static PProcessData g_debugger_process = NULL;

static uint64_t get_thread_pc(thread_t thread);
static int set_single_step(thread_t thread, int enable);
static int is_thread_invalid_error(kern_return_t err);
static int get_debug_state(thread_t thread, arm_debug_state64_t *dbgstate, kern_return_t *out_err);
static int set_debug_state(thread_t thread, const arm_debug_state64_t *dbgstate, kern_return_t *out_err);
static int set_task_debug_state(task_t task, const arm_debug_state64_t *dbgstate, kern_return_t *out_err);
static int apply_breakpoint_state(thread_t thread, int debugreg, uint64_t address, int size, int enable, kern_return_t *out_err);
static int update_breakpoint_state_in_dbg(arm_debug_state64_t *dbgstate, int debugreg, uint64_t address, int size, int enable);
static int update_watchpoint_state_in_dbg(arm_debug_state64_t *dbgstate, int debugreg, const WatchpointSpec *spec, int bptype, int enable);
static int build_watchpoint_regs(const WatchpointSpec *spec, int bptype, uint64_t *out_wvr, uint64_t *out_wcr);
static int apply_breakpoint_state_transaction(DebuggerData *dbg, thread_t *threads, mach_msg_type_number_t thread_count,
                                              int debugreg, uint64_t address, int size, int enable);
static int apply_watchpoint_state_transaction(DebuggerData *dbg, thread_t *threads, mach_msg_type_number_t thread_count,
                                              const WatchpointSpec *specs, const int *hw_index, int hw_count, int bptype, int enable);
static int apply_breakpoint_state_best_effort(DebuggerData *dbg, int debugreg, uint64_t address, int size, int enable);
static int apply_watchpoint_state_best_effort(DebuggerData *dbg, const WatchpointSpec *specs, const int *hw_index,
                                              int hw_count, int bptype, int enable);
static void apply_breakpoints_to_thread(DebuggerData *dbg, thread_t thread);
static void announce_new_thread(DebuggerData *dbg, thread_t thread);
static void refresh_thread_list(DebuggerData *dbg, task_t task);
static int enqueue_pending_exception(DebuggerData *dbg, thread_t thread, mach_port_t reply_port, mach_msg_id_t msg_id);
static int reply_pending_exception(DebuggerData *dbg, thread_t thread, kern_return_t retcode);
static int reply_all_pending_for_thread(DebuggerData *dbg, thread_t thread, kern_return_t retcode);
static int thread_has_pending_exception(DebuggerData *dbg, thread_t thread);
static int suspend_thread_for_debug(DebuggerData *dbg, thread_t thread, int *out_suspended, kern_return_t *out_err);
static void resume_thread_for_debug(DebuggerData *dbg, thread_t thread, int was_suspended);
static void prune_thread_if_invalid(DebuggerData *dbg, thread_t thread, kern_return_t err);
static uint8_t get_watchpoint_count(void);
static int find_breakpoint_base(DebuggerData *dbg, uint64_t addr, uint64_t *base);
static int get_exception_esr_far(thread_t thread, uint64_t *esr, uint64_t *far);
static int is_watchpoint_exception_esr(uint64_t esr);
static int get_watchpoint_hw_index_from_esr(uint64_t esr, uint32_t *out_index);
static int get_watchpoint_hw_index_from_state(thread_t thread, uint64_t *addr, int *out_index);
static int align_requested_watchpoint(uint64_t requested_addr, uint64_t requested_size, WatchpointSpec *out, int out_cap);
static int enable_watchpoint_on_thread(DebuggerData *dbg, thread_t thread, const DebuggerBreakpoint *bp, kern_return_t *out_err);
static int disable_watchpoint_on_thread(thread_t thread, const DebuggerBreakpoint *bp, kern_return_t *out_err);
static DebuggerBreakpoint *find_watchpoint_by_addr(DebuggerData *dbg, thread_t thread, uint64_t addr);
static DebuggerBreakpoint *find_watchpoint_by_hw_index(DebuggerData *dbg, thread_t thread, int hw_index, int *out_slot);

static uint64_t bit_ceil_u64(uint64_t input)
{
  uint64_t value = 1;
  while (value < input)
  {
    uint64_t next = value << 1;
    if (next <= value)
      return 0;
    value = next;
  }
  return value;
}

static uint64_t bits_u64(uint64_t value, uint32_t msbit, uint32_t lsbit)
{
  uint64_t shift_left = (sizeof(value) * 8u) - 1u - msbit;
  value <<= shift_left;
  value >>= shift_left + lsbit;
  return value;
}

static uint64_t bit_u64(uint64_t value, uint32_t bit)
{
  return bits_u64(value, bit, bit);
}

static int lowest_bit_set_u32(uint32_t value)
{
  for (int i = 0; i < 8; i++)
  {
    if (value & (1u << i))
      return i;
  }
  return -1;
}

static int align_requested_watchpoint(uint64_t requested_addr, uint64_t requested_size, WatchpointSpec *out, int out_cap)
{
  if (requested_size == 0 || out_cap <= 0)
    return 0;

  const uint64_t min_watchpoint_alignment = 8;
  uint64_t aligned_size = requested_size < min_watchpoint_alignment ? min_watchpoint_alignment : requested_size;
  aligned_size = bit_ceil_u64(aligned_size);
  if (aligned_size == 0)
    return 0;

  uint64_t aligned_start = requested_addr & ~(aligned_size - 1);
  if (aligned_start + aligned_size >= requested_addr + requested_size)
  {
    out[0].aligned_start = aligned_start;
    out[0].aligned_size = aligned_size;
    out[0].requested_start = requested_addr;
    out[0].requested_size = requested_size;
    return 1;
  }

  if (out_cap < 2)
    return 0;

  uint64_t split_addr = aligned_start + aligned_size;
  uint64_t first_requested_addr = requested_addr;
  uint64_t first_requested_size = split_addr - requested_addr;
  uint64_t second_requested_addr = split_addr;
  uint64_t second_requested_size = requested_size - first_requested_size;

  WatchpointSpec first;
  WatchpointSpec second;
  if (align_requested_watchpoint(first_requested_addr, first_requested_size, &first, 1) != 1)
    return 0;
  if (align_requested_watchpoint(second_requested_addr, second_requested_size, &second, 1) != 1)
    return 0;

  out[0] = first;
  out[1] = second;
  return 2;
}

static int is_watchpoint_hw_index_used_locked(DebuggerData *dbg, int hw_index)
{
  for (DebuggerBreakpoint *bp = dbg->breakpoints; bp; bp = bp->next)
  {
    if (bp->bptype == 0 || bp->hw_count <= 0)
      continue;
    for (int i = 0; i < bp->hw_count; i++)
    {
      if (bp->hw_index[i] == hw_index)
        return 1;
    }
  }
  return 0;
}

static int allocate_watchpoint_hw_indices_locked(DebuggerData *dbg, int count, int *out_indices)
{
  uint8_t max_watchpoints = get_watchpoint_count();
  int found = 0;

  for (uint8_t i = 0; i < max_watchpoints && found < count; i++)
  {
    if (!is_watchpoint_hw_index_used_locked(dbg, i))
    {
      out_indices[found] = i;
      found++;
    }
  }

  return found == count;
}

static void queue_event(DebuggerData *dbg, const DebugEvent *ev)
{
  DebugEventQueueElement *elem = (DebugEventQueueElement *)malloc(sizeof(DebugEventQueueElement));
  if (!elem)
    return;
  elem->de = *ev;
  elem->next = NULL;

  pthread_mutex_lock(&dbg->queue_mutex);
  if (dbg->queue_tail)
    dbg->queue_tail->next = elem;
  else
    dbg->queue_head = elem;
  dbg->queue_tail = elem;
  pthread_cond_signal(&dbg->queue_cond);
  pthread_mutex_unlock(&dbg->queue_mutex);
}

static int wait_for_event(DebuggerData *dbg, DebugEvent *ev, int timeout_ms)
{
  int has_event = 0;
  pthread_mutex_lock(&dbg->queue_mutex);
  while (!dbg->queue_head && !has_event)
  {
    if (timeout_ms < 0)
    {
      pthread_cond_wait(&dbg->queue_cond, &dbg->queue_mutex);
    }
    else if (timeout_ms == 0)
    {
      break;
    }
    else
    {
      struct timespec ts;
      clock_gettime(CLOCK_REALTIME, &ts);
      ts.tv_sec += timeout_ms / 1000;
      ts.tv_nsec += (timeout_ms % 1000) * 1000000L;
      if (ts.tv_nsec >= 1000000000L)
      {
        ts.tv_sec += 1;
        ts.tv_nsec -= 1000000000L;
      }
      if (pthread_cond_timedwait(&dbg->queue_cond, &dbg->queue_mutex, &ts) == ETIMEDOUT)
        break;
    }
  }

  if (dbg->queue_head)
  {
    DebugEventQueueElement *elem = dbg->queue_head;
    dbg->queue_head = elem->next;
    if (!dbg->queue_head)
      dbg->queue_tail = NULL;
    *ev = elem->de;
    free(elem);
    has_event = 1;
  }
  pthread_mutex_unlock(&dbg->queue_mutex);
  return has_event;
}

static uint8_t get_breakpoint_count(void)
{
  uint32_t n = 0;
  size_t len = sizeof(n);
  if (sysctlbyname("hw.optional.breakpoint", &n, &len, NULL, 0) == 0)
    return (uint8_t)n;
  return 0;
}

static uint8_t get_watchpoint_count(void)
{
  uint32_t n = 0;
  size_t len = sizeof(n);
  if (sysctlbyname("hw.optional.watchpoint", &n, &len, NULL, 0) == 0)
    return (uint8_t)n;
  return 0;
}

static PProcessData get_process_for_exception(mach_port_t task)
{
  (void)task;
  PProcessData p = NULL;
  pthread_mutex_lock(&g_debugger_lock);
  p = g_debugger_process;
  pthread_mutex_unlock(&g_debugger_lock);
  return p;
}

static int register_thread(DebuggerData *dbg, thread_t thread)
{
  for (mach_msg_type_number_t i = 0; i < dbg->thread_count; i++)
  {
    if (dbg->threads[i] == thread)
    {
      mach_port_deallocate(mach_task_self(), thread);
      return 0;
    }
  }

  thread_t *newlist = (thread_t *)realloc(dbg->threads, sizeof(thread_t) * (dbg->thread_count + 1));
  if (!newlist)
  {
    mach_port_deallocate(mach_task_self(), thread);
    return 0;
  }
  dbg->threads = newlist;
  dbg->threads[dbg->thread_count] = thread;
  dbg->thread_count++;

  announce_new_thread(dbg, thread);
  return 1;
}

static kern_return_t handle_exception_raise(DebuggerData *dbg, __Request__exception_raise_t *req)
{
  PProcessData p = get_process_for_exception(req->task.name);
  if (!p || !p->debuggerData)
    return KERN_FAILURE;

  uint64_t exc_code = 0;
  uint64_t exc_subcode = 0;
  if (req->codeCnt > 0)
    exc_code = (uint64_t)req->code[0];
  if (req->codeCnt > 1)
    exc_subcode = (uint64_t)req->code[1];

  register_thread(dbg, req->thread.name);
  mach_port_deallocate(mach_task_self(), req->task.name);

  if (!enqueue_pending_exception(dbg, req->thread.name, req->Head.msgh_remote_port, req->Head.msgh_id))
    debug_log("Failed to queue pending exception for thread %u\n", req->thread.name);

  int signo = SIGTRAP;
  switch (req->exception)
  {
    case EXC_BAD_ACCESS:
      signo = SIGBUS;
      break;
    case EXC_BAD_INSTRUCTION:
      signo = SIGILL;
      break;
    case EXC_ARITHMETIC:
      signo = SIGFPE;
      break;
    case EXC_BREAKPOINT:
    default:
      signo = SIGTRAP;
      break;
  }

  if (dbg->single_step_thread == req->thread.name)
  {
    set_single_step(req->thread.name, 0);
    dbg->single_step_thread = MACH_PORT_NULL;
  }

  DebugEvent ev;
  memset(&ev, 0, sizeof(ev));
  ev.debugevent = signo;
  ev.threadid = (int64_t)req->thread.name;
  ev.address = get_thread_pc(req->thread.name);

  if (req->exception == EXC_BREAKPOINT)
  {
    uint64_t pc = ev.address;
    uint64_t esr = 0;
    uint64_t far = 0;
    int have_esr_far = get_exception_esr_far(req->thread.name, &esr, &far);
    DebuggerBreakpoint *wp = NULL;
    uint64_t candidate = far ? far : exc_subcode;

    if (have_esr_far && is_watchpoint_exception_esr(esr))
    {
      uint32_t hw_index = 0;
      int slot = -1;
      if (get_watchpoint_hw_index_from_esr(esr, &hw_index))
        wp = find_watchpoint_by_hw_index(dbg, req->thread.name, (int)hw_index, &slot);
      if (!wp && candidate)
      {
        int hw_index_state = -1;
        uint64_t candidate_state = candidate;
        if (get_watchpoint_hw_index_from_state(req->thread.name, &candidate_state, &hw_index_state))
        {
          wp = find_watchpoint_by_hw_index(dbg, req->thread.name, hw_index_state, NULL);
          if (candidate_state)
            candidate = candidate_state;
        }
      }
      if (!wp && candidate)
        wp = find_watchpoint_by_addr(dbg, req->thread.name, candidate);
    }
    else if (exc_code == EXC_ARM_DA_DEBUG)
    {
      if (candidate)
      {
        int hw_index_state = -1;
        uint64_t candidate_state = candidate;
        if (get_watchpoint_hw_index_from_state(req->thread.name, &candidate_state, &hw_index_state))
        {
          wp = find_watchpoint_by_hw_index(dbg, req->thread.name, hw_index_state, NULL);
          if (candidate_state)
            candidate = candidate_state;
        }
        if (!wp)
          wp = find_watchpoint_by_addr(dbg, req->thread.name, candidate);
      }
    }

    if (wp)
    {
      ev.address = wp->address;
    }
    else if (exc_code == 1 && exc_subcode)
    {
      DebuggerBreakpoint *addr_wp = find_watchpoint_by_addr(dbg, req->thread.name, exc_subcode);
      if (addr_wp)
      {
        ev.address = addr_wp->address;
      }
      else
      {
        uint64_t base = 0;
        if (find_breakpoint_base(dbg, exc_subcode, &base))
          ev.address = base;
        else if (find_breakpoint_base(dbg, pc, &base))
          ev.address = base;
        else
          ev.address = exc_subcode;
      }
    }
    else if (exc_code == 2 && exc_subcode)
    {
      uint64_t base = 0;
      if (find_breakpoint_base(dbg, exc_subcode, &base))
      {
        ev.address = base;
      }
      else if (find_breakpoint_base(dbg, pc, &base))
      {
        ev.address = base;
      }
      else
      {
        ev.address = exc_subcode;
      }
    }
    else
    {
      uint64_t base = 0;
      if (find_breakpoint_base(dbg, pc, &base))
        ev.address = base;
      else
        ev.address = pc;
    }
  }
  else if (req->exception == EXC_BAD_ACCESS)
  {
    ev.address = exc_subcode ? exc_subcode : ev.address;
  }
  queue_event(dbg, &ev);

  return KERN_SUCCESS;
}

static void *exception_thread_main(void *arg)
{
  PProcessData p = (PProcessData)arg;
  DebuggerData *dbg = (DebuggerData *)p->debuggerData;
  if (dbg && dbg->exception_thread_port == MACH_PORT_NULL)
    dbg->exception_thread_port = mach_thread_self();

  union __RequestUnion__exc_subsystem request;

  while (dbg->exception_thread_running)
  {
    kern_return_t kr = mach_msg(&request.Request_exception_raise.Head, MACH_RCV_MSG, 0,
                                sizeof(request), dbg->exception_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (kr == MACH_RCV_INTERRUPTED)
      continue;
    if (kr != KERN_SUCCESS)
      break;

    mach_msg_header_t *in = &request.Request_exception_raise.Head;

    if (in->msgh_id == 2401)
    {
      handle_exception_raise(dbg, &request.Request_exception_raise);
    }
    else if (in->msgh_id == 2402 || in->msgh_id == 2403)
    {
      debug_log("Unhandled exception message id=%d\n", in->msgh_id);
    }
  }

  return NULL;
}

static uint64_t get_thread_pc(thread_t thread)
{
  arm_thread_state64_t state;
  mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
  if (thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&state, &count) != KERN_SUCCESS)
    return 0;
  return (uint64_t)state.__pc;
}

static int set_single_step(thread_t thread, int enable)
{
  arm_debug_state64_t dbgstate;
  mach_msg_type_number_t count = ARM_DEBUG_STATE64_COUNT;
  if (thread_get_state(thread, ARM_DEBUG_STATE64, (thread_state_t)&dbgstate, &count) != KERN_SUCCESS)
    return 0;

  if (enable)
    dbgstate.__mdscr_el1 |= 1u;
  else
    dbgstate.__mdscr_el1 &= ~1u;

  return thread_set_state(thread, ARM_DEBUG_STATE64, (thread_state_t)&dbgstate, ARM_DEBUG_STATE64_COUNT) == KERN_SUCCESS;
}

static int is_thread_invalid_error(kern_return_t err)
{
  return err == KERN_INVALID_ARGUMENT || err == KERN_INVALID_CAPABILITY || err == KERN_TERMINATED;
}

static int get_debug_state(thread_t thread, arm_debug_state64_t *dbgstate, kern_return_t *out_err)
{
  mach_msg_type_number_t count = ARM_DEBUG_STATE64_COUNT;
  kern_return_t kr = thread_get_state(thread, ARM_DEBUG_STATE64, (thread_state_t)dbgstate, &count);
  if (out_err)
    *out_err = kr;
  return kr == KERN_SUCCESS;
}

static int set_debug_state(thread_t thread, const arm_debug_state64_t *dbgstate, kern_return_t *out_err)
{
  kern_return_t kr = thread_set_state(thread, ARM_DEBUG_STATE64, (thread_state_t)dbgstate, ARM_DEBUG_STATE64_COUNT);
  if (out_err)
    *out_err = kr;
  return kr == KERN_SUCCESS;
}

static int set_task_debug_state(task_t task, const arm_debug_state64_t *dbgstate, kern_return_t *out_err)
{
  if (task == MACH_PORT_NULL)
  {
    if (out_err)
      *out_err = KERN_INVALID_ARGUMENT;
    return 0;
  }
  kern_return_t kr = task_set_state(task, ARM_DEBUG_STATE64, (thread_state_t)dbgstate, ARM_DEBUG_STATE64_COUNT);
  if (out_err)
    *out_err = kr;
  return kr == KERN_SUCCESS;
}

static int update_breakpoint_state_in_dbg(arm_debug_state64_t *dbgstate, int debugreg, uint64_t address, int size, int enable)
{
  if (debugreg < 0 || debugreg >= (int)(sizeof(dbgstate->__bcr) / sizeof(dbgstate->__bcr[0])))
    return 0;

  if (enable)
  {
    uint64_t aligned = address;
    uint32_t control_value = 0;
    if (size <= 1)
    {
      control_value = (0x1u << 5) | 7u;
    }
    else if (size == 2)
    {
      control_value = (0x3u << 5) | 7u;
      aligned &= ~1ull;
    }
    else
    {
      control_value = (0xfu << 5) | 7u;
      aligned &= ~3ull;
    }
    dbgstate->__bvr[debugreg] = aligned;
    dbgstate->__bcr[debugreg] = control_value;
  }
  else
  {
    dbgstate->__bvr[debugreg] = 0;
    dbgstate->__bcr[debugreg] = 0;
  }
  return 1;
}

static int build_watchpoint_regs(const WatchpointSpec *spec, int bptype, uint64_t *out_wvr, uint64_t *out_wcr)
{
  if (!spec || !out_wvr || !out_wcr)
    return 0;
  if (bptype < 1 || bptype > 3)
    return 0;
  if (spec->requested_size == 0)
    return 0;

  const int watch_read = (bptype == 2 || bptype == 3);
  const int watch_write = (bptype == 1 || bptype == 3);

  uint64_t aligned_dword = spec->aligned_start;
  uint64_t offset = spec->requested_start - spec->aligned_start;
  uint64_t watch_size = spec->requested_size;

  if (spec->aligned_size <= 8 && watch_size <= 8 && (offset + watch_size) <= 8)
  {
    uint64_t bas = ((1ull << watch_size) - 1ull) << offset;
    uint64_t wcr = (bas << 5) | S_USER |
                   (watch_read ? WCR_LOAD : 0) |
                   (watch_write ? WCR_STORE : 0) |
                   WCR_ENABLE;
    *out_wvr = aligned_dword;
    *out_wcr = wcr;
  }
  else
  {
    uint64_t mask = (uint64_t)__builtin_popcountll(spec->aligned_size - 1) << 24;
    uint64_t not_bas_wp = (uint64_t)0xff << 5;
    uint64_t wcr = mask | not_bas_wp | S_USER |
                   (watch_read ? WCR_LOAD : 0) |
                   (watch_write ? WCR_STORE : 0) |
                   WCR_ENABLE;
    *out_wvr = spec->aligned_start;
    *out_wcr = wcr;
  }

  return 1;
}

static int update_watchpoint_state_in_dbg(arm_debug_state64_t *dbgstate, int debugreg, const WatchpointSpec *spec, int bptype,
                                          int enable)
{
  if (debugreg < 0 || debugreg >= (int)(sizeof(dbgstate->__wcr) / sizeof(dbgstate->__wcr[0])))
    return 0;

  if (enable)
  {
    uint64_t wvr = 0;
    uint64_t wcr = 0;
    if (!build_watchpoint_regs(spec, bptype, &wvr, &wcr))
      return 0;
    dbgstate->__wvr[debugreg] = wvr;
    dbgstate->__wcr[debugreg] = wcr;
  }
  else
  {
    dbgstate->__wvr[debugreg] = 0;
    dbgstate->__wcr[debugreg] = 0;
  }
  return 1;
}

typedef struct ThreadDebugStateSnapshot
{
  thread_t thread;
  arm_debug_state64_t state;
  int suspended;
  int applied;
} ThreadDebugStateSnapshot;

static int apply_breakpoint_state_transaction(DebuggerData *dbg, thread_t *threads, mach_msg_type_number_t thread_count,
                                              int debugreg, uint64_t address, int size, int enable)
{
  if (!threads || thread_count == 0)
    return 0;

  ThreadDebugStateSnapshot *snapshots = (ThreadDebugStateSnapshot *)calloc(thread_count, sizeof(ThreadDebugStateSnapshot));
  if (!snapshots)
    return 0;

  thread_t self_thread = mach_thread_self();
  thread_t exception_thread = dbg ? dbg->exception_thread_port : MACH_PORT_NULL;
  int ok = 1;
  int applied = 0;
  int task_state_pending = 0;
  arm_debug_state64_t task_state_new;
  for (mach_msg_type_number_t i = 0; i < thread_count; i++)
  {
    thread_t thread = threads[i];
    kern_return_t err = KERN_SUCCESS;
    int suspended = 0;

    if (thread != self_thread && thread != exception_thread && !suspend_thread_for_debug(dbg, thread, &suspended, &err))
    {
      if (is_thread_invalid_error(err))
      {
        prune_thread_if_invalid(dbg, thread, err);
        continue;
      }
      ok = 0;
      break;
    }

    snapshots[i].thread = thread;
    snapshots[i].suspended = suspended;

    if (!get_debug_state(thread, &snapshots[i].state, &err))
    {
      if (is_thread_invalid_error(err))
      {
        prune_thread_if_invalid(dbg, thread, err);
        resume_thread_for_debug(dbg, thread, suspended);
        continue;
      }
      ok = 0;
      break;
    }

    arm_debug_state64_t new_state = snapshots[i].state;
    if (!update_breakpoint_state_in_dbg(&new_state, debugreg, address, size, enable))
    {
      ok = 0;
      break;
    }

    if (!set_debug_state(thread, &new_state, &err))
    {
      if (is_thread_invalid_error(err))
      {
        prune_thread_if_invalid(dbg, thread, err);
        resume_thread_for_debug(dbg, thread, suspended);
        continue;
      }
      ok = 0;
      break;
    }

    snapshots[i].applied = 1;
    applied++;
    if (!task_state_pending && dbg && dbg->task != MACH_PORT_NULL)
    {
      task_state_new = new_state;
      task_state_pending = 1;
    }
  }

  if (!ok)
  {
    for (mach_msg_type_number_t i = 0; i < thread_count; i++)
    {
      if (snapshots[i].applied)
        set_debug_state(snapshots[i].thread, &snapshots[i].state, NULL);
    }
  }
  else if (applied > 0 && task_state_pending && dbg && dbg->task != MACH_PORT_NULL)
  {
    set_task_debug_state(dbg->task, &task_state_new, NULL);
  }

  for (mach_msg_type_number_t i = 0; i < thread_count; i++)
  {
    if (snapshots[i].suspended)
      resume_thread_for_debug(dbg, snapshots[i].thread, snapshots[i].suspended);
  }

  if (self_thread != MACH_PORT_NULL)
    mach_port_deallocate(mach_task_self(), self_thread);
  free(snapshots);
  return ok && applied > 0;
}

static int apply_breakpoint_state_best_effort(DebuggerData *dbg, int debugreg, uint64_t address, int size, int enable)
{
  if (!dbg || !dbg->threads || dbg->thread_count == 0)
    return 0;

  thread_t self_thread = mach_thread_self();
  thread_t exception_thread = dbg ? dbg->exception_thread_port : MACH_PORT_NULL;
  int ok = 0;
  int task_state_pending = 0;
  arm_debug_state64_t task_state_new;
  for (mach_msg_type_number_t i = 0; i < dbg->thread_count; i++)
  {
    thread_t thread = dbg->threads[i];
    kern_return_t err = KERN_SUCCESS;
    int suspended = 0;
    if (thread != self_thread && thread != exception_thread && !suspend_thread_for_debug(dbg, thread, &suspended, &err))
    {
      prune_thread_if_invalid(dbg, thread, err);
      continue;
    }
    if (apply_breakpoint_state(thread, debugreg, address, size, enable, &err))
    {
      ok = 1;
      if (!task_state_pending && dbg->task != MACH_PORT_NULL)
      {
        if (get_debug_state(thread, &task_state_new, NULL))
          task_state_pending = 1;
      }
    }
    else
      prune_thread_if_invalid(dbg, thread, err);
    resume_thread_for_debug(dbg, thread, suspended);
  }

  if (self_thread != MACH_PORT_NULL)
    mach_port_deallocate(mach_task_self(), self_thread);
  if (ok && task_state_pending && dbg->task != MACH_PORT_NULL)
    set_task_debug_state(dbg->task, &task_state_new, NULL);

  return ok;
}

static int apply_watchpoint_state_best_effort(DebuggerData *dbg, const WatchpointSpec *specs, const int *hw_index,
                                              int hw_count, int bptype, int enable)
{
  if (!dbg || !dbg->threads || dbg->thread_count == 0)
    return 0;
  if (hw_count <= 0 || !hw_index)
    return 0;
  if (enable && !specs)
    return 0;

  DebuggerBreakpoint temp_wp;
  memset(&temp_wp, 0, sizeof(temp_wp));
  temp_wp.bptype = bptype;
  temp_wp.hw_count = hw_count;
  temp_wp.hw_index[0] = hw_index[0];
  temp_wp.hw_index[1] = hw_count > 1 ? hw_index[1] : hw_index[0];
  if (enable)
  {
    temp_wp.wp[0] = specs[0];
    temp_wp.wp[1] = hw_count > 1 ? specs[1] : specs[0];
  }

  thread_t self_thread = mach_thread_self();
  thread_t exception_thread = dbg ? dbg->exception_thread_port : MACH_PORT_NULL;
  int ok = 0;
  int task_state_pending = 0;
  arm_debug_state64_t task_state_new;
  for (mach_msg_type_number_t i = 0; i < dbg->thread_count; i++)
  {
    thread_t thread = dbg->threads[i];
    kern_return_t err = KERN_SUCCESS;
    int suspended = 0;
    if (thread != self_thread && thread != exception_thread && !suspend_thread_for_debug(dbg, thread, &suspended, &err))
    {
      prune_thread_if_invalid(dbg, thread, err);
      continue;
    }
    if (enable ? enable_watchpoint_on_thread(dbg, thread, &temp_wp, &err)
               : disable_watchpoint_on_thread(thread, &temp_wp, &err))
    {
      ok = 1;
      if (!task_state_pending && dbg->task != MACH_PORT_NULL)
      {
        if (get_debug_state(thread, &task_state_new, NULL))
          task_state_pending = 1;
      }
    }
    else
    {
      prune_thread_if_invalid(dbg, thread, err);
    }
    resume_thread_for_debug(dbg, thread, suspended);
  }

  if (self_thread != MACH_PORT_NULL)
    mach_port_deallocate(mach_task_self(), self_thread);
  if (ok && task_state_pending && dbg->task != MACH_PORT_NULL)
    set_task_debug_state(dbg->task, &task_state_new, NULL);

  return ok;
}

static int apply_watchpoint_state_transaction(DebuggerData *dbg, thread_t *threads, mach_msg_type_number_t thread_count,
                                              const WatchpointSpec *specs, const int *hw_index, int hw_count, int bptype, int enable)
{
  if (!threads || thread_count == 0)
    return 0;
  if (hw_count <= 0 || !hw_index)
    return 0;
  if (enable && !specs)
    return 0;

  ThreadDebugStateSnapshot *snapshots = (ThreadDebugStateSnapshot *)calloc(thread_count, sizeof(ThreadDebugStateSnapshot));
  if (!snapshots)
    return 0;

  thread_t self_thread = mach_thread_self();
  thread_t exception_thread = dbg ? dbg->exception_thread_port : MACH_PORT_NULL;
  int ok = 1;
  int applied = 0;
  int task_state_pending = 0;
  arm_debug_state64_t task_state_new;
  for (mach_msg_type_number_t i = 0; i < thread_count; i++)
  {
    thread_t thread = threads[i];
    kern_return_t err = KERN_SUCCESS;
    int suspended = 0;

    if (thread != self_thread && thread != exception_thread && !suspend_thread_for_debug(dbg, thread, &suspended, &err))
    {
      if (is_thread_invalid_error(err))
      {
        prune_thread_if_invalid(dbg, thread, err);
        continue;
      }
      ok = 0;
      break;
    }

    snapshots[i].thread = thread;
    snapshots[i].suspended = suspended;

    if (!get_debug_state(thread, &snapshots[i].state, &err))
    {
      if (is_thread_invalid_error(err))
      {
        prune_thread_if_invalid(dbg, thread, err);
        resume_thread_for_debug(dbg, thread, suspended);
        continue;
      }
      ok = 0;
      break;
    }

    arm_debug_state64_t new_state = snapshots[i].state;
    for (int j = 0; j < hw_count; j++)
    {
      const WatchpointSpec *spec = enable ? &specs[j] : NULL;
      if (!update_watchpoint_state_in_dbg(&new_state, hw_index[j], spec, bptype, enable))
      {
        ok = 0;
        break;
      }
    }
    if (!ok)
      break;

    if (!set_debug_state(thread, &new_state, &err))
    {
      if (is_thread_invalid_error(err))
      {
        prune_thread_if_invalid(dbg, thread, err);
        resume_thread_for_debug(dbg, thread, suspended);
        continue;
      }
      ok = 0;
      break;
    }

    snapshots[i].applied = 1;
    applied++;
    if (!task_state_pending && dbg && dbg->task != MACH_PORT_NULL)
    {
      task_state_new = new_state;
      task_state_pending = 1;
    }
  }

  if (!ok)
  {
    for (mach_msg_type_number_t i = 0; i < thread_count; i++)
    {
      if (snapshots[i].applied)
        set_debug_state(snapshots[i].thread, &snapshots[i].state, NULL);
    }
  }
  else if (applied > 0 && task_state_pending && dbg && dbg->task != MACH_PORT_NULL)
  {
    set_task_debug_state(dbg->task, &task_state_new, NULL);
  }

  for (mach_msg_type_number_t i = 0; i < thread_count; i++)
  {
    if (snapshots[i].suspended)
      resume_thread_for_debug(dbg, snapshots[i].thread, snapshots[i].suspended);
  }

  if (self_thread != MACH_PORT_NULL)
    mach_port_deallocate(mach_task_self(), self_thread);
  free(snapshots);
  return ok && applied > 0;
}
static void fill_context_from_thread(thread_t thread, PCONTEXT Context)
{
  arm_thread_state64_t gpr;
  mach_msg_type_number_t gpr_count = ARM_THREAD_STATE64_COUNT;
  memset(Context, 0, sizeof(*Context));

  if (thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&gpr, &gpr_count) == KERN_SUCCESS)
  {
    for (int i = 0; i < 29; i++)
      Context->regs.regs[i] = gpr.__x[i];
    Context->regs.regs[29] = gpr.__fp;
    Context->regs.regs[30] = gpr.__lr;
    Context->regs.sp = gpr.__sp;
    Context->regs.pc = gpr.__pc;
    Context->regs.pstate = gpr.__cpsr;
  }

  arm_neon_state64_t neon;
  mach_msg_type_number_t neon_count = ARM_NEON_STATE64_COUNT;
  if (thread_get_state(thread, ARM_NEON_STATE64, (thread_state_t)&neon, &neon_count) == KERN_SUCCESS)
  {
    memcpy(Context->fp.vregs, neon.__v, sizeof(neon.__v));
    Context->fp.fpsr = neon.__fpsr;
    Context->fp.fpcr = neon.__fpcr;
  }

  Context->structsize = sizeof(CONTEXT);
  Context->type = 3;
}

static int apply_breakpoint_state(thread_t thread, int debugreg, uint64_t address, int size, int enable, kern_return_t *out_err)
{
  arm_debug_state64_t dbgstate;
  mach_msg_type_number_t count = ARM_DEBUG_STATE64_COUNT;
  kern_return_t kr = thread_get_state(thread, ARM_DEBUG_STATE64, (thread_state_t)&dbgstate, &count);
  if (kr != KERN_SUCCESS)
  {
    if (out_err)
      *out_err = kr;
    return 0;
  }

  if (debugreg < 0 || debugreg >= (int)(sizeof(dbgstate.__bcr) / sizeof(dbgstate.__bcr[0])))
    return 0;

  if (enable)
  {
    uint64_t aligned = address;
    uint32_t control_value = 0;
    if (size <= 1)
    {
      control_value = (0x1u << 5) | 7u;
    }
    else if (size == 2)
    {
      control_value = (0x3u << 5) | 7u;
      aligned &= ~1ull;
    }
    else
    {
      control_value = (0xfu << 5) | 7u;
      aligned &= ~3ull;
    }
    dbgstate.__bvr[debugreg] = aligned;
    dbgstate.__bcr[debugreg] = control_value;
  }
  else
  {
    dbgstate.__bvr[debugreg] = 0;
    dbgstate.__bcr[debugreg] = 0;
  }

  kr = thread_set_state(thread, ARM_DEBUG_STATE64, (thread_state_t)&dbgstate, ARM_DEBUG_STATE64_COUNT);
  if (kr != KERN_SUCCESS)
  {
    if (out_err)
      *out_err = kr;
    return 0;
  }
  if (out_err)
    *out_err = KERN_SUCCESS;
  return 1;
}

static int enable_watchpoint_on_thread(DebuggerData *dbg, thread_t thread, const DebuggerBreakpoint *bp,
                                       kern_return_t *out_err)
{
  (void)dbg;
  if (!bp || bp->bptype == 0 || bp->hw_count <= 0)
    return 0;

  arm_debug_state64_t dbgstate;
  kern_return_t err = KERN_SUCCESS;
  if (!get_debug_state(thread, &dbgstate, &err))
  {
    if (out_err)
      *out_err = err;
    return 0;
  }

  arm_debug_state64_t new_state = dbgstate;
  for (int i = 0; i < bp->hw_count; i++)
  {
    if (!update_watchpoint_state_in_dbg(&new_state, bp->hw_index[i], &bp->wp[i], bp->bptype, 1))
      return 0;
  }

  if (!set_debug_state(thread, &new_state, &err))
  {
    if (out_err)
      *out_err = err;
    return 0;
  }

  if (out_err)
    *out_err = KERN_SUCCESS;
  return 1;
}

static int disable_watchpoint_on_thread(thread_t thread, const DebuggerBreakpoint *bp, kern_return_t *out_err)
{
  if (!bp || bp->bptype == 0 || bp->hw_count <= 0)
    return 0;

  arm_debug_state64_t dbgstate;
  kern_return_t err = KERN_SUCCESS;
  if (!get_debug_state(thread, &dbgstate, &err))
  {
    if (out_err)
      *out_err = err;
    return 0;
  }

  arm_debug_state64_t new_state = dbgstate;
  for (int i = 0; i < bp->hw_count; i++)
  {
    if (!update_watchpoint_state_in_dbg(&new_state, bp->hw_index[i], NULL, bp->bptype, 0))
      return 0;
  }

  if (!set_debug_state(thread, &new_state, &err))
  {
    if (out_err)
      *out_err = err;
    return 0;
  }

  if (out_err)
    *out_err = KERN_SUCCESS;
  return 1;
}

static int enqueue_pending_exception(DebuggerData *dbg, thread_t thread, mach_port_t reply_port, mach_msg_id_t msg_id)
{
  PendingException *pe = (PendingException *)malloc(sizeof(PendingException));
  if (!pe)
    return 0;
  pe->thread = thread;
  pe->reply_port = reply_port;
  pe->msg_id = msg_id;
  pe->next = NULL;

  pthread_mutex_lock(&dbg->queue_mutex);
  if (dbg->pending_tail)
    dbg->pending_tail->next = pe;
  else
    dbg->pending_head = pe;
  dbg->pending_tail = pe;
  pthread_mutex_unlock(&dbg->queue_mutex);
  return 1;
}

static int reply_pending_exception(DebuggerData *dbg, thread_t thread, kern_return_t retcode)
{
  PendingException *prev = NULL;
  PendingException *cur = NULL;

  pthread_mutex_lock(&dbg->queue_mutex);
  cur = dbg->pending_head;
  while (cur)
  {
    if (cur->thread == thread)
      break;
    prev = cur;
    cur = cur->next;
  }

  if (!cur)
  {
    pthread_mutex_unlock(&dbg->queue_mutex);
    return 0;
  }

  if (prev)
    prev->next = cur->next;
  else
    dbg->pending_head = cur->next;
  if (dbg->pending_tail == cur)
    dbg->pending_tail = prev;
  pthread_mutex_unlock(&dbg->queue_mutex);

  if (cur->msg_id == 2401)
  {
    __Reply__exception_raise_t r;
    memset(&r, 0, sizeof(r));
    r.Head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
    r.Head.msgh_size = sizeof(r);
    r.Head.msgh_remote_port = cur->reply_port;
    r.Head.msgh_local_port = MACH_PORT_NULL;
    r.Head.msgh_id = cur->msg_id + 100;
    r.NDR = NDR_record;
    r.RetCode = retcode;
    mach_msg(&r.Head, MACH_SEND_MSG, r.Head.msgh_size, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
  }

  free(cur);
  return 1;
}

static int reply_all_pending_for_thread(DebuggerData *dbg, thread_t thread, kern_return_t retcode)
{
  int count = 0;
  while (reply_pending_exception(dbg, thread, retcode))
    count++;
  return count;
}

static int thread_has_pending_exception(DebuggerData *dbg, thread_t thread)
{
  int found = 0;
  pthread_mutex_lock(&dbg->queue_mutex);
  PendingException *cur = dbg->pending_head;
  while (cur)
  {
    if (cur->thread == thread)
    {
      found = 1;
      break;
    }
    cur = cur->next;
  }
  pthread_mutex_unlock(&dbg->queue_mutex);
  return found;
}

static int suspend_thread_for_debug(DebuggerData *dbg, thread_t thread, int *out_suspended, kern_return_t *out_err)
{
  if (out_suspended)
    *out_suspended = 0;

  if (thread_has_pending_exception(dbg, thread))
  {
    if (out_err)
      *out_err = KERN_SUCCESS;
    // Thread is already stopped in the exception handler; do not suspend.
    return 1;
  }

  kern_return_t kr = thread_suspend(thread);
  if (kr != KERN_SUCCESS)
  {
    if (out_err)
      *out_err = kr;
    return 0;
  }

  if (out_suspended)
    *out_suspended = 1;
  return 1;
}

static void resume_thread_for_debug(DebuggerData *dbg, thread_t thread, int was_suspended)
{
  if (!was_suspended)
    return;
  kern_return_t kr = thread_resume(thread);
  if (kr != KERN_SUCCESS)
    prune_thread_if_invalid(dbg, thread, kr);
}

static void prune_thread_if_invalid(DebuggerData *dbg, thread_t thread, kern_return_t err)
{
  if (err != KERN_INVALID_ARGUMENT && err != KERN_INVALID_CAPABILITY && err != KERN_TERMINATED)
    return;

  for (mach_msg_type_number_t i = 0; i < dbg->thread_count; i++)
  {
    if (dbg->threads[i] == thread)
    {
      mach_port_deallocate(mach_task_self(), dbg->threads[i]);
      for (mach_msg_type_number_t j = i + 1; j < dbg->thread_count; j++)
        dbg->threads[j - 1] = dbg->threads[j];
      dbg->thread_count--;
      break;
    }
  }
}

static DebuggerBreakpoint *find_watchpoint_by_addr(DebuggerData *dbg, thread_t thread, uint64_t addr)
{
  DebuggerBreakpoint *found = NULL;

  pthread_mutex_lock(&dbg->breakpoint_mutex);
  for (DebuggerBreakpoint *bp = dbg->breakpoints; bp; bp = bp->next)
  {
    if (bp->bptype == 0 || bp->size <= 0)
      continue;
    if (bp->tid != -1 && bp->tid != thread)
      continue;

    int slot_count = bp->hw_count > 0 ? bp->hw_count : 0;
    if (slot_count == 0)
    {
      uint64_t start = bp->address;
      uint64_t end = start + (uint64_t)bp->size;
      if (addr >= start && addr < end)
      {
        found = bp;
        break;
      }
      continue;
    }

    for (int i = 0; i < slot_count; i++)
    {
      const WatchpointSpec *spec = &bp->wp[i];
      uint64_t start = spec->aligned_size ? spec->aligned_start : bp->address;
      uint64_t size = spec->aligned_size ? spec->aligned_size : (uint64_t)bp->size;
      uint64_t end = start + size;
      if (addr >= start && addr < end)
      {
        found = bp;
        break;
      }
    }
    if (found)
      break;
  }

  pthread_mutex_unlock(&dbg->breakpoint_mutex);
  return found;
}

static DebuggerBreakpoint *find_watchpoint_by_hw_index_locked(DebuggerData *dbg, thread_t thread, int hw_index, int *out_slot)
{
  DebuggerBreakpoint *found = NULL;
  for (DebuggerBreakpoint *bp = dbg->breakpoints; bp; bp = bp->next)
  {
    if (bp->bptype == 0 || bp->hw_count <= 0)
      continue;
    if (bp->tid != -1 && bp->tid != thread)
      continue;
    for (int i = 0; i < bp->hw_count; i++)
    {
      if (bp->hw_index[i] == hw_index)
      {
        found = bp;
        if (out_slot)
          *out_slot = i;
        break;
      }
    }
    if (found)
      break;
  }
  return found;
}

static DebuggerBreakpoint *find_watchpoint_by_hw_index(DebuggerData *dbg, thread_t thread, int hw_index, int *out_slot)
{
  DebuggerBreakpoint *found = NULL;
  pthread_mutex_lock(&dbg->breakpoint_mutex);
  found = find_watchpoint_by_hw_index_locked(dbg, thread, hw_index, out_slot);
  pthread_mutex_unlock(&dbg->breakpoint_mutex);
  return found;
}

static int find_breakpoint_base(DebuggerData *dbg, uint64_t addr, uint64_t *base)
{
  int found = 0;
  pthread_mutex_lock(&dbg->breakpoint_mutex);
  for (DebuggerBreakpoint *bp = dbg->breakpoints; bp; bp = bp->next)
  {
    if (bp->bptype != 0 || bp->size <= 0)
      continue;
    if (addr >= bp->address && (addr - bp->address) < (uint64_t)bp->size)
    {
      if (base)
        *base = bp->address;
      found = 1;
      break;
    }
  }
  pthread_mutex_unlock(&dbg->breakpoint_mutex);
  return found;
}

static int get_exception_esr_far(thread_t thread, uint64_t *esr, uint64_t *far)
{
#ifdef ARM_EXCEPTION_STATE64
  arm_exception_state64_t exc;
  mach_msg_type_number_t count = ARM_EXCEPTION_STATE64_COUNT;
  if (thread_get_state(thread, ARM_EXCEPTION_STATE64, (thread_state_t)&exc, &count) != KERN_SUCCESS)
    return 0;
  if (esr)
    *esr = (uint64_t)exc.__esr;
  if (far)
    *far = (uint64_t)exc.__far;
  return 1;
#else
  (void)thread;
  (void)esr;
  (void)far;
  return 0;
#endif
}

static int is_watchpoint_exception_esr(uint64_t esr)
{
  return ((esr >> 26) & 0x3fu) == 0x34u;
}

static int get_watchpoint_hw_index_from_esr(uint64_t esr, uint32_t *out_index)
{
  if (!is_watchpoint_exception_esr(esr))
    return 0;
  uint64_t iss = bits_u64(esr, 23, 0);
  uint32_t wpt = (uint32_t)bits_u64(iss, 23, 18);
  uint32_t wptv = (uint32_t)bit_u64(iss, 17);
  if (!wptv)
    return 0;
  if (out_index)
    *out_index = wpt;
  return 1;
}

static int get_watchpoint_hw_index_from_state(thread_t thread, uint64_t *addr, int *out_index)
{
  if (!addr)
    return 0;

  arm_debug_state64_t dbgstate;
  if (!get_debug_state(thread, &dbgstate, NULL))
    return 0;

  int count = (int)(sizeof(dbgstate.__wcr) / sizeof(dbgstate.__wcr[0]));
  for (int i = 0; i < count; i++)
  {
    uint64_t wcr = dbgstate.__wcr[i];
    if ((wcr & WCR_ENABLE) == 0)
      continue;

    uint64_t wvr = dbgstate.__wvr[i];
    uint32_t mask = (uint32_t)bits_u64(wcr, 28, 24);
    if (mask == 0)
    {
      if (bits_u64(wvr, 48, 3) != bits_u64(*addr, 48, 3))
        continue;

      uint32_t bas = (uint32_t)bits_u64(wcr, 12, 5);
      int lsb = lowest_bit_set_u32(bas);
      if (lsb < 0)
        continue;

      uint32_t byte = (uint32_t)bits_u64(*addr, 2, 0);
      if (bas & (1u << byte))
      {
        *addr = wvr + (uint64_t)lsb;
        if (out_index)
          *out_index = i;
        return 1;
      }
    }
    else
    {
      if (bits_u64(wvr, 48, mask) == bits_u64(*addr, 48, mask))
      {
        if (out_index)
          *out_index = i;
        return 1;
      }
    }
  }

  return 0;
}

static void apply_breakpoints_to_thread(DebuggerData *dbg, thread_t thread)
{
  typedef struct BreakpointApplyItem
  {
    uint64_t address;
    int debugreg;
    int size;
    int bptype;
    int hw_count;
    int hw_index[2];
    WatchpointSpec wp[2];
  } BreakpointApplyItem;

  BreakpointApplyItem *items = NULL;
  size_t count = 0;

  pthread_mutex_lock(&dbg->breakpoint_mutex);
  for (DebuggerBreakpoint *bp = dbg->breakpoints; bp; bp = bp->next)
  {
    if (bp->tid != -1 && bp->tid != thread)
      continue;
    count++;
  }

  if (count > 0)
  {
    items = (BreakpointApplyItem *)calloc(count, sizeof(BreakpointApplyItem));
    if (!items)
    {
      pthread_mutex_unlock(&dbg->breakpoint_mutex);
      return;
    }

    size_t idx = 0;
    for (DebuggerBreakpoint *bp = dbg->breakpoints; bp; bp = bp->next)
    {
      if (bp->tid != -1 && bp->tid != thread)
        continue;
      items[idx].address = bp->address;
      items[idx].debugreg = bp->debugreg;
      items[idx].size = bp->size;
      items[idx].bptype = bp->bptype;
      items[idx].hw_count = bp->hw_count;
      items[idx].hw_index[0] = bp->hw_index[0];
      items[idx].hw_index[1] = bp->hw_index[1];
      items[idx].wp[0] = bp->wp[0];
      items[idx].wp[1] = bp->wp[1];
      idx++;
    }
  }
  pthread_mutex_unlock(&dbg->breakpoint_mutex);

  if (!items)
    return;

  kern_return_t err = KERN_SUCCESS;
  int suspended = 0;
  if (!suspend_thread_for_debug(dbg, thread, &suspended, &err))
  {
    prune_thread_if_invalid(dbg, thread, err);
    free(items);
    return;
  }

  for (size_t i = 0; i < count; i++)
  {
    if (items[i].bptype == 0)
    {
      if (!apply_breakpoint_state(thread, items[i].debugreg, items[i].address, items[i].size, 1, &err))
      {
        prune_thread_if_invalid(dbg, thread, err);
        break;
      }
    }
    else
    {
      DebuggerBreakpoint temp_wp;
      memset(&temp_wp, 0, sizeof(temp_wp));
      temp_wp.bptype = items[i].bptype;
      temp_wp.hw_count = items[i].hw_count;
      temp_wp.hw_index[0] = items[i].hw_index[0];
      temp_wp.hw_index[1] = items[i].hw_index[1];
      temp_wp.wp[0] = items[i].wp[0];
      temp_wp.wp[1] = items[i].wp[1];
      if (!enable_watchpoint_on_thread(dbg, thread, &temp_wp, &err))
      {
        prune_thread_if_invalid(dbg, thread, err);
        break;
      }
    }
  }

  resume_thread_for_debug(dbg, thread, suspended);
  free(items);
}

static void announce_new_thread(DebuggerData *dbg, thread_t thread)
{
  apply_breakpoints_to_thread(dbg, thread);
  DebugEvent create_thread;
  memset(&create_thread, 0, sizeof(create_thread));
  create_thread.debugevent = -1;
  create_thread.threadid = (int64_t)thread;
  queue_event(dbg, &create_thread);
}

static void refresh_thread_list(DebuggerData *dbg, task_t task)
{
  thread_act_array_t threads = NULL;
  mach_msg_type_number_t thread_count = 0;
  if (task_threads(task, &threads, &thread_count) != KERN_SUCCESS)
    return;

  if (!threads || thread_count == 0)
  {
    if (threads)
      mach_vm_deallocate(mach_task_self(), (mach_vm_address_t)threads, thread_count * sizeof(thread_t));
    if (dbg->threads)
    {
      for (mach_msg_type_number_t i = 0; i < dbg->thread_count; i++)
        mach_port_deallocate(mach_task_self(), dbg->threads[i]);
      free(dbg->threads);
      dbg->threads = NULL;
      dbg->thread_count = 0;
    }
    return;
  }

  thread_t *newlist = (thread_t *)malloc(sizeof(thread_t) * thread_count);
  if (!newlist)
  {
    for (mach_msg_type_number_t i = 0; i < thread_count; i++)
      mach_port_deallocate(mach_task_self(), threads[i]);
    mach_vm_deallocate(mach_task_self(), (mach_vm_address_t)threads, thread_count * sizeof(thread_t));
    return;
  }

  mach_msg_type_number_t newcount = 0;
  for (mach_msg_type_number_t i = 0; i < thread_count; i++)
  {
    thread_t thread = threads[i];
    int exists = 0;
    for (mach_msg_type_number_t j = 0; j < dbg->thread_count; j++)
    {
      if (dbg->threads && dbg->threads[j] == thread)
      {
        exists = 1;
        break;
      }
    }

    newlist[newcount++] = thread;
    if (exists)
    {
      mach_port_deallocate(mach_task_self(), thread);
    }
    else
    {
      announce_new_thread(dbg, thread);
    }
  }

  if (dbg->threads)
  {
    for (mach_msg_type_number_t i = 0; i < dbg->thread_count; i++)
    {
      thread_t old = dbg->threads[i];
      int still_present = 0;
      for (mach_msg_type_number_t j = 0; j < newcount; j++)
      {
        if (newlist[j] == old)
        {
          still_present = 1;
          break;
        }
      }
      if (!still_present)
        mach_port_deallocate(mach_task_self(), old);
    }
    free(dbg->threads);
  }

  dbg->threads = newlist;
  dbg->thread_count = newcount;

  if (threads)
    mach_vm_deallocate(mach_task_self(), (mach_vm_address_t)threads, thread_count * sizeof(thread_t));
}

int StartDebug(HANDLE hProcess)
{
  if (GetHandleType(hProcess) != htProcesHandle)
    return FALSE;

  PProcessData p = (PProcessData)GetPointerFromHandle(hProcess);
  if (!p)
    return FALSE;

  pthread_mutex_lock(&g_debugger_lock);
  if (g_debugger_process && g_debugger_process != p)
  {
    pthread_mutex_unlock(&g_debugger_lock);
    debug_log("StartDebug: only one debugged process supported\n");
    return FALSE;
  }
  pthread_mutex_unlock(&g_debugger_lock);

  DebuggerData *dbg = (DebuggerData *)calloc(1, sizeof(DebuggerData));
  if (!dbg)
    return FALSE;

  pthread_mutex_init(&dbg->queue_mutex, NULL);
  pthread_cond_init(&dbg->queue_cond, NULL);
  pthread_mutex_init(&dbg->breakpoint_mutex, NULL);
  dbg->exception_mask = EXC_MASK_BREAKPOINT | EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION | EXC_MASK_ARITHMETIC;
  dbg->task = p->task;

  dbg->saved_count = EXC_TYPES_COUNT;
  kern_return_t kr = task_get_exception_ports(p->task, dbg->exception_mask, dbg->saved_masks, &dbg->saved_count,
                                              dbg->saved_ports, dbg->saved_behaviors, dbg->saved_flavors);
  if (kr != KERN_SUCCESS)
    debug_log("task_get_exception_ports failed: %d\n", kr);

  kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &dbg->exception_port);
  if (kr != KERN_SUCCESS)
  {
    debug_log("mach_port_allocate failed: %d\n", kr);
    free(dbg);
    return FALSE;
  }

  kr = mach_port_insert_right(mach_task_self(), dbg->exception_port, dbg->exception_port, MACH_MSG_TYPE_MAKE_SEND);
  if (kr != KERN_SUCCESS)
  {
    debug_log("mach_port_insert_right failed: %d\n", kr);
    mach_port_deallocate(mach_task_self(), dbg->exception_port);
    free(dbg);
    return FALSE;
  }

  kr = task_set_exception_ports(p->task, dbg->exception_mask, dbg->exception_port,
                                EXCEPTION_DEFAULT, THREAD_STATE_NONE);
  if (kr != KERN_SUCCESS)
  {
    debug_log("task_set_exception_ports failed: %d\n", kr);
    mach_port_deallocate(mach_task_self(), dbg->exception_port);
    free(dbg);
    return FALSE;
  }

  dbg->exception_thread_running = 1;
  p->debuggerData = dbg;

  pthread_mutex_lock(&g_debugger_lock);
  g_debugger_process = p;
  pthread_mutex_unlock(&g_debugger_lock);

  if (pthread_create(&dbg->exception_thread, NULL, exception_thread_main, p) != 0)
  {
    debug_log("Failed to create exception thread\n");
    StopDebug(hProcess);
    return FALSE;
  }
  dbg->exception_thread_started = 1;

  DebugEvent create_process;
  memset(&create_process, 0, sizeof(create_process));
  create_process.debugevent = -2;
  create_process.threadid = p->pid;
  create_process.maxBreakpointCount = get_breakpoint_count();
  create_process.maxWatchpointCount = get_watchpoint_count();
  create_process.maxSharedBreakpoints = 0;
  queue_event(dbg, &create_process);

  mach_msg_type_number_t thread_count = 0;
  thread_act_array_t threads = NULL;
  kr = task_threads(p->task, &threads, &thread_count);
  if (kr == KERN_SUCCESS && thread_count > 0)
  {
    dbg->threads = (thread_t *)malloc(sizeof(thread_t) * thread_count);
    if (dbg->threads)
    {
      dbg->thread_count = thread_count;
      for (mach_msg_type_number_t i = 0; i < thread_count; i++)
      {
        dbg->threads[i] = threads[i];
        DebugEvent create_thread;
        memset(&create_thread, 0, sizeof(create_thread));
        create_thread.debugevent = -1;
        create_thread.threadid = (int64_t)threads[i];
        queue_event(dbg, &create_thread);
      }
    }
    else
    {
      for (mach_msg_type_number_t i = 0; i < thread_count; i++)
        mach_port_deallocate(mach_task_self(), threads[i]);
    }
    mach_vm_deallocate(mach_task_self(), (mach_vm_address_t)threads, thread_count * sizeof(thread_t));
  }

  debug_log("StartDebug(%d) ok\n", hProcess);
  return TRUE;
}

int StopDebug(HANDLE hProcess)
{
  if (GetHandleType(hProcess) != htProcesHandle)
    return FALSE;

  PProcessData p = (PProcessData)GetPointerFromHandle(hProcess);
  if (!p || !p->debuggerData)
    return FALSE;

  DebuggerData *dbg = (DebuggerData *)p->debuggerData;
  dbg->exception_thread_running = 0;

  if (dbg->exception_port != MACH_PORT_NULL)
    mach_port_destroy(mach_task_self(), dbg->exception_port);

  if (dbg->exception_thread_started)
    pthread_join(dbg->exception_thread, NULL);

  if (dbg->exception_thread_port != MACH_PORT_NULL)
  {
    mach_port_deallocate(mach_task_self(), dbg->exception_thread_port);
    dbg->exception_thread_port = MACH_PORT_NULL;
  }

  if (dbg->saved_count > 0)
  {
    for (mach_msg_type_number_t i = 0; i < dbg->saved_count; i++)
    {
      task_set_exception_ports(p->task, dbg->saved_masks[i], dbg->saved_ports[i],
                               dbg->saved_behaviors[i], dbg->saved_flavors[i]);
    }
  }

  pthread_mutex_lock(&g_debugger_lock);
  if (g_debugger_process == p)
    g_debugger_process = NULL;
  pthread_mutex_unlock(&g_debugger_lock);

  if (dbg->threads)
  {
    for (mach_msg_type_number_t i = 0; i < dbg->thread_count; i++)
      mach_port_deallocate(mach_task_self(), dbg->threads[i]);
    free(dbg->threads);
  }

  while (dbg->pending_head)
  {
    reply_pending_exception(dbg, dbg->pending_head->thread, KERN_SUCCESS);
  }

  DebugEventQueueElement *elem = dbg->queue_head;
  while (elem)
  {
    DebugEventQueueElement *next = elem->next;
    free(elem);
    elem = next;
  }

  DebuggerBreakpoint *bp = dbg->breakpoints;
  while (bp)
  {
    DebuggerBreakpoint *next = bp->next;
    free(bp);
    bp = next;
  }

  pthread_mutex_destroy(&dbg->queue_mutex);
  pthread_cond_destroy(&dbg->queue_cond);
  pthread_mutex_destroy(&dbg->breakpoint_mutex);
  free(dbg);
  p->debuggerData = NULL;

  debug_log("StopDebug(%d) ok\n", hProcess);
  return TRUE;
}

int WaitForDebugEvent(HANDLE hProcess, PDebugEvent devent, int timeout)
{
  if (GetHandleType(hProcess) != htProcesHandle)
    return FALSE;

  PProcessData p = (PProcessData)GetPointerFromHandle(hProcess);
  if (!p || !p->debuggerData)
    return FALSE;

  DebuggerData *dbg = (DebuggerData *)p->debuggerData;
  if (!devent)
    return FALSE;

  refresh_thread_list(dbg, p->task);
  int ok = wait_for_event(dbg, devent, timeout);
  return ok;
}

int ContinueFromDebugEvent(HANDLE hProcess, int tid, int ignoresignal)
{
  if (GetHandleType(hProcess) != htProcesHandle)
    return FALSE;

  PProcessData p = (PProcessData)GetPointerFromHandle(hProcess);
  if (!p || !p->debuggerData)
    return FALSE;

  thread_t thread = (thread_t)tid;
  if (thread == MACH_PORT_NULL)
    return FALSE;

  DebuggerData *dbg = (DebuggerData *)p->debuggerData;
  if (ignoresignal == 2)
  {
    if (set_single_step(thread, 1))
      dbg->single_step_thread = thread;
  }

  {
    reply_all_pending_for_thread(dbg, thread, KERN_SUCCESS);
  }

  return TRUE;
}

int GetDebugPort(HANDLE hProcess)
{
  (void)hProcess;
  return -1;
}

int SetBreakpoint(HANDLE hProcess, int tid, int debugreg, void *address, int bptype, int bpsize)
{
  if (GetHandleType(hProcess) != htProcesHandle)
    return FALSE;

  if (bptype < 0 || bptype > 3)
    return FALSE;

  PProcessData p = (PProcessData)GetPointerFromHandle(hProcess);
  if (!p || !p->debuggerData)
    return FALSE;

  DebuggerData *dbg = (DebuggerData *)p->debuggerData;
  uint64_t addr = (uint64_t)(uintptr_t)address;
  int size = 4;
  if (bptype == 0)
  {
    if (bpsize == 1)
      size = 1;
    else if (bpsize == 2)
      size = 2;
  }
  else
  {
    size = bpsize > 0 ? bpsize : 1;
  }

  WatchpointSpec wp_specs[2];
  int wp_spec_count = 0;
  int wp_hw_index[2] = {-1, -1};
  if (bptype != 0)
  {
    wp_spec_count = align_requested_watchpoint(addr, (uint64_t)size, wp_specs, 2);
    if (wp_spec_count == 0)
      return FALSE;
  }

  pthread_mutex_lock(&dbg->breakpoint_mutex);
  DebuggerBreakpoint *bp = dbg->breakpoints;
  while (bp)
  {
    if (bp->address == addr && bp->debugreg == debugreg && bp->tid == (thread_t)tid &&
        bp->bptype == bptype && bp->size == size)
    {
      DebuggerBreakpoint existing;
      int have_existing = 0;
      if (bptype != 0)
      {
        existing = *bp;
        have_existing = 1;
      }
      pthread_mutex_unlock(&dbg->breakpoint_mutex);
      if (!have_existing)
        return TRUE;

      {
        int re_ok = 0;
        if (tid != -1)
        {
          kern_return_t err = KERN_SUCCESS;
          int suspended = 0;
          if (!suspend_thread_for_debug(dbg, (thread_t)tid, &suspended, &err))
          {
            prune_thread_if_invalid(dbg, (thread_t)tid, err);
            return FALSE;
          }
          if (enable_watchpoint_on_thread(dbg, (thread_t)tid, &existing, &err))
            re_ok = 1;
          else
            prune_thread_if_invalid(dbg, (thread_t)tid, err);
          resume_thread_for_debug(dbg, (thread_t)tid, suspended);
        }
        else if (dbg->threads && dbg->thread_count > 0)
        {
          re_ok = apply_watchpoint_state_transaction(dbg, dbg->threads, dbg->thread_count,
                                                     existing.wp, existing.hw_index, existing.hw_count, existing.bptype, 1);
          if (!re_ok)
            re_ok = apply_watchpoint_state_best_effort(dbg, existing.wp, existing.hw_index, existing.hw_count, existing.bptype, 1);
        }
        return re_ok ? TRUE : FALSE;
      }
    }
    bp = bp->next;
  }

  if (bptype != 0)
  {
    if (!allocate_watchpoint_hw_indices_locked(dbg, wp_spec_count, wp_hw_index))
    {
      pthread_mutex_unlock(&dbg->breakpoint_mutex);
      return FALSE;
    }
  }

  pthread_mutex_unlock(&dbg->breakpoint_mutex);

  DebuggerBreakpoint temp_wp;
  if (bptype != 0)
  {
    memset(&temp_wp, 0, sizeof(temp_wp));
    temp_wp.bptype = bptype;
    temp_wp.hw_count = wp_spec_count;
    temp_wp.hw_index[0] = wp_hw_index[0];
    temp_wp.hw_index[1] = wp_hw_index[1];
    if (wp_spec_count > 0)
    {
      temp_wp.wp[0] = wp_specs[0];
      temp_wp.wp[1] = wp_spec_count > 1 ? wp_specs[1] : wp_specs[0];
    }
  }

  int ok = 0;
  if (tid != -1)
  {
    kern_return_t err = KERN_SUCCESS;
    int suspended = 0;
    if (!suspend_thread_for_debug(dbg, (thread_t)tid, &suspended, &err))
    {
      prune_thread_if_invalid(dbg, (thread_t)tid, err);
      return FALSE;
    }
    if ((bptype == 0)
          ? apply_breakpoint_state((thread_t)tid, debugreg, addr, size, 1, &err)
          : enable_watchpoint_on_thread(dbg, (thread_t)tid, &temp_wp, &err))
    {
      ok = 1;
    }
    else
    {
      prune_thread_if_invalid(dbg, (thread_t)tid, err);
    }
    resume_thread_for_debug(dbg, (thread_t)tid, suspended);
  }
  else if (dbg->threads && dbg->thread_count > 0)
  {
    if (bptype == 0)
    {
      ok = apply_breakpoint_state_transaction(dbg, dbg->threads, dbg->thread_count, debugreg, addr, size, 1);
      if (!ok)
        ok = apply_breakpoint_state_best_effort(dbg, debugreg, addr, size, 1);
    }
    else
    {
      ok = apply_watchpoint_state_transaction(dbg, dbg->threads, dbg->thread_count,
                                              temp_wp.wp, temp_wp.hw_index, temp_wp.hw_count, bptype, 1);
      if (!ok)
        ok = apply_watchpoint_state_best_effort(dbg, temp_wp.wp, temp_wp.hw_index, temp_wp.hw_count, bptype, 1);
    }
  }
  if (!ok)
    return FALSE;

  DebuggerBreakpoint *nb = (DebuggerBreakpoint *)malloc(sizeof(DebuggerBreakpoint));
  if (!nb)
    return FALSE;
  nb->address = addr;
  nb->debugreg = debugreg;
  nb->size = size;
  nb->bptype = bptype;
  nb->tid = (thread_t)tid;
  nb->hw_count = wp_spec_count;
  nb->hw_index[0] = wp_hw_index[0];
  nb->hw_index[1] = wp_hw_index[1];
  if (wp_spec_count > 0)
  {
    nb->wp[0] = wp_specs[0];
    nb->wp[1] = wp_spec_count > 1 ? wp_specs[1] : wp_specs[0];
  }
  pthread_mutex_lock(&dbg->breakpoint_mutex);
  nb->next = dbg->breakpoints;
  dbg->breakpoints = nb;
  pthread_mutex_unlock(&dbg->breakpoint_mutex);

  return TRUE;
}

int RemoveBreakpoint(HANDLE hProcess, int tid, int debugreg, int wasWatchpoint)
{
  if (GetHandleType(hProcess) != htProcesHandle)
    return FALSE;

  PProcessData p = (PProcessData)GetPointerFromHandle(hProcess);
  if (!p || !p->debuggerData)
    return FALSE;

  DebuggerData *dbg = (DebuggerData *)p->debuggerData;

  int ok = 0;

  if (!wasWatchpoint)
  {
    if (tid != -1)
    {
      kern_return_t err = KERN_SUCCESS;
      int suspended = 0;
      if (!suspend_thread_for_debug(dbg, (thread_t)tid, &suspended, &err))
      {
        prune_thread_if_invalid(dbg, (thread_t)tid, err);
        return FALSE;
      }
      if (apply_breakpoint_state((thread_t)tid, debugreg, 0, 0, 0, &err))
      {
        ok = 1;
      }
      else
      {
        prune_thread_if_invalid(dbg, (thread_t)tid, err);
      }
      resume_thread_for_debug(dbg, (thread_t)tid, suspended);
    }
    else if (dbg->threads && dbg->thread_count > 0)
    {
      ok = apply_breakpoint_state_transaction(dbg, dbg->threads, dbg->thread_count, debugreg, 0, 0, 0);
      if (!ok)
        ok = apply_breakpoint_state_best_effort(dbg, debugreg, 0, 0, 0);
    }

    pthread_mutex_lock(&dbg->breakpoint_mutex);
    DebuggerBreakpoint **cur = &dbg->breakpoints;
    while (*cur)
    {
      if ((*cur)->debugreg == debugreg &&
          ((*cur)->tid == (thread_t)tid || tid == -1) &&
          (*cur)->bptype == 0)
      {
        DebuggerBreakpoint *dead = *cur;
        *cur = dead->next;
        free(dead);
        if (tid != -1)
          break;
        continue;
      }
      cur = &(*cur)->next;
    }
    pthread_mutex_unlock(&dbg->breakpoint_mutex);
    return ok ? TRUE : FALSE;
  }

  typedef struct WatchpointRemoveItem
  {
    DebuggerBreakpoint bp;
    int disable_ok;
    struct WatchpointRemoveItem *next;
  } WatchpointRemoveItem;

  WatchpointRemoveItem *targets = NULL;
  WatchpointRemoveItem *tmp = NULL;

  pthread_mutex_lock(&dbg->breakpoint_mutex);
  DebuggerBreakpoint *entry = dbg->breakpoints;
  while (entry)
  {
    if (entry->debugreg == debugreg &&
        (tid == -1 || entry->tid == (thread_t)tid || entry->tid == (thread_t)-1) &&
        entry->bptype != 0)
    {
      WatchpointRemoveItem *copy = (WatchpointRemoveItem *)calloc(1, sizeof(WatchpointRemoveItem));
      if (copy)
      {
        copy->bp = *entry;
        copy->disable_ok = 0;
        copy->next = targets;
        targets = copy;
      }
      if (tid != -1)
        break;
    }
    entry = entry->next;
  }
  pthread_mutex_unlock(&dbg->breakpoint_mutex);

  if (tid != -1)
  {
    tmp = targets;
    while (tmp)
    {
      kern_return_t err = KERN_SUCCESS;
      int suspended = 0;
      if (!suspend_thread_for_debug(dbg, (thread_t)tid, &suspended, &err))
      {
        prune_thread_if_invalid(dbg, (thread_t)tid, err);
      }
      else
      {
        if (disable_watchpoint_on_thread((thread_t)tid, &tmp->bp, &err))
          ok = 1;
        else
          prune_thread_if_invalid(dbg, (thread_t)tid, err);
        resume_thread_for_debug(dbg, (thread_t)tid, suspended);
      }
      tmp = tmp->next;
    }

    while (targets)
    {
      tmp = targets;
      targets = targets->next;
      free(tmp);
    }
    return ok ? TRUE : FALSE;
  }

  tmp = targets;
  while (tmp)
  {
    if (dbg->threads && dbg->thread_count > 0)
    {
      if (apply_watchpoint_state_transaction(dbg, dbg->threads, dbg->thread_count,
                                             tmp->bp.wp, tmp->bp.hw_index, tmp->bp.hw_count, tmp->bp.bptype, 0))
      {
        ok = 1;
        tmp->disable_ok = 1;
      }
      else if (apply_watchpoint_state_best_effort(dbg, tmp->bp.wp, tmp->bp.hw_index, tmp->bp.hw_count, tmp->bp.bptype, 0))
      {
        ok = 1;
        tmp->disable_ok = 1;
      }
    }
    tmp = tmp->next;
  }

  pthread_mutex_lock(&dbg->breakpoint_mutex);
  while (targets)
  {
    WatchpointRemoveItem *copy = targets;
    targets = targets->next;

    if (copy->disable_ok)
    {
      DebuggerBreakpoint **cur = &dbg->breakpoints;
      while (*cur)
      {
        DebuggerBreakpoint *bp = *cur;
        if (bp->debugreg == copy->bp.debugreg &&
            bp->address == copy->bp.address &&
            bp->size == copy->bp.size &&
            ((bp->tid == (thread_t)tid) || tid == -1) &&
            bp->bptype != 0)
        {
          *cur = bp->next;
          free(bp);
          if (tid != -1)
            break;
          continue;
        }
        cur = &(*cur)->next;
      }
    }

    free(copy);
  }
  pthread_mutex_unlock(&dbg->breakpoint_mutex);

  return ok ? TRUE : FALSE;
}

int SuspendThread(HANDLE hProcess, int tid)
{
  (void)hProcess;
  thread_t thread = (thread_t)tid;
  if (thread == MACH_PORT_NULL)
    return FALSE;
  return thread_suspend(thread) == KERN_SUCCESS;
}

int ResumeThread(HANDLE hProcess, int tid)
{
  (void)hProcess;
  thread_t thread = (thread_t)tid;
  if (thread == MACH_PORT_NULL)
    return FALSE;
  return thread_resume(thread) == KERN_SUCCESS;
}

BOOL GetThreadContext(HANDLE hProcess, int tid, PCONTEXT Context)
{
  if (GetHandleType(hProcess) != htProcesHandle || !Context)
    return FALSE;

  thread_t thread = (thread_t)tid;
  if (thread == MACH_PORT_NULL)
    return FALSE;

  fill_context_from_thread(thread, Context);
  return TRUE;
}

BOOL SetThreadContext(HANDLE hProcess, int tid, PCONTEXT Context)
{
  if (GetHandleType(hProcess) != htProcesHandle || !Context)
    return FALSE;

  thread_t thread = (thread_t)tid;
  if (thread == MACH_PORT_NULL)
    return FALSE;

  arm_thread_state64_t gpr;
  mach_msg_type_number_t gpr_count = ARM_THREAD_STATE64_COUNT;
  if (thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&gpr, &gpr_count) != KERN_SUCCESS)
    return FALSE;

  for (int i = 0; i < 29; i++)
    gpr.__x[i] = Context->regs.regs[i];
  gpr.__fp = Context->regs.regs[29];
  gpr.__lr = Context->regs.regs[30];
  gpr.__sp = Context->regs.sp;
  gpr.__pc = Context->regs.pc;
  gpr.__cpsr = (uint32_t)Context->regs.pstate;

  if (thread_set_state(thread, ARM_THREAD_STATE64, (thread_state_t)&gpr, ARM_THREAD_STATE64_COUNT) != KERN_SUCCESS)
    return FALSE;

  arm_neon_state64_t neon;
  mach_msg_type_number_t neon_count = ARM_NEON_STATE64_COUNT;
  if (thread_get_state(thread, ARM_NEON_STATE64, (thread_state_t)&neon, &neon_count) != KERN_SUCCESS)
    return FALSE;

  memcpy(neon.__v, Context->fp.vregs, sizeof(neon.__v));
  neon.__fpsr = Context->fp.fpsr;
  neon.__fpcr = Context->fp.fpcr;

  if (thread_set_state(thread, ARM_NEON_STATE64, (thread_state_t)&neon, ARM_NEON_STATE64_COUNT) != KERN_SUCCESS)
    return FALSE;

  return TRUE;
}

int WakeDebuggerThread(void)
{
  return 0;
}
