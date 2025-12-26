#include "api.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <limits.h>
#include <mach-o/loader.h>
#include <mach/mach_host.h>
#include <mach/vm_region.h>
#include <mach/mach_vm.h>
#include <pthread.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <uuid/uuid.h>

#include "debugger.h"

extern kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size,
                                            mach_vm_address_t data, mach_vm_size_t *outsize);
extern kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);

int debug_log(const char *format, ...)
{
  (void)format;
  return 0;
}

int getArchitecture(HANDLE hProcess)
{
  if (GetHandleType(hProcess) == htProcesHandle)
  {

    return 3;
  }

  return -1;
}

static int SearchHandleListProcessCallback(PProcessData data, int *pid)
{
  return (data->pid == *pid);
}

static int read_target(task_t task, mach_vm_address_t address, void *buf, size_t size)
{
  if (address == 0 || buf == NULL || size == 0)
    return 0;
  if (size > (size_t)INT_MAX)
    return 0;

  mach_vm_size_t outsize = 0;
  kern_return_t kr = mach_vm_read_overwrite(task, address, (mach_vm_size_t)size, (mach_vm_address_t)buf, &outsize);
  if (kr != KERN_SUCCESS)
    return 0;

  if (outsize > (mach_vm_size_t)INT_MAX)
    return 0;

  return (int)outsize;
}

static int read_target_exact(task_t task, mach_vm_address_t address, void *buf, size_t size)
{
  return read_target(task, address, buf, size) == (int)size;
}

static int is_macho64_magic(uint32_t magic)
{
  return (magic == MH_MAGIC_64) || (magic == MH_CIGAM_64);
}

static uint32_t bswap32_if_needed(uint32_t x, int swapped)
{
  return swapped ? __builtin_bswap32(x) : x;
}

static uint64_t bswap64_if_needed(uint64_t x, int swapped)
{
  return swapped ? __builtin_bswap64(x) : x;
}

typedef void *dyld_process_info;
typedef void *(*dyld_process_info_create_fn)(task_t task, uint64_t timestamp, kern_return_t *kernelError);
typedef void (^dyld_process_info_image_callback)(uint64_t machHeaderAddress, const uuid_t uuid, const char *path);
typedef void (*dyld_process_info_for_each_image_fn)(dyld_process_info info, dyld_process_info_image_callback callback);
typedef void (*dyld_process_info_release_fn)(dyld_process_info info);

typedef struct
{
  dyld_process_info_create_fn create;
  dyld_process_info_for_each_image_fn for_each_image;
  dyld_process_info_release_fn release;
} DyldSPI;

static DyldSPI dyld_spi = {0};
static pthread_once_t dyld_spi_once = PTHREAD_ONCE_INIT;

typedef struct
{
  uint64_t load_address;
  char *path;
} DyldImageInfo;

typedef struct
{
  DyldImageInfo *items;
  size_t count;
  size_t cap;
} DyldImageList;

typedef struct
{
  uint64_t *items;
  size_t count;
  size_t cap;
} AddressSet;

static void init_dyld_spi(void)
{
  dyld_spi.create = (dyld_process_info_create_fn)dlsym(RTLD_DEFAULT, "_dyld_process_info_create");
  dyld_spi.for_each_image = (dyld_process_info_for_each_image_fn)dlsym(RTLD_DEFAULT, "_dyld_process_info_for_each_image");
  dyld_spi.release = (dyld_process_info_release_fn)dlsym(RTLD_DEFAULT, "_dyld_process_info_release");
}

static void dyld_image_list_free(DyldImageList *list)
{
  if (!list || !list->items)
    return;

  for (size_t i = 0; i < list->count; i++)
    free(list->items[i].path);
  free(list->items);
  list->items = NULL;
  list->count = 0;
  list->cap = 0;
}

static int dyld_image_list_append(DyldImageList *list, uint64_t load_address, const char *path)
{
  if (!list)
    return 0;

  if (list->count >= list->cap)
  {
    size_t newcap = (list->cap == 0) ? 64 : list->cap * 2;
    void *newp = realloc(list->items, newcap * sizeof(DyldImageInfo));
    if (!newp)
      return 0;
    list->items = (DyldImageInfo *)newp;
    list->cap = newcap;
  }

  DyldImageInfo *entry = &list->items[list->count++];
  entry->load_address = load_address;
  entry->path = strdup(path);
  if (!entry->path)
    return 0;
  return 1;
}

static void address_set_free(AddressSet *set)
{
  if (!set)
    return;
  free(set->items);
  set->items = NULL;
  set->count = 0;
  set->cap = 0;
}

static int address_set_add(AddressSet *set, uint64_t addr)
{
  if (!set)
    return -1;

  for (size_t i = 0; i < set->count; i++)
  {
    if (set->items[i] == addr)
      return 0;
  }

  if (set->count >= set->cap)
  {
    size_t newcap = (set->cap == 0) ? 64 : set->cap * 2;
    void *newp = realloc(set->items, newcap * sizeof(uint64_t));
    if (!newp)
      return -1;
    set->items = (uint64_t *)newp;
    set->cap = newcap;
  }

  set->items[set->count++] = addr;
  return 1;
}

static int collect_dyld_spi_images(task_t task, DyldImageList *list)
{
  if (!list)
    return 0;

  pthread_once(&dyld_spi_once, init_dyld_spi);
  if (!dyld_spi.create || !dyld_spi.for_each_image || !dyld_spi.release)
    return 0;

  kern_return_t kr = KERN_FAILURE;
  dyld_process_info info = dyld_spi.create(task, 0, &kr);
  if (!info)
    return 0;

  __block int ok = 1;
  __block AddressSet seen = {0};
  __block DyldImageList *out = list;

  dyld_spi.for_each_image(info, ^(uint64_t machHeaderAddress, const uuid_t uuid, const char *path) {
    (void)uuid;
    if (!ok)
      return;
    uint64_t addr = machHeaderAddress;
    int add = address_set_add(&seen, addr);
    if (add <= 0)
    {
      if (add < 0)
        ok = 0;
      return;
    }
    if (!dyld_image_list_append(out, addr, path))
      ok = 0;
  });

  dyld_spi.release(info);
  address_set_free(&seen);

  if (!ok)
  {
    dyld_image_list_free(list);
    return 0;
  }

  return list->count > 0;
}

static uint64_t get_macho_image_size_64(task_t task, mach_vm_address_t base)
{
  struct mach_header_64 hdr;
  if (!read_target_exact(task, base, &hdr, sizeof(hdr)))
    return 0;

  if (!is_macho64_magic(hdr.magic))
    return 0;

  int swapped = (hdr.magic == MH_CIGAM_64);
  uint32_t ncmds = bswap32_if_needed(hdr.ncmds, swapped);
  uint32_t sizeofcmds = bswap32_if_needed(hdr.sizeofcmds, swapped);

  mach_vm_address_t cursor = base + sizeof(struct mach_header_64);
  mach_vm_address_t end = cursor + (mach_vm_address_t)sizeofcmds;
  if (end < cursor)
    return 0;

  uint64_t min_vmaddr = UINT64_MAX;
  uint64_t max_end = 0;


  if (ncmds > 4096)
    return 0;
  if (sizeofcmds > (16U * 1024U * 1024U))
    return 0;

  for (uint32_t i = 0; i < ncmds; i++)
  {
    struct load_command lc;
    if (cursor + sizeof(struct load_command) > end)
      return 0;

    if (!read_target_exact(task, cursor, &lc, sizeof(lc)))
      return 0;

    uint32_t cmd = bswap32_if_needed(lc.cmd, swapped);
    uint32_t cmdsize = bswap32_if_needed(lc.cmdsize, swapped);
    if (cmdsize < sizeof(struct load_command))
      return 0;
    if (cursor + cmdsize > end)
      return 0;

    if (cmd == LC_SEGMENT_64)
    {
      struct segment_command_64 seg;
      if (cmdsize < sizeof(struct segment_command_64))
        return 0;

      if (!read_target_exact(task, cursor, &seg, sizeof(seg)))
        return 0;


      if (strncmp(seg.segname, "__PAGEZERO", 16) != 0)
      {
        uint64_t vmaddr = bswap64_if_needed(seg.vmaddr, swapped);
        uint64_t vmsize = bswap64_if_needed(seg.vmsize, swapped);

        if (vmaddr < min_vmaddr)
          min_vmaddr = vmaddr;


        if (UINT64_MAX - vmaddr < vmsize)
          return 0;

        uint64_t endaddr = vmaddr + vmsize;
        if (endaddr > max_end)
          max_end = endaddr;
      }
    }

    cursor += cmdsize;
  }

  if (min_vmaddr == UINT64_MAX || max_end <= min_vmaddr)
    return 0;

  return max_end - min_vmaddr;
}

static int get_exec_path_sysctl(int pid, char *out, size_t outcap)
{
  if (outcap == 0)
    return 0;

  out[0] = 0;

  int mib[3] = {CTL_KERN, KERN_PROCARGS2, pid};
  size_t size = 0;
  if (sysctl(mib, 3, NULL, &size, NULL, 0) != 0 || size < sizeof(int))
    return 0;

  char *buf = (char *)malloc(size);
  if (!buf)
    return 0;

  if (sysctl(mib, 3, buf, &size, NULL, 0) != 0 || size < sizeof(int))
  {
    free(buf);
    return 0;
  }


  size_t pos = sizeof(int);
  while (pos < size && buf[pos] == '\0')
    pos++;

  size_t i = 0;
  while (pos < size && buf[pos] != '\0' && i + 1 < outcap)
    out[i++] = buf[pos++];
  out[i] = 0;

  free(buf);
  return i > 0;
}

static uint32_t vm_prot_to_page(uint32_t protectioninfo)
{
  
  int r = (protectioninfo & VM_PROT_READ) ? 1 : 0;
  int w = (protectioninfo & VM_PROT_WRITE) ? 1 : 0;
  int x = (protectioninfo & VM_PROT_EXECUTE) ? 1 : 0;

  if (r && w && x)
    return PAGE_EXECUTE_READWRITE;
  if (r && x)
    return PAGE_EXECUTE_READ;
  if (x)
    return PAGE_EXECUTE;
  if (r && w)
    return PAGE_READWRITE;
  if (w)
    return PAGE_READWRITE;
  if (r)
    return PAGE_READONLY;
  return PAGE_NOACCESS;
}

static uint32_t vm_info_to_type(const vm_region_submap_info_data_64_t *info)
{
#if defined(SM_PRIVATE) && defined(SM_COW) && defined(SM_SHARED)
  switch (info->share_mode)
  {
    case SM_PRIVATE:
    case SM_COW:
      return MEM_PRIVATE;
    case SM_SHARED:
    case SM_TRUESHARED:
#ifdef SM_SHARED_ALIASED
    case SM_SHARED_ALIASED:
#endif
      return MEM_MAPPED;
    default:

      return MEM_PRIVATE;
  }
#else
  (void)info;
  return MEM_PRIVATE;
#endif
}

static uint32_t windows_protection_to_vmprot(uint32_t windowsprotection)
{
  
  switch (windowsprotection)
  {
    case PAGE_NOACCESS:
      return VM_PROT_NONE;
    case PAGE_EXECUTE_READWRITE:
      return VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE;
    case PAGE_EXECUTE_READ:
      return VM_PROT_READ | VM_PROT_EXECUTE;
    case PAGE_EXECUTE:
      return VM_PROT_EXECUTE;
    case PAGE_READWRITE:
      return VM_PROT_READ | VM_PROT_WRITE;
    case PAGE_READONLY:
      return VM_PROT_READ;
    default:
      return 0;
  }
}

static pthread_once_t pagesize_once = PTHREAD_ONCE_INIT;
static uint64_t pagesize_cached = 0;

static void init_pagesize(void)
{
  long p = sysconf(_SC_PAGESIZE);
  if (p > 0)
  {
    uint64_t ps = (uint64_t)p;
    if ((ps & (ps - 1)) == 0)
    {
      pagesize_cached = ps;
      return;
    }
  }

  vm_size_t hostps = 0;
  mach_port_t host = mach_host_self();
  if (host_page_size(host, &hostps) == KERN_SUCCESS && hostps > 0)
  {
    uint64_t ps = (uint64_t)hostps;
    if ((ps & (ps - 1)) == 0)
    {
      pagesize_cached = ps;
      mach_port_deallocate(mach_task_self(), host);
      return;
    }
  }
  mach_port_deallocate(mach_task_self(), host);


  pagesize_cached = 4096;
}

static uint64_t get_page_size(void)
{
  pthread_once(&pagesize_once, init_pagesize);
  return pagesize_cached;
}


static void pageprot_to_perms(uint32_t pageprot, int shared, char perms[5])
{
  perms[0] = perms[1] = perms[2] = '-';
  perms[3] = shared ? 's' : 'p';

  switch (pageprot)
  {
    case PAGE_EXECUTE_READWRITE:
      perms[0] = 'r'; perms[1] = 'w'; perms[2] = 'x'; break;
    case PAGE_EXECUTE_READ:
      perms[0] = 'r'; perms[1] = '-'; perms[2] = 'x'; break;
    case PAGE_EXECUTE:
      perms[0] = '-'; perms[1] = '-'; perms[2] = 'x'; break;
    case PAGE_READWRITE:
      perms[0] = 'r'; perms[1] = 'w'; perms[2] = '-'; break;
    case PAGE_READONLY:
      perms[0] = 'r'; perms[1] = '-'; perms[2] = '-'; break;
    default:
      break;
  }
  perms[4] = 0;
}


static int query_leaf_region(task_t task,
                             mach_vm_address_t probe,
                             mach_vm_address_t *out_base,
                             mach_vm_size_t *out_size,
                             vm_region_submap_info_data_64_t *out_info)
{
  mach_vm_address_t want = probe;
  mach_vm_address_t addr = probe;
  natural_t depth = 0;

  while (1)
  {
    mach_vm_address_t q = addr;
    mach_vm_size_t vmsize = 0;
    vm_region_submap_info_data_64_t info;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;

    kern_return_t kr = mach_vm_region_recurse(task, &q, &vmsize, &depth, (vm_region_recurse_info_t)&info, &info_count);
    if (kr != KERN_SUCCESS)
      return 0;

    if (!info.is_submap)
    {
      *out_base = q;
      *out_size = vmsize;
      *out_info = info;
      return 1;
    }

    if (++depth > 64)
      return 0;


    if (vmsize != 0 && want >= q && want - q < vmsize)
      addr = want;
    else
      addr = q;
  }
}

int VirtualQueryEx(HANDLE hProcess, void *lpAddress, PRegionInfo rinfo, char *mapsline)
{
  if (mapsline)
    mapsline[0] = 0;

  if (GetHandleType(hProcess) != htProcesHandle)
    return 0;


  if (rinfo == NULL)
    return 0;

  PProcessData p = (PProcessData)GetPointerFromHandle(hProcess);

  uint64_t start = (uint64_t)(uintptr_t)lpAddress;
  uint64_t pagesize = get_page_size();
  if (pagesize == 0 || (pagesize & (pagesize - 1)) != 0)
    return 0;
  uint64_t pagemask = ~(pagesize - 1);
  uint64_t pagebase = start & pagemask;
  mach_vm_address_t probe = (mach_vm_address_t)pagebase;

  mach_vm_address_t region_base = 0;
  mach_vm_size_t vmsize = 0;
  vm_region_submap_info_data_64_t info;

  if (!query_leaf_region(p->task, probe, &region_base, &vmsize, &info))
    return 0;


  if ((uint64_t)region_base > pagebase)
  {
    rinfo->baseaddress = pagebase;
    rinfo->size = (uint64_t)region_base - pagebase;
    rinfo->protection = PAGE_NOACCESS;
    rinfo->type = 0;
    if (mapsline)
    {
      uint64_t region_start = (uint64_t)region_base;
      uint64_t region_size = (uint64_t)vmsize;
      if (UINT64_MAX - region_start < region_size)
        region_size = 0;
      uint64_t region_end = region_start + region_size;
      uint32_t p = vm_prot_to_page(info.protection);
      char perms[5];
      int shared = 0;
#if defined(SM_SHARED) && defined(SM_TRUESHARED)
      if (info.share_mode == SM_SHARED || info.share_mode == SM_TRUESHARED
#ifdef SM_SHARED_ALIASED
          || info.share_mode == SM_SHARED_ALIASED
#endif
      )
        shared = 1;
#endif
      pageprot_to_perms(p, shared, perms);

      snprintf(mapsline, 200, "%016llx-%016llx %s %016llx 00:00 0", (unsigned long long)region_start,
               (unsigned long long)region_end, perms, (unsigned long long)info.offset);
      mapsline[199] = 0;
    }
    return 1;
  }


  uint64_t region_start = (uint64_t)region_base;
  uint64_t region_size = (uint64_t)vmsize;
  if (UINT64_MAX - region_start < region_size)
    return 0;
  uint64_t region_end = region_start + region_size;
  if (region_end <= pagebase)
    return 0;

  rinfo->baseaddress = pagebase;
  rinfo->size = region_end - pagebase;
  rinfo->protection = vm_prot_to_page(info.protection);
  rinfo->type = vm_info_to_type(&info);

  if (mapsline)
  {
    uint32_t p = rinfo->protection;
    char perms[5];
    int shared = 0;
#if defined(SM_SHARED) && defined(SM_TRUESHARED)
    if (info.share_mode == SM_SHARED || info.share_mode == SM_TRUESHARED
#ifdef SM_SHARED_ALIASED
        || info.share_mode == SM_SHARED_ALIASED
#endif
    )
      shared = 1;
#endif
    pageprot_to_perms(p, shared, perms);

    snprintf(mapsline, 200, "%016llx-%016llx %s %016llx 00:00 0", (unsigned long long)region_start,
             (unsigned long long)region_end, perms, (unsigned long long)info.offset);
    mapsline[199] = 0;
  }

  return 1;
}


#define VQE_PAGEDONLY 1
#define VQE_DIRTYONLY 2
#define VQE_NOSHARED 4

int VirtualQueryExFull(HANDLE hProcess, uint32_t flags, RegionInfo **rinfo, uint32_t *count)
{
  if (!rinfo || !count)
    return 0;

  *rinfo = NULL;
  *count = 0;

  if (GetHandleType(hProcess) != htProcesHandle)
    return 0;

  PProcessData p = (PProcessData)GetPointerFromHandle(hProcess);

  uint64_t pagesize = get_page_size();
  if (pagesize == 0 || (pagesize & (pagesize - 1)) != 0)
    return 0;

  int max = 128;
  RegionInfo *list = (RegionInfo *)malloc(sizeof(RegionInfo) * (size_t)max);
  if (!list)
    return 0;

  uint32_t pos = 0;
  mach_vm_address_t probe = 0;

  while (1)
  {
    mach_vm_address_t query = probe;
    mach_vm_size_t vmsize = 0;
    vm_region_submap_info_data_64_t info;
    if (!query_leaf_region(p->task, query, &query, &vmsize, &info))
      goto vqfull_done;

    uint64_t region_start = (uint64_t)query;
    uint64_t region_size = (uint64_t)vmsize;
    if (UINT64_MAX - region_start < region_size)
      goto vqfull_done;


    if ((flags & VQE_PAGEDONLY) && info.pages_resident == 0)
    {
      if (vmsize == 0 || UINT64_MAX - (uint64_t)query < (uint64_t)vmsize)
        goto vqfull_done;
      probe = query + vmsize;
      continue;
    }
    if ((flags & VQE_DIRTYONLY) && info.pages_dirtied == 0)
    {
      if (vmsize == 0 || UINT64_MAX - (uint64_t)query < (uint64_t)vmsize)
        goto vqfull_done;
      probe = query + vmsize;
      continue;
    }


    if ((flags & VQE_NOSHARED) && vm_info_to_type(&info) == MEM_MAPPED)
    {

      if (vmsize == 0 || UINT64_MAX - (uint64_t)query < (uint64_t)vmsize)
        goto vqfull_done;
      probe = query + vmsize;
      continue;
    }


    if (vmsize == 0)
      goto vqfull_done;

    if (pos >= (uint32_t)max)
    {
      max *= 2;
      RegionInfo *newlist = (RegionInfo *)realloc(list, sizeof(RegionInfo) * (size_t)max);
      if (!newlist)
        goto vqfull_done;
      list = newlist;
    }

    list[pos].baseaddress = region_start;
    list[pos].size = region_size;
    list[pos].protection = vm_prot_to_page(info.protection);
    list[pos].type = vm_info_to_type(&info);
    pos++;


    if (UINT64_MAX - (uint64_t)query < (uint64_t)vmsize)
      goto vqfull_done;
    probe = query + vmsize;

    if (probe == 0)
      break;
  }

vqfull_done:
  if (pos == 0)
  {
    free(list);
    return 0;
  }

  *rinfo = list;
  *count = pos;
  return 1;
}

int ChangeMemoryProtection(HANDLE hProcess, uint64_t address, uint32_t size, uint32_t windowsprotection, uint32_t *oldprotection)
{
  if (oldprotection)
    *oldprotection = 0;

  if (GetHandleType(hProcess) != htProcesHandle)
    return 0;
  if (size == 0)
    return 0;









  // On iOS, setting RWX can drop execute due to W^X. Treat as success.
  if (windowsprotection == PAGE_EXECUTE_READWRITE)
    return 1;

  PProcessData p = (PProcessData)GetPointerFromHandle(hProcess);
  uint32_t vmprot = windows_protection_to_vmprot(windowsprotection);

  if (windowsprotection != PAGE_NOACCESS && vmprot == 0)
    return 0;

  if (oldprotection)
  {
    RegionInfo ri;
    if (VirtualQueryEx(hProcess, (void *)(uintptr_t)address, &ri, NULL))
      *oldprotection = ri.protection;
  }

  uint64_t ps = get_page_size();
  if (ps == 0 || (ps & (ps - 1)) != 0)
    return 0;


 
  if (vmprot & VM_PROT_WRITE)
    vmprot |= VM_PROT_COPY;


  
  uint64_t start = address & ~(ps - 1);
  if (UINT64_MAX - address < size)
    return 0;
  uint64_t end = address + size;
  uint64_t len64 = end - start;
  uint64_t rem = len64 & (ps - 1);
  if (rem)
  {
    if (UINT64_MAX - len64 < (ps - rem))
      return 0;
    len64 += (ps - rem);
  }

  mach_vm_size_t len = (mach_vm_size_t)len64;
  kern_return_t kr = mach_vm_protect(p->task, (mach_vm_address_t)start, len, FALSE, vmprot);
  return (kr == KERN_SUCCESS) ? 1 : 0;
}

int ReadProcessMemory(HANDLE hProcess, void *lpAddress, void *buffer, int size)
{
  if (GetHandleType(hProcess) != htProcesHandle)
    return 0;

  if (lpAddress == NULL || size <= 0 || buffer == NULL)
    return 0;

  PProcessData p = (PProcessData)GetPointerFromHandle(hProcess);

  return read_target(p->task, (mach_vm_address_t)lpAddress, buffer, (size_t)size);
}

int WriteProcessMemory(HANDLE hProcess, void *lpAddress, void *buffer, int size)
{
  if (GetHandleType(hProcess) != htProcesHandle)
    return 0;

  if (lpAddress == NULL || size <= 0 || buffer == NULL)
    return 0;
  if ((unsigned long)size > UINT32_MAX)
    return 0;

  PProcessData p = (PProcessData)GetPointerFromHandle(hProcess);
  mach_port_t task = p->task;


  kern_return_t kr = mach_vm_write(task, (mach_vm_address_t)lpAddress, (vm_offset_t)(uintptr_t)buffer,
                                   (mach_msg_type_number_t)(uint32_t)size);
  if (kr == KERN_SUCCESS)
    return size;


  uint64_t ps = get_page_size();
  if (ps == 0 || (ps & (ps - 1)) != 0)
    return 0;

  uint64_t start = (uint64_t)(uintptr_t)lpAddress;
  uint64_t end;
  if (UINT64_MAX - start < (uint64_t)size)
    return 0;
  end = start + (uint64_t)size;

  uint64_t page_start = start & ~(ps - 1);
  uint64_t page_end = (end + (ps - 1)) & ~(ps - 1);
  uint64_t page_count = (page_end - page_start) / ps;

  if (page_count == 0 || page_count > SIZE_MAX / sizeof(uint32_t))
    return 0;

  uint32_t *orig_prot = (uint32_t *)malloc((size_t)page_count * sizeof(uint32_t));
  if (!orig_prot)
    return 0;

  mach_vm_address_t cursor = (mach_vm_address_t)page_start;
  uint64_t idx = 0;
  int ok = 1;

  while (cursor < (mach_vm_address_t)page_end)
  {
    mach_vm_address_t rbase = 0;
    mach_vm_size_t rsize = 0;
    vm_region_submap_info_data_64_t info;

    if (!query_leaf_region(task, cursor, &rbase, &rsize, &info))
    {
      ok = 0;
      break;
    }

    orig_prot[idx] = info.protection;

    uint32_t newprot = info.protection | VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY;
    mach_vm_address_t ap_base = cursor;
    mach_vm_size_t ap_len = (mach_vm_size_t)ps;

    if (mach_vm_protect(task, ap_base, ap_len, FALSE, newprot) != KERN_SUCCESS)
    {
      ok = 0;
      break;
    }

    if (UINT64_MAX - (uint64_t)cursor < ps)
    {
      ok = 0;
      break;
    }
    cursor += ps;
    idx++;
  }


  if (ok)
    kr = mach_vm_write(task, (mach_vm_address_t)lpAddress, (vm_offset_t)(uintptr_t)buffer,
                       (mach_msg_type_number_t)(uint32_t)size);


  if (idx > 0)
  {
    cursor = (mach_vm_address_t)page_start;
    for (uint64_t i = 0; i < idx; i++)
    {
      mach_vm_protect(task, cursor, (mach_vm_size_t)ps, FALSE, orig_prot[i]);
      if (UINT64_MAX - (uint64_t)cursor < ps)
        break;
      cursor += ps;
    }
  }

  free(orig_prot);

  if (!ok || kr != KERN_SUCCESS)
    return 0;


  if (idx > 0)
  {
    int state = MATTR_VAL_ICACHE_FLUSH;
    vm_address_t cache_base = (vm_address_t)page_start;
    vm_size_t cache_len = (vm_size_t)(page_end - page_start);
    vm_machine_attribute(task, cache_base, cache_len, MATTR_CACHE, &state);
  }
  return size;
}

HANDLE OpenProcess(DWORD pid)
{
  int handle = SearchHandleList(htProcesHandle, (HANDLESEARCHCALLBACK)SearchHandleListProcessCallback, &pid);
  if (handle)
  {
    PProcessData p = (PProcessData)GetPointerFromHandle(handle);
    p->ReferenceCount++;
    return handle;
  }

  mach_port_t task = MACH_PORT_NULL;
  kern_return_t err = task_for_pid(mach_task_self(), pid, &task);
  if (err != KERN_SUCCESS)
  {
    debug_log("task_for_pid(%d) failed: %d\n", pid, err);
    return 0;
  }

  PProcessData p = (PProcessData)malloc(sizeof(ProcessData));
  if (!p)
  {
    debug_log("OpenProcess: malloc failed for ProcessData\n");
    mach_port_deallocate(mach_task_self(), task);
    return 0;
  }

  memset(p, 0, sizeof(ProcessData));
  p->ReferenceCount = 1;
  p->pid = (int)pid;
  p->is64bit = 1;
  p->task = task;

  HANDLE h = CreateHandleFromPointer(p, htProcesHandle);
  if (!h)
  {
    mach_port_deallocate(mach_task_self(), task);
    free(p);
    return 0;
  }

  return h;
}

HANDLE CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID)
{
  if (dwFlags & TH32CS_SNAPPROCESS)
  {
    PProcessList pl = NULL;
    struct kinfo_proc *result = NULL;
    int max = 2048;
    int ok = 0;

    size_t length = 0;
    static const int name[] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};

    pl = (PProcessList)malloc(sizeof(ProcessList));
    if (!pl)
      goto cleanup;

    memset(pl, 0, sizeof(ProcessList));
    pl->ReferenceCount = 1;
    pl->processCount = 0;
    pl->processList = (PProcessListEntry)malloc(sizeof(ProcessListEntry) * max);
    if (!pl->processList)
      goto cleanup;


    int gotList = 0;
    for (int attempt = 0; attempt < 3; attempt++)
    {
      free(result);
      result = NULL;
      length = 0;

      if (sysctl((int *)name, (sizeof(name) / sizeof(*name)) - 1, NULL, &length, NULL, 0) == -1)
      {
        debug_log("sysctl(KERN_PROC_ALL) size failed: %d\n", errno);
        goto cleanup;
      }

      result = (struct kinfo_proc *)malloc(length);
      if (result == NULL)
        goto cleanup;

      if (sysctl((int *)name, (sizeof(name) / sizeof(*name)) - 1, result, &length, NULL, 0) == 0)
      {
        gotList = 1;
        break;
      }


      if (errno != ENOMEM)
      {
        debug_log("sysctl(KERN_PROC_ALL) read failed: %d\n", errno);
        goto cleanup;
      }
    }

    if (!gotList || !result)
      goto cleanup;

    size_t procCount = length / sizeof(struct kinfo_proc);
    for (size_t i = 0; i < procCount; i++)
    {
      int pid = result[i].kp_proc.p_pid;
      char pathbuf[PATH_MAX];
      memset(pathbuf, 0, sizeof(pathbuf));
      const char *procname = get_exec_path_sysctl(pid, pathbuf, sizeof(pathbuf)) ? pathbuf : result[i].kp_proc.p_comm;

      pl->processList[pl->processCount].PID = pid;
      pl->processList[pl->processCount].ProcessName = strdup(procname);
      if (!pl->processList[pl->processCount].ProcessName)
        continue;

      pl->processCount++;

      if (pl->processCount >= max)
      {
        max *= 2;
        void *newp = realloc(pl->processList, (size_t)max * sizeof(ProcessListEntry));
        if (!newp)
          break;
        pl->processList = (PProcessListEntry)newp;
      }
    }

    ok = 1;

  cleanup:
    if (result)
      free(result);

    if (!ok)
    {
      if (pl)
      {
        if (pl->processList)
        {
          for (int i = 0; i < pl->processCount; i++)
            free(pl->processList[i].ProcessName);
          free(pl->processList);
        }
        free(pl);
      }

      return 0;
    }

    HANDLE hs = CreateHandleFromPointer(pl, htTHSProcess);
    if (!hs)
    {
      for (int i = 0; i < pl->processCount; i++)
        free(pl->processList[i].ProcessName);
      free(pl->processList);
      free(pl);
      return 0;
    }

    return hs;
  }

  if ((dwFlags & TH32CS_SNAPMODULE) || (dwFlags & TH32CS_SNAPFIRSTMODULE))
  {
    int max = 64;
    PModuleList ml = (PModuleList)malloc(sizeof(ModuleList));
    if (!ml)
      return 0;
    memset(ml, 0, sizeof(ModuleList));

    ml->ReferenceCount = 1;
    ml->moduleCount = 0;
    ml->moduleList = (PModuleListEntry)malloc(sizeof(ModuleListEntry) * max);
    if (!ml->moduleList)
    {
      free(ml);
      return 0;
    }

    HANDLE pHandle = OpenProcess(th32ProcessID);
    if (!pHandle)
    {
      free(ml->moduleList);
      free(ml);
      return 0;
    }
    PProcessData p = (PProcessData)GetPointerFromHandle(pHandle);

    char mainpath[PATH_MAX];
    memset(mainpath, 0, sizeof(mainpath));
    get_exec_path_sysctl(th32ProcessID, mainpath, sizeof(mainpath));

    DyldImageList images;
    memset(&images, 0, sizeof(images));
    if (!collect_dyld_spi_images(p->task, &images))
    {
      dyld_image_list_free(&images);
      CloseHandle(pHandle);
      free(ml->moduleList);
      free(ml);
      return 0;
    }

    size_t imageCount = images.count;
    if (imageCount == 0)
    {
      dyld_image_list_free(&images);
      CloseHandle(pHandle);
      free(ml->moduleList);
      free(ml);
      return 0;
    }

    size_t firstIndex = 0;
    if ((dwFlags & TH32CS_SNAPFIRSTMODULE) && mainpath[0])
    {
      for (size_t i = 0; i < imageCount; i++)
      {
        if (strcmp(images.items[i].path, mainpath) == 0)
        {
          firstIndex = i;
          break;
        }
      }
    }

    for (size_t ii = 0; ii < imageCount; ii++)
    {
      size_t i = (firstIndex + ii) % imageCount;

      uint64_t base = images.items[i].load_address;
      const char *pathbuf = images.items[i].path;

      if (ml->moduleCount >= max)
      {
        int newmax = max * 2;
        void *newp = realloc(ml->moduleList, sizeof(ModuleListEntry) * (size_t)newmax);
        if (!newp)
          break;
        ml->moduleList = (PModuleListEntry)newp;
        max = newmax;
      }

      int part = 0;
      for (int j = ml->moduleCount - 1; j >= 0; j--)
      {
        if (strcmp(ml->moduleList[j].moduleName, pathbuf) == 0)
        {
          part = ml->moduleList[j].part + 1;
          break;
        }
      }

      PModuleListEntry mle = &ml->moduleList[ml->moduleCount];
      memset(mle, 0, sizeof(*mle));
      mle->moduleName = strdup(pathbuf);
      if (!mle->moduleName)
        continue;
      mle->baseAddress = (unsigned long long)base;
      mle->fileOffset = 0;
      {
        uint64_t s64 = get_macho_image_size_64(p->task, (mach_vm_address_t)base);


      mle->moduleSize = (s64 > (uint64_t)INT_MAX) ? INT_MAX : (int)s64;
      }
      mle->part = part;
      mle->is64bit = 1;

      ml->moduleCount++;

      if (dwFlags & TH32CS_SNAPFIRSTMODULE)
        break;
    }

    dyld_image_list_free(&images);
    CloseHandle(pHandle);

    HANDLE hm = CreateHandleFromPointer(ml, htTHSModule);
    if (!hm)
    {
      for (int i = 0; i < ml->moduleCount; i++)
        free(ml->moduleList[i].moduleName);
      free(ml->moduleList);
      free(ml);
      return 0;
    }

    return hm;
  }

  debug_log("Unhandled toolhelp32snapshot flags: %x\n", dwFlags);
  return 0;
}

BOOL Process32Next(HANDLE hSnapshot, PProcessListEntry processentry)
{
  if (GetHandleType(hSnapshot) == htTHSProcess)
  {
    PProcessList pl = (PProcessList)GetPointerFromHandle(hSnapshot);

    if (pl->processListIterator < pl->processCount)
    {
      processentry->PID = pl->processList[pl->processListIterator].PID;
      processentry->ProcessName = pl->processList[pl->processListIterator].ProcessName;
      pl->processListIterator++;
      return TRUE;
    }

    return FALSE;
  }

  return FALSE;
}

BOOL Process32First(HANDLE hSnapshot, PProcessListEntry processentry)
{
  if (GetHandleType(hSnapshot) == htTHSProcess)
  {
    PProcessList pl = (PProcessList)GetPointerFromHandle(hSnapshot);
    pl->processListIterator = 0;
    return Process32Next(hSnapshot, processentry);
  }

  return FALSE;
}

BOOL Module32Next(HANDLE hSnapshot, PModuleListEntry moduleentry)
{
  if (GetHandleType(hSnapshot) == htTHSModule)
  {
    PModuleList ml = (PModuleList)GetPointerFromHandle(hSnapshot);
    if (ml->moduleListIterator < ml->moduleCount)
    {
      *moduleentry = ml->moduleList[ml->moduleListIterator];
      ml->moduleListIterator++;
      return TRUE;
    }
    return FALSE;
  }
  return FALSE;
}

BOOL Module32First(HANDLE hSnapshot, PModuleListEntry moduleentry)
{
  if (GetHandleType(hSnapshot) == htTHSModule)
  {
    PModuleList ml = (PModuleList)GetPointerFromHandle(hSnapshot);
    ml->moduleListIterator = 0;
    return Module32Next(hSnapshot, moduleentry);
  }
  return FALSE;
}

void CloseHandle(HANDLE h)
{
  handleType ht = GetHandleType(h);

  if (ht == htTHSProcess)
  {
    PProcessList pl = (PProcessList)GetPointerFromHandle(h);
    pl->ReferenceCount--;
    if (pl->ReferenceCount <= 0)
    {
      for (int i = 0; i < pl->processCount; i++)
        free(pl->processList[i].ProcessName);
      free(pl->processList);
      free(pl);
      RemoveHandle(h);
    }
  }
  else if (ht == htTHSModule)
  {
    PModuleList ml = (PModuleList)GetPointerFromHandle(h);
    ml->ReferenceCount--;
    if (ml->ReferenceCount <= 0)
    {
      for (int i = 0; i < ml->moduleCount; i++)
        free(ml->moduleList[i].moduleName);
      free(ml->moduleList);
      free(ml);
      RemoveHandle(h);
    }
  }
  else if (ht == htProcesHandle)
  {
    PProcessData pd = (PProcessData)GetPointerFromHandle(h);
    pd->ReferenceCount--;
    if (pd->ReferenceCount <= 0)
    {
      if (pd->debuggerData)
        StopDebug(h);
      if (pd->task != MACH_PORT_NULL)
        mach_port_deallocate(mach_task_self(), pd->task);
      free(pd);
      RemoveHandle(h);
    }
  }
  else
  {
    RemoveHandle(h);
  }
}

void initAPI(void)
{

}
