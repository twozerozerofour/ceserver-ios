
#ifndef DEBUGGER_H_
#define DEBUGGER_H_

#include <stdint.h>

#include "context.h"
#include "porthelp.h"

#pragma pack(push, 1)
typedef struct
{
  int debugevent;
  int64_t threadid;
  union
  {
    uint64_t address;
    struct
    {
      uint8_t maxBreakpointCount;
      uint8_t maxWatchpointCount;
      uint8_t maxSharedBreakpoints;
    };
  };
} DebugEvent, *PDebugEvent;
#pragma pack(pop)

int StartDebug(HANDLE hProcess);
int StopDebug(HANDLE hProcess);
int WaitForDebugEvent(HANDLE hProcess, PDebugEvent devent, int timeout);
int ContinueFromDebugEvent(HANDLE hProcess, int tid, int ignoresignal);
int GetDebugPort(HANDLE hProcess);

int SetBreakpoint(HANDLE hProcess, int tid, int debugreg, void *address, int bptype, int bpsize);
int RemoveBreakpoint(HANDLE hProcess, int tid, int debugreg, int wasWatchpoint);

int SuspendThread(HANDLE hProcess, int tid);
int ResumeThread(HANDLE hProcess, int tid);

BOOL GetThreadContext(HANDLE hProcess, int tid, PCONTEXT Context);
BOOL SetThreadContext(HANDLE hProcess, int tid, PCONTEXT Context);

int WakeDebuggerThread(void);

#endif 