
#ifndef API_H_
#define API_H_

#include <stdint.h>

#include <mach/mach.h>
#include <mach-o/dyld_images.h>
#include <stddef.h>

#include "porthelp.h"

typedef struct
{
  unsigned long long baseAddress;
  uint32_t fileOffset;
  int part;
  int is64bit;
  int moduleSize;
  char *moduleName;
} ModuleListEntry, *PModuleListEntry;

typedef struct
{
  int ReferenceCount;
  int moduleListIterator;
  int moduleCount;
  PModuleListEntry moduleList;
} ModuleList, *PModuleList;

typedef struct
{
  int PID;
  char *ProcessName;
} ProcessListEntry, *PProcessListEntry;

typedef struct
{
  int ReferenceCount;
  int processListIterator;
  int processCount;
  PProcessListEntry processList;
} ProcessList, *PProcessList;

typedef struct
{
  int ReferenceCount;
  int pid;
  int is64bit;
  mach_port_t task;
  void *debuggerData;
} ProcessData, *PProcessData;

typedef struct
{
  uint64_t baseaddress;
  uint64_t size;
  uint32_t protection;
  uint32_t type;
} RegionInfo, *PRegionInfo;

int debug_log(const char *format, ...);

void initAPI(void);

HANDLE CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
BOOL Process32First(HANDLE hSnapshot, PProcessListEntry processentry);
BOOL Process32Next(HANDLE hSnapshot, PProcessListEntry processentry);
BOOL Module32First(HANDLE hSnapshot, PModuleListEntry moduleentry);
BOOL Module32Next(HANDLE hSnapshot, PModuleListEntry moduleentry);
void CloseHandle(HANDLE h);

HANDLE OpenProcess(DWORD pid);
int getArchitecture(HANDLE hProcess);

int ReadProcessMemory(HANDLE hProcess, void *lpAddress, void *buffer, int size);
int WriteProcessMemory(HANDLE hProcess, void *lpAddress, void *buffer, int size);

int VirtualQueryEx(HANDLE hProcess, void *lpAddress, PRegionInfo rinfo, char *mapsline);
int VirtualQueryExFull(HANDLE hProcess, uint32_t flags, RegionInfo **rinfo, uint32_t *count);
int ChangeMemoryProtection(HANDLE hProcess, uint64_t address, uint32_t size, uint32_t windowsprotection, uint32_t *oldprotection);

#endif
