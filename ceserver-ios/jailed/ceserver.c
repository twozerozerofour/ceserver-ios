#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <unistd.h>

#include <zlib.h>

#include "api.h"
#include "ceserver.h"
#include "debugger.h"
#include "porthelp.h"
#include "symbols.h"

#define CESERVERVERSION 6
#ifndef MSG_MORE
#define MSG_MORE 0
#endif

static char versionstring[] = "CHEATENGINE Network 2.3";
static char ceserverpath[] = ".";

__thread char *threadname;
__thread int isDebuggerThread;
__thread int debugfd;

static int can_alloc_size(size_t a, size_t b)
{
  return a <= SIZE_MAX - b;
}

ssize_t recvall(int s, void *buf, size_t size, int flags)
{
  ssize_t totalreceived = 0;
  ssize_t sizeleft = (ssize_t)size;
  unsigned char *buffer = (unsigned char *)buf;

  flags |= MSG_WAITALL;

  while (sizeleft > 0)
  {
    ssize_t i = recv(s, &buffer[totalreceived], (size_t)sizeleft, flags);

    if (i == 0)
      return 0;

    if (i == -1)
    {
      if (errno == EINTR)
        continue;
      return -1;
    }

    totalreceived += i;
    sizeleft -= i;
  }

  return totalreceived;
}

ssize_t sendall(int s, void *buf, size_t size, int flags)
{
  ssize_t totalsent = 0;
  ssize_t sizeleft = (ssize_t)size;
  const unsigned char *buffer = (const unsigned char *)buf;

  while (sizeleft > 0)
  {
    ssize_t i = send(s, &buffer[totalsent], (size_t)sizeleft, flags);
    if (i == 0)
      return 0;
    if (i == -1)
    {
      if (errno == EINTR)
        continue;
      return -1;
    }
    totalsent += i;
    sizeleft -= i;
  }

  return totalsent;
}

ssize_t sendstring16(int s, char *str, int flags)
{
  uint16_t l;
  if (str)
    l = (uint16_t)strlen(str);
  else
    l = 0;

  sendall(s, &l, sizeof(l), l ? MSG_MORE : flags);
  if (l)
    sendall(s, str, l, flags);

  return l;
}

char *receivestring16(int s)
{
  uint16_t l = 0;
  if (recvall(s, &l, sizeof(l), 0) <= 0)
    return NULL;

  if (l == 0)
    return NULL;

  char *str = (char *)malloc((size_t)l + 1);
  if (!str)
    return NULL;

  if (recvall(s, str, l, 0) <= 0)
  {
    free(str);
    return NULL;
  }

  str[l] = 0;
  return str;
}

int DispatchCommand(int currentsocket, unsigned char command)
{
  switch (command)
  {
    case CMD_GETVERSION:
    {
      int versionsize = (int)strlen(versionstring);
      PCeVersion v = (PCeVersion)malloc(sizeof(CeVersion) + versionsize);
      v->stringsize = (unsigned char)versionsize;
      v->version = CESERVERVERSION;
      memcpy((char *)v + sizeof(CeVersion), versionstring, (size_t)versionsize);
      sendall(currentsocket, v, sizeof(CeVersion) + (size_t)versionsize, 0);
      free(v);
      break;
    }

    case CMD_SET_CONNECTION_NAME:
    {
      uint32_t namelength;
      if (recvall(currentsocket, &namelength, sizeof(namelength), 0) > 0)
      {
        char *name = (char *)malloc((size_t)namelength + 1);
        if (recvall(currentsocket, name, namelength, 0) <= 0)
        {
          free(name);
          break;
        }
        name[namelength] = 0;
        free(threadname);
        threadname = name;
      }
      break;
    }

    case CMD_GETABI:
    {
      unsigned char abi = 1;
      sendall(currentsocket, &abi, sizeof(abi), 0);
      break;
    }

    case CMD_GETARCHITECTURE:
    {
      unsigned char arch = 3;
      HANDLE h;
      if (recvall(currentsocket, &h, sizeof(h), 0) > 0)
      {
        int a = getArchitecture(h);
        if (a >= 0)
          arch = (unsigned char)a;
      }
      sendall(currentsocket, &arch, sizeof(arch), 0);
      break;
    }

    case CMD_GETOPTIONS:
    {

      uint16_t count = 0;
      sendall(currentsocket, &count, sizeof(count), 0);
      break;
    }

    case CMD_GETCESERVERPATH:
    {
      sendstring16(currentsocket, ceserverpath, 0);
      break;
    }

    case CMD_ISANDROID:
    {
      unsigned char r = 0;
      sendall(currentsocket, &r, sizeof(r), 0);
      break;
    }

    case CMD_OPENPROCESS:
    {
      int pid = 0;
      if (recvall(currentsocket, &pid, sizeof(pid), 0) > 0)
      {
        int processhandle = (int)OpenProcess((DWORD)pid);
        sendall(currentsocket, &processhandle, sizeof(processhandle), 0);
      }
      break;
    }

    case CMD_STARTDEBUG:
    {
      HANDLE h;
      if (recvall(currentsocket, &h, sizeof(h), MSG_WAITALL) > 0)
      {
        int r;
        debug_log("Calling StartDebug(%d)\n", h);
        r = StartDebug(h);
        sendall(currentsocket, &r, sizeof(r), 0);

        if (r)
        {
          isDebuggerThread = h;
          debugfd = GetDebugPort(h);
        }
      }
      break;
    }

    case CMD_WAITFORDEBUGEVENT:
    {
      struct
      {
        HANDLE pHandle;
        int timeout;
      } wfd;

      if (recvall(currentsocket, &wfd, sizeof(wfd), MSG_WAITALL) > 0)
      {
        int r;
        DebugEvent event;
        memset(&event, 0, sizeof(event));

        r = WaitForDebugEvent(wfd.pHandle, &event, wfd.timeout);
        sendall(currentsocket, &r, sizeof(r), r ? MSG_MORE : 0);

        if (r)
        {
          if (event.debugevent == SIGTRAP)
          {
            debug_log("!!!SIGTRAP!!!\n");
            debug_log("event.address=%llx\n", event.address);
          }

          sendall(currentsocket, &event, sizeof(event), 0);
        }
      }
      break;
    }

    case CMD_CONTINUEFROMDEBUGEVENT:
    {
      struct
      {
        HANDLE pHandle;
        int tid;
        int ignore;
      } cfd;

      if (recvall(currentsocket, &cfd, sizeof(cfd), MSG_WAITALL) > 0)
      {
        int r;
        r = ContinueFromDebugEvent(cfd.pHandle, cfd.tid, cfd.ignore);
        sendall(currentsocket, &r, sizeof(r), 0);
      }
      break;
    }

    case CMD_SETBREAKPOINT:
    {
      CeSetBreapointInput sb;

      debug_log("CMD_SETBREAKPOINT. sizeof(sb)=%d\n", (int)sizeof(sb));

      if (recvall(currentsocket, &sb, sizeof(sb), MSG_WAITALL) > 0)
      {
        int r;

        debug_log("Calling SetBreakpoint\n");
        r = SetBreakpoint(sb.hProcess, sb.tid, sb.debugreg, (void *)sb.Address, sb.bptype, sb.bpsize);
        debug_log("SetBreakpoint returned %d\n", r);
        sendall(currentsocket, &r, sizeof(r), 0);
      }
      break;
    }

    case CMD_REMOVEBREAKPOINT:
    {
      CeRemoveBreapointInput rb;

      if (recvall(currentsocket, &rb, sizeof(rb), MSG_WAITALL) > 0)
      {
        int r;

        debug_log("%s: Calling RemoveBreakpoint\n", threadname ? threadname : "thread");
        r = RemoveBreakpoint(rb.hProcess, rb.tid, rb.debugreg, rb.wasWatchpoint);
        debug_log("RemoveBreakpoint returned: %d\n", r);
        sendall(currentsocket, &r, sizeof(r), 0);
      }
      break;
    }

    case CMD_GETTHREADCONTEXT:
    {
#pragma pack(1)
      struct
      {
        HANDLE hProcess;
        uint32_t tid;
      } gtc;
#pragma pack()

      CONTEXT Context;
      uint32_t result;

      debug_log("CMD_GETTHREADCONTEXT:\n");

      recvall(currentsocket, &gtc, sizeof(gtc), MSG_WAITALL);

      debug_log("Going to call GetThreadContext(%d, %d, %p)\n", gtc.hProcess, gtc.tid, &Context);
      memset(&Context, 0, sizeof(Context));

      result = GetThreadContext(gtc.hProcess, gtc.tid, &Context);

      debug_log("result=%d\n", result);

      if (result)
      {
        debug_log("Context.structsize=%d\n", Context.structsize);
        uint32_t structsize = Context.structsize;
        sendall(currentsocket, &result, sizeof(result), MSG_MORE);
        sendall(currentsocket, &structsize, sizeof(structsize), MSG_MORE);
        sendall(currentsocket, &Context, structsize, 0);
      }
      else
      {
        sendall(currentsocket, &result, sizeof(result), 0);
      }

      break;
    }

    case CMD_SETTHREADCONTEXT:
    {
#pragma pack(1)
      struct
      {
        HANDLE hProcess;
        uint32_t tid;
        uint32_t structsize;
      } stc;
#pragma pack()

      uint32_t result;
      PCONTEXT c;

      debug_log("CMD_SETTHREADCONTEXT:\n");

      recvall(currentsocket, &stc, sizeof(stc), MSG_WAITALL);
      debug_log("hProcess=%d tid=%d structsize=%d\n", stc.hProcess, stc.tid, stc.structsize);

      c = (PCONTEXT)malloc(stc.structsize);
      recvall(currentsocket, c, stc.structsize, MSG_WAITALL);

      debug_log("received a context with data: structsize=%d type=%d\n", c->structsize, c->type);
      debug_log("Going to call SetThreadContext(%d, %d, %p)\n", stc.hProcess, stc.tid, c);

      result = SetThreadContext(stc.hProcess, stc.tid, c);
      free(c);

      debug_log("result=%d\n", result);
      sendall(currentsocket, &result, sizeof(result), 0);

      break;
    }

    case CMD_SUSPENDTHREAD:
    {
      CeSuspendThreadInput st;

      if (recvall(currentsocket, &st, sizeof(st), MSG_WAITALL) > 0)
      {
        int r;
        r = SuspendThread(st.hProcess, st.tid);
        sendall(currentsocket, &r, sizeof(r), 0);
      }
      break;
    }

    case CMD_RESUMETHREAD:
    {
      CeResumeThreadInput rt;

      if (recvall(currentsocket, &rt, sizeof(rt), MSG_WAITALL) > 0)
      {
        int r;
        r = ResumeThread(rt.hProcess, rt.tid);
        sendall(currentsocket, &r, sizeof(r), 0);
      }
      break;
    }

    case CMD_GETREGIONINFO:
    case CMD_VIRTUALQUERYEX:
    {
      CeVirtualQueryExInput c;
      if (recvall(currentsocket, &c, sizeof(c), 0) > 0)
      {
        RegionInfo rinfo;
        CeVirtualQueryExOutput o;
        memset(&rinfo, 0, sizeof(rinfo));
        memset(&o, 0, sizeof(o));

        char mapsline[200];
        mapsline[0] = 0;

        if (command == CMD_VIRTUALQUERYEX)
          o.result = (uint8_t)VirtualQueryEx((HANDLE)c.handle, (void *)(uintptr_t)c.baseaddress, &rinfo, NULL);
        else
          o.result = (uint8_t)VirtualQueryEx((HANDLE)c.handle, (void *)(uintptr_t)c.baseaddress, &rinfo, mapsline);

        o.protection = rinfo.protection;
        o.type = rinfo.type;
        o.baseaddress = rinfo.baseaddress;
        o.size = rinfo.size;

        sendall(currentsocket, &o, sizeof(o), 0);

        if (command == CMD_GETREGIONINFO)
        {
          uint8_t size = (uint8_t)strlen(mapsline);
          sendall(currentsocket, &size, sizeof(size), 0);
          if (size)
            sendall(currentsocket, mapsline, size, 0);
        }
      }
      break;
    }

    case CMD_CREATETOOLHELP32SNAPSHOT:
    {
      CeCreateToolhelp32Snapshot params;
      if (recvall(currentsocket, &params, sizeof(params), 0) > 0)
      {
        HANDLE result = CreateToolhelp32Snapshot(params.dwFlags, params.th32ProcessID);
        sendall(currentsocket, &result, sizeof(result), 0);
      }
      break;
    }

    case CMD_CREATETOOLHELP32SNAPSHOTEX:
    {
      CeCreateToolhelp32Snapshot params;
      if (recvall(currentsocket, &params, sizeof(params), 0) > 0)
      {
        HANDLE r = CreateToolhelp32Snapshot(params.dwFlags, params.th32ProcessID);

        if ((params.dwFlags & TH32CS_SNAPTHREAD) == TH32CS_SNAPTHREAD)
        {


          int n = 0;
          sendall(currentsocket, &n, sizeof(n), 0);

          if (r)
            CloseHandle(r);
        }
        else if ((params.dwFlags & TH32CS_SNAPMODULE) == TH32CS_SNAPMODULE)
        {
          ModuleListEntry me;
          char *outputstream = (char *)malloc(65536);
          int pos = 0;
          if (outputstream)
            memset(outputstream, 0, 65536);

          if (outputstream && r && Module32First(r, &me))
          {
            do
            {
              int namelen = (int)strlen(me.moduleName);
              if ((pos + (int)sizeof(CeModuleEntry) + namelen) > 65536)
              {
                sendall(currentsocket, outputstream, (size_t)pos, 0);
                pos = 0;
              }

              PCeModuleEntry m = (PCeModuleEntry)&outputstream[pos];
              m->modulebase = (int64_t)me.baseAddress;
              m->modulesize = me.moduleSize;
              m->modulefileoffset = me.fileOffset;
              m->modulenamesize = namelen;
              m->modulepart = me.part;
              m->result = 1;

              memcpy((char *)m + sizeof(CeModuleEntry), me.moduleName, (size_t)namelen);
              pos += (int)sizeof(CeModuleEntry) + namelen;
            } while (Module32Next(r, &me));
          }

          if (pos)
            sendall(currentsocket, outputstream, (size_t)pos, 0);

          CeModuleEntry eol;
          memset(&eol, 0, sizeof(eol));
          eol.result = 0;
          eol.modulenamesize = 0;
          sendall(currentsocket, &eol, sizeof(eol), 0);

          if (outputstream)
            free(outputstream);
          if (r)
            CloseHandle(r);
        }
        else
        {
          sendall(currentsocket, &r, sizeof(r), 0);
        }
      }
      break;
    }

    case CMD_PROCESS32FIRST:
    case CMD_PROCESS32NEXT:
    {
      HANDLE toolhelpsnapshot;
      if (recvall(currentsocket, &toolhelpsnapshot, sizeof(toolhelpsnapshot), 0) > 0)
      {
        ProcessListEntry pe;
        BOOL result = (command == CMD_PROCESS32FIRST) ? Process32First(toolhelpsnapshot, &pe) : Process32Next(toolhelpsnapshot, &pe);

        CeProcessEntry *r;
        int size;
        if (result)
        {
          int namelen = (int)strlen(pe.ProcessName);
          size = (int)sizeof(CeProcessEntry) + namelen;
          r = (PCeProcessEntry)malloc((size_t)size);
          r->processnamesize = namelen;
          r->pid = pe.PID;
          memcpy((char *)r + sizeof(CeProcessEntry), pe.ProcessName, (size_t)namelen);
        }
        else
        {
          size = (int)sizeof(CeProcessEntry);
          r = (PCeProcessEntry)malloc((size_t)size);
          r->processnamesize = 0;
          r->pid = 0;
        }

        r->result = result;
        sendall(currentsocket, r, (size_t)size, 0);
        free(r);
      }
      break;
    }

    case CMD_MODULE32FIRST:
    case CMD_MODULE32NEXT:
    {
      HANDLE toolhelpsnapshot;
      if (recvall(currentsocket, &toolhelpsnapshot, sizeof(toolhelpsnapshot), 0) > 0)
      {
        ModuleListEntry me;
        BOOL result = (command == CMD_MODULE32FIRST) ? Module32First(toolhelpsnapshot, &me) : Module32Next(toolhelpsnapshot, &me);

        CeModuleEntry *r;
        int size;
        if (result)
        {
          int namelen = (int)strlen(me.moduleName);
          size = (int)sizeof(CeModuleEntry) + namelen;
          r = (PCeModuleEntry)malloc((size_t)size);
          r->modulebase = (int64_t)me.baseAddress;
          r->modulepart = me.part;
          r->modulesize = me.moduleSize;
          r->modulefileoffset = me.fileOffset;
          r->modulenamesize = namelen;
          memcpy((char *)r + sizeof(CeModuleEntry), me.moduleName, (size_t)namelen);
        }
        else
        {
          size = (int)sizeof(CeModuleEntry);
          r = (PCeModuleEntry)malloc((size_t)size);
          memset(r, 0, (size_t)size);
        }

        r->result = result;
        sendall(currentsocket, r, (size_t)size, 0);
        free(r);
      }
      break;
    }

    case CMD_GETSYMBOLLISTFROMFILE:
    {
      struct
      {
        uint32_t fileoffset;
        uint32_t symbolpathsize;
      } input;

      if (recvall(currentsocket, &input, sizeof(input), 0) > 0)
      {
        char *symbolpath = (char *)malloc((size_t)input.symbolpathsize + 1);
        if (!symbolpath)
          break;

        symbolpath[input.symbolpathsize] = 0;
        if (input.symbolpathsize && recvall(currentsocket, symbolpath, input.symbolpathsize, 0) <= 0)
        {
          free(symbolpath);
          break;
        }

        unsigned char *output = NULL;
        if (memcmp("/dev/", symbolpath, 5) != 0)
          GetSymbolListFromFile(symbolpath, input.fileoffset, &output);

        if (output)
        {
          sendall(currentsocket, output, *(uint32_t *)&output[4], 0);
          free(output);
        }
        else
        {
          uint64_t fail = 0;
          sendall(currentsocket, &fail, sizeof(fail), 0);
        }

        free(symbolpath);
      }
      break;
    }

    case CMD_READPROCESSMEMORY:
    {
      CeReadProcessMemoryInput c;
      if (recvall(currentsocket, &c, sizeof(c), 0) > 0)
      {

        if (c.size > (uint32_t)INT_MAX || !can_alloc_size(sizeof(CeReadProcessMemoryOutput), (size_t)c.size))
        {
          PCeReadProcessMemoryOutput o = (PCeReadProcessMemoryOutput)malloc(sizeof(CeReadProcessMemoryOutput));
          if (o)
          {
            o->read = 0;
            sendall(currentsocket, o, sizeof(CeReadProcessMemoryOutput), 0);
            free(o);
          }
          break;
        }

        PCeReadProcessMemoryOutput o = (PCeReadProcessMemoryOutput)malloc(sizeof(CeReadProcessMemoryOutput) + (size_t)c.size);
        if (!o)
        {

          PCeReadProcessMemoryOutput o2 = (PCeReadProcessMemoryOutput)malloc(sizeof(CeReadProcessMemoryOutput));
          if (o2)
          {
            o2->read = 0;
            sendall(currentsocket, o2, sizeof(CeReadProcessMemoryOutput), 0);
            free(o2);
          }
          break;
        }

        o->read = ReadProcessMemory((HANDLE)c.handle, (void *)(uintptr_t)c.address, &o[1], (int)c.size);

        if (c.compress)
        {
#define COMPRESS_BLOCKSIZE (64 * 1024)
          unsigned char *uncompressed = (unsigned char *)&o[1];
          uint32_t uncompressedSize = (uint32_t)o->read;
          uint32_t compressedSize = 0;

          unsigned char **compressedBlocks = NULL;
          int maxBlocks = 0;
          int currentBlock = 0;
          int blocksAllocated = 0;

          z_stream strm;
          memset(&strm, 0, sizeof(strm));
          int zinit = Z_ERRNO;
          int ok = 1;

          if (uncompressedSize == 0)
          {
            sendall(currentsocket, &uncompressedSize, sizeof(uncompressedSize), MSG_MORE);
            sendall(currentsocket, &compressedSize, sizeof(compressedSize), 0);
            free(o);
            break;
          }

          maxBlocks = 1 + ((int)uncompressedSize / COMPRESS_BLOCKSIZE);
          compressedBlocks = (unsigned char **)malloc((size_t)maxBlocks * sizeof(unsigned char *));
          if (!compressedBlocks)
            ok = 0;

          if (ok)
          {
            zinit = deflateInit(&strm, c.compress);
            if (zinit != Z_OK)
              ok = 0;
          }

          if (ok)
          {
            compressedBlocks[0] = (unsigned char *)malloc(COMPRESS_BLOCKSIZE);
            if (!compressedBlocks[0])
              ok = 0;
            else
            {
              blocksAllocated = 1;
              strm.avail_out = COMPRESS_BLOCKSIZE;
              strm.next_out = compressedBlocks[0];
              strm.next_in = uncompressed;
              strm.avail_in = uncompressedSize;
            }
          }

          while (ok && strm.avail_in)
          {
            int zr = deflate(&strm, Z_NO_FLUSH);
            if (zr != Z_OK && zr != Z_STREAM_END)
            {
              ok = 0;
              break;
            }

            if (strm.avail_out == 0)
            {
              currentBlock++;
              if (currentBlock >= maxBlocks)
              {
                maxBlocks *= 2;
                void *newp = realloc(compressedBlocks, (size_t)maxBlocks * sizeof(unsigned char *));
                if (!newp)
                {
                  ok = 0;
                  break;
                }
                compressedBlocks = (unsigned char **)newp;
              }

              compressedBlocks[currentBlock] = (unsigned char *)malloc(COMPRESS_BLOCKSIZE);
              if (!compressedBlocks[currentBlock])
              {
                ok = 0;
                break;
              }

              blocksAllocated = currentBlock + 1;
              strm.avail_out = COMPRESS_BLOCKSIZE;
              strm.next_out = compressedBlocks[currentBlock];
            }
          }

          while (ok)
          {
            int zr = deflate(&strm, Z_FINISH);
            if (zr == Z_STREAM_END)
              break;
            if (zr != Z_OK)
            {
              ok = 0;
              break;
            }

            if (strm.avail_out == 0)
            {
              currentBlock++;
              if (currentBlock >= maxBlocks)
              {
                maxBlocks *= 2;
                void *newp = realloc(compressedBlocks, (size_t)maxBlocks * sizeof(unsigned char *));
                if (!newp)
                {
                  ok = 0;
                  break;
                }
                compressedBlocks = (unsigned char **)newp;
              }

              compressedBlocks[currentBlock] = (unsigned char *)malloc(COMPRESS_BLOCKSIZE);
              if (!compressedBlocks[currentBlock])
              {
                ok = 0;
                break;
              }

              blocksAllocated = currentBlock + 1;
              strm.avail_out = COMPRESS_BLOCKSIZE;
              strm.next_out = compressedBlocks[currentBlock];
            }
          }

          if (zinit == Z_OK)
            deflateEnd(&strm);

          if (!ok)
          {

            compressedSize = 0;
            sendall(currentsocket, &uncompressedSize, sizeof(uncompressedSize), MSG_MORE);
            sendall(currentsocket, &compressedSize, sizeof(compressedSize), 0);

            for (int i = 0; i < blocksAllocated; i++)
              free(compressedBlocks[i]);
            free(compressedBlocks);
            free(o);
            break;
          }

          compressedSize = (uint32_t)strm.total_out;
          sendall(currentsocket, &uncompressedSize, sizeof(uncompressedSize), MSG_MORE);
          sendall(currentsocket, &compressedSize, sizeof(compressedSize), MSG_MORE);

          for (int i = 0; i < blocksAllocated; i++)
          {
            if (i != currentBlock)
              sendall(currentsocket, compressedBlocks[i], COMPRESS_BLOCKSIZE, MSG_MORE);
            else
              sendall(currentsocket, compressedBlocks[i], COMPRESS_BLOCKSIZE - strm.avail_out, 0);
            free(compressedBlocks[i]);
          }
          free(compressedBlocks);
        }
        else
        {
          sendall(currentsocket, o, sizeof(CeReadProcessMemoryOutput) + (size_t)o->read, 0);
        }

        free(o);
      }
      break;
    }

    case CMD_WRITEPROCESSMEMORY:
    {
      CeWriteProcessMemoryInput c;
      if (recvall(currentsocket, &c, sizeof(c), 0) > 0)
      {
        CeWriteProcessMemoryOutput o;
        unsigned char *buf = NULL;
        if (c.size > 0)
        {

          size_t want = (size_t)c.size;
          buf = (unsigned char *)malloc(want);
          if (buf)
          {
            if (recvall(currentsocket, buf, want, 0) > 0)
              o.written = WriteProcessMemory((HANDLE)c.handle, (void *)(uintptr_t)c.address, buf, (int)c.size);
            else
              o.written = 0;
            free(buf);
          }
          else
          {

            char discard[64 * 1024];
            size_t left = want;
            while (left)
            {
              size_t n = left > sizeof(discard) ? sizeof(discard) : left;
              if (recvall(currentsocket, discard, n, 0) <= 0)
                break;
              left -= n;
            }
            o.written = 0;
          }
        }
        else
        {
          o.written = 0;
        }

        sendall(currentsocket, &o, sizeof(o), 0);
      }
      break;
    }

    case CMD_VIRTUALQUERYEXFULL:
    {
      CeVirtualQueryExFullInput c;
      if (recvall(currentsocket, &c, sizeof(c), MSG_WAITALL) > 0)
      {
        RegionInfo *rinfo = NULL;
        uint32_t count = 0;
        if (VirtualQueryExFull((HANDLE)c.handle, c.flags, &rinfo, &count))
        {
          sendall(currentsocket, &count, sizeof(count), 0);
          for (uint32_t i = 0; i < count; i++)
            sendall(currentsocket, &rinfo[i], sizeof(RegionInfo), 0);
        }
        else
        {

          sendall(currentsocket, &count, sizeof(count), 0);
        }
        free(rinfo);
      }
      break;
    }

    case CMD_CHANGEMEMORYPROTECTION:
    {
      CeChangeMemoryProtection c;
      if (recvall(currentsocket, &c, sizeof(c), 0) > 0)
      {






        uint32_t oldprot = 0;
        uint32_t result = ChangeMemoryProtection(c.hProcess, c.address, c.size, c.windowsprotection, &oldprot);
        sendall(currentsocket, &result, sizeof(result), MSG_MORE);
        sendall(currentsocket, &oldprot, sizeof(oldprot), 0);
      }
      break;
    }

    case CMD_CLOSEHANDLE:
    {
      HANDLE h;
      if (recvall(currentsocket, &h, sizeof(h), 0) > 0)
      {
        CloseHandle(h);
        int ok = 1;
        sendall(currentsocket, &ok, sizeof(ok), 0);
      }
      break;
    }

    case CMD_CLOSECONNECTION:
      close(currentsocket);
      return 0;

    default:
      debug_log("Unknown command received: %u\n", command);

      close(currentsocket);
      return 0;
  }

  return 1;
}

static void *newconnection(void *arg)
{
  int s = (int)(intptr_t)arg;
  int currentsocket = s;
  threadname = NULL;
  isDebuggerThread = 0;
  debugfd = -1;

  while (1)
  {
    if (isDebuggerThread && (debugfd != -1))
    {
      fd_set readfds;
      int maxfd = s;
      int sret;

      FD_ZERO(&readfds);
      FD_SET(s, &readfds);
      FD_SET(debugfd, &readfds);

      if (debugfd > maxfd)
        maxfd = debugfd;

      sret = select(maxfd + 1, &readfds, NULL, NULL, NULL);
      if (sret == -1)
      {
        if (errno == EINTR)
          continue;
        debug_log("select failed: %d\n", errno);
        break;
      }

      if (FD_ISSET(debugfd, &readfds) && FD_ISSET(s, &readfds))
      {
        if (currentsocket == debugfd)
          currentsocket = s;
        else
          currentsocket = debugfd;
      }
      else if (FD_ISSET(debugfd, &readfds))
      {
        currentsocket = debugfd;
      }
      else if (FD_ISSET(s, &readfds))
      {
        currentsocket = s;
      }
      else
      {
        continue;
      }
    }
    else
    {
      currentsocket = s;
    }

    unsigned char command;
    ssize_t r = recvall(currentsocket, &command, 1, MSG_WAITALL);
    if (r == 1)
    {
      if (!DispatchCommand(currentsocket, command))
        break;
    }
    else
    {
      if (r == -1)
        debug_log("read error on socket %d (%d)\n", s, errno);
      else if (threadname)
        debug_log("%s has disconnected\n", threadname);

      if (isDebuggerThread)
      {
        debug_log("This was a debugger thread\n");
        StopDebug(isDebuggerThread);
      }
      break;
    }
  }

  free(threadname);
  threadname = NULL;
  close(s);
  return NULL;
}

static void *ceserver_thread_main(void *arg)
{
  (void)arg;

  initAPI();

  int sock0 = socket(AF_INET, SOCK_STREAM, 0);
  if (sock0 < 0)
  {
    perror("socket");
    return NULL;
  }

  int yes = 1;
  setsockopt(sock0, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(52736);
  addr.sin_addr.s_addr = INADDR_ANY;

  if (bind(sock0, (struct sockaddr *)&addr, sizeof(addr)) != 0)
  {
    perror("bind");
    close(sock0);
    return NULL;
  }

  if (listen(sock0, 32) != 0)
  {
    perror("listen");
    close(sock0);
    return NULL;
  }

  printf("CEServer. Waiting for client connection\n");
  fflush(stdout);

  while (1)
  {
    int sock = accept(sock0, NULL, NULL);
    if (sock < 0)
      continue;

    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&yes, sizeof(yes));

    pthread_t th;
    if (pthread_create(&th, NULL, newconnection, (void *)(intptr_t)sock) == 0)
      pthread_detach(th);
    else
      close(sock);
  }

  return NULL;
}

static int g_server_started = 0;

__attribute__((constructor))
static void ceserver_autostart(void)
{
  if (!__sync_bool_compare_and_swap(&g_server_started, 0, 1))
    return;

  pthread_t th;
  if (pthread_create(&th, NULL, ceserver_thread_main, NULL) == 0)
    pthread_detach(th);
}
