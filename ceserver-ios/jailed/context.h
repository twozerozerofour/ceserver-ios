#ifndef CONTEXT_H_
#define CONTEXT_H_

#include <stdint.h>

typedef struct
{
  uint64_t regs[31];
  uint64_t sp;
  uint64_t pc;
  uint64_t pstate;
} CONTEXT_REGS;

typedef struct
{
  __uint128_t vregs[32];
  uint32_t fpsr;
  uint32_t fpcr;
  uint32_t __reserved[2];
} CONTEXT_FP;

#pragma pack(push, 1)
typedef struct
{
  uint32_t structsize;
  uint32_t type;
  CONTEXT_REGS regs;
  CONTEXT_FP fp;
} CONTEXT, *PCONTEXT;
#pragma pack(pop)

#endif
