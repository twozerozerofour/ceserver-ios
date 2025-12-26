#ifndef SYMBOLS_H_
#define SYMBOLS_H_

#include "api.h"

typedef void (*symcallback)(uintptr_t address, char *symbolname, void *context);

int GetSymbolListFromFile(char *filename, uint32_t fileoffset, unsigned char **output);
int FindSymbol(HANDLE hProcess, char *symbolname, symcallback cb, void *context);

#endif
