
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <zlib.h>

#include "api.h"
#include "symbols.h"

#ifndef n_strx
#define n_strx n_un.n_strx
#endif

#pragma pack(1)
typedef struct
{
  uint64_t address;
  int size;
  int type;
  unsigned char namelength;
  char name[0];
} symbolinfo, *psymbolinfo;
#pragma pack()

#ifndef EXPORT_SYMBOL_FLAGS_REEXPORT
#define EXPORT_SYMBOL_FLAGS_REEXPORT 0x08u
#endif
#ifndef EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER
#define EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER 0x10u
#endif
#ifndef INDIRECT_SYMBOL_ABS
#define INDIRECT_SYMBOL_ABS 0x40000000u
#endif
#ifndef INDIRECT_SYMBOL_LOCAL
#define INDIRECT_SYMBOL_LOCAL 0x80000000u
#endif
#ifndef CPU_TYPE_ARM64_32
#define CPU_TYPE_ARM64_32 ((cpu_type_t)0x0200000c)
#endif

#ifndef DW_EH_PE_omit
#define DW_EH_PE_omit 0xff
#endif
#ifndef DW_EH_PE_absptr
#define DW_EH_PE_absptr 0x00
#endif
#ifndef DW_EH_PE_uleb128
#define DW_EH_PE_uleb128 0x01
#endif
#ifndef DW_EH_PE_udata2
#define DW_EH_PE_udata2 0x02
#endif
#ifndef DW_EH_PE_udata4
#define DW_EH_PE_udata4 0x03
#endif
#ifndef DW_EH_PE_udata8
#define DW_EH_PE_udata8 0x04
#endif
#ifndef DW_EH_PE_sleb128
#define DW_EH_PE_sleb128 0x09
#endif
#ifndef DW_EH_PE_sdata2
#define DW_EH_PE_sdata2 0x0a
#endif
#ifndef DW_EH_PE_sdata4
#define DW_EH_PE_sdata4 0x0b
#endif
#ifndef DW_EH_PE_sdata8
#define DW_EH_PE_sdata8 0x0c
#endif
#ifndef DW_EH_PE_pcrel
#define DW_EH_PE_pcrel 0x10
#endif
#ifndef DW_EH_PE_textrel
#define DW_EH_PE_textrel 0x20
#endif
#ifndef DW_EH_PE_datarel
#define DW_EH_PE_datarel 0x30
#endif
#ifndef DW_EH_PE_funcrel
#define DW_EH_PE_funcrel 0x40
#endif
#ifndef DW_EH_PE_aligned
#define DW_EH_PE_aligned 0x50
#endif
#ifndef DW_EH_PE_indirect
#define DW_EH_PE_indirect 0x80
#endif

#define TEMPBUFSIZE (64 * 1024)

typedef struct
{
  uint64_t addr;
  uint64_t size;
  uint32_t flags;
  uint32_t reserved1;
  uint32_t reserved2;
  uint32_t fileoff;
  char segname[17];
  char sectname[17];
} MachSection;

typedef struct
{
  MachSection *items;
  size_t count;
  size_t cap;
} MachSectionList;

typedef struct
{
  uint64_t addr;
  uint32_t size;
  uint32_t type;
  char *name;
} SymbolEntry;

typedef struct
{
  SymbolEntry *items;
  size_t count;
  size_t cap;
} SymbolList;

typedef struct
{
  uint64_t *slots;
  size_t cap;
  size_t count;
} AddrSet;

typedef struct
{
  uint32_t ncmds;
  uint32_t sizeofcmds;
  uint32_t filetype;
  uint32_t flags;
  int is64;
  int swap;
  uint64_t base_vmaddr;
  uint64_t text_vmaddr;
  struct symtab_command symtab;
  struct dysymtab_command dysymtab;
  struct dyld_info_command dyld_info;
  struct linkedit_data_command exports_trie;
  struct linkedit_data_command function_starts;
  MachSectionList sections;
} MachOInfo;

static uint32_t swap32_if(uint32_t v, int swap)
{
  return swap ? __builtin_bswap32(v) : v;
}

static uint16_t swap16_if(uint16_t v, int swap)
{
  return swap ? __builtin_bswap16(v) : v;
}

static uint64_t swap64_if(uint64_t v, int swap)
{
  return swap ? __builtin_bswap64(v) : v;
}

static int read_at(int fd, uint64_t offset, void *buf, size_t size)
{
  ssize_t r = pread(fd, buf, size, (off_t)offset);
  return (r == (ssize_t)size);
}

static int section_list_append(MachSectionList *list, const MachSection *sec)
{
  if (!list || !sec)
    return 0;

  if (list->count >= list->cap)
  {
    size_t newcap = list->cap ? list->cap * 2 : 64;
    void *p = realloc(list->items, newcap * sizeof(MachSection));
    if (!p)
      return 0;
    list->items = (MachSection *)p;
    list->cap = newcap;
  }

  list->items[list->count++] = *sec;
  return 1;
}

static void section_list_free(MachSectionList *list)
{
  if (!list)
    return;
  free(list->items);
  list->items = NULL;
  list->count = 0;
  list->cap = 0;
}

static int symbol_list_append(SymbolList *list, uint64_t addr, uint32_t size, uint32_t type, const char *name)
{
  if (!list || !name || !name[0])
    return 0;

  if (list->count >= list->cap)
  {
    size_t newcap = list->cap ? list->cap * 2 : 1024;
    void *p = realloc(list->items, newcap * sizeof(SymbolEntry));
    if (!p)
      return 0;
    list->items = (SymbolEntry *)p;
    list->cap = newcap;
  }

  SymbolEntry *e = &list->items[list->count++];
  e->addr = addr;
  e->size = size;
  e->type = type;
  e->name = strdup(name);
  if (!e->name)
  {
    list->count--;
    return 0;
  }

  return 1;
}

static void symbol_list_free(SymbolList *list)
{
  if (!list)
    return;
  for (size_t i = 0; i < list->count; i++)
    free(list->items[i].name);
  free(list->items);
  list->items = NULL;
  list->count = 0;
  list->cap = 0;
}

static int addrset_init(AddrSet *set, size_t cap)
{
  if (!set)
    return 0;
  if (cap < 16)
    cap = 16;
  size_t p = 1;
  while (p < cap)
    p <<= 1;
  cap = p;
  set->slots = (uint64_t *)calloc(cap, sizeof(uint64_t));
  if (!set->slots)
    return 0;
  set->cap = cap;
  set->count = 0;
  return 1;
}

static void addrset_free(AddrSet *set)
{
  if (!set)
    return;
  free(set->slots);
  set->slots = NULL;
  set->cap = 0;
  set->count = 0;
}

static int addrset_grow(AddrSet *set)
{
  size_t newcap = set->cap ? set->cap * 2 : 64;
  uint64_t *newslots = (uint64_t *)calloc(newcap, sizeof(uint64_t));
  if (!newslots)
    return 0;

  for (size_t i = 0; i < set->cap; i++)
  {
    uint64_t v = set->slots[i];
    if (v == 0)
      continue;
    size_t mask = newcap - 1;
    size_t idx = (size_t)(v ^ (v >> 32)) & mask;
    while (newslots[idx] != 0)
      idx = (idx + 1) & mask;
    newslots[idx] = v;
  }

  free(set->slots);
  set->slots = newslots;
  set->cap = newcap;
  return 1;
}

static int addrset_contains(const AddrSet *set, uint64_t v)
{
  if (!set || !set->slots || v == 0)
    return 0;
  size_t mask = set->cap - 1;
  size_t idx = (size_t)(v ^ (v >> 32)) & mask;
  while (set->slots[idx] != 0)
  {
    if (set->slots[idx] == v)
      return 1;
    idx = (idx + 1) & mask;
  }
  return 0;
}

static int addrset_insert(AddrSet *set, uint64_t v)
{
  if (!set || !set->slots || v == 0)
    return 0;
  if ((set->count + 1) * 4 >= set->cap * 3)
  {
    if (!addrset_grow(set))
      return 0;
  }

  size_t mask = set->cap - 1;
  size_t idx = (size_t)(v ^ (v >> 32)) & mask;
  while (set->slots[idx] != 0)
  {
    if (set->slots[idx] == v)
      return 1;
    idx = (idx + 1) & mask;
  }
  set->slots[idx] = v;
  set->count++;
  return 1;
}

static int read_uleb(const unsigned char *data, size_t size, size_t *offset, uint64_t *value)
{
  uint64_t result = 0;
  uint32_t shift = 0;
  while (*offset < size)
  {
    uint8_t byte = data[(*offset)++];
    result |= ((uint64_t)(byte & 0x7f)) << shift;
    if ((byte & 0x80) == 0)
    {
      *value = result;
      return 1;
    }
    shift += 7;
    if (shift > 63)
      return 0;
  }
  return 0;
}

static int read_sleb(const unsigned char *data, size_t size, size_t *offset, int64_t *value)
{
  int64_t result = 0;
  uint32_t shift = 0;
  uint8_t byte = 0;
  while (*offset < size)
  {
    byte = data[(*offset)++];
    result |= ((int64_t)(byte & 0x7f)) << shift;
    shift += 7;
    if ((byte & 0x80) == 0)
      break;
    if (shift > 63)
      return 0;
  }

  if (shift < 64 && (byte & 0x40))
    result |= -((int64_t)1 << shift);

  *value = result;
  return 1;
}

static const char *read_cstr(const unsigned char *data, size_t size, size_t *offset)
{
  size_t start = *offset;
  while (*offset < size)
  {
    if (data[*offset] == 0)
    {
      const char *s = (const char *)&data[start];
      (*offset)++;
      return s;
    }
    (*offset)++;
  }
  return NULL;
}

static int read_encoded_value(const unsigned char *data, size_t size, size_t *offset, uint8_t encoding,
                              uint64_t pc, int swap, int is64, int apply_rel, uint64_t *out)
{
  if (encoding == DW_EH_PE_omit)
    return 0;

  uint8_t fmt = encoding & 0x0f;
  uint8_t rel = encoding & 0x70;
  uint8_t ind = encoding & 0x80;

  uint64_t uval = 0;
  int64_t sval = 0;

  switch (fmt)
  {
    case DW_EH_PE_absptr:
      if (is64)
      {
        if (*offset + 8 > size)
          return 0;
        uint64_t v = 0;
        memcpy(&v, data + *offset, 8);
        uval = swap64_if(v, swap);
        *offset += 8;
      }
      else
      {
        if (*offset + 4 > size)
          return 0;
        uint32_t v = 0;
        memcpy(&v, data + *offset, 4);
        uval = swap32_if(v, swap);
        *offset += 4;
      }
      break;
    case DW_EH_PE_uleb128:
      if (!read_uleb(data, size, offset, &uval))
        return 0;
      break;
    case DW_EH_PE_udata2:
      if (*offset + 2 > size)
        return 0;
      {
        uint16_t v = 0;
        memcpy(&v, data + *offset, 2);
        uval = swap16_if(v, swap);
        *offset += 2;
      }
      break;
    case DW_EH_PE_udata4:
      if (*offset + 4 > size)
        return 0;
      {
        uint32_t v = 0;
        memcpy(&v, data + *offset, 4);
        uval = swap32_if(v, swap);
        *offset += 4;
      }
      break;
    case DW_EH_PE_udata8:
      if (*offset + 8 > size)
        return 0;
      {
        uint64_t v = 0;
        memcpy(&v, data + *offset, 8);
        uval = swap64_if(v, swap);
        *offset += 8;
      }
      break;
    case DW_EH_PE_sleb128:
      if (!read_sleb(data, size, offset, &sval))
        return 0;
      uval = (uint64_t)sval;
      break;
    case DW_EH_PE_sdata2:
      if (*offset + 2 > size)
        return 0;
      {
        int16_t v = 0;
        memcpy(&v, data + *offset, 2);
        v = (int16_t)swap16_if((uint16_t)v, swap);
        sval = v;
        uval = (uint64_t)sval;
        *offset += 2;
      }
      break;
    case DW_EH_PE_sdata4:
      if (*offset + 4 > size)
        return 0;
      {
        int32_t v = 0;
        memcpy(&v, data + *offset, 4);
        v = (int32_t)swap32_if((uint32_t)v, swap);
        sval = v;
        uval = (uint64_t)sval;
        *offset += 4;
      }
      break;
    case DW_EH_PE_sdata8:
      if (*offset + 8 > size)
        return 0;
      {
        int64_t v = 0;
        memcpy(&v, data + *offset, 8);
        v = (int64_t)swap64_if((uint64_t)v, swap);
        sval = v;
        uval = (uint64_t)sval;
        *offset += 8;
      }
      break;
    default:
      return 0;
  }

  if (apply_rel)
  {
    if (rel == DW_EH_PE_pcrel)
      uval += pc;
    else if (rel != 0)
      return 0;
  }

  if (ind)
    return 0;

  *out = uval;
  return 1;
}

static uint64_t adjust_address(uint64_t addr, uint64_t base_vmaddr, int isexe)
{
  if (!isexe && base_vmaddr && addr >= base_vmaddr)
    return addr - base_vmaddr;
  return addr;
}

typedef struct
{
  uint64_t offset;
  uint8_t encoding;
} CieInfo;

static int cie_list_add(CieInfo **list, size_t *count, size_t *cap, uint64_t offset, uint8_t encoding)
{
  if (!list || !count || !cap)
    return 0;
  if (*count >= *cap)
  {
    size_t newcap = *cap ? (*cap * 2) : 32;
    void *p = realloc(*list, newcap * sizeof(CieInfo));
    if (!p)
      return 0;
    *list = (CieInfo *)p;
    *cap = newcap;
  }
  (*list)[*count].offset = offset;
  (*list)[*count].encoding = encoding;
  (*count)++;
  return 1;
}

static int cie_list_find(CieInfo *list, size_t count, uint64_t offset, uint8_t *encoding)
{
  if (!list || !encoding)
    return 0;
  for (size_t i = 0; i < count; i++)
  {
    if (list[i].offset == offset)
    {
      *encoding = list[i].encoding;
      return 1;
    }
  }
  return 0;
}

static int find_section_by_name(const MachOInfo *info, const char *sectname, MachSection *out)
{
  if (!info || !sectname || !out)
    return 0;

  int found = 0;
  MachSection best;
  memset(&best, 0, sizeof(best));

  for (size_t i = 0; i < info->sections.count; i++)
  {
    const MachSection *sec = &info->sections.items[i];
    if (strncmp(sec->sectname, sectname, 16) == 0)
    {
      if (strncmp(sec->segname, "__TEXT", 16) == 0)
      {
        *out = *sec;
        return 1;
      }
      if (!found)
      {
        best = *sec;
        found = 1;
      }
    }
  }

  if (found)
  {
    *out = best;
    return 1;
  }

  return 0;
}

static void apply_eh_frame_sizes(const unsigned char *data, size_t size, const MachSection *sec,
                                 const MachOInfo *info, SymbolList *list)
{
  if (!data || !sec || !info || !list || size == 0)
    return;

  CieInfo *cies = NULL;
  size_t cie_count = 0;
  size_t cie_cap = 0;

  size_t off = 0;
  while (off + 4 <= size)
  {
    size_t record_start = off;
    uint32_t len32 = 0;
    memcpy(&len32, data + off, sizeof(len32));
    len32 = swap32_if(len32, info->swap);
    off += 4;

    if (len32 == 0)
      break;

    uint64_t length = len32;
    int len64 = 0;
    if (len32 == 0xffffffff)
    {
      if (off + 8 > size)
        break;
      uint64_t len = 0;
      memcpy(&len, data + off, sizeof(len));
      length = swap64_if(len, info->swap);
      off += 8;
      len64 = 1;
    }

    size_t content_start = off;
    size_t record_end = content_start + (size_t)length;
    if (record_end > size)
      break;

    size_t id_size = len64 ? 8 : 4;
    if (content_start + id_size > record_end)
    {
      off = record_end;
      continue;
    }

    uint64_t cie_id = 0;
    if (len64)
    {
      uint64_t v = 0;
      memcpy(&v, data + content_start, 8);
      cie_id = swap64_if(v, info->swap);
    }
    else
    {
      uint32_t v = 0;
      memcpy(&v, data + content_start, 4);
      cie_id = swap32_if(v, info->swap);
    }

    size_t cur = content_start + id_size;
    if (cie_id == 0)
    {
      if (cur >= record_end)
      {
        off = record_end;
        continue;
      }
      uint8_t version = data[cur++];
      (void)version;

      size_t aug_start = cur;
      while (cur < record_end && data[cur] != 0)
        cur++;
      if (cur >= record_end)
      {
        off = record_end;
        continue;
      }
      const char *aug = (const char *)&data[aug_start];
      cur++;

      uint64_t dummy_u = 0;
      int64_t dummy_s = 0;
      read_uleb(data, record_end, &cur, &dummy_u);
      read_sleb(data, record_end, &cur, &dummy_s);
      read_uleb(data, record_end, &cur, &dummy_u);

      if (version >= 4 && cur + 2 <= record_end)
        cur += 2;

      uint8_t encoding = DW_EH_PE_absptr;
      if (strchr(aug, 'z') != NULL)
      {
        uint64_t aug_len = 0;
        if (read_uleb(data, record_end, &cur, &aug_len))
        {
          size_t aug_end = cur + (size_t)aug_len;
          size_t sub = cur;
          const char *p = aug;
          if (*p == 'z')
            p++;
          while (*p && sub < aug_end)
          {
            if (*p == 'R')
            {
              encoding = data[sub++];
            }
            else if (*p == 'L')
            {
              sub++;
            }
            else if (*p == 'P')
            {
              uint8_t enc = 0;
              if (sub < aug_end)
                enc = data[sub++];
              uint64_t tmp = 0;
              size_t tmp_off = sub;
              if (read_encoded_value(data, aug_end, &tmp_off, enc,
                                     sec->addr + sub, info->swap, info->is64, 1, &tmp))
                sub = tmp_off;
              else
                sub = aug_end;
            }
            else if (*p == 'S')
            {

            }
            p++;
          }
          cur = aug_end;
        }
      }

      cie_list_add(&cies, &cie_count, &cie_cap, record_start, encoding);
    }
    else
    {
      uint64_t cie_offset = content_start - cie_id;
      uint8_t encoding = DW_EH_PE_absptr;
      if (!cie_list_find(cies, cie_count, cie_offset, &encoding))
      {
        off = record_end;
        continue;
      }

      if (encoding != DW_EH_PE_omit)
      {
        uint64_t start = 0;
        uint64_t range = 0;
        size_t start_off = cur;
        if (read_encoded_value(data, record_end, &cur, encoding,
                               sec->addr + start_off, info->swap, info->is64, 1, &start))
        {
          uint8_t range_enc = (encoding & 0x0f);
          if (range_enc == DW_EH_PE_omit)
          {

          }
          else if (read_encoded_value(data, record_end, &cur, range_enc,
                                      0, info->swap, info->is64, 0, &range))
          {
            if (range > 0)
            {
              uint64_t adj = adjust_address(start, info->base_vmaddr, (info->filetype == MH_EXECUTE && (info->flags & MH_PIE) == 0));
              for (size_t i = 0; i < list->count; i++)
              {
                if (list->items[i].addr == adj && list->items[i].size == 0)
                  list->items[i].size = (uint32_t)range;
              }
            }
          }
        }
      }
    }

    off = record_end;
  }

  free(cies);
}

static int parse_fat_slice(int fd, uint32_t fileoffset, uint32_t *out_offset, uint32_t *out_size)
{
  uint32_t magic = 0;
  if (!read_at(fd, fileoffset, &magic, sizeof(magic)))
    return 0;

  if (magic != FAT_MAGIC && magic != FAT_CIGAM && magic != FAT_MAGIC_64 && magic != FAT_CIGAM_64)
  {
    *out_offset = fileoffset;
    if (out_size)
      *out_size = 0;
    return 1;
  }

  int swap = (magic == FAT_CIGAM || magic == FAT_CIGAM_64);
  int is64 = (magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64);

  struct fat_header fh;
  if (!read_at(fd, fileoffset, &fh, sizeof(fh)))
    return 0;
  uint32_t nfat = swap32_if(fh.nfat_arch, swap);

  uint32_t best_off = 0;
  uint32_t best_size = 0;
  int found = 0;

  for (uint32_t i = 0; i < nfat; i++)
  {
    if (is64)
    {
      struct fat_arch_64 fa;
      uint64_t off = fileoffset + sizeof(fh) + (uint64_t)i * sizeof(fa);
      if (!read_at(fd, off, &fa, sizeof(fa)))
        break;

      cpu_type_t cputype = (cpu_type_t)swap32_if(fa.cputype, swap);
      if (cputype == CPU_TYPE_ARM64 || cputype == CPU_TYPE_ARM64_32)
      {
        best_off = swap32_if((uint32_t)fa.offset, swap);
        best_size = swap32_if((uint32_t)fa.size, swap);
        found = 1;
        break;
      }

      if (!found)
      {
        best_off = swap32_if((uint32_t)fa.offset, swap);
        best_size = swap32_if((uint32_t)fa.size, swap);
      }
    }
    else
    {
      struct fat_arch fa;
      uint64_t off = fileoffset + sizeof(fh) + (uint64_t)i * sizeof(fa);
      if (!read_at(fd, off, &fa, sizeof(fa)))
        break;

      cpu_type_t cputype = (cpu_type_t)swap32_if(fa.cputype, swap);
      if (cputype == CPU_TYPE_ARM64 || cputype == CPU_TYPE_ARM64_32)
      {
        best_off = swap32_if(fa.offset, swap);
        best_size = swap32_if(fa.size, swap);
        found = 1;
        break;
      }

      if (!found)
      {
        best_off = swap32_if(fa.offset, swap);
        best_size = swap32_if(fa.size, swap);
      }
    }
  }

  if (!best_off)
    return 0;

  *out_offset = fileoffset + best_off;
  if (out_size)
    *out_size = best_size;
  return 1;
}

static int parse_macho_header(int fd, uint32_t fileoffset, MachOInfo *info)
{
  uint32_t magic = 0;
  if (!read_at(fd, fileoffset, &magic, sizeof(magic)))
    return 0;

  memset(info, 0, sizeof(*info));

  if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64)
  {
    struct mach_header_64 mh;
    if (!read_at(fd, fileoffset, &mh, sizeof(mh)))
      return 0;
    info->swap = (magic == MH_CIGAM_64);
    info->is64 = 1;
    info->ncmds = swap32_if(mh.ncmds, info->swap);
    info->sizeofcmds = swap32_if(mh.sizeofcmds, info->swap);
    info->filetype = swap32_if(mh.filetype, info->swap);
    info->flags = swap32_if(mh.flags, info->swap);
  }
  else if (magic == MH_MAGIC || magic == MH_CIGAM)
  {
    struct mach_header mh;
    if (!read_at(fd, fileoffset, &mh, sizeof(mh)))
      return 0;
    info->swap = (magic == MH_CIGAM);
    info->is64 = 0;
    info->ncmds = swap32_if(mh.ncmds, info->swap);
    info->sizeofcmds = swap32_if(mh.sizeofcmds, info->swap);
    info->filetype = swap32_if(mh.filetype, info->swap);
    info->flags = swap32_if(mh.flags, info->swap);
  }
  else
    return 0;

  if (info->sizeofcmds == 0 || info->ncmds == 0)
    return 0;

  uint64_t cmds_offset = fileoffset + (info->is64 ? sizeof(struct mach_header_64) : sizeof(struct mach_header));
  unsigned char *cmds = (unsigned char *)malloc(info->sizeofcmds);
  if (!cmds)
    return 0;

  if (!read_at(fd, cmds_offset, cmds, info->sizeofcmds))
  {
    free(cmds);
    return 0;
  }

  uint64_t cursor = 0;
  for (uint32_t i = 0; i < info->ncmds; i++)
  {
    if (cursor + sizeof(struct load_command) > info->sizeofcmds)
      break;

    struct load_command *lc = (struct load_command *)&cmds[cursor];
    uint32_t cmd = swap32_if(lc->cmd, info->swap);
    uint32_t cmdsize = swap32_if(lc->cmdsize, info->swap);
    if (cmdsize < sizeof(struct load_command) || cursor + cmdsize > info->sizeofcmds)
      break;

    if (cmd == LC_SEGMENT_64 && info->is64)
    {
      struct segment_command_64 seg;
      memcpy(&seg, lc, sizeof(seg));
      seg.vmaddr = swap64_if(seg.vmaddr, info->swap);
      seg.vmsize = swap64_if(seg.vmsize, info->swap);
      seg.fileoff = swap64_if(seg.fileoff, info->swap);
      seg.filesize = swap64_if(seg.filesize, info->swap);
      seg.nsects = swap32_if(seg.nsects, info->swap);
      seg.flags = swap32_if(seg.flags, info->swap);

      if (seg.fileoff == 0 && info->base_vmaddr == 0)
        info->base_vmaddr = seg.vmaddr;

      if (strncmp(seg.segname, "__TEXT", 16) == 0 && info->text_vmaddr == 0)
        info->text_vmaddr = seg.vmaddr;

      size_t sect_offset = cursor + sizeof(struct segment_command_64);
      for (uint32_t s = 0; s < seg.nsects; s++)
      {
        if (sect_offset + sizeof(struct section_64) > cursor + cmdsize)
          break;
        struct section_64 sec;
        memcpy(&sec, &cmds[sect_offset], sizeof(sec));
        MachSection ms;
        memset(&ms, 0, sizeof(ms));
        memcpy(ms.segname, sec.segname, 16);
        memcpy(ms.sectname, sec.sectname, 16);
        ms.segname[16] = 0;
        ms.sectname[16] = 0;
        ms.addr = swap64_if(sec.addr, info->swap);
        ms.size = swap64_if(sec.size, info->swap);
        ms.flags = swap32_if(sec.flags, info->swap);
        ms.reserved1 = swap32_if(sec.reserved1, info->swap);
        ms.reserved2 = swap32_if(sec.reserved2, info->swap);
        ms.fileoff = swap32_if(sec.offset, info->swap);
        section_list_append(&info->sections, &ms);
        sect_offset += sizeof(struct section_64);
      }
    }
    else if (cmd == LC_SEGMENT && !info->is64)
    {
      struct segment_command seg;
      memcpy(&seg, lc, sizeof(seg));
      seg.vmaddr = swap32_if(seg.vmaddr, info->swap);
      seg.vmsize = swap32_if(seg.vmsize, info->swap);
      seg.fileoff = swap32_if(seg.fileoff, info->swap);
      seg.filesize = swap32_if(seg.filesize, info->swap);
      seg.nsects = swap32_if(seg.nsects, info->swap);
      seg.flags = swap32_if(seg.flags, info->swap);

      if (seg.fileoff == 0 && info->base_vmaddr == 0)
        info->base_vmaddr = seg.vmaddr;

      if (strncmp(seg.segname, "__TEXT", 16) == 0 && info->text_vmaddr == 0)
        info->text_vmaddr = seg.vmaddr;

      size_t sect_offset = cursor + sizeof(struct segment_command);
      for (uint32_t s = 0; s < seg.nsects; s++)
      {
        if (sect_offset + sizeof(struct section) > cursor + cmdsize)
          break;
        struct section sec;
        memcpy(&sec, &cmds[sect_offset], sizeof(sec));
        MachSection ms;
        memset(&ms, 0, sizeof(ms));
        memcpy(ms.segname, sec.segname, 16);
        memcpy(ms.sectname, sec.sectname, 16);
        ms.segname[16] = 0;
        ms.sectname[16] = 0;
        ms.addr = swap32_if(sec.addr, info->swap);
        ms.size = swap32_if(sec.size, info->swap);
        ms.flags = swap32_if(sec.flags, info->swap);
        ms.reserved1 = swap32_if(sec.reserved1, info->swap);
        ms.reserved2 = swap32_if(sec.reserved2, info->swap);
        ms.fileoff = swap32_if(sec.offset, info->swap);
        section_list_append(&info->sections, &ms);
        sect_offset += sizeof(struct section);
      }
    }
    else if (cmd == LC_SYMTAB)
    {
      struct symtab_command st;
      memcpy(&st, lc, sizeof(st));
      st.cmd = cmd;
      st.cmdsize = cmdsize;
      st.symoff = swap32_if(st.symoff, info->swap);
      st.nsyms = swap32_if(st.nsyms, info->swap);
      st.stroff = swap32_if(st.stroff, info->swap);
      st.strsize = swap32_if(st.strsize, info->swap);
      info->symtab = st;
    }
    else if (cmd == LC_DYSYMTAB)
    {
      struct dysymtab_command dt;
      memcpy(&dt, lc, sizeof(dt));
      dt.cmd = cmd;
      dt.cmdsize = cmdsize;
      dt.ilocalsym = swap32_if(dt.ilocalsym, info->swap);
      dt.nlocalsym = swap32_if(dt.nlocalsym, info->swap);
      dt.iextdefsym = swap32_if(dt.iextdefsym, info->swap);
      dt.nextdefsym = swap32_if(dt.nextdefsym, info->swap);
      dt.iundefsym = swap32_if(dt.iundefsym, info->swap);
      dt.nundefsym = swap32_if(dt.nundefsym, info->swap);
      dt.tocoff = swap32_if(dt.tocoff, info->swap);
      dt.ntoc = swap32_if(dt.ntoc, info->swap);
      dt.modtaboff = swap32_if(dt.modtaboff, info->swap);
      dt.nmodtab = swap32_if(dt.nmodtab, info->swap);
      dt.extrefsymoff = swap32_if(dt.extrefsymoff, info->swap);
      dt.nextrefsyms = swap32_if(dt.nextrefsyms, info->swap);
      dt.indirectsymoff = swap32_if(dt.indirectsymoff, info->swap);
      dt.nindirectsyms = swap32_if(dt.nindirectsyms, info->swap);
      dt.extreloff = swap32_if(dt.extreloff, info->swap);
      dt.nextrel = swap32_if(dt.nextrel, info->swap);
      dt.locreloff = swap32_if(dt.locreloff, info->swap);
      dt.nlocrel = swap32_if(dt.nlocrel, info->swap);
      info->dysymtab = dt;
    }
    else if (cmd == LC_DYLD_INFO || cmd == LC_DYLD_INFO_ONLY)
    {
      struct dyld_info_command di;
      memcpy(&di, lc, sizeof(di));
      di.cmd = cmd;
      di.cmdsize = cmdsize;
      di.export_off = swap32_if(di.export_off, info->swap);
      di.export_size = swap32_if(di.export_size, info->swap);
      info->dyld_info = di;
    }
    else if (cmd == LC_DYLD_EXPORTS_TRIE)
    {
      struct linkedit_data_command le;
      memcpy(&le, lc, sizeof(le));
      le.cmd = cmd;
      le.cmdsize = cmdsize;
      le.dataoff = swap32_if(le.dataoff, info->swap);
      le.datasize = swap32_if(le.datasize, info->swap);
      info->exports_trie = le;
    }
    else if (cmd == LC_FUNCTION_STARTS)
    {
      struct linkedit_data_command le;
      memcpy(&le, lc, sizeof(le));
      le.cmd = cmd;
      le.cmdsize = cmdsize;
      le.dataoff = swap32_if(le.dataoff, info->swap);
      le.datasize = swap32_if(le.datasize, info->swap);
      info->function_starts = le;
    }

    cursor += cmdsize;
  }

  free(cmds);
  return info->symtab.cmd == LC_SYMTAB;
}

static int read_symtab_data(int fd, uint32_t fileoffset, const MachOInfo *info,
                            unsigned char **symtab, size_t *symtab_size,
                            unsigned char **strtab, size_t *strtab_size)
{
  if (!info->symtab.symoff || !info->symtab.nsyms || !info->symtab.stroff || !info->symtab.strsize)
    return 0;

  size_t nlist_size = info->is64 ? sizeof(struct nlist_64) : sizeof(struct nlist);
  size_t symtab_bytes = info->symtab.nsyms * nlist_size;
  size_t strtab_bytes = info->symtab.strsize;

  *symtab = (unsigned char *)malloc(symtab_bytes);
  *strtab = (unsigned char *)malloc(strtab_bytes);
  if (!*symtab || !*strtab)
  {
    free(*symtab);
    free(*strtab);
    *symtab = NULL;
    *strtab = NULL;
    return 0;
  }

  if (!read_at(fd, (uint64_t)fileoffset + info->symtab.symoff, *symtab, symtab_bytes))
  {
    free(*symtab);
    free(*strtab);
    *symtab = NULL;
    *strtab = NULL;
    return 0;
  }
  if (!read_at(fd, (uint64_t)fileoffset + info->symtab.stroff, *strtab, strtab_bytes))
  {
    free(*symtab);
    free(*strtab);
    *symtab = NULL;
    *strtab = NULL;
    return 0;
  }

  *symtab_size = symtab_bytes;
  *strtab_size = strtab_bytes;
  return 1;
}

static int get_nlist_entry(const unsigned char *symtab, size_t nsyms, size_t index,
                           int is64, int swap, struct nlist_64 *out)
{
  if (index >= nsyms)
    return 0;

  if (is64)
  {
    struct nlist_64 n;
    memcpy(&n, symtab + index * sizeof(struct nlist_64), sizeof(n));
    n.n_strx = swap32_if(n.n_strx, swap);
    n.n_desc = swap16_if(n.n_desc, swap);
    n.n_value = swap64_if(n.n_value, swap);
    *out = n;
    return 1;
  }
  else
  {
    struct nlist n32;
    memcpy(&n32, symtab + index * sizeof(struct nlist), sizeof(n32));
    struct nlist_64 n;
    memset(&n, 0, sizeof(n));
    n.n_strx = swap32_if(n32.n_strx, swap);
    n.n_type = n32.n_type;
    n.n_sect = n32.n_sect;
    n.n_desc = swap16_if(n32.n_desc, swap);
    n.n_value = swap32_if(n32.n_value, swap);
    *out = n;
    return 1;
  }
}

static const char *get_symbol_name(const unsigned char *strtab, size_t strtab_size, uint32_t strx)
{
  if (!strtab || strx >= strtab_size)
    return NULL;
  return (const char *)&strtab[strx];
}

static int parse_exports_trie(const unsigned char *data, size_t size, size_t node_offset,
                              char **namebuf, size_t *name_cap, size_t name_len,
                              uint64_t text_base, int is_arm,
                              SymbolList *symbols, AddrSet *addrset,
                              uint64_t base_vmaddr, int isexe)
{
  if (node_offset >= size)
    return 1;

  char *name = *namebuf;
  size_t cap = *name_cap;

  size_t offset = node_offset;
  uint64_t terminal_size = 0;
  if (!read_uleb(data, size, &offset, &terminal_size))
    return 0;

  size_t children_offset = offset + (size_t)terminal_size;
  if (children_offset > size)
    return 0;

  if (terminal_size)
  {
    uint64_t flags = 0;
    if (!read_uleb(data, size, &offset, &flags))
      return 0;

    const char *import_name = NULL;
    uint64_t address = 0;
    if (flags & EXPORT_SYMBOL_FLAGS_REEXPORT)
    {
      uint64_t ordinal = 0;
      if (!read_uleb(data, size, &offset, &ordinal))
        return 0;
      import_name = read_cstr(data, size, &offset);
      (void)ordinal;
    }
    else
    {
      if (!read_uleb(data, size, &offset, &address))
        return 0;
      address += text_base;
      if (flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER)
      {
        uint64_t resolver = 0;
        if (!read_uleb(data, size, &offset, &resolver))
          return 0;
        (void)resolver;
      }
      if (is_arm && (address & 1))
        address &= 0xfffffffffffffffeULL;
    }

    if (name_len > 1 && (flags == 0 || (flags & EXPORT_SYMBOL_FLAGS_REEXPORT)))
    {
      const char *final_name = name;
      if (final_name[0] == '_')
        final_name++;

      if (!(flags & EXPORT_SYMBOL_FLAGS_REEXPORT))
      {
        uint64_t adj = adjust_address(address, base_vmaddr, isexe);
        if (!addrset_contains(addrset, adj))
        {
          if (symbol_list_append(symbols, adj, 0, (uint32_t)flags, final_name))
            addrset_insert(addrset, adj);
        }
      }
      (void)import_name;
    }
  }

  if (children_offset >= size)
    return 1;

  uint8_t child_count = data[children_offset++];
  for (uint8_t i = 0; i < child_count; i++)
  {
    const char *edge = read_cstr(data, size, &children_offset);
    if (!edge)
      return 0;

    size_t edge_len = strlen(edge);
    if (name_len + edge_len + 1 > cap)
    {
      size_t newcap = cap * 2;
      while (name_len + edge_len + 1 > newcap)
        newcap *= 2;
      char *newbuf = (char *)realloc(name, newcap);
      if (!newbuf)
        return 0;
      name = newbuf;
      cap = newcap;
      *namebuf = newbuf;
      *name_cap = newcap;
    }

    memcpy(name + name_len, edge, edge_len + 1);
    size_t next_len = name_len + edge_len;

    uint64_t child_node = 0;
    if (!read_uleb(data, size, &children_offset, &child_node))
      return 0;

    if (child_node)
    {
      if (!parse_exports_trie(data, size, (size_t)child_node, namebuf, name_cap, next_len,
                              text_base, is_arm, symbols, addrset, base_vmaddr, isexe))
        return 0;
    }

    name = *namebuf;
    name[name_len] = 0;
  }

  return 1;
}

static int build_uncompressed_buffer(const SymbolList *list, unsigned char **out, size_t *out_size)
{
  size_t total = 0;
  for (size_t i = 0; i < list->count; i++)
  {
    size_t name_len = strlen(list->items[i].name);
    if (name_len > 255)
      name_len = 255;
    total += sizeof(symbolinfo) + name_len;
  }

  if (total == 0)
    return 0;

  unsigned char *buf = (unsigned char *)malloc(total);
  if (!buf)
    return 0;

  size_t pos = 0;
  for (size_t i = 0; i < list->count; i++)
  {
    size_t name_len = strlen(list->items[i].name);
    if (name_len > 255)
      name_len = 255;

    symbolinfo si;
    si.address = list->items[i].addr;
    si.size = (int)list->items[i].size;
    si.type = (int)list->items[i].type;
    si.namelength = (unsigned char)name_len;

    memcpy(&buf[pos], &si, sizeof(si));
    pos += sizeof(si);
    memcpy(&buf[pos], list->items[i].name, name_len);
    pos += name_len;
  }

  *out = buf;
  *out_size = total;
  return 1;
}

static int cmp_u64(const void *a, const void *b)
{
  uint64_t va = *(const uint64_t *)a;
  uint64_t vb = *(const uint64_t *)b;
  if (va < vb)
    return -1;
  if (va > vb)
    return 1;
  return 0;
}

static int compress_symbol_list(const SymbolList *list, int isexe, unsigned char **output)
{
  unsigned char *uncompressed = NULL;
  size_t uncompressed_size = 0;
  if (!build_uncompressed_buffer(list, &uncompressed, &uncompressed_size))
    return -1;

  uLongf bound = compressBound((uLong)uncompressed_size);
  if (bound + (3 * sizeof(uint32_t)) > UINT32_MAX)
  {
    free(uncompressed);
    return -1;
  }

  unsigned char *out = (unsigned char *)malloc(bound + (3 * sizeof(uint32_t)));
  if (!out)
  {
    free(uncompressed);
    return -1;
  }

  uLongf comp_size = bound;
  int z = compress2(out + (3 * sizeof(uint32_t)), &comp_size, uncompressed, (uLong)uncompressed_size, 9);
  free(uncompressed);
  if (z != Z_OK)
  {
    free(out);
    return -1;
  }

  *(uint32_t *)&out[0] = (uint32_t)isexe;
  *(uint32_t *)&out[4] = (uint32_t)(comp_size + (3 * sizeof(uint32_t)));
  *(uint32_t *)&out[8] = (uint32_t)uncompressed_size;

  *output = out;
  return 0;
}

int GetSymbolListFromFile(char *filename, uint32_t fileoffset, unsigned char **output)
{
  int fd;
  MachOInfo info;
  unsigned char *symtab = NULL;
  unsigned char *strtab = NULL;
  size_t symtab_size = 0;
  size_t strtab_size = 0;

  *output = NULL;

  fd = open(filename, O_RDONLY);
  if (fd == -1)
    return -1;

  uint32_t slice_offset = 0;
  uint32_t slice_size = 0;
  if (!parse_fat_slice(fd, fileoffset, &slice_offset, &slice_size))
  {
    close(fd);
    return -1;
  }

  if (!parse_macho_header(fd, slice_offset, &info))
  {
    section_list_free(&info.sections);
    close(fd);
    return -1;
  }

  if (info.text_vmaddr == 0)
    info.text_vmaddr = info.base_vmaddr;
  if (info.base_vmaddr == 0)
    info.base_vmaddr = info.text_vmaddr;

  if (!read_symtab_data(fd, slice_offset, &info, &symtab, &symtab_size, &strtab, &strtab_size))
  {
    section_list_free(&info.sections);
    close(fd);
    free(symtab);
    free(strtab);
    return -1;
  }

  int isexe = (info.filetype == MH_EXECUTE && (info.flags & MH_PIE) == 0);

  SymbolList list;
  memset(&list, 0, sizeof(list));

  AddrSet addrset;
  memset(&addrset, 0, sizeof(addrset));
  addrset_init(&addrset, 16384);

  size_t nsyms = info.symtab.nsyms;
  for (size_t i = 0; i < nsyms; i++)
  {
    struct nlist_64 n;
    if (!get_nlist_entry(symtab, nsyms, i, info.is64, info.swap, &n))
      continue;

    if (n.n_value == 0)
      continue;

    const char *name = get_symbol_name(strtab, strtab_size, n.n_strx);
    if (!name || !name[0])
      continue;

    uint64_t addr = adjust_address(n.n_value, info.base_vmaddr, isexe);
    symbol_list_append(&list, addr, 0, n.n_type, name);
    addrset_insert(&addrset, addr);
  }


  uint32_t trie_off = 0;
  uint32_t trie_size = 0;
  if (info.exports_trie.dataoff && info.exports_trie.datasize)
  {
    trie_off = info.exports_trie.dataoff;
    trie_size = info.exports_trie.datasize;
  }
  else if (info.dyld_info.export_off && info.dyld_info.export_size)
  {
    trie_off = info.dyld_info.export_off;
    trie_size = info.dyld_info.export_size;
  }

  if (trie_off && trie_size)
  {
    unsigned char *trie_data = (unsigned char *)malloc(trie_size);
    if (trie_data && read_at(fd, (uint64_t)slice_offset + trie_off, trie_data, trie_size))
    {
      size_t name_cap = 256;
      char *namebuf = (char *)malloc(name_cap);
      if (namebuf)
      {
        namebuf[0] = 0;
        parse_exports_trie(trie_data, trie_size, 0, &namebuf, &name_cap, 0, info.text_vmaddr,
                           0, &list, &addrset, info.base_vmaddr, isexe);
        free(namebuf);
      }
    }
    free(trie_data);
  }


  if (info.function_starts.dataoff && info.function_starts.datasize && info.text_vmaddr)
  {
    unsigned char *fs_data = (unsigned char *)malloc(info.function_starts.datasize);
    if (fs_data && read_at(fd, (uint64_t)slice_offset + info.function_starts.dataoff, fs_data,
                           info.function_starts.datasize))
    {
      size_t fs_count = 0;
      size_t fs_cap = 256;
      uint64_t *fs_addrs = (uint64_t *)malloc(fs_cap * sizeof(uint64_t));
      if (fs_addrs)
      {
        size_t off = 0;
        uint64_t addr = info.text_vmaddr;
        while (off < info.function_starts.datasize)
        {
          uint64_t delta = 0;
          if (!read_uleb(fs_data, info.function_starts.datasize, &off, &delta))
            break;
          if (delta == 0)
            break;
          addr += delta;
          uint64_t rel = adjust_address(addr, info.base_vmaddr, isexe);
          if (fs_count >= fs_cap)
          {
            size_t newcap = fs_cap * 2;
            uint64_t *newp = (uint64_t *)realloc(fs_addrs, newcap * sizeof(uint64_t));
            if (!newp)
              break;
            fs_addrs = newp;
            fs_cap = newcap;
          }
          fs_addrs[fs_count++] = rel;
        }

        if (fs_count > 1)
        {
          qsort(fs_addrs, fs_count, sizeof(uint64_t), cmp_u64);

          for (size_t i = 0; i + 1 < fs_count; i++)
          {
            uint64_t start = fs_addrs[i];
            uint64_t end = fs_addrs[i + 1];
            uint64_t size = (end > start) ? (end - start) : 0;
            if (size == 0)
              continue;
            for (size_t s = 0; s < list.count; s++)
            {
              if (list.items[s].addr == start && list.items[s].size == 0)
                list.items[s].size = (uint32_t)size;
            }
          }
        }

        free(fs_addrs);
      }
    }
    free(fs_data);
  }


  {
    MachSection eh_sec;
    if (find_section_by_name(&info, "__eh_frame", &eh_sec) && eh_sec.size > 0)
    {
      unsigned char *eh_data = (unsigned char *)malloc((size_t)eh_sec.size);
      if (eh_data && read_at(fd, (uint64_t)slice_offset + eh_sec.fileoff, eh_data, (size_t)eh_sec.size))
        apply_eh_frame_sizes(eh_data, (size_t)eh_sec.size, &eh_sec, &info, &list);
      free(eh_data);
    }
  }


  if (info.dysymtab.nindirectsyms && info.dysymtab.indirectsymoff && info.sections.count)
  {
    size_t indirect_count = info.dysymtab.nindirectsyms;
    size_t indirect_bytes = indirect_count * sizeof(uint32_t);
    uint32_t *indirect = (uint32_t *)malloc(indirect_bytes);
    if (indirect && read_at(fd, (uint64_t)slice_offset + info.dysymtab.indirectsymoff, indirect, indirect_bytes))
    {
      for (size_t i = 0; i < indirect_count; i++)
        indirect[i] = swap32_if(indirect[i], info.swap);

      for (size_t s = 0; s < info.sections.count; s++)
      {
        MachSection *sec = &info.sections.items[s];
        if ((sec->flags & SECTION_TYPE) != S_SYMBOL_STUBS)
          continue;
        if (sec->reserved2 == 0)
          continue;

        uint32_t stub_size = sec->reserved2;
        uint32_t num_stubs = (uint32_t)(sec->size / stub_size);
        uint32_t index_offset = sec->reserved1;

        for (uint32_t j = 0; j < num_stubs; j++)
        {
          uint32_t idx = index_offset + j;
          if (idx >= indirect_count)
            break;

          uint32_t sym_index = indirect[idx];
          if (sym_index & (INDIRECT_SYMBOL_ABS | INDIRECT_SYMBOL_LOCAL))
            continue;

          struct nlist_64 n;
          if (!get_nlist_entry(symtab, nsyms, sym_index, info.is64, info.swap, &n))
            continue;

          const char *name = get_symbol_name(strtab, strtab_size, n.n_strx);
          if (!name || !name[0])
            continue;

          uint64_t stub_addr = sec->addr + (uint64_t)j * stub_size;
          uint64_t addr = adjust_address(stub_addr, info.base_vmaddr, isexe);
          if (addrset_contains(&addrset, addr))
            continue;

          if (symbol_list_append(&list, addr, stub_size, N_SECT, name))
            addrset_insert(&addrset, addr);
        }
      }
    }
    free(indirect);
  }

  int r = compress_symbol_list(&list, isexe, output);

  addrset_free(&addrset);
  symbol_list_free(&list);
  section_list_free(&info.sections);
  free(symtab);
  free(strtab);
  close(fd);

  return r;
}

typedef struct _fsc
{
  uintptr_t modulebase;
  symcallback originalCallback;
  void *originalContext;
} FindSymbolContext, *PFindSymbolContext;

void FindSymbol_internal(uintptr_t address, char *symbolname, PFindSymbolContext context)
{
  context->originalCallback(context->modulebase + address, symbolname, context->originalContext);
}

int FindSymbol(HANDLE hProcess, char *symbolname, symcallback cb, void *context)
{
  HANDLE ths;
  ModuleListEntry mle;

  if (GetHandleType(hProcess) == htProcesHandle)
  {
    FindSymbolContext c;
    c.originalCallback = cb;
    c.originalContext = context;
    PProcessData p = (PProcessData)GetPointerFromHandle(hProcess);
    if (p == NULL)
      return FALSE;

    ths = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, p->pid);

    if (Module32First(ths, &mle))
      do
      {
        if (mle.part == 0)
        {
          int fd;
          uint32_t fileoffset = mle.fileOffset;

          c.modulebase = (uintptr_t)mle.baseAddress;

          fd = open(mle.moduleName, O_RDONLY);
          if (fd == -1)
            continue;

          unsigned char *symtab = NULL;
          unsigned char *strtab = NULL;
          size_t symtab_size = 0;
          size_t strtab_size = 0;
          MachOInfo info;
          uint32_t slice_offset = 0;
          uint32_t slice_size = 0;

          if (!parse_fat_slice(fd, fileoffset, &slice_offset, &slice_size))
          {
            close(fd);
            continue;
          }

          if (!parse_macho_header(fd, slice_offset, &info))
          {
            close(fd);
            continue;
          }

          if (read_symtab_data(fd, slice_offset, &info, &symtab, &symtab_size, &strtab, &strtab_size))
          {
            size_t nsyms = info.symtab.nsyms;
            for (size_t i = 0; i < nsyms; i++)
            {
              struct nlist_64 n;
              if (!get_nlist_entry(symtab, nsyms, i, info.is64, info.swap, &n))
                continue;
              if (n.n_value == 0)
                continue;
              const char *name = get_symbol_name(strtab, strtab_size, n.n_strx);
              if (!name)
                continue;
              if (strcmp(name, symbolname) == 0)
              {
                uint64_t addr = adjust_address(n.n_value, info.base_vmaddr, 0);
                FindSymbol_internal((uintptr_t)addr, (char *)name, &c);
                break;
              }
            }
          }

          free(symtab);
          free(strtab);
          section_list_free(&info.sections);
          close(fd);
        }
      } while (Module32Next(ths, &mle));

    CloseHandle(ths);
  }

  return 0;
}
