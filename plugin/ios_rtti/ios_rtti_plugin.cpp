#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstddef>
#include <string>
#include <vector>
#include <set>

#include "itanium_abi_rtti.h"
#include "llvm/Demangle/Demangle.h"

extern "C" {
#include "cepluginsdk.h"
}

static_assert(sizeof(void*) == 8, " build as x64.");

typedef BOOL (__stdcall *ReadProcessMemory_FuncType)(HANDLE hProcess, LPCVOID lpBaseAddress,
                                                     LPVOID lpBuffer, SIZE_T nSize,
                                                     SIZE_T *lpNumberOfBytesRead);

typedef void* (*TPluginFunc)(void* parameters);

typedef intptr_t lua_KContext;
typedef int (*lua_KFunction)(lua_State* L, int status, lua_KContext ctx);

typedef void (*P_lua_getglobal)(lua_State *L, const char *name);
typedef void (*P_lua_setglobal)(lua_State *L, const char *name);
typedef void (*P_lua_pushcclosure)(lua_State *L, lua_CFunction f, int n);
typedef void (*P_lua_pushstring)(lua_State *L, const char *s);
typedef void (*P_lua_pushboolean)(lua_State *L, int b);
typedef void (*P_lua_pushinteger)(lua_State *L, lua_Integer n);
typedef void (*P_lua_settop)(lua_State *L, int idx);
typedef int  (*P_luaL_loadstring)(lua_State *L, const char *s);

typedef int  (*P_lua_pcall)(lua_State *L, int nargs, int nresults, int errfunc);
typedef int  (*P_lua_pcallk)(lua_State *L, int nargs, int nresults, int errfunc,
                            lua_KContext ctx, lua_KFunction k);

typedef lua_Integer (*P_lua_tointegerx)(lua_State *L, int idx, int *isnum);
typedef lua_Integer (*P_lua_tointeger)(lua_State *L, int idx);

static HANDLE* g_OpenedProcessHandlePtr = nullptr;
static ReadProcessMemory_FuncType* g_ReadProcessMemoryPtr = nullptr;
static bool g_Initialized = false;

static P_lua_getglobal g_lua_getglobal = nullptr;
static P_lua_setglobal g_lua_setglobal = nullptr;
static P_lua_pushcclosure g_lua_pushcclosure = nullptr;
static P_lua_pushstring g_lua_pushstring = nullptr;
static P_lua_pushboolean g_lua_pushboolean = nullptr;
static P_lua_pushinteger g_lua_pushinteger = nullptr;
static P_lua_settop g_lua_settop = nullptr;
static P_luaL_loadstring g_luaL_loadstring = nullptr;
static P_lua_pcall g_lua_pcall = nullptr;
static P_lua_pcallk g_lua_pcallk = nullptr;
static P_lua_tointegerx g_lua_tointegerx = nullptr;
static P_lua_tointeger g_lua_tointeger = nullptr;

static lua_State* g_L = nullptr;
static CEP_REGISTERFUNCTION g_RegisterFunction = nullptr;
static CEP_UNREGISTERFUNCTION g_UnregisterFunction = nullptr;
static int g_plugin_id = -1;
static int g_menu_id = -1;

static int My_lua_pcall(lua_State *L, int nargs, int nresults, int errfunc) {
  if (g_lua_pcall) {
    return g_lua_pcall(L, nargs, nresults, errfunc);
  }
  if (g_lua_pcallk) {
    return g_lua_pcallk(L, nargs, nresults, errfunc, (lua_KContext)0, nullptr);
  }
  return -1;
}

static lua_Integer My_lua_tointeger(lua_State *L, int idx, bool *isnum) {
  if (g_lua_tointegerx) {
    int ok = 0;
    lua_Integer v = g_lua_tointegerx(L, idx, &ok);
    if (isnum) *isnum = (ok != 0);
    return v;
  }
  if (g_lua_tointeger) {
    if (isnum) *isnum = true;
    return g_lua_tointeger(L, idx);
  }
  if (isnum) *isnum = false;
  return 0;
}

static void lua_pop_all(lua_State *L) {
  if (g_lua_settop) g_lua_settop(L, 0);
}

static bool exported_struct_valid(const ExportedFunctions* f) {
  const size_t sz = (size_t)f->sizeofExportedFunctions;
  if (sz < offsetof(ExportedFunctions, OpenedProcessHandle) + sizeof(f->OpenedProcessHandle)) return false;
  if (sz < offsetof(ExportedFunctions, ReadProcessMemory) + sizeof(f->ReadProcessMemory)) return false;
  if (sz < offsetof(ExportedFunctions, GetLuaState) + sizeof(f->GetLuaState)) return false;
  if (sz < offsetof(ExportedFunctions, MainThreadCall) + sizeof(f->MainThreadCall)) return false;
  if (sz < offsetof(ExportedFunctions, RegisterFunction) + sizeof(f->RegisterFunction)) return false;
  if (sz < offsetof(ExportedFunctions, UnregisterFunction) + sizeof(f->UnregisterFunction)) return false;
  return true;
}

static uint64_t strip_pac(uint64_t p) {
  return p & 0x0000007FFFFFFFFFULL;
}

static bool read_mem(uint64_t address, void* buffer, size_t size) {
  if (!g_Initialized) return false;
  if (!g_OpenedProcessHandlePtr || !g_ReadProcessMemoryPtr) return false;

  HANDLE hToUse = *g_OpenedProcessHandlePtr;
  if (!hToUse) return false;

  ReadProcessMemory_FuncType rpmFunc = *g_ReadProcessMemoryPtr;
  if (!rpmFunc) return false;

  SIZE_T bytesRead = 0;
  BOOL res = rpmFunc(hToUse, (LPCVOID)address, buffer, size, &bytesRead);
  if (!res || bytesRead != size) return false;
  return true;
}

static bool read_string_safe(uint64_t address, char* buf, size_t size) {
  size_t bytes_read = 0;
  const size_t chunk_size = 64;
  char chunk[64];

  while (bytes_read < size - 1) {
    size_t to_read = (size - 1 - bytes_read) < chunk_size ? (size - 1 - bytes_read) : chunk_size;
    if (!read_mem(address + bytes_read, chunk, to_read)) {
      if (bytes_read == 0) return false;
      break;
    }

    bool found_null = false;
    for (size_t i = 0; i < to_read; i++) {
      buf[bytes_read + i] = chunk[i];
      if (chunk[i] == '\0') {
        found_null = true;
        break;
      }
    }

    bytes_read += to_read;
    if (found_null) return true;
  }

  buf[bytes_read] = '\0';
  return bytes_read > 0;
}

static std::string demangle_name(const char* raw) {
  if (!raw) return std::string();
  char* demangled = llvm::itaniumDemangle(raw);
  if (demangled) {
    std::string res = demangled;
    std::free(demangled);
    return res;
  }
  return std::string(raw);
}

static bool read_typename_from_typeinfo(uint64_t typeinfo_ptr, std::string &raw, std::string &demangled) {
  if (typeinfo_ptr == 0) return false;

  itanium_abi_rtti::Remote_TypeInfo typeInfoLocal;
  if (!read_mem(typeinfo_ptr, &typeInfoLocal, sizeof(typeInfoLocal))) return false;

  uint64_t name_ptr = strip_pac(typeInfoLocal.name_ptr);
  if (name_ptr == 0) return false;

  char name_buf[512] = {0};
  if (!read_string_safe(name_ptr, name_buf, sizeof(name_buf))) return false;

  raw = name_buf;
  demangled = demangle_name(name_buf);
  return true;
}

struct RTTIObjectInfo {
  uint64_t object_addr;
  uint64_t vtable_raw;
  uint64_t vtable;
  uint64_t typeinfo_raw;
  uint64_t typeinfo_ptr;
  int64_t offset_to_top;
  bool offset_to_top_valid;
  uint64_t top_addr;
};

static bool read_object_rtti_info(uint64_t object_addr, RTTIObjectInfo &info, std::string *error) {
  memset(&info, 0, sizeof(info));
  info.object_addr = object_addr;
  if (object_addr == 0) {
    if (error) *error = "Object address is 0";
    return false;
  }

  if (!read_mem(object_addr, &info.vtable_raw, sizeof(info.vtable_raw))) {
    if (error) *error = "Failed to read vtable";
    return false;
  }

  info.vtable = strip_pac(info.vtable_raw);
  if (info.vtable == 0) {
    if (error) *error = "VTable is 0";
    return false;
  }

  info.offset_to_top = 0;
  info.offset_to_top_valid = read_mem(info.vtable - (int64_t)(sizeof(uint64_t) * 2),
                                      &info.offset_to_top, sizeof(info.offset_to_top));
  info.top_addr = object_addr;
  if (info.offset_to_top_valid) {
    info.top_addr = (uint64_t)((int64_t)object_addr + info.offset_to_top);
  }

  if (!read_mem(info.vtable - sizeof(uint64_t), &info.typeinfo_raw, sizeof(info.typeinfo_raw))) {
    if (error) *error = "Failed to read typeinfo";
    return false;
  }

  info.typeinfo_ptr = strip_pac(info.typeinfo_raw);
  if (info.typeinfo_ptr == 0) {
    if (error) *error = "TypeInfo is 0";
    return false;
  }

  return true;
}

static bool get_rtti_name_only(uint64_t object_addr, std::string &demangled) {
  RTTIObjectInfo info;
  if (!read_object_rtti_info(object_addr, info, nullptr)) return false;
  std::string raw;
  if (!read_typename_from_typeinfo(info.typeinfo_ptr, raw, demangled)) return false;
  return !demangled.empty();
}

static int RTTI_Name_Lookup_Lua(lua_State* L) {
  if (!g_lua_pushstring || !g_lua_pushboolean) return 0;

  bool isnum = false;
  uint64_t addr = (uint64_t)My_lua_tointeger(L, 1, &isnum);
  if (!isnum || addr == 0) {
    g_lua_pushboolean(L, 0);
    return 1;
  }

  std::string demangled;
  if (get_rtti_name_only(addr, demangled)) {
    g_lua_pushstring(L, demangled.c_str());
    return 1;
  }

  g_lua_pushboolean(L, 0);
  return 1;
}

static bool read_rtti_kind(uint64_t typeinfo_ptr, std::string &raw, std::string &demangled) {
  uint64_t meta_vtable_raw = 0;
  if (!read_mem(typeinfo_ptr, &meta_vtable_raw, sizeof(meta_vtable_raw))) return false;
  uint64_t meta_vtable = strip_pac(meta_vtable_raw);
  if (meta_vtable == 0) return false;

  uint64_t meta_typeinfo_raw = 0;
  if (!read_mem(meta_vtable - sizeof(uint64_t), &meta_typeinfo_raw, sizeof(meta_typeinfo_raw))) return false;
  uint64_t meta_typeinfo = strip_pac(meta_typeinfo_raw);

  return read_typename_from_typeinfo(meta_typeinfo, raw, demangled);
}

static std::string hex_u64(uint64_t v) {
  char buf[32];
  snprintf(buf, sizeof(buf), "0x%llX", (unsigned long long)v);
  return std::string(buf);
}

static const int kDefaultTreeDepth = 8;
static const uint32_t kMaxBaseCount = 64;
static const char* kKeyError = "Error";
static const char* kKeyTree = "Tree";
static const char* kKeyInputAddress = "Input Address";
static const char* kKeyOffsetToTop = "Offset-to-top";
static const char* kKeyCompleteObjectTop = "Complete Object Top";
static const char* kKeyInputRole = "Input Role";
static const char* kKeyVTableStrip = "VTable (strip)";
static const char* kKeyVTableRaw = "VTable (raw)";
static const char* kKeyTypeInfoStrip = "TypeInfo (strip)";
static const char* kKeyTypeInfoRaw = "TypeInfo (raw)";
static const char* kKeyRttiKind = "RTTI Kind";
static const char* kKeyRttiKindRaw = "RTTI Kind (raw)";
static const char* kKeyName = "Name";
static const char* kKeyMangled = "Mangled";
static const char* kKeyVmiFlags = "VMI Flags";
static const char* kKeyVmiFlagsRaw = "VMI Flags (raw)";
static const char* kKeyVmiBaseCount = "VMI Base Count";
static const char* kKeyPBaseFlags = "PBase Flags";
static const char* kKeyPointee = "Pointee";
static const char* kKeyPointeeRaw = "Pointee (raw)";
static const char* kKeyContext = "Context";
static const char* kKeyContextRaw = "Context (raw)";
static const char* kKeyTreeDepthLimit = "Tree Depth Limit";
static const char* kKeyVTableModule = "VTable Module";
static const char* kKeyVTableRva = "VTable RVA";
static const char* kKeyTypeInfoModule = "TypeInfo Module";
static const char* kKeyTypeInfoRva = "TypeInfo RVA";

static const char* kSummaryOrder[] = {
  kKeyInputAddress,
  kKeyOffsetToTop,
  kKeyCompleteObjectTop,
  kKeyInputRole,
  kKeyName,
  kKeyMangled,
  kKeyRttiKind,
  kKeyRttiKindRaw,
  kKeyVmiFlags,
  kKeyVmiFlagsRaw,
  kKeyVmiBaseCount,
  kKeyPBaseFlags,
  kKeyPointee,
  kKeyPointeeRaw,
  kKeyContext,
  kKeyContextRaw,
  kKeyVTableStrip,
  kKeyVTableRaw,
  kKeyVTableModule,
  kKeyVTableRva,
  kKeyTypeInfoStrip,
  kKeyTypeInfoRaw,
  kKeyTypeInfoModule,
  kKeyTypeInfoRva,
  kKeyTreeDepthLimit,
};
static const size_t kSummaryOrderCount = sizeof(kSummaryOrder) / sizeof(kSummaryOrder[0]);

static const char* kBaseFieldName = "Name";
static const char* kBaseFieldAccess = "Access";
static const char* kBaseFieldVirtual = "Virtual";
static const char* kBaseFieldOffTop = "OffTop";
static const char* kBaseFieldOffEdge = "OffEdge";
static const char* kBaseFieldBaseAddr = "BaseAddr";
static const char* kBaseFieldVTableSlot = "VTableSlot";
static const char* kBaseFieldVBaseOffset = "VBaseOffset";
static const char* kBaseFieldOrder[] = {
  kBaseFieldName,
  kBaseFieldAccess,
  kBaseFieldVirtual,
  kBaseFieldOffTop,
  kBaseFieldOffEdge,
  kBaseFieldBaseAddr,
  kBaseFieldVTableSlot,
  kBaseFieldVBaseOffset,
};
static const size_t kBaseFieldOrderCount = sizeof(kBaseFieldOrder) / sizeof(kBaseFieldOrder[0]);

static std::string build_csv(const char* const* items, size_t count) {
  std::string out;
  for (size_t i = 0; i < count; ++i) {
    if (i) out += ",";
    out += items[i];
  }
  return out;
}

static std::string format_signed_hex_dec(int64_t v) {
  char buf[64];
  uint64_t abs = (v < 0) ? (uint64_t)(-(v + 1)) + 1 : (uint64_t)v;
  if (v < 0) {
    snprintf(buf, sizeof(buf), "-0x%llX (%lld)", (unsigned long long)abs, (long long)v);
  } else {
    snprintf(buf, sizeof(buf), "0x%llX (%lld)", (unsigned long long)abs, (long long)v);
  }
  return std::string(buf);
}

static std::string format_vtable_slot(int64_t byte_offset) {
  int64_t slot = byte_offset / (int64_t)sizeof(uint64_t);
  char buf[96];
  snprintf(buf, sizeof(buf), "slot=%lld (off=%s)",
           (long long)slot, format_signed_hex_dec(byte_offset).c_str());
  return std::string(buf);
}

static void append_line(std::string &out, const std::string &key, const std::string &value) {
  out += key;
  out += "\t";
  out += value;
  out += "\n";
}

static std::string vmi_flags_to_string(uint32_t flags) {
  std::string res;
  if (flags & itanium_abi_rtti::Remote_VmiClassTypeInfo::non_diamond_repeat_mask) {
    if (!res.empty()) res += ", ";
    res += "non_diamond_repeat";
  }
  if (flags & itanium_abi_rtti::Remote_VmiClassTypeInfo::diamond_shaped_mask) {
    if (!res.empty()) res += ", ";
    res += "diamond_shaped";
  }
  if (res.empty()) res = "none";
  return res;
}

static std::string pbase_flags_to_string(uint32_t flags) {
  std::string res;
  auto add = [&res](const char* s) {
    if (!res.empty()) res += " | ";
    res += s;
  };

  if (flags & itanium_abi_rtti::Remote_PBaseTypeInfo::const_mask) add("const");
  if (flags & itanium_abi_rtti::Remote_PBaseTypeInfo::volatile_mask) add("volatile");
  if (flags & itanium_abi_rtti::Remote_PBaseTypeInfo::restrict_mask) add("restrict");
  if (flags & itanium_abi_rtti::Remote_PBaseTypeInfo::incomplete_mask) add("incomplete");
  if (flags & itanium_abi_rtti::Remote_PBaseTypeInfo::incomplete_class_mask) add("incomplete_class");
  if (flags & itanium_abi_rtti::Remote_PBaseTypeInfo::transaction_safe_mask) add("transaction_safe");
  if (flags & itanium_abi_rtti::Remote_PBaseTypeInfo::noexcept_mask) add("noexcept");

  if (res.empty()) res = "none";
  return res;
}

struct BaseEntry {
  uint64_t typeinfo_ptr;
  std::string raw_name;
  std::string demangled;
  int64_t offset;
  int64_t base_offset;
  bool base_offset_valid;
  int64_t edge_offset;
  bool edge_offset_valid;
  uint64_t base_addr;
  bool base_addr_valid;
  int64_t vtable_slot;
  int64_t vbase_offset;
  bool vbase_valid;
  bool is_public;
  bool is_virtual;
};

static void decode_base_offset(int64_t offset_flags, int64_t &offset, bool &is_virtual, bool &is_public) {
  is_virtual = (offset_flags & itanium_abi_rtti::Remote_BaseClassTypeInfo::virtual_mask) != 0;
  is_public = (offset_flags & itanium_abi_rtti::Remote_BaseClassTypeInfo::public_mask) != 0;

  uint64_t offset_raw = (uint64_t)offset_flags >> 8;
  int64_t signed_offset = (int64_t)offset_raw;
  if (signed_offset & (1LL << 55)) {
    signed_offset |= 0xFF00000000000000ULL;
  }
  offset = signed_offset;
}

static bool read_bases(uint64_t typeinfo_ptr, const std::string &kind_raw, std::vector<BaseEntry> &bases, uint32_t &vmi_flags, uint32_t &vmi_count) {
  vmi_flags = 0;
  vmi_count = 0;
  bases.clear();

  if (kind_raw.find("vmi_class_type_info") != std::string::npos) {
    itanium_abi_rtti::Remote_VmiClassTypeInfo vmiInfo;
    if (!read_mem(typeinfo_ptr, &vmiInfo, sizeof(vmiInfo))) return false;

    vmi_flags = vmiInfo.flags;
    vmi_count = vmiInfo.base_count;
    if (vmi_count == 0 || vmi_count > kMaxBaseCount) return true;

    uint64_t base_array_addr = typeinfo_ptr + sizeof(itanium_abi_rtti::Remote_VmiClassTypeInfo);
    for (uint32_t i = 0; i < vmi_count; i++) {
      itanium_abi_rtti::Remote_BaseClassTypeInfo baseEntry;
      uint64_t entry_addr = base_array_addr + (i * sizeof(itanium_abi_rtti::Remote_BaseClassTypeInfo));
      if (!read_mem(entry_addr, &baseEntry, sizeof(baseEntry))) continue;

      uint64_t base_ptr = strip_pac(baseEntry.base_type_ptr);
      std::string raw, dem;
      if (!read_typename_from_typeinfo(base_ptr, raw, dem)) continue;

      BaseEntry b;
      b.typeinfo_ptr = base_ptr;
      b.raw_name = raw;
      b.demangled = dem;
      decode_base_offset(baseEntry.offset_flags, b.offset, b.is_virtual, b.is_public);
      b.base_offset = 0;
      b.base_offset_valid = false;
      b.edge_offset = 0;
      b.edge_offset_valid = false;
      b.base_addr = 0;
      b.base_addr_valid = false;
      b.vtable_slot = 0;
      b.vbase_offset = 0;
      b.vbase_valid = false;
      bases.push_back(b);
    }
    return true;
  }

  if (kind_raw.find("si_class_type_info") != std::string::npos) {
    itanium_abi_rtti::Remote_SiClassTypeInfo siInfo;
    if (!read_mem(typeinfo_ptr, &siInfo, sizeof(siInfo))) return false;

    uint64_t base_ptr = strip_pac(siInfo.base_type_ptr);
    std::string raw, dem;
    if (read_typename_from_typeinfo(base_ptr, raw, dem)) {
      BaseEntry b;
      b.typeinfo_ptr = base_ptr;
      b.raw_name = raw;
      b.demangled = dem;
      b.offset = 0;
      b.is_public = true;
      b.is_virtual = false;
      b.base_offset = 0;
      b.base_offset_valid = true;
      b.edge_offset = 0;
      b.edge_offset_valid = true;
      b.base_addr = 0;
      b.base_addr_valid = false;
      b.vtable_slot = 0;
      b.vbase_offset = 0;
      b.vbase_valid = false;
      bases.push_back(b);
    }
    return true;
  }

  return true;
}

static void compute_base_details(uint64_t top_addr, uint64_t vtable, int64_t current_offset, BaseEntry &b) {
  b.base_offset_valid = false;
  b.edge_offset_valid = false;
  b.base_addr_valid = false;
  b.vbase_valid = false;
  b.base_offset = 0;
  b.edge_offset = 0;
  b.base_addr = 0;
  b.vtable_slot = 0;
  b.vbase_offset = 0;

  if (b.is_virtual) {
    b.vtable_slot = b.offset;
    int64_t vbase_offset = 0;
    uint64_t vbase_addr = (uint64_t)((int64_t)vtable + b.vtable_slot);
    if (read_mem(vbase_addr, &vbase_offset, sizeof(vbase_offset))) {
      b.vbase_offset = vbase_offset;
      b.vbase_valid = true;
      b.base_offset = vbase_offset;
      b.base_offset_valid = true;
      b.base_addr = (uint64_t)((int64_t)top_addr + b.base_offset);
      b.base_addr_valid = true;
      b.edge_offset = b.base_offset - current_offset;
      b.edge_offset_valid = true;
    }
  } else {
    b.base_offset = current_offset + b.offset;
    b.base_offset_valid = true;
    b.base_addr = (uint64_t)((int64_t)top_addr + b.base_offset);
    b.base_addr_valid = true;
    b.edge_offset = b.base_offset - current_offset;
    b.edge_offset_valid = true;
  }
}

static void build_tree(uint64_t typeinfo_ptr, uint64_t top_addr, uint64_t vtable, int64_t current_offset,
                       int depth, int depth_limit, const BaseEntry* edge,
                       std::set<uint64_t> &visited, std::string &out) {
  if (typeinfo_ptr == 0) return;
  if (depth > depth_limit) {
    append_line(out, kKeyTree, std::string(depth * 2, ' ') + "[d=" + std::to_string(depth) + "] <max depth>");
    return;
  }

  std::string raw, dem;
  if (!read_typename_from_typeinfo(typeinfo_ptr, raw, dem)) return;

  std::string line = std::string(depth * 2, ' ') + "[d=" + std::to_string(depth) + "] " + dem;
  if (edge) {
    line += " [" + std::string(edge->is_public ? "public" : "non-public") + "]";
    if (edge->is_virtual) line += " [virtual]";
    if (edge->base_offset_valid) {
      line += " off_top=" + format_signed_hex_dec(edge->base_offset);
    }
    if (edge->edge_offset_valid) {
      line += " off_edge=" + format_signed_hex_dec(edge->edge_offset);
    }
    if (edge->is_virtual) {
      line += " vslot=" + format_vtable_slot(edge->vtable_slot);
      if (edge->vbase_valid) {
        line += " vbase=" + format_signed_hex_dec(edge->vbase_offset);
      }
    }
    if (edge->base_addr_valid) {
      line += " addr=" + hex_u64(edge->base_addr);
    } else if (edge->is_virtual) {
      line += " addr=unresolved";
    }
  } else {
    line += " [root] off_top=" + format_signed_hex_dec(current_offset) + " addr=" + hex_u64((uint64_t)((int64_t)top_addr + current_offset));
  }

  if (visited.count(typeinfo_ptr)) {
    line += " (seen)";
    append_line(out, kKeyTree, line);
    return;
  }
  visited.insert(typeinfo_ptr);

  append_line(out, kKeyTree, line);

  std::string kind_raw, kind_dem;
  if (!read_rtti_kind(typeinfo_ptr, kind_raw, kind_dem)) return;

  std::vector<BaseEntry> bases;
  uint32_t vmi_flags = 0;
  uint32_t vmi_count = 0;
  if (!read_bases(typeinfo_ptr, kind_raw, bases, vmi_flags, vmi_count)) return;

  for (auto &b : bases) {
    compute_base_details(top_addr, vtable, current_offset, b);
    int64_t next_offset = b.base_offset_valid ? b.base_offset : current_offset;
    build_tree(b.typeinfo_ptr, top_addr, vtable, next_offset, depth + 1, depth_limit, &b, visited, out);
  }
}

static bool build_rtti_report(uint64_t object_addr, int depth_limit, std::string &out) {
  out.clear();
  RTTIObjectInfo info;
  std::string err;
  if (!read_object_rtti_info(object_addr, info, &err)) {
    append_line(out, kKeyError, err);
    return false;
  }

  std::string type_raw, type_dem;
  if (!read_typename_from_typeinfo(info.typeinfo_ptr, type_raw, type_dem)) {
    append_line(out, kKeyError, "Failed to read type name");
    return false;
  }

  std::string kind_raw, kind_dem;
  read_rtti_kind(info.typeinfo_ptr, kind_raw, kind_dem);

  append_line(out, kKeyInputAddress, hex_u64(object_addr));
  append_line(out, kKeyOffsetToTop, info.offset_to_top_valid ? format_signed_hex_dec(info.offset_to_top) : "n/a");
  append_line(out, kKeyCompleteObjectTop, info.offset_to_top_valid ? hex_u64(info.top_addr) : "n/a");
  append_line(out, kKeyInputRole, info.offset_to_top_valid ? (info.offset_to_top == 0 ? "top" : "subobject") : "unknown");
  append_line(out, kKeyVTableStrip, hex_u64(info.vtable));
  append_line(out, kKeyVTableRaw, hex_u64(info.vtable_raw));
  append_line(out, kKeyTypeInfoStrip, hex_u64(info.typeinfo_ptr));
  append_line(out, kKeyTypeInfoRaw, hex_u64(info.typeinfo_raw));
  append_line(out, kKeyRttiKind, kind_dem.empty() ? "unknown" : kind_dem);
  append_line(out, kKeyRttiKindRaw, kind_raw.empty() ? "unknown" : kind_raw);
  append_line(out, kKeyName, type_dem);
  append_line(out, kKeyMangled, type_raw);

  if (kind_raw.find("vmi_class_type_info") != std::string::npos) {
    itanium_abi_rtti::Remote_VmiClassTypeInfo vmiInfo;
    if (read_mem(info.typeinfo_ptr, &vmiInfo, sizeof(vmiInfo))) {
      append_line(out, kKeyVmiFlags, vmi_flags_to_string(vmiInfo.flags));
      append_line(out, kKeyVmiFlagsRaw, hex_u64(vmiInfo.flags));
      append_line(out, kKeyVmiBaseCount, std::to_string(vmiInfo.base_count));
    }
  }

  std::vector<BaseEntry> bases;
  uint32_t vmi_flags = 0;
  uint32_t vmi_count = 0;
  if (read_bases(info.typeinfo_ptr, kind_raw, bases, vmi_flags, vmi_count)) {
    for (size_t i = 0; i < bases.size(); i++) {
      auto &b = bases[i];
      compute_base_details(info.top_addr, info.vtable, 0, b);
      std::string line;
      line += std::string(kBaseFieldName) + "=" + b.demangled;
      line += ";" + std::string(kBaseFieldAccess) + "=" + std::string(b.is_public ? "public" : "non-public");
      line += ";" + std::string(kBaseFieldVirtual) + "=" + std::string(b.is_virtual ? "virtual" : "");
      line += ";" + std::string(kBaseFieldOffTop) + "=" + std::string(b.base_offset_valid ? format_signed_hex_dec(b.base_offset) : "unresolved");
      line += ";" + std::string(kBaseFieldOffEdge) + "=" + std::string(b.edge_offset_valid ? format_signed_hex_dec(b.edge_offset) : "unresolved");
      line += ";" + std::string(kBaseFieldBaseAddr) + "=" + std::string(b.base_addr_valid ? hex_u64(b.base_addr) : "unresolved");
      line += ";" + std::string(kBaseFieldVTableSlot) + "=" + std::string(b.is_virtual ? format_vtable_slot(b.vtable_slot) : "");
      line += ";" + std::string(kBaseFieldVBaseOffset) + "=" + std::string(b.vbase_valid ? format_signed_hex_dec(b.vbase_offset) : "unresolved");
      append_line(out, "Base[" + std::to_string(i) + "]", line);
    }
  }

  if (kind_raw.find("pbase_type_info") != std::string::npos ||
      kind_raw.find("pointer_type_info") != std::string::npos ||
      kind_raw.find("pointer_to_member_type_info") != std::string::npos) {
    itanium_abi_rtti::Remote_PBaseTypeInfo pbase;
    if (read_mem(info.typeinfo_ptr, &pbase, sizeof(pbase))) {
      append_line(out, kKeyPBaseFlags, pbase_flags_to_string(pbase.flags));
      uint64_t pointee_ptr = strip_pac(pbase.pointee_type_ptr);
      std::string pointee_raw, pointee_dem;
      if (read_typename_from_typeinfo(pointee_ptr, pointee_raw, pointee_dem)) {
        append_line(out, kKeyPointee, pointee_dem);
        append_line(out, kKeyPointeeRaw, pointee_raw);
      }
    }
  }

  if (kind_raw.find("pointer_to_member_type_info") != std::string::npos) {
    uint64_t context_ptr = 0;
    uint64_t context_addr = info.typeinfo_ptr + sizeof(itanium_abi_rtti::Remote_PBaseTypeInfo);
    if (read_mem(context_addr, &context_ptr, sizeof(context_ptr))) {
      context_ptr = strip_pac(context_ptr);
      std::string ctx_raw, ctx_dem;
      if (read_typename_from_typeinfo(context_ptr, ctx_raw, ctx_dem)) {
        append_line(out, kKeyContext, ctx_dem);
        append_line(out, kKeyContextRaw, ctx_raw);
      }
    }
  }

  if (depth_limit <= 0) depth_limit = kDefaultTreeDepth;
  append_line(out, kKeyTreeDepthLimit, std::to_string(depth_limit));
  std::set<uint64_t> visited;
  build_tree(info.typeinfo_ptr, info.top_addr, info.vtable, 0, 0, depth_limit, nullptr, visited, out);
  return true;
}

static int RTTI_Report_Lua(lua_State* L) {
  if (!g_lua_pushstring || !g_lua_pushboolean) return 0;

  bool isnum = false;
  uint64_t addr = (uint64_t)My_lua_tointeger(L, 1, &isnum);
  if (!isnum || addr == 0) {
    g_lua_pushboolean(L, 0);
    return 1;
  }

  bool isdepth = false;
  int depth = (int)My_lua_tointeger(L, 2, &isdepth);
  if (!isdepth || depth <= 0) depth = kDefaultTreeDepth;

  std::string report;
  build_rtti_report(addr, depth, report);
  g_lua_pushstring(L, report.c_str());
  return 1;
}

static const char* kLuaScript = R"CE(
local ios_rtti_ui = {}

local function ios_rtti_parse_addr(s)
  if s == nil then return nil end
  s = string.gsub(s, "^%s+", "")
  s = string.gsub(s, "%s+$", "")
  if s == "" then return nil end
  if string.sub(s, 1, 2) == "0x" or string.sub(s, 1, 2) == "0X" then
    return tonumber(s)
  end
  if string.find(s, "[a-fA-F]") then
    return tonumber("0x" .. s)
  end
  return tonumber(s)
end

local function ios_rtti_render(report)
  local ui = ios_rtti_ui
  if ui.listSummary == nil or ui.listBases == nil or ui.memoTree == nil then return end

  ui.listSummary.Items.Clear()
  ui.listBases.Items.Clear()
  ui.memoTree.Lines.Text = ''
  if report == nil then return end

  local function tohex(v)
    if v == nil then return '' end
    return string.format('0x%X', v)
  end

  local function parse_hex(s)
    return ios_rtti_parse_addr(s)
  end

  local function find_module(addr)
    if addr == nil or addr == 0 then return nil end
    if enumModules == nil or getModuleSize == nil then return nil end
    local mods = enumModules()
    if mods == nil then return nil end
    for i = 1, #mods do
      local m = mods[i]
      if m ~= nil and m.Address ~= nil and m.Name ~= nil then
        local base = m.Address
        local size = getModuleSize(m.Name)
        if base ~= nil and size ~= nil and addr >= base and addr < (base + size) then
          return m.Name, base, size
        end
      end
    end
    return nil
  end

  local kv = {}
  local bases = {}
  local tree = {}
  local vtable_strip = nil
  local typeinfo_strip = nil

  for line in string.gmatch(report, "[^\r\n]+") do
    local key, value = string.match(line, "^(.-)\t(.*)$")
    if key == nil then
      key = line
      value = ""
    end

    if key == "Tree" then
      table.insert(tree, value)
    elseif string.sub(key, 1, 5) == "Base[" then
      local fields = {}
      for kvpair in string.gmatch(value, "([^;]+)") do
        local k, v = string.match(kvpair, "^(.-)=(.*)$")
        if k ~= nil then fields[k] = v end
      end
      table.insert(bases, fields)
    else
      if key == "VTable (strip)" then
        vtable_strip = parse_hex(value)
      elseif key == "TypeInfo (strip)" then
        typeinfo_strip = parse_hex(value)
      end
      kv[key] = value
    end
  end

  if vtable_strip ~= nil then
    local name, base, size = find_module(vtable_strip)
    if name ~= nil and base ~= nil then
      kv["VTable Module"] = name
      kv["VTable RVA"] = tohex(vtable_strip - base)
    end
  end

  if typeinfo_strip ~= nil then
    local name, base, size = find_module(typeinfo_strip)
    if name ~= nil and base ~= nil then
      kv["TypeInfo Module"] = name
      kv["TypeInfo RVA"] = tohex(typeinfo_strip - base)
    end
  end

  local function raw_equals_strip(strip_key, raw_key)
    if kv[strip_key] == nil or kv[raw_key] == nil then return false end
    return kv[strip_key] == kv[raw_key]
  end

  local function build_csv_table(csv)
    if csv == nil or csv == '' then return {} end
    local t = {}
    for token in string.gmatch(csv, '([^,]+)') do
      token = string.gsub(token, '^%s+', '')
      token = string.gsub(token, '%s+$', '')
      if token ~= '' then table.insert(t, token) end
    end
    return t
  end
  local summary_order = build_csv_table(ios_rtti_summary_order_csv)
  local base_fields = build_csv_table(ios_rtti_base_fields_csv)

  for i = 1, #summary_order do
    local key = summary_order[i]
    local value = kv[key]
    if value ~= nil and value ~= '' then
      if key == "VTable (raw)" and raw_equals_strip("VTable (strip)", "VTable (raw)") then
        value = nil
      elseif key == "TypeInfo (raw)" and raw_equals_strip("TypeInfo (strip)", "TypeInfo (raw)") then
        value = nil
      end
    end
    if value ~= nil and value ~= '' then
      local item = ui.listSummary.Items.Add()
      item.Caption = key
      item.SubItems.Add(value)
    end
  end

  for i, b in ipairs(bases) do
    local item = ui.listBases.Items.Add()
    if #base_fields > 0 then
      item.Caption = b[base_fields[1]] or ""
      for col = 2, #base_fields do
        item.SubItems.Add(b[base_fields[col]] or "")
      end
    end
  end

  if #tree > 0 then
    ui.memoTree.Lines.Text = table.concat(tree, "\n")
  end
end

function ios_rtti_ui_analyze()
  local ui = ios_rtti_ui
  if ui.edtAddr == nil then return end
  local addr = ios_rtti_parse_addr(ui.edtAddr.Text)
  if addr == nil or addr == 0 then return end
  local default_depth = ios_rtti_default_depth
  local depth = nil
  if ui.edtDepth ~= nil then
    local s = ui.edtDepth.Text
    if s ~= nil then
      s = string.gsub(s, "^%s+", "")
      s = string.gsub(s, "%s+$", "")
      if s ~= "" then
        depth = tonumber(s)
      end
    end
  end
  if depth ~= nil and depth <= 0 then
    depth = nil
  end
  if depth == nil or depth <= 0 then
    depth = default_depth
  end
  local report = ios_rtti_report(addr, depth)
  ios_rtti_render(report)
end

function ios_rtti_open()
  local ui = ios_rtti_ui
  if ui.form == nil then
    local f = createForm(false)
    f.Caption = 'RTTI Viewer'
    f.BorderStyle = 'bsSizeable'
    f.BorderIcons = '[biSystemMenu, biMinimize, biMaximize]'
    f.Width = 920
    f.Height = 580

    local top = createPanel(f)
    top.Align = 'alTop'
    top.Height = 30

    local lbl = createLabel(top)
    lbl.Caption = 'Address:'
    lbl.Left = 8
    lbl.Top = 7

    local edt = createEdit(top)
    edt.Left = 70
    edt.Top = 4
    edt.Width = 260

    local lblDepth = createLabel(top)
    lblDepth.Caption = 'Depth:'
    lblDepth.Left = 340
    lblDepth.Top = 7

    local edtDepth = createEdit(top)
    edtDepth.Left = 390
    edtDepth.Top = 4
    edtDepth.Width = 60

    local btn = createButton(top)
    btn.Caption = 'Analyze'
    btn.Left = 460
    btn.Top = 3
    btn.OnClick = ios_rtti_ui_analyze

    local body = createPanel(f)
    body.Align = 'alClient'

    local right = createPanel(body)
    right.Align = 'alRight'
    right.Width = 420

    local splitRight = createSplitter(body)
    splitRight.Align = 'alRight'
    splitRight.Width = 6

    local left = createPanel(body)
    left.Align = 'alClient'

    local grpSummary = createGroupBox(left)
    grpSummary.Caption = 'Summary'
    grpSummary.Align = 'alTop'
    grpSummary.Height = 200

    local lvSummary = createListView(grpSummary)
    lvSummary.Align = 'alClient'
    lvSummary.ViewStyle = 'vsReport'
    lvSummary.ReadOnly = true
    lvSummary.RowSelect = true
    lvSummary.HideSelection = false
    lvSummary.GridLines = true
    lvSummary.Font.Name = 'Consolas'
    lvSummary.Font.Size = 9

    local c = lvSummary.Columns.add()
    c.Caption = 'Field'
    c.Width = 200
    c = lvSummary.Columns.add()
    c.Caption = 'Value'
    c.AutoSize = true

    local splitSummary = createSplitter(left)
    splitSummary.Align = 'alTop'
    splitSummary.Height = 12

    local grpBases = createGroupBox(left)
    grpBases.Caption = 'Bases'
    grpBases.Align = 'alClient'

    local lvBases = createListView(grpBases)
    lvBases.Align = 'alClient'
    lvBases.ViewStyle = 'vsReport'
    lvBases.ReadOnly = true
    lvBases.RowSelect = true
    lvBases.HideSelection = false
    lvBases.GridLines = true
    lvBases.Font.Name = 'Consolas'
    lvBases.Font.Size = 9

    c = lvBases.Columns.add()
    c.Caption = 'Base'
    c.Width = 220
    c = lvBases.Columns.add()
    c.Caption = 'Access'
    c.Width = 70
    c = lvBases.Columns.add()
    c.Caption = 'Virtual'
    c.Width = 60
    c = lvBases.Columns.add()
    c.Caption = 'OffTop'
    c.Width = 160
    c = lvBases.Columns.add()
    c.Caption = 'OffEdge'
    c.Width = 160
    c = lvBases.Columns.add()
    c.Caption = 'BaseAddr'
    c.Width = 150
    c = lvBases.Columns.add()
    c.Caption = 'VTableSlot'
    c.Width = 170
    c = lvBases.Columns.add()
    c.Caption = 'VBaseOff'
    c.AutoSize = true


    local grpTree = createGroupBox(right)
    grpTree.Caption = 'Inheritance Tree'
    grpTree.Align = 'alClient'

    local memo = createMemo(grpTree)
    memo.Align = 'alClient'
    memo.ScrollBars = 'ssBoth'
    memo.ReadOnly = true
    memo.Font.Name = 'Consolas'
    memo.Font.Size = 9

    local function copy_selected(lv, subindex)
      if lv == nil then return end
      local item = lv.Selected
      if item == nil then return end
      local v = item.Caption
      if subindex ~= nil then
        v = item.SubItems[subindex] or item.Caption
      end
      if writeToClipboard ~= nil then
        writeToClipboard(v)
      end
    end

    lvSummary.OnDblClick = function() copy_selected(lvSummary, 0) end
    lvBases.OnDblClick = function() copy_selected(lvBases, 4) end

    f.OnClose = function(sender)
      ios_rtti_ui.form = nil
      ios_rtti_ui.listSummary = nil
      ios_rtti_ui.listBases = nil
      ios_rtti_ui.memoTree = nil
      ios_rtti_ui.edtAddr = nil
      ios_rtti_ui.edtDepth = nil
      return caFree
    end

    ios_rtti_ui.form = f
    ios_rtti_ui.listSummary = lvSummary
    ios_rtti_ui.listBases = lvBases
    ios_rtti_ui.memoTree = memo
    ios_rtti_ui.edtAddr = edt
    ios_rtti_ui.edtDepth = edtDepth
  end

  ios_rtti_ui.form.show()
end
)CE";

static void run_lua_script(lua_State *L, const char *script) {
  if (!g_luaL_loadstring) return;
  if (g_luaL_loadstring(L, script) != 0) {
    lua_pop_all(L);
    return;
  }
  My_lua_pcall(L, 0, 0, 0);
  lua_pop_all(L);
}

static BOOL __stdcall OnMainMenu() {
  if (!g_L || !g_lua_getglobal) return FALSE;
  g_lua_getglobal(g_L, "ios_rtti_open");
  My_lua_pcall(g_L, 0, 0, 0);
  lua_pop_all(g_L);
  return TRUE;
}

static void* RegisterCallbackSafe(void* parameters) {
  lua_State* L = (lua_State*)parameters;
  g_L = L;

  HMODULE hLua = GetModuleHandleA("lua53-64.dll");
  if (!hLua) hLua = GetModuleHandleA("lua53-32.dll");
  if (!hLua) hLua = GetModuleHandleA("lua53.dll");
  if (!hLua) {
    return nullptr;
  }

  g_lua_getglobal = (P_lua_getglobal)GetProcAddress(hLua, "lua_getglobal");
  g_lua_setglobal = (P_lua_setglobal)GetProcAddress(hLua, "lua_setglobal");
  g_lua_pushcclosure = (P_lua_pushcclosure)GetProcAddress(hLua, "lua_pushcclosure");
  g_lua_pushstring = (P_lua_pushstring)GetProcAddress(hLua, "lua_pushstring");
  g_lua_pushboolean = (P_lua_pushboolean)GetProcAddress(hLua, "lua_pushboolean");
  g_lua_pushinteger = (P_lua_pushinteger)GetProcAddress(hLua, "lua_pushinteger");
  g_lua_settop = (P_lua_settop)GetProcAddress(hLua, "lua_settop");
  g_luaL_loadstring = (P_luaL_loadstring)GetProcAddress(hLua, "luaL_loadstring");

  g_lua_pcall = (P_lua_pcall)GetProcAddress(hLua, "lua_pcall");
  if (!g_lua_pcall) {
    g_lua_pcallk = (P_lua_pcallk)GetProcAddress(hLua, "lua_pcallk");
  }

  g_lua_tointegerx = (P_lua_tointegerx)GetProcAddress(hLua, "lua_tointegerx");
  if (!g_lua_tointegerx) {
    g_lua_tointeger = (P_lua_tointeger)GetProcAddress(hLua, "lua_tointeger");
  }

  if (!g_lua_getglobal || !g_lua_pushcclosure || !g_lua_pushstring || !g_lua_pushboolean ||
      (!g_lua_pcall && !g_lua_pcallk) || (!g_lua_tointegerx && !g_lua_tointeger) || !g_luaL_loadstring) {
    return nullptr;
  }

  g_lua_getglobal(L, "registerStructureNameLookup");
  g_lua_pushcclosure(L, RTTI_Name_Lookup_Lua, 0);
  if (My_lua_pcall(L, 1, 0, 0) != 0) {
    lua_pop_all(L);
  }

  g_lua_pushcclosure(L, RTTI_Report_Lua, 0);
  g_lua_setglobal(L, "ios_rtti_report");

  g_lua_pushinteger(L, kDefaultTreeDepth);
  g_lua_setglobal(L, "ios_rtti_default_depth");
  std::string summary_csv = build_csv(kSummaryOrder, kSummaryOrderCount);
  g_lua_pushstring(L, summary_csv.c_str());
  g_lua_setglobal(L, "ios_rtti_summary_order_csv");
  std::string base_fields_csv = build_csv(kBaseFieldOrder, kBaseFieldOrderCount);
  g_lua_pushstring(L, base_fields_csv.c_str());
  g_lua_setglobal(L, "ios_rtti_base_fields_csv");

  run_lua_script(L, kLuaScript);
  return nullptr;
}

extern "C" __attribute__((dllexport)) BOOL __stdcall CEPlugin_GetVersion(PPluginVersion pv, int cbsize) {
  if (cbsize != sizeof(PluginVersion)) return FALSE;
  pv->version = CESDK_VERSION;
  pv->pluginname = (char*)"iOS-RTTI-Viewer";
  return TRUE;
}

extern "C" __attribute__((dllexport)) BOOL __stdcall CEPlugin_InitializePlugin(PExportedFunctions cefuncs_ptr, int pluginid) {
  if (!cefuncs_ptr) return FALSE;
  if (!exported_struct_valid(cefuncs_ptr)) return FALSE;

  g_plugin_id = pluginid;
  g_RegisterFunction = cefuncs_ptr->RegisterFunction;
  g_UnregisterFunction = cefuncs_ptr->UnregisterFunction;

  g_OpenedProcessHandlePtr = cefuncs_ptr->OpenedProcessHandle;
  g_ReadProcessMemoryPtr = (ReadProcessMemory_FuncType*)cefuncs_ptr->ReadProcessMemory;

  if (!g_OpenedProcessHandlePtr || !g_ReadProcessMemoryPtr) return FALSE;

  if (!cefuncs_ptr->GetLuaState) return TRUE;
  lua_State* L = cefuncs_ptr->GetLuaState();
  if (!L) return TRUE;

  if (cefuncs_ptr->MainThreadCall) {
    typedef void (__stdcall *CEP_MAINTHREADCALL)(TPluginFunc func, void* parameters);
    ((CEP_MAINTHREADCALL)cefuncs_ptr->MainThreadCall)(RegisterCallbackSafe, L);
  } else {
    RegisterCallbackSafe(L);
  }

  g_Initialized = true;

  if (g_RegisterFunction) {
    PLUGINTYPE5_INIT mi;
    memset(&mi, 0, sizeof(mi));
    mi.name = (char*)"iOS-RTTI-Viewer";
    mi.callbackroutine = (CEP_PLUGINTYPE5)OnMainMenu;
    mi.shortcut = (char*)"";
    g_menu_id = g_RegisterFunction(pluginid, ptMainMenu, &mi);
  }

  return TRUE;
}

extern "C" __attribute__((dllexport)) BOOL __stdcall CEPlugin_DisablePlugin() {
  if (g_UnregisterFunction && g_menu_id >= 0 && g_plugin_id >= 0) {
    g_UnregisterFunction(g_plugin_id, g_menu_id);
  }
  g_Initialized = false;
  g_OpenedProcessHandlePtr = nullptr;
  g_ReadProcessMemoryPtr = nullptr;

  g_lua_getglobal = nullptr;
  g_lua_setglobal = nullptr;
  g_lua_pushcclosure = nullptr;
  g_lua_pushstring = nullptr;
  g_lua_pushboolean = nullptr;
  g_lua_pushinteger = nullptr;
  g_lua_settop = nullptr;
  g_luaL_loadstring = nullptr;
  g_lua_pcall = nullptr;
  g_lua_pcallk = nullptr;
  g_lua_tointegerx = nullptr;
  g_lua_tointeger = nullptr;
  g_L = nullptr;
  g_RegisterFunction = nullptr;
  g_UnregisterFunction = nullptr;
  g_plugin_id = -1;
  g_menu_id = -1;
  return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
  return TRUE;
}
