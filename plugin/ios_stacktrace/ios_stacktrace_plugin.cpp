#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstddef>
#include <vector>

extern "C" {
#include "cepluginsdk.h"
}

static_assert(sizeof(void*) == 8, "built as x64.");

typedef BOOL (__stdcall *ReadProcessMemory_FuncType)(HANDLE hProcess, LPCVOID lpBaseAddress,
                                                     LPVOID lpBuffer, SIZE_T nSize,
                                                     SIZE_T *lpNumberOfBytesRead);

typedef void* (*TPluginFunc)(void* parameters);

// Lua function pointer types
typedef intptr_t lua_KContext;
typedef int (*lua_KFunction)(lua_State* L, int status, lua_KContext ctx);

typedef void (*P_lua_getglobal)(lua_State *L, const char *name);
typedef void (*P_lua_setglobal)(lua_State *L, const char *name);
typedef void (*P_lua_pushcclosure)(lua_State *L, lua_CFunction f, int n);
typedef void (*P_lua_pushstring)(lua_State *L, const char *s);
typedef void (*P_lua_pushboolean)(lua_State *L, int b);
typedef void (*P_lua_pushinteger)(lua_State *L, lua_Integer n);
typedef void (*P_lua_settop)(lua_State *L, int idx);
typedef void (*P_lua_createtable)(lua_State *L, int narr, int nrec);
typedef void (*P_lua_rawseti)(lua_State *L, int idx, lua_Integer n);
typedef int  (*P_lua_toboolean)(lua_State *L, int idx);
typedef void (*P_lua_settable)(lua_State *L, int idx);
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
static P_lua_createtable g_lua_createtable = nullptr;
static P_lua_rawseti g_lua_rawseti = nullptr;
static P_lua_toboolean g_lua_toboolean = nullptr;
static P_lua_settable g_lua_settable = nullptr;
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

static const int kDefaultMaxFrames = 64;
static const int kMaxFramesLimit = 2048;

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

static int clamp_max_frames(lua_State *L, int idx, int fallback) {
  bool isnum = false;
  if (g_lua_tointegerx || g_lua_tointeger) {
    lua_Integer v = My_lua_tointeger(L, idx, &isnum);
    if (isnum && v > 0 && v < kMaxFramesLimit) return (int)v;
  }
  return fallback;
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

static bool read_mem_mapped(uint64_t address, void* buffer, size_t size,
                            bool use_shadow, uint64_t shadow_orig,
                            uint64_t shadow_new, uint64_t shadow_size) {
  if (use_shadow && shadow_size > 0) {
    uint64_t shadow_end = shadow_orig + shadow_size;
    if (address >= shadow_orig && address < shadow_end) {
      address = shadow_new + (address - shadow_orig);
    }
  }
  return read_mem(address, buffer, size);
}

static bool read_frame_pair(uint64_t fp, uint64_t* prev_fp, uint64_t* ret_addr,
                            bool use_shadow, uint64_t shadow_orig,
                            uint64_t shadow_new, uint64_t shadow_size) {
  if (!prev_fp || !ret_addr) return false;
  if (!read_mem_mapped(fp, prev_fp, sizeof(*prev_fp), use_shadow, shadow_orig, shadow_new, shadow_size)) return false;
  if (!read_mem_mapped(fp + sizeof(uint64_t), ret_addr, sizeof(*ret_addr), use_shadow, shadow_orig, shadow_new, shadow_size)) return false;
  return true;
}

struct FrameEntry {
  uint64_t pc;
  uint64_t sp;
  uint64_t fp;
  uint64_t ret;
};

static void unwind_frames(std::vector<FrameEntry>& out, uint64_t pc, uint64_t sp, uint64_t fp,
                          int max_frames, bool use_shadow, uint64_t shadow_orig,
                          uint64_t shadow_new, uint64_t shadow_size) {
  out.clear();

  uint64_t cur_pc = strip_pac(pc);
  uint64_t cur_sp = sp;
  uint64_t cur_fp = strip_pac(fp);

  for (int i = 0; i < max_frames; i++) {
    uint64_t prev_fp = 0;
    uint64_t ret_addr = 0;
    bool has_fp = (cur_fp != 0 && (cur_fp & 0xF) == 0);
    if (has_fp) {
      if (!read_frame_pair(cur_fp, &prev_fp, &ret_addr, use_shadow, shadow_orig, shadow_new, shadow_size)) {
        break;
      }
    }

    prev_fp = strip_pac(prev_fp);
    ret_addr = strip_pac(ret_addr);

    FrameEntry entry;
    entry.pc = cur_pc;
    entry.sp = cur_sp;
    entry.fp = cur_fp;
    entry.ret = ret_addr;
    out.push_back(entry);

    if (ret_addr == 0) break;
    if (prev_fp == 0 || prev_fp <= cur_fp) break;

    cur_pc = ret_addr;
    cur_sp = cur_fp;
    cur_fp = prev_fp;
  }
}

static bool call_debug_get_context(lua_State *L) {
  if (!g_lua_getglobal || !g_lua_settop) return false;

  g_lua_getglobal(L, "debug_getContext");
  if (My_lua_pcall(L, 0, 1, 0) == 0) {
    bool ok = false;
    if (g_lua_toboolean) {
      ok = (g_lua_toboolean(L, -1) != 0);
    } else {
      bool isnum = false;
      lua_Integer v = My_lua_tointeger(L, -1, &isnum);
      if (isnum) ok = (v != 0);
    }
    lua_pop_all(L);
    return ok;
  }

  lua_pop_all(L);
  g_lua_getglobal(L, "getDebugContext");
  if (My_lua_pcall(L, 0, 1, 0) == 0) {
    bool ok = false;
    if (g_lua_toboolean) {
      ok = (g_lua_toboolean(L, -1) != 0);
    } else {
      bool isnum = false;
      lua_Integer v = My_lua_tointeger(L, -1, &isnum);
      if (isnum) ok = (v != 0);
    }
    lua_pop_all(L);
    return ok;
  }

  lua_pop_all(L);
  return false;
}

static bool lua_get_u64_global(lua_State *L, const char *name, uint64_t *out) {
  if (!g_lua_getglobal || !g_lua_settop) return false;
  g_lua_getglobal(L, name);

  bool isnum = false;
  lua_Integer v = My_lua_tointeger(L, -1, &isnum);
  lua_pop_all(L);

  if (!isnum) return false;
  *out = (uint64_t)v;
  return true;
}

static void push_frame(lua_State *L, int index, uint64_t pc) {
  char buf[64];
  _snprintf_s(buf, sizeof(buf), _TRUNCATE, "0x%llX", (unsigned long long)pc);
  g_lua_pushstring(L, buf);
  g_lua_rawseti(L, -2, index);
}

static void set_field_u64(lua_State *L, const char *name, uint64_t value) {
  if (!g_lua_settable || !g_lua_pushstring || !g_lua_pushinteger) return;
  g_lua_pushstring(L, name);
  g_lua_pushinteger(L, (lua_Integer)value);
  g_lua_settable(L, -3);
}

static void push_frame_table(lua_State *L, uint64_t pc, uint64_t sp, uint64_t fp, uint64_t ret) {
  g_lua_createtable(L, 0, 4);
  set_field_u64(L, "pc", pc);
  set_field_u64(L, "sp", sp);
  set_field_u64(L, "fp", fp);
  set_field_u64(L, "ret", ret);
}

static int IOS_Stacktrace_GetDefaults_Lua(lua_State* L) {
  if (!g_Initialized || !g_lua_createtable || !g_lua_settable) {
    if (g_lua_pushboolean) g_lua_pushboolean(L, 0);
    return 1;
  }

  if (!call_debug_get_context(L)) {
    if (g_lua_pushboolean) g_lua_pushboolean(L, 0);
    return 1;
  }

  uint64_t sp = 0;
  uint64_t fp = 0;
  uint64_t pc = 0;
  if (!lua_get_u64_global(L, "SP", &sp)) sp = 0;
  if (!lua_get_u64_global(L, "X29", &fp)) fp = 0;
  if (!lua_get_u64_global(L, "PC", &pc)) pc = 0;

  g_lua_createtable(L, 0, 3);
  set_field_u64(L, "pc", pc);
  set_field_u64(L, "sp", sp);
  set_field_u64(L, "fp", fp);
  return 1;
}

static int IOS_Stacktrace_Lua(lua_State* L) {
  if (!g_Initialized || !g_lua_createtable || !g_lua_rawseti) {
    if (g_lua_pushboolean) g_lua_pushboolean(L, 0);
    return 1;
  }

  int max_frames = clamp_max_frames(L, 1, kDefaultMaxFrames);

  if (!call_debug_get_context(L)) {
    if (g_lua_pushboolean) g_lua_pushboolean(L, 0);
    return 1;
  }

  uint64_t sp = 0;
  uint64_t fp = 0;
  uint64_t pc = 0;

  if (!lua_get_u64_global(L, "SP", &sp)) sp = 0;
  if (!lua_get_u64_global(L, "X29", &fp)) fp = 0;
  if (!lua_get_u64_global(L, "PC", &pc)) pc = 0;

  std::vector<FrameEntry> frames;
  unwind_frames(frames, pc, sp, fp, max_frames, false, 0, 0, 0);

  g_lua_createtable(L, (int)frames.size(), 0);
  int out_index = 1;
  for (const auto& f : frames) {
    if (f.pc == 0) continue;
    push_frame(L, out_index++, f.pc);
  }

  return 1;
}

static int IOS_Stacktrace_FramesFrom_Lua(lua_State* L) {
  if (!g_Initialized || !g_lua_createtable || !g_lua_rawseti) {
    if (g_lua_pushboolean) g_lua_pushboolean(L, 0);
    return 1;
  }

  int max_frames = kDefaultMaxFrames;
  uint64_t pc = 0;
  uint64_t sp = 0;
  uint64_t fp = 0;
  uint64_t shadow_orig = 0;
  uint64_t shadow_new = 0;
  uint64_t shadow_size = 0;
  bool ok = false;

  if (g_lua_tointegerx || g_lua_tointeger) {
    lua_Integer v = My_lua_tointeger(L, 1, &ok);
    if (ok) pc = (uint64_t)v;
    v = My_lua_tointeger(L, 2, &ok);
    if (ok) sp = (uint64_t)v;
    v = My_lua_tointeger(L, 3, &ok);
    if (ok) fp = (uint64_t)v;
    max_frames = clamp_max_frames(L, 4, kDefaultMaxFrames);
    v = My_lua_tointeger(L, 5, &ok);
    if (ok) shadow_orig = (uint64_t)v;
    v = My_lua_tointeger(L, 6, &ok);
    if (ok) shadow_new = (uint64_t)v;
    v = My_lua_tointeger(L, 7, &ok);
    if (ok) shadow_size = (uint64_t)v;
  }

  bool use_shadow = (shadow_size > 0 && shadow_orig != 0 && shadow_new != 0);
  std::vector<FrameEntry> frames;
  unwind_frames(frames, pc, sp, fp, max_frames, use_shadow, shadow_orig, shadow_new, shadow_size);

  g_lua_createtable(L, (int)frames.size(), 0);
  for (size_t i = 0; i < frames.size(); i++) {
    const auto& f = frames[i];
    push_frame_table(L, f.pc, f.sp, f.fp, f.ret);
    g_lua_rawseti(L, -2, (int)i + 1);
  }

  return 1;
}

static int IOS_Stacktrace_Frames_Lua(lua_State* L) {
  if (!g_Initialized || !g_lua_createtable || !g_lua_rawseti) {
    if (g_lua_pushboolean) g_lua_pushboolean(L, 0);
    return 1;
  }

  int max_frames = clamp_max_frames(L, 1, kDefaultMaxFrames);

  if (!call_debug_get_context(L)) {
    if (g_lua_pushboolean) g_lua_pushboolean(L, 0);
    return 1;
  }

  uint64_t sp = 0;
  uint64_t fp = 0;
  uint64_t pc = 0;

  if (!lua_get_u64_global(L, "SP", &sp)) sp = 0;
  if (!lua_get_u64_global(L, "X29", &fp)) fp = 0;
  if (!lua_get_u64_global(L, "PC", &pc)) pc = 0;

  std::vector<FrameEntry> frames;
  unwind_frames(frames, pc, sp, fp, max_frames, false, 0, 0, 0);

  g_lua_createtable(L, (int)frames.size(), 0);
  for (size_t i = 0; i < frames.size(); i++) {
    const auto& f = frames[i];
    push_frame_table(L, f.pc, f.sp, f.fp, f.ret);
    g_lua_rawseti(L, -2, (int)i + 1);
  }

  return 1;
}

static const char kLuaScript[] = R"Lua(
if ios_stacktrace_ui==nil then
  ios_stacktrace_ui={}
end

local ui_text = {
  main_title = 'Stacktrace',
  manual_title = 'Manual stacktrace config',
  refresh = 'Refresh',
  manual = 'Manual input',
  pc = 'PC',
  sp = 'SP',
  fp = 'FP (X29)',
  shadow = 'Use shadow copy',
  orig = 'Original base',
  new = 'New copy',
  size = 'Size',
  ok = 'OK',
  cancel = 'Cancel',
  arrow = '->',
}

local default_max_frames = ios_stacktrace_default_max_frames or 64

local function ios_hex(v)
  if v==nil then return '' end
  if v==0 then return '0' end
  return string.format('%X', v)
end

local function ios_parse_addr(s)
  if s==nil then return nil end
  s=string.gsub(s,'^%s+','')
  s=string.gsub(s,'%s+$','')
  if s=='' then return nil end
  local v=getAddressSafe(s)
  if v==nil then
    v=tonumber(s,16) or tonumber(s)
  end
  return v
end

local function ios_get_defaults()
  if ios_stacktrace_get_defaults~=nil then
    local t=ios_stacktrace_get_defaults()
    if type(t)=='table' then
      return t.pc or 0, t.sp or 0, t.fp or 0
    end
  end
  return 0, 0, 0
end

local function ios_build_params(n)
  if n==nil or n<=0 then return '' end
  local t={}
  for r=0,n-1 do
    local v=_G['X'..r]
    if v~=nil then
      table.insert(t, 'X'..r..'='..ios_hex(v))
    end
  end
  return table.concat(t, ', ')
end

local function ios_stacktrace_frames_from_safe(pc, sp, fp, max_frames, shadow_orig, shadow_new, shadow_size)
  local raw = ios_stacktrace_frames_from
  if raw==nil then return {} end
  if type(pc)=='string' then pc=ios_parse_addr(pc) end
  if type(sp)=='string' then sp=ios_parse_addr(sp) end
  if type(fp)=='string' then fp=ios_parse_addr(fp) end
  if type(shadow_orig)=='string' then shadow_orig=ios_parse_addr(shadow_orig) end
  if type(shadow_new)=='string' then shadow_new=ios_parse_addr(shadow_new) end
  if type(shadow_size)=='string' then shadow_size=tonumber(shadow_size) end

  pc = pc or 0
  sp = sp or 0
  fp = fp or 0
  shadow_orig = shadow_orig or 0
  shadow_new = shadow_new or 0
  shadow_size = shadow_size or 0
  max_frames = max_frames or default_max_frames
  return raw(pc, sp, fp, max_frames, shadow_orig, shadow_new, shadow_size)
end

local function ios_stacktrace_ui_render(frames)
  local ui=ios_stacktrace_ui
  if ui.list==nil then return end
  if ui.param_count==nil then ui.param_count=4 end
  local params_first=ios_build_params(ui.param_count)
  ui.list.Items.clear()
  if type(frames)~='table' then return end
  for i,fr in ipairs(frames) do
    local pc=fr.pc or fr[1]
    local sp=fr.sp or fr[2]
    local fp=fr.fp or fr[3]
    local ret=fr.ret or fr[4]

    local li=ui.list.Items.add()
    li.Data=pc or 0

    if pc~=nil and pc~=0 then
      li.Caption=getNameFromAddress(pc)
    else
      li.Caption=''
    end

    li.SubItems.add(ios_hex(sp))
    li.SubItems.add(ios_hex(fp))

    if ret~=nil and ret~=0 then
      li.SubItems.add(getNameFromAddress(ret))
    else
      li.SubItems.add('')
    end

    local params = (i==1) and params_first or ''
    li.SubItems.add(params)
  end
end

function ios_stacktrace_ui_refresh()
  local ui=ios_stacktrace_ui
  if ui.list==nil then return end
  local frames=ios_stacktrace_frames(ui.maxframes or default_max_frames)
  ios_stacktrace_ui_render(frames)
end

local function ios_stacktrace_manual_form()
  local ui=ios_stacktrace_ui
  if ui.manual_form~=nil then return ui.manual_form end

  local f=createForm(false)
  f.Caption=ui_text.manual_title
  f.BorderStyle='bsSizeable'
  f.BorderIcons='[biSystemMenu, biMinimize, biMaximize]'
  f.Width=360
  f.Height=230

  local lblPC=createLabel(f)
  lblPC.Caption=ui_text.pc
  lblPC.Left=8
  lblPC.Top=4

  local edtPC=createEdit(f)
  edtPC.Left=8
  edtPC.Top=20
  edtPC.Width=170

  local lblSP=createLabel(f)
  lblSP.Caption=ui_text.sp
  lblSP.Left=8
  lblSP.Top=46

  local edtSP=createEdit(f)
  edtSP.Left=8
  edtSP.Top=62
  edtSP.Width=170

  local lblFP=createLabel(f)
  lblFP.Caption=ui_text.fp
  lblFP.Left=8
  lblFP.Top=88

  local edtFP=createEdit(f)
  edtFP.Left=8
  edtFP.Top=104
  edtFP.Width=170

  local cbShadow=createCheckBox(f)
  cbShadow.Caption=ui_text.shadow
  cbShadow.Left=8
  cbShadow.Top=132

  local lblOrig=createLabel(f)
  lblOrig.Caption=ui_text.orig
  lblOrig.Left=8
  lblOrig.Top=156

  local edtShadowOrig=createEdit(f)
  edtShadowOrig.Left=8
  edtShadowOrig.Top=172
  edtShadowOrig.Width=120

  local lblArrow=createLabel(f)
  lblArrow.Caption=ui_text.arrow
  lblArrow.Left=134
  lblArrow.Top=176

  local lblNew=createLabel(f)
  lblNew.Caption=ui_text.new
  lblNew.Left=150
  lblNew.Top=156

  local edtShadowNew=createEdit(f)
  edtShadowNew.Left=150
  edtShadowNew.Top=172
  edtShadowNew.Width=100

  local lblSize=createLabel(f)
  lblSize.Caption=ui_text.size
  lblSize.Left=260
  lblSize.Top=156

  local edtShadowSize=createEdit(f)
  edtShadowSize.Left=260
  edtShadowSize.Top=172
  edtShadowSize.Width=80
  edtShadowSize.Text='4096'

  local panel=createPanel(f)
  panel.Left=100
  panel.Top=200
  panel.Width=160
  panel.Height=26

  local btnOK=createButton(panel)
  btnOK.Caption=ui_text.ok
  btnOK.Left=0
  btnOK.Top=0
  btnOK.Width=75
  btnOK.OnClick=function() f.ModalResult=1 end

  local btnCancel=createButton(panel)
  btnCancel.Caption=ui_text.cancel
  btnCancel.Left=82
  btnCancel.Top=0
  btnCancel.Width=75
  btnCancel.OnClick=function() f.ModalResult=2 end

  ui.manual_form=f
  ui.edtPC=edtPC
  ui.edtSP=edtSP
  ui.edtFP=edtFP
  ui.cbShadow=cbShadow
  ui.edtShadowOrig=edtShadowOrig
  ui.edtShadowNew=edtShadowNew
  ui.edtShadowSize=edtShadowSize
  return f
end

function ios_stacktrace_ui_manual()
  local ui=ios_stacktrace_ui
  if ui.list==nil then return end

  local f=ios_stacktrace_manual_form()
  local pc0, sp0, fp0 = ios_get_defaults()
  ui.edtPC.Text=pc0~=0 and ios_hex(pc0) or ''
  ui.edtSP.Text=sp0~=0 and ios_hex(sp0) or ''
  ui.edtFP.Text=fp0~=0 and ios_hex(fp0) or ''

  local res=f.showModal()
  if res~=1 then return end

  local pc = ios_parse_addr(ui.edtPC.Text) or 0
  local sp = ios_parse_addr(ui.edtSP.Text) or 0
  local fp = ios_parse_addr(ui.edtFP.Text) or 0

  local shadow_orig = ios_parse_addr(ui.edtShadowOrig.Text) or 0
  local shadow_new = ios_parse_addr(ui.edtShadowNew.Text) or 0
  local shadow_size = tonumber(ui.edtShadowSize.Text) or 0
  if ui.cbShadow.Checked~=true then
    shadow_orig = 0
    shadow_new = 0
    shadow_size = 0
  end

  local frames = ios_stacktrace_frames_from_safe(pc, sp, fp, ui.maxframes or default_max_frames, shadow_orig, shadow_new, shadow_size)
  ios_stacktrace_ui_render(frames)
end

function ios_stacktrace_ui_dblclick(sender)
  local ui=ios_stacktrace_ui
  if ui.list==nil then return end
  local item=ui.list.Selected
  if item==nil then return end
  local addr=item.Data
  if addr==nil or addr==0 then return end
  local mv=getMemoryViewForm()
  if mv and mv.DisassemblerView then
    mv.DisassemblerView.TopAddress=addr
  end
end

function ios_stacktrace_open()
  local ui=ios_stacktrace_ui
  if ui.form==nil then
    local f=createForm(false)
    f.Caption=ui_text.main_title
    f.BorderStyle='bsSizeable'
    f.BorderIcons='[biSystemMenu, biMinimize, biMaximize]'
    f.Width=700
    f.Height=280

    local top=createPanel(f)
    top.Align='alTop'
    top.Height=26

    local btnRefresh=createButton(top)
    btnRefresh.Caption=ui_text.refresh
    btnRefresh.Left=6
    btnRefresh.Top=2
    btnRefresh.OnClick=ios_stacktrace_ui_refresh

    local btnManual=createButton(top)
    btnManual.Caption=ui_text.manual
    btnManual.Left=90
    btnManual.Top=2
    btnManual.OnClick=ios_stacktrace_ui_manual

    local lv=createListView(f)
    lv.Align='alClient'
    lv.ViewStyle='vsReport'
    lv.ReadOnly=true
    lv.RowSelect=true
    lv.HideSelection=false
    lv.AutoWidthLastColumn=true

    local c=lv.Columns.add()
    c.Caption='PC'
    c.Width=120
    c=lv.Columns.add()
    c.Caption='Stack'
    c.Width=120
    c=lv.Columns.add()
    c.Caption='Frame'
    c.Width=120
    c=lv.Columns.add()
    c.Caption='Return'
    c.Width=120
    c=lv.Columns.add()
    c.Caption='Parameters'
    c.AutoSize=true

    local pm=createPopupMenu(f)
    local miRefresh=createMenuItem(pm)
    miRefresh.Caption=ui_text.refresh
    miRefresh.OnClick=ios_stacktrace_ui_refresh
    pm.Items.add(miRefresh)

    local miManual=createMenuItem(pm)
    miManual.Caption=ui_text.manual
    miManual.OnClick=ios_stacktrace_ui_manual
    pm.Items.add(miManual)

    lv.PopupMenu=pm
    lv.OnDblClick=ios_stacktrace_ui_dblclick

    f.OnClose=function(sender)
      ui.form=nil
      ui.list=nil
      return caFree
    end

    ui.form=f
    ui.list=lv
  end

  ui.form.show()
  ios_stacktrace_ui_refresh()
end
)Lua";

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
  g_lua_getglobal(g_L, "ios_stacktrace_open");
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

  if (!hLua) return nullptr;

  g_lua_getglobal = (P_lua_getglobal)GetProcAddress(hLua, "lua_getglobal");
  g_lua_setglobal = (P_lua_setglobal)GetProcAddress(hLua, "lua_setglobal");
  g_lua_pushcclosure = (P_lua_pushcclosure)GetProcAddress(hLua, "lua_pushcclosure");
  g_lua_pushstring = (P_lua_pushstring)GetProcAddress(hLua, "lua_pushstring");
  g_lua_pushboolean = (P_lua_pushboolean)GetProcAddress(hLua, "lua_pushboolean");
  g_lua_pushinteger = (P_lua_pushinteger)GetProcAddress(hLua, "lua_pushinteger");
  g_lua_settop = (P_lua_settop)GetProcAddress(hLua, "lua_settop");
  g_lua_createtable = (P_lua_createtable)GetProcAddress(hLua, "lua_createtable");
  g_lua_rawseti = (P_lua_rawseti)GetProcAddress(hLua, "lua_rawseti");
  g_lua_toboolean = (P_lua_toboolean)GetProcAddress(hLua, "lua_toboolean");
  g_lua_settable = (P_lua_settable)GetProcAddress(hLua, "lua_settable");
  g_luaL_loadstring = (P_luaL_loadstring)GetProcAddress(hLua, "luaL_loadstring");

  g_lua_pcall = (P_lua_pcall)GetProcAddress(hLua, "lua_pcall");
  if (!g_lua_pcall) {
    g_lua_pcallk = (P_lua_pcallk)GetProcAddress(hLua, "lua_pcallk");
  }

  g_lua_tointegerx = (P_lua_tointegerx)GetProcAddress(hLua, "lua_tointegerx");
  if (!g_lua_tointegerx) {
    g_lua_tointeger = (P_lua_tointeger)GetProcAddress(hLua, "lua_tointeger");
  }

  if (!g_lua_getglobal || !g_lua_setglobal || !g_lua_pushcclosure || !g_lua_pushstring ||
      !g_lua_settop || !g_lua_createtable || !g_lua_rawseti || !g_lua_toboolean ||
      !g_lua_settable || !g_luaL_loadstring || (!g_lua_pcall && !g_lua_pcallk) ||
      (!g_lua_tointegerx && !g_lua_tointeger)) {
    return nullptr;
  }

  g_lua_pushcclosure(L, IOS_Stacktrace_Lua, 0);
  g_lua_setglobal(L, "ios_stacktrace");

  g_lua_pushcclosure(L, IOS_Stacktrace_Frames_Lua, 0);
  g_lua_setglobal(L, "ios_stacktrace_frames");

  g_lua_pushcclosure(L, IOS_Stacktrace_FramesFrom_Lua, 0);
  g_lua_setglobal(L, "ios_stacktrace_frames_from");

  g_lua_pushcclosure(L, IOS_Stacktrace_GetDefaults_Lua, 0);
  g_lua_setglobal(L, "ios_stacktrace_get_defaults");

  g_lua_pushinteger(L, kDefaultMaxFrames);
  g_lua_setglobal(L, "ios_stacktrace_default_max_frames");

  run_lua_script(L, kLuaScript);

  return nullptr;
}

extern "C" __attribute__((dllexport)) BOOL __stdcall CEPlugin_GetVersion(PPluginVersion pv, int cbsize) {
  if (cbsize != sizeof(PluginVersion)) return FALSE;
  pv->version = CESDK_VERSION;
  pv->pluginname = (char*)"iOS-Stacktrace";
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
    mi.name = (char*)"iOS-Stacktrace";
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
  g_lua_createtable = nullptr;
  g_lua_rawseti = nullptr;
  g_lua_pcall = nullptr;
  g_lua_pcallk = nullptr;
  g_lua_tointegerx = nullptr;
  g_lua_tointeger = nullptr;
  g_lua_settable = nullptr;
  g_luaL_loadstring = nullptr;
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
