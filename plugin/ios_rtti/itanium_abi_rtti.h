#ifndef ITANIUM_ABI_RTTI_H
#define ITANIUM_ABI_RTTI_H

// Reference: llvm-project-main/libcxxabi/src/private_typeinfo.h

#include <cstdint>

namespace itanium_abi_rtti {

// __shim_type_info
struct Remote_TypeInfo {
    uint64_t vtable_ptr;
    uint64_t name_ptr;
};

// __fundamental_type_info
struct Remote_FundamentalTypeInfo : public Remote_TypeInfo {
};

// __class_type_info
struct Remote_ClassTypeInfo : public Remote_TypeInfo {
};

// __si_class_type_info
struct Remote_SiClassTypeInfo : public Remote_ClassTypeInfo {
    uint64_t base_type_ptr;
};

// __base_class_type_info
struct Remote_BaseClassTypeInfo {
    uint64_t base_type_ptr;
    int64_t offset_flags;   // LP64

    static const int64_t virtual_mask = 0x1;
    static const int64_t public_mask  = 0x2;
    static const int64_t offset_shift = 8;
};

// __vmi_class_type_info
struct Remote_VmiClassTypeInfo : public Remote_ClassTypeInfo {
    uint32_t flags;
    uint32_t base_count;

    enum Flags {
        non_diamond_repeat_mask = 0x1,
        diamond_shaped_mask = 0x2
    };
};

// __pbase_type_info
struct Remote_PBaseTypeInfo : public Remote_TypeInfo {
    uint32_t flags;
    uint32_t _padding;
    uint64_t pointee_type_ptr;

    enum Masks {
        const_mask = 0x1,
        volatile_mask = 0x2,
        restrict_mask = 0x4,
        incomplete_mask = 0x8,
        incomplete_class_mask = 0x10,
        transaction_safe_mask = 0x20,
        noexcept_mask = 0x40
    };
};

} // namespace itanium_abi_rtti

#endif 
