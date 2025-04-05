#pragma once
#include <cstdint>
#include <string>

#ifdef _WIN32
    #include <windows.h>
#endif

extern "C" void* MmGetHostAddress(uint32_t ptr);
template<typename T>
struct xpointer
{
    uint32_t ptr;

    xpointer() : ptr(0)
    {
    }

    xpointer(T* p) : ptr(p != nullptr ? (reinterpret_cast<size_t>(p) - reinterpret_cast<size_t>(MmGetHostAddress(0))) : 0)
    {
    }

    T* get() const
    {
        if (!ptr.value)
        {
            return nullptr;
        }

        return reinterpret_cast<T*>(MmGetHostAddress(ptr));
    }

    operator T* () const
    {
        return get();
    }

    T* operator->() const
    {
        return get();
    }
};


using void_xt = void;
using char_xt = char;
using cchar_xt = char;
using wchar_xt = char16_t;
using short_xt = std::int16_t;
using cshort_xt = std::int16_t;
using long_xt = std::int32_t;
using uchar_xt = std::uint8_t;
using byte_xt = std::uint8_t;
using boolean_xt = std::uint8_t;
using ushort_xt = std::uint16_t;
using word_xt = std::uint16_t;
using ulong_xt = std::uint32_t;
using dword_xt = std::uint32_t;
using size_xt = ulong_xt;
using access_mask_xt = ulong_xt;
using physical_address_xt = ulong_xt;
using uint_xt = std::uint32_t;
using int_xt = std::int32_t;
using int_ptr_xt = int_xt;
using long_ptr_xt = long_xt;
using ulong_ptr_xt = ulong_xt;
using longlong_xt = std::int64_t;
using ulonglong_xt = std::uint64_t;
using quad_xt = std::uint64_t; // 8 byte aligned 8 byte long
using bool_xt = std::int32_t;
using hresult_xt = long_xt;
using ntstatus_xt = long_xt;
using float_xt = float;

typedef void_xt(*PKDEFERRED_ROUTINE)
(
    IN struct _KDPC* Dpc,
    IN PVOID         DeferredContext,
    IN PVOID         SystemArgument1,
    IN PVOID         SystemArgument2
    );


typedef struct _KDPC
{
    cshort_xt              Type;               // 0x00
    union
    {
        uchar_xt           Number;             // 0x02
        boolean_xt         Inserted;           // 0x02
    };
    uchar_xt               Importance;         // 0x03
    LIST_ENTRY          DpcListEntry;       // 0x04
    PKDEFERRED_ROUTINE  DeferredRoutine;    // 0x0C
    PVOID               DeferredContext;
    PVOID               SystemArgument1;
    PVOID               SystemArgument2;
}
KDPC, * PKDPC;

