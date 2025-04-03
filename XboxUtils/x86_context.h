
#ifndef X86_CONTEXT_H_INCLUDED
#define X86_CONTEXT_H_INCLUDED

#ifndef X86_CONFIG_H_INCLUDED
#error "x86_config.h must be included before x86_context.h"
#endif

#include <climits>
#include <cmath>
#include <csetjmp>
#include <cstdint>
#include <cstdlib>
#include <cstring>

//#include <immintrin.h> //SSE/AVX intrinsics
#include <x86intrin.h>
#ifdef _WIN32
#include <intrin.h>
#else
#include <xmmintrin.h>
#include <smmintrin.h>
#endif

#define X86_JOIN(x, y) x##y
#define X86_XSTRINGIFY(x) #x
#define X86_STRINGIFY(x) X86_XSTRINGIFY(x)
#define X86_FUNC(x) void x(X86Context& __restrict ctx, uint8_t* base)
#define X86_FUNC_IMPL(x) extern "C" X86_FUNC(x)
#define X86_EXTERN_FUNC(x) extern X86_FUNC(x)
#define X86_WEAK_FUNC(x) __attribute__((weak,noinline)) X86_FUNC(x)

//Memory Load Macros
#define X86_LOAD_U8(addr)  (*reinterpret_cast<volatile uint8_t*>(base + (addr)))
#define X86_LOAD_U16(addr) (*reinterpret_cast<volatile uint16_t*>(base + (addr)))
#define X86_LOAD_U32(addr) (*reinterpret_cast<volatile uint32_t*>(base + (addr)))
#define X86_LOAD_U64(addr) (*reinterpret_cast<volatile uint64_t*>(base + (addr)))

#define X86_LOAD_F32(addr) (*reinterpret_cast<volatile float*>(base + (addr)))
#define X86_LOAD_F64(addr) (*reinterpret_cast<volatile double*>(base + (addr)))

//Memory Store Macros
#define X86_STORE_U8(addr, value)  (*reinterpret_cast<volatile uint8_t*>(base + (addr)) = (value))
#define X86_STORE_U16(addr, value) (*reinterpret_cast<volatile uint16_t*>(base + (addr)) = (value))
#define X86_STORE_U32(addr, value) (*reinterpret_cast<volatile uint32_t*>(base + (addr)) = (value))
#define X86_STORE_U64(addr, value) (*reinterpret_cast<volatile uint64_t*>(base + (addr)) = (value))

//Floating point variants
#define X86_STORE_F32(addr, value) (*reinterpret_cast<volatile float*>(base + (addr)) = static_cast<float>(value))
#define X86_STORE_F64(addr, value) (*reinterpret_cast<volatile double*>(base + (addr)) = static_cast<double>(value))

// Safe component access macros
#define XMM_F32(reg, idx) (ctx.vec[reg].f32[idx])
#define XMM_U32(reg, idx) (ctx.vec[reg].u32[idx])

#ifndef X86_CALL_FUNC
#define X86_CALL_FUNC(x) x(ctx, base)
#endif

#define X86_MEMORY_SIZE 0x7FFFFFFull

#define X86_LOOKUP_FUNC(x, y) *(X86Func**)(x + X86_IMAGE_BASE + X86_IMAGE_SIZE + (uint64_t(uint32_t(y) - X86_CODE_BASE) * 2))

#ifndef X86_CALL_INDIRECT_FUNC
#define X86_CALL_INDIRECT_FUNC(x) (X86_LOOKUP_FUNC(base, x))(ctx, base)
#endif


typedef void X86Func(struct X86Context& __restrict__ ctx, uint8_t* base);

struct X86FuncMapping
{
    size_t guest;
    X86Func* host;
};

extern X86FuncMapping X86FuncMappings[];

struct X86Register
{
    union {
        struct {
            uint32_t u32;
            uint16_t u16;
            struct {
                uint8_t u8_lo;  // AL/CL/DL/BL
                uint8_t u8_hi;  // AH/CH/DH/BH
            };
        };
    };
};

struct X86EFlags
{
    uint32_t value = 0;

    // Flag bitmasks
    enum : uint32_t {
        CF = (1 << 0),  // Carry Flag
        PF = (1 << 2),  // Parity Flag
        AF = (1 << 4),  // Adjust Flag
        ZF = (1 << 6),  // Zero Flag
        SF = (1 << 7),  // Sign Flag
        DF = (1 << 10),
        OF = (1 << 11)  // Overflow Flag
    };

    // Clear all flags affected by CMP
    void clear_compare_flags() {
        value &= ~(CF | PF | ZF | SF | OF);
    }

    template<typename T>
    void update_compare_flags(T lhs, T rhs) {
        clear_compare_flags();
        T result = lhs - rhs;

        // Zero Flag (ZF)
        if (result == 0)
            value |= ZF;

        // Sign Flag (SF)
        if (std::make_signed_t<T>(result) < 0)
            value |= SF;

        // Carry Flag (CF) - unsigned overflow
        if (lhs < rhs)
            value |= CF;

        // Overflow Flag (OF) - signed overflow
        if constexpr (std::is_floating_point_v<T>)
        {
            // For floating-point, check for infinity
            if (std::isinf(lhs) || std::isinf(rhs))
                value |= OF;
        }
        else {
            // Original integer overflow check
            if (((lhs ^ rhs) & (lhs ^ result)))
                value |= OF;
        }

        // Parity Flag (PF) - least significant byte parity
        if constexpr (!std::is_floating_point_v<T>) {
            uint8_t lsb = static_cast<uint8_t>(result);
            if (__builtin_parity(lsb))
                value |= PF;
        }
    }

    void update_compare_flags_sse(float lhs, float rhs)
    {
        clear_compare_flags();

        // ZF: equal (including unordered)
        if (lhs == rhs || (std::isnan(lhs) || std::isnan(rhs)))
            value |= ZF;

        // SF: less than (or unordered)
        if (lhs < rhs || (std::isnan(lhs) || std::isnan(rhs)))
            value |= SF;

        // PF: unordered (either is NaN)
        if (std::isnan(lhs) || std::isnan(rhs))
            value |= PF;

        // OF/CF: cleared for SSE comparisons
        value &= ~(OF | CF);
    }

    void update_sub_flags(uint32_t a, uint32_t b, uint32_t carry_in) {
        uint64_t a_wide = a;
        uint64_t b_wide = b + carry_in;
        uint64_t result_wide = a_wide - b_wide;
        uint32_t result = static_cast<uint32_t>(result_wide);

        // Clear affected flags
        value &= ~(CF | PF | AF | ZF | SF | OF);

        // 1. Carry Flag (unsigned overflow)
        if (result_wide > a_wide) {
            value |= CF;
        }

        // 2. Parity Flag (least significant byte only)
        uint8_t lsb = static_cast<uint8_t>(result);
        if (__builtin_parity(lsb)) {
            value |= PF;
        }

        // 3. Adjust Flag (BCD carry for nibble)
        if (((a ^ b ^ result) & 0x10) != 0) {
            value |= AF;
        }

        // 4. Zero Flag
        if (result == 0) {
            value |= ZF;
        }

        // 5. Sign Flag (MSB of result)
        if (result & 0x80000000) {
            value |= SF;
        }

        // 6. Overflow Flag (signed overflow)
        if ((a ^ result) & (b ^ result) & 0x80000000) {
            value |= OF;
        }
    }

    void update_test_flags(uint32_t result)
    {
        value &= ~(CF | OF | SF | ZF | PF);  //Clear affected flags
        if (result == 0) value |= ZF;
        if (result & (1 << 31)) value |= SF;
        if (__builtin_parity(result & 0xFF)) value |= PF;
    }

    // For STOS/MOVS instructions (just updates pointers)
    void update_string_pointer(uint32_t& reg) {
        reg += (value & DF) ? -1 : 1;
    }

    // Direction Flag control
    void set_df(bool backward) {
        if (backward) value |= DF;
        else value &= ~DF;
    }
};

struct X87FPU
{
    double st[8];  //8-register stack (ST0-ST7)
    uint16_t top = 0; //Stack pointer (0-7)
    uint16_t cw = 0x037F; //Control word (default: round-to-nearest, 64-bit precision)
    uint16_t sw = 0;  //Status word
    enum : uint16_t {
        C0 = (1 << 8),  // Condition bit 0
        C1 = (1 << 9),  // Condition bit 1
        C2 = (1 << 10), // Condition bit 2 (for FCOS range reduction)
        C3 = (1 << 14)  // Condition bit 3
    };
    uint16_t tw = 0xFFFF; //Tag word (all empty by default)

    void push(double val)
    {
        top = (top - 1) & 7; // Decrement (wraps from 0→7)
        st[top] = val;
    }

    double pop()
    {
        double val = st[top];
        top = (top + 1) & 7; // Increment (wraps from 7→0)
        return val;
    }

    double& st0() { return st[top]; }
    double& st1() { return st[(top + 1) & 7]; }
    double& st2() { return st[(top + 2) & 7]; }
    double& st3() { return st[(top + 3) & 7]; }
    double& st4() { return st[(top + 4) & 7]; }
    double& st5() { return st[(top + 5) & 7]; }
    double& st6() { return st[(top + 6) & 7]; }
    double& st7() { return st[(top + 7) & 7]; }
};

struct X86Context
{

    X86Register eax; //Accumulator
    X86Register ebx; //Base
    X86Register ecx; //Counter
    X86Register edx; //Data
    X86Register esi; //Source Index
    X86Register edi; //Destination Index
    X86Register ebp; //Base Pointer
    X86Register esp; //Stack Pointer

    //Segment registers (16-bit)
    uint16_t es = 0;  //Extra Segment
    uint16_t cs = 0;  //Code Segment
    uint16_t ss = 0;  //Stack Segment
    uint16_t ds = 0;  //Data Segment
    uint16_t fs = 0;  //Additional Segment
    uint16_t gs = 0;  //Additional Segment

    // Flags Register
    X86EFlags eflags;

    // Floating-Point and SIMD Registers
    union {
        __m128 xmm[8];  // Intrinsic access (for _mm_load_ps, etc.)
        struct {
            float   f32[4];  // Per-lane float access
            uint32_t u32[4]; // Per-lane integer access
        } vec[8];  // Indexed by register number (0-7)
    };
    uint32_t mxcsr = 0x1F80;
    X87FPU fpu;
    // Other State Information (optional)
    uint8_t* base; // Base address for memory access

    struct { //technically only used by xbox kernel stuff should't be needed since function will have to be patched
        uint16_t limit;  // GDT size - 1
        uint32_t base;   // Linear address of GDT
    } gdtr = { 0, 0 };     // Initialize to zero
};



inline void X86_PUSH(X86Context& ctx, uint8_t* base, uint32_t value)
{
    ctx.esp.u32 -= 4; // 32-bit x86 uses 4-byte stack ops
    X86_STORE_U32(ctx.esp.u32, value);
}

inline uint32_t X86_POP(X86Context& ctx, uint8_t* base)
{
    uint32_t value = X86_LOAD_U32(ctx.esp.u32);
    ctx.esp.u32 += 4;
    return value;
}


// Flag Macros
#define SET_FLAG(flag, condition) (ctx.RFLAGS = (condition) ? (ctx.RFLAGS | (flag)) : (ctx.RFLAGS & ~(flag)))
#define GET_FLAG(flag) (ctx.RFLAGS & (flag))

// x86 Flags in RFLAGS
#define CARRY_FLAG     (1 << 0)
#define ZERO_FLAG      (1 << 6)
#define OVERFLOW_FLAG  (1 << 11)

// SIMD Helpers (if needed)
inline __m128i X86_ADD_EPU32(__m128i a, __m128i b) {
    return _mm_add_epi32(a, _mm_min_epu32(_mm_xor_si128(a, _mm_cmpeq_epi32(a, a)), b));
}

inline __m128i X86_AVG_EPU8(__m128i a, __m128i b) {
    return _mm_avg_epu8(a, b);
}

inline __m128i X86_AVG_EPU16(__m128i a, __m128i b)
{
    return _mm_avg_epu16(a, b);
}


#endif // X86_CONTEXT_H_INCLUDED
