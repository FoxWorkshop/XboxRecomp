
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

#include "stdio.h"
#include "assert.h"

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

#define X86_FS_LOAD(offset) X86_LOAD_U32(ctx.fs_base + (offset))
#define X86_FS_STORE(offset, value) X86_STORE_U32(ctx.fs_base + (offset), (value))

#ifndef X86_CALL_FUNC
#define X86_CALL_FUNC(x) x(ctx, base)
#endif

#define X86_MEMORY_SIZE 0x100000000ull

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

struct X86Register {
    union {
        uint32_t u32;
        int32_t i32;
        struct {
            uint16_t u16;
            int16_t i16;
        };
        struct {
            uint8_t u8_lo;
            uint8_t u8_hi;
        };
    };
};

struct X86EFlags
{
    uint32_t value = 0;

    // Flag bits (matches x86 architecture)
    enum : uint32_t {
        CF = 1 << 0,  // Carry
        PF = 1 << 2,  // Parity
        AF = 1 << 4,  // Adjust
        ZF = 1 << 6,  // Zero
        SF = 1 << 7,  // Sign
        DF = (1 << 10),
        OF = 1 << 11  // Overflow
    };



    // Clear all flags affected by CMP
    void clear_compare_flags()
    {
        //value &= ~(CF | PF | ZF | SF | OF);
        value &= ~(CF | PF | AF | ZF | SF | OF);
    }

    // Primary comparison function
    void update_compare_flags(uint32_t lhs, uint32_t rhs) {

        clear_compare_flags();

        // Calculate result and flags
        uint32_t result = lhs - rhs;
        bool carry = lhs < rhs;  // Unsigned overflow

        // Zero Flag
        if (result == 0) 
            value |= ZF;

        // Sign Flag (MSB of result)
        if (result & 0x80000000) 
            value |= SF;

        // Parity Flag (even parity of LSB)
        uint8_t lsb = result & 0xFF;
        if ((__builtin_popcount(lsb) % 2) == 0) value |= PF;

        // Carry Flag
        if (carry)
            value |= CF;

        // Overflow Flag (signed overflow)
        bool overflow = ((lhs ^ rhs) & (lhs ^ result)) & 0x80000000;
        if (overflow) value |= OF;
    }

    // Template alias for backward compatibility
    template<typename T>
    void update_compare_flags(T lhs, T rhs) {
        update_compare_flags(static_cast<uint32_t>(lhs),
            static_cast<uint32_t>(rhs));
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

        clear_compare_flags();

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
        clear_compare_flags();

        if (result == 0)
            value |= ZF;
        if (result & (1 << 31))
            value |= SF;
        if (!(__builtin_popcount(result & 0xFF) & 1))
            value |= PF;
    }

    //and, or, xor etc.
    void update_flags_logic(uint32_t result) 
    {
        clear_compare_flags(); 

        value |= (result == 0) ? ZF : 0;
        value |= (result >> 31) & SF;

        uint8_t lsb = result & 0xFF;
        value |= (__builtin_popcount(lsb) % 2 == 0) ? PF : 0;
    }

    void update_flags_add(uint32_t lhs, uint32_t rhs, uint32_t result) 
    {
        clear_compare_flags();

        value |= (result < lhs) ? CF : 0;
        value |= (result == 0) ? ZF : 0;

        // Sign Flag
        value |= (result >> 31) & SF;

        // Overflow Flag (signed overflow)
        value |= ((lhs ^ rhs ^ 0x80000000) & (result ^ rhs) >> 31) & OF;

        // Parity Flag
        uint8_t lsb = result & 0xFF;
        value |= (__builtin_popcount(lsb) % 2 == 0) ? PF : 0;

        // Adjust Flag (BCD carry)
        value |= ((lhs ^ rhs ^ result) >> 4) & AF;
    }

    void update_flags_sub(uint32_t lhs, uint32_t rhs, uint32_t result) {
        clear_compare_flags();

        // Carry Flag (unsigned underflow)
        value |= (lhs < rhs) ? CF : 0;
        value |= (result == 0) ? ZF : 0;
        value |= (result >> 31) & SF;

        // Overflow Flag (signed underflow)
        value |= ((lhs ^ rhs) & (lhs ^ result) >> 31) & OF;

        //Parity/Adjust same as ADD
        uint8_t lsb = result & 0xFF;
        value |= (__builtin_popcount(lsb) % 2 == 0) ? PF : 0;
        value |= ((lhs ^ rhs ^ result) >> 4) & AF;
    }

    void update_flags_mul(bool overflow) 
    {
        clear_compare_flags();

        if (overflow) 
            value |= (CF | OF);       
    }

    void update_flags_inc(uint32_t old_val, uint32_t result) {
        // Preserve Carry Flag
        uint32_t saved_cf = value & CF;
        clear_compare_flags();
        value |= saved_cf;

        value |= (result == 0) ? ZF : 0;
        value |= (result >> 31) & SF;

        // Overflow Flag (only if 0x7FFFFFFF -> 0x80000000)
        value |= (old_val == 0x7FFFFFFF) ? OF : 0;


        uint8_t lsb = result & 0xFF;
        value |= (__builtin_popcount(lsb) % 2 == 0) ? PF : 0;
        value |= ((result & 0x0F) == 0) ? AF : 0;
    }

    void update_flags_dec(uint32_t old_val, uint32_t result) 
    {     
        // Preserve Carry Flag
        uint32_t saved_cf = value & CF;
        clear_compare_flags();
        value |= saved_cf;

        value |= (result == 0) ? ZF : 0;

        value |= (result >> 31) & SF;

        // Overflow Flag (only if 0x80000000 -> 0x7FFFFFFF)
        value |= (old_val == 0x80000000) ? OF : 0;

        //Parity Flag
        uint8_t lsb = result & 0xFF;
        value |= (__builtin_popcount(lsb) % 2 == 0) ? PF : 0;
        value |= ((result & 0x0F) == 0x0F) ? AF : 0;
    }

    // For STOS/MOVS instructions 
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
    uint32_t fs_base = 0; //Base address for FS segment
    uint16_t gs = 0;  //Additional Segment

    uint8_t* teb_ptr; //Thread Environment Block pointer (for FS segment)

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
    uint32_t new_esp = ctx.esp.u32 - 4;
    X86_STORE_U32(new_esp, value);
    ctx.esp.u32 = new_esp;
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
