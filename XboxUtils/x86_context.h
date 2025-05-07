
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
#include <limits>
#include <atomic>

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

#define XMM_F32(reg, idx) (ctx.vec[reg].f32[idx])
#define XMM_U32(reg, idx) (ctx.vec[reg].u32[idx])

// SSE Load Operations
#define X86_MOVUPS(reg, addr) \
    ctx.xmm[(reg)] = _mm_loadu_ps(reinterpret_cast<const float*>(base + (addr)))

#define X86_MOVAPS(reg, addr) \
    ctx.xmm[(reg)] = _mm_load_ps(reinterpret_cast<const float*>(base + (addr)))

// SSE Store Operations
#define X86_MOVUPS_STORE(addr, reg) \
    _mm_storeu_ps(reinterpret_cast<float*>(base + (addr)), ctx.xmm[(reg)])

#define X86_MOVAPS_STORE(addr, reg) \
    _mm_store_ps(reinterpret_cast<float*>(base + (addr)), ctx.xmm[(reg)])

#define X86_MOVNTPS(addr, reg) \
    _mm_stream_ps(reinterpret_cast<float*>(base + (addr)), ctx.xmm[(reg)])

// Register Operations
#define X86_MOVAPS_REG(dest, src) \
    ctx.xmm[(dest)] = ctx.xmm[(src)]

#define X86_MOVLHPS(dest, src) \
    ctx.xmm[(dest)] = _mm_movelh_ps(ctx.xmm[(dest)], ctx.xmm[(src)])

#define X86_MOVHLPS(dest, src) \
    ctx.xmm[(dest)] = _mm_movehl_ps(ctx.xmm[(dest)], ctx.xmm[(src)])

// Arithmetic Operations
#define X86_ADDPS(dest, src) \
    ctx.xmm[(dest)] = _mm_add_ps(ctx.xmm[(dest)], ctx.xmm[(src)])

#define X86_MULPS(dest, src) \
    ctx.xmm[(dest)] = _mm_mul_ps(ctx.xmm[(dest)], ctx.xmm[(src)])

#define X86_SHUFPS(dest, src, imm) \
    ctx.xmm[(dest)] = _mm_shuffle_ps(ctx.xmm[(dest)], ctx.xmm[(src)], (imm))

// MMX Load/Store
#define X86_MMX_LOAD(addr) (*reinterpret_cast<uint64_t*>(base + (addr)))
#define X86_MMX_STORE(addr, value) (*reinterpret_cast<uint64_t*>(base + (addr)) = (value))
#define MMX_REG(reg, offset) (ctx.mmx[(reg) - offset])

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
        uint64_t u64;
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
        bool overflow = (((lhs ^ rhs) & (lhs ^ result)) >> 31) != 0;
        if (overflow)
            value |= OF;
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
        const bool unordered = std::isnan(lhs) || std::isnan(rhs);

        // ZF: equal (including unordered)
        if (lhs == rhs || unordered)
            value |= ZF;

        // CF: set when lhs < rhs (for jb instruction)
        if (lhs < rhs)
            value |= CF;

        // PF: unordered (either is NaN)
        if (unordered)
            value |= PF;

        // SF: typically not used in FP comparisons
        // OF: typically cleared in FP comparisons
        value &= ~OF;
    }

    void update_sub_flags(uint32_t lhs, uint32_t rhs, uint32_t result)
    {
        clear_compare_flags();
        value &= ~(X86EFlags::CF | X86EFlags::PF | X86EFlags::AF | X86EFlags::ZF | X86EFlags::SF | X86EFlags::OF);

        // CF: set if unsigned overflow (lhs < rhs)
        value |= (lhs < rhs) ? X86EFlags::CF : 0;
        // OF: Signed overflow
        value |= (((lhs ^ rhs) & (lhs ^ result)) >> 31) ? X86EFlags::OF : 0;

        // ZF: Result zero
        value |= (result == 0) ? X86EFlags::ZF : 0;

        // SF: Negative result
        value |= (result & 0x80000000) ? X86EFlags::SF : 0;
        uint8_t lsb = result & 0xFF;
        value |= (__builtin_popcount(lsb) % 2 == 0) ? X86EFlags::PF : 0;
        value |= ((lhs ^ rhs ^ result) & 0x10) ? X86EFlags::AF : 0;
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

    void update_flags_adc(uint32_t lhs, uint32_t rhs, uint32_t carry, uint32_t result)
    {
        clear_compare_flags();
        value |= ((result < lhs) || (result == lhs && carry == 1)) ? CF : 0;
        value |= (result == 0) ? ZF : 0;
        value |= (result >> 31) & SF;
        value |= ((((lhs ^ result) & (rhs ^ result)) >> 31) != 0) ? OF : 0;
        uint8_t lsb = result & 0xFF;
        value |= (__builtin_popcount(lsb) % 2 == 0) ? PF : 0;
        value |= (((lhs & 0xF) + (rhs & 0xF) + carry) > 0xF) ? AF : 0;
    }

    void update_flags_add(uint32_t lhs, uint32_t rhs, uint32_t result)
    {
        clear_compare_flags();

        // Carry Flag: Set if result < either operand (unsigned overflow)
        value |= (result < lhs) ? CF : 0;

        // Zero Flag: Set if result is zero
        value |= (result == 0) ? ZF : 0;

        // Sign Flag: Set if result is negative (bit 31 is 1)
        value |= (result >> 31) & SF;

        // Overflow Flag: Set if signed overflow occurs (same sign inputs, different sign output)

        value |= ((((lhs ^ result) & (rhs ^ result)) >> 31) != 0) ? OF : 0;

        // Parity Flag: Set if result has even number of set bits in lowest byte
        uint8_t lsb = result & 0xFF;
        value |= (__builtin_popcount(lsb) % 2 == 0) ? PF : 0;

        // Auxiliary Flag: Set if carry from bit 3 to bit 4
        value |= (((lhs & 0xF) + (rhs & 0xF)) > 0xF) ? AF : 0;
    }

    void update_flags_sub(uint32_t lhs, uint32_t rhs, uint32_t result)
    {
        clear_compare_flags();

        // Special case: SUB X,0 is identical to TEST X,X (only affects SF/ZF/PF)
        if (rhs == 0) 
        {
            value |= (result == 0) ? ZF : 0;
            value |= (result >> 31) & SF;
            uint8_t lsb = result & 0xFF;
            value |= (__builtin_popcount(lsb) % 2 == 0) ? PF : 0;
            return;  // Skip CF/OF/AF for this case!
        }

        // For unsigned comparison, CF is set if rhs > lhs (borrow needed)
        value |= (lhs < rhs) ? CF : 0;
        value |= (result == 0) ? ZF : 0;
        value |= (result >> 31) & SF;
        value |= ((((lhs ^ rhs) & (lhs ^ result)) >> 31) != 0) ? OF : 0;
        uint8_t lsb = result & 0xFF;
        value |= (__builtin_popcount(lsb) % 2 == 0) ? PF : 0;
        value |= ((lhs ^ rhs ^ result) & 0x10) ? AF : 0;
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

        // Zero Flag
        value |= (result == 0) ? ZF : 0;

        // Sign Flag - explicitly check the highest bit (bit 31)
        if (result & 0x80000000) {
            value |= SF;  // Set SF if bit 31 is set (negative)
        }

        // Overflow Flag (only if 0x80000000 -> 0x7FFFFFFF)
        value |= (old_val == 0x80000000) ? OF : 0;

        // Parity Flag
        uint8_t lsb = result & 0xFF;
        value |= (__builtin_popcount(lsb) % 2 == 0) ? PF : 0;

        // Auxiliary Flag
        value |= ((result & 0x0F) == 0x0F) ? AF : 0;
    }

    void update_flags_neg(uint32_t original_value, uint32_t result)
    {
        clear_compare_flags();
        // Correct CF behavior for NEG:
        value |= (original_value != 0) ? X86EFlags::CF : 0; 

        // OF set if negating INT_MIN
        value |= (original_value == 0x80000000) ? X86EFlags::OF : 0;

        // Other flags
        value |= (result == 0) ? X86EFlags::ZF : 0;
        value |= (result & X86EFlags::SF);

        uint8_t lsb = result & 0xFF;
        value |= (__builtin_popcount(lsb) % 2 == 0) ? X86EFlags::PF : 0;
        value |= ((original_value ^ result) & 0x10) ? X86EFlags::AF : 0;
    }

    // Updates flags after SHL (Shift Left)
    void update_flags_shl(uint32_t value_before, uint32_t shift_count, uint32_t result) {
        clear_compare_flags();

        // CF = Last bit shifted out (MSB before shift)
        if (shift_count > 0) {
            uint32_t last_shifted_out = (value_before >> (32 - shift_count)) & 1;
            value |= (last_shifted_out) ? CF : 0;
        }

        // OF = Set if sign bit changed (only for 1-bit shifts)
        if (shift_count == 1) {
            bool sign_before = (value_before >> 31) & 1;
            bool sign_after = (result >> 31) & 1;
            value |= (sign_before != sign_after) ? OF : 0;
        }

        // SF = MSB of result
        value |= (result >> 31) & SF;

        // ZF = Result is zero
        value |= (result == 0) ? ZF : 0;

        // PF = Parity of LSB
        uint8_t lsb = result & 0xFF;
        value |= (__builtin_popcount(lsb) % 2 == 0) ? PF : 0;
    }

    // Updates flags after SHR (Shift Right)
    void update_flags_shr(uint32_t value_before, uint32_t shift_count, uint32_t result) {
        clear_compare_flags();

        // CF = Last bit shifted out (LSB before shift)
        if (shift_count > 0) {
            uint32_t last_shifted_out = (value_before >> (shift_count - 1)) & 1;
            value |= (last_shifted_out) ? CF : 0;
        }

        // OF = Undefined for multi-bit shifts (but some CPUs leave it unchanged)
        // For 1-bit shifts, OF = old MSB (Intel manual says undefined, but some CPUs set it)
        if (shift_count == 1) {
            bool msb_before = (value_before >> 31) & 1;
            value |= msb_before ? OF : 0;
        }

        // SF = MSB of result
        value |= (result >> 31) & SF;

        // ZF = Result is zero
        value |= (result == 0) ? ZF : 0;

        // PF = Parity of LSB
        uint8_t lsb = result & 0xFF;
        value |= (__builtin_popcount(lsb) % 2 == 0) ? PF : 0;
    }



    // Updates flags after SAR (Shift Arithmetic Right)
    void update_flags_sar(uint32_t value_before, uint32_t shift_count, uint32_t result) {
        clear_compare_flags();

        // CF = Last bit shifted out (LSB before shift)
        if (shift_count > 0) {
            uint32_t last_shifted_out = (value_before >> (shift_count - 1)) & 1;
            value |= (last_shifted_out) ? CF : 0;
        }

        // OF = Cleared for SAR (Intel manual specifies this)
        value &= ~OF;

        // SF = MSB of result
        value |= (result >> 31) & SF;

        // ZF = Result is zero
        value |= (result == 0) ? ZF : 0;

        // PF = Parity of LSB
        uint8_t lsb = result & 0xFF;
        value |= (__builtin_popcount(lsb) % 2 == 0 ? PF : 0);
    }

    // Updates flags after ROL (Rotate Left)
    void update_flags_rol(uint32_t value_before, uint32_t shift_count, uint32_t result)
    {
        clear_compare_flags();

        //CF = Last bit rotated out (MSB before rotation)
        if (shift_count > 0)
        {
            uint32_t last_rotated_out = (value_before >> (32 - (shift_count % 32))) & 1;
            value |= (last_rotated_out) ? CF : 0;
        }

        //OF = (CF ^ MSB) for 1-bit shifts (undefined otherwise)
        if (shift_count == 1)
        {
            bool new_cf = (value & CF) != 0;
            bool new_msb = (result >> 31) & 1;
            value |= (new_cf ^ new_msb) ? OF : 0;
        }
    }

    // Updates flags after ROR (Rotate Right)
    void update_flags_ror(uint32_t value_before, uint32_t shift_count, uint32_t result)
    {
        clear_compare_flags();

        // CF = Last bit rotated out (LSB before rotation)
        if (shift_count > 0) {
            uint32_t last_rotated_out = (value_before >> ((shift_count % 32) - 1)) & 1;
            value |= (last_rotated_out) ? CF : 0;
        }

        // OF = (new MSB ^ new MSB-1) for 1-bit shifts (undefined otherwise)
        if (shift_count == 1) {
            bool new_msb = (result >> 31) & 1;
            bool new_msb_minus_1 = (result >> 30) & 1;
            value |= (new_msb ^ new_msb_minus_1) ? OF : 0;
        }
    }

    // For STOS/MOVS instructions 
    void update_string_pointer(uint32_t& reg) {
        reg += (value & DF) ? -1 : 1;
    }

    void update_string_pointer_word(uint32_t& reg) {
        reg += (value & DF) ? -2 : 2;
    }

    // Direction Flag control
    void set_df(bool backward) {
        if (backward) value |= DF;
        else value &= ~DF;
    }
};

struct X87FPU
{
    long double st[8];  //8-register stack (ST0-ST7)
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

    void push(long double value) 
    {
        top = (top - 1) & 7;  

        if ((tw & (1 << top)) == 0) {
            sw |= C0 | C1;  
            if (value != value) 
            { 
                sw |= C2;
            }
        }

        st[top] = value;
        tw &= ~(1 << top);  // Mark register as used
    }

    long double pop() 
    {

        if (tw & (1 << top)) 
        {
            sw |= C0 | C1; 
            return std::numeric_limits<double>::quiet_NaN();
        }

        long double val = st[top];
        tw |= (1 << top);   // Mark register as empty
        top = (top + 1) & 7;
        return val;
    }


    long double& st0() { return st[top]; }
    long double& st1() { return st[(top + 1) & 7]; }
    long double& st2() { return st[(top + 2) & 7]; }
    long double& st3() { return st[(top + 3) & 7]; }
    long double& st4() { return st[(top + 4) & 7]; }
    long double& st5() { return st[(top + 5) & 7]; }
    long double& st6() { return st[(top + 6) & 7]; }
    long double& st7() { return st[(top + 7) & 7]; }

    void flag_invalid() { sw |= C0 | C2; }  // For NaN/Invalid ops
    void flag_divzero() { sw |= C0 | C3; }  // For x/0 cases
    void flag_stackfault() { sw |= C0 | C1; }  // Stack overflow/underflow

    void clear_flags() {
        sw &= ~(C0 | C1 | C2 | C3);
    }

    void set_unordered() {
        sw |= C0 | C2 | C3; // Set for NaN comparisons
    }

    void set_compare_flags(bool less, bool equal) {
        clear_flags();
        if (less) sw |= C0;
        else if (equal) sw |= C3;
    }


    void set_exception_flags(uint8_t exception_type) 
    {
        constexpr uint16_t FLAGS_INVALID = C0 | C2;  // For NaN/Invalid ops
        constexpr uint16_t FLAGS_DIVZERO = C0 | C3;  // For x/0
        constexpr uint16_t FLAGS_STACK = C0 | C1;  // Stack faults

        switch (exception_type) {
        case 1:  sw |= FLAGS_INVALID;  break;  // Most common case
        case 2:  sw |= FLAGS_DIVZERO;  break;  // Common in physics
        case 3:  sw |= FLAGS_STACK;    break;  // Rare but critical
        default: sw |= C0;             break;  // Catch-all
        }
    }


    void handle_exceptions() 
    {
        const uint16_t exceptions = sw & 0x3F; // Get exception flags

        if (exceptions & 0x01) { //Invalid operation
            sw |= C0; // Set condition code
            if (cw & 0x01) 
            { 
                printf("FPU Invalid Operation\n");
            }
        }

        if (exceptions & 0x04) { // Division by zero
            sw |= C2; // Set condition code
            if (cw & 0x04) 
            { 
                printf("FPU Divide by zero\n");
            }
        }

        sw &= ~0x3F; // Clear exception flags after handling
    }

    double round_to_control(double value) const 
    {
        const int rounding_mode = (cw >> 10) & 3;
        const int precision = (cw >> 8) & 3;

        // Apply precision first
        double result;
        switch (precision) {
        case 0: result = (double)(float)value; break; // Single
        case 2: result = (long double)value; break;    // Extended
        default: result = value; break;                // Double
        }

        // Apply rounding
        switch (rounding_mode) {
        case 0: return std::nearbyint(result);
        case 1: return std::floor(result);
        case 2: return std::ceil(result);
        case 3: return std::trunc(result);
        default: return result;
        }
    }

    void compare_and_pop(long double rhs, int pops = 0) 
    {
        clear_flags();

        if (std::isnan(st0()) || std::isnan(rhs)) {
            sw |= C0 | C2 | C3;
        }
        else if (st0() < rhs) {
            sw |= C0;
        }
        else if (st0() == rhs) {
            sw |= C3;
        }

        while (pops--) pop();
    }
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

    uint32_t kpcr_ptr; //FS Segment (Xbox kernel)
    uint32_t stack_ptr; //FS Stack Ptr FS: 4

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

    uint64_t mmx[8];
    uint32_t mxcsr = 0x1F80;
    X87FPU fpu;

    // In X86Context struct
    void set_mxcsr(uint32_t value) 
    {
        mxcsr = value & 0xFFC0; // Mask reserved bits
        _mm_setcsr(mxcsr);
    }

    uint32_t get_mxcsr() const 
    {
        return _mm_getcsr();
    }

    void handle_sse_exceptions() {
        uint32_t exceptions = mxcsr & 0x3F;
        if (exceptions) 
        {
            mxcsr &= ~0x3F; // Clear exception flags
        }
    }

    uint8_t* base; // Base address for memory access

    struct { //technically only used by xbox kernel stuff should't be needed 
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

inline uint64_t X86_PSHUFW(uint64_t src, uint8_t control) 
{
    const uint16_t w0 = (src >> (0 * 16)) & 0xFFFF;
    const uint16_t w1 = (src >> (1 * 16)) & 0xFFFF;
    const uint16_t w2 = (src >> (2 * 16)) & 0xFFFF;
    const uint16_t w3 = (src >> (3 * 16)) & 0xFFFF;


    const uint16_t ws[4] = { w0, w1, w2, w3 };

    return (uint64_t)ws[control & 3] |  // Word 0
        ((uint64_t)ws[(control >> 2) & 3] << 16) |  // Word 1
        ((uint64_t)ws[(control >> 4) & 3] << 32) |  // Word 2
        ((uint64_t)ws[(control >> 6) & 3] << 48);   // Word 3
}

#endif // X86_CONTEXT_H_INCLUDED
