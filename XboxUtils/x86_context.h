
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

#ifndef M_LOG2E
#define M_LOG2E 1.44269504088896340735992468100189214L
#endif

#ifndef M_PI
#define M_PI 3.14159265358979323846L
#endif

// X87_DOUBLE_PRECISION: speed hack. x87 stack and math run in `double`,
// not `long double`. MSVC `long double` is already 64-bit, so this only
// affects GCC/Clang. F80 memory ops stay 80-bit either way.
#ifdef X87_DOUBLE_PRECISION
using x87_float = double;
#else
using x87_float = long double;
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
#define X86_LOAD_F80(addr) (*reinterpret_cast<volatile long double*>(base + (addr)))

//Memory Store Macros
#define X86_STORE_U8(addr, value)  (*reinterpret_cast<volatile uint8_t*>(base + (addr)) = (value))
#define X86_STORE_U16(addr, value) (*reinterpret_cast<volatile uint16_t*>(base + (addr)) = (value))
#define X86_STORE_U32(addr, value) (*reinterpret_cast<volatile uint32_t*>(base + (addr)) = (value))
#define X86_STORE_U64(addr, value) (*reinterpret_cast<volatile uint64_t*>(base + (addr)) = (value))

//Floating point variants
#define X86_STORE_F32(addr, value) (*reinterpret_cast<volatile float*>(base + (addr)) = static_cast<float>(value))
#define X86_STORE_F64(addr, value) (*reinterpret_cast<volatile double*>(base + (addr)) = static_cast<double>(value))
#define X86_STORE_F80(addr, value) (*reinterpret_cast<volatile long double*>(base + (addr)) = static_cast<long double>(value))

// SSE Load/Store 128-bit Macros
#define XMM_F32(reg, idx) (ctx.xmm[reg].f32[idx])
#define XMM_U32(reg, idx) (ctx.xmm[reg].u32[idx])

#define X86_LOAD_PS(addr) _mm_loadu_ps(reinterpret_cast<const float*>(base + (addr)))
#define X86_STORE_PS(addr, val) _mm_storeu_ps(reinterpret_cast<float*>(base + (addr)), (val))


// Aligned SSE Load/Store (16-byte alignment required)
#define X86_LOAD_APS(addr) _mm_load_ps(reinterpret_cast<const float*>(base + (addr)))
#define X86_STORE_APS(addr, val) _mm_store_ps(reinterpret_cast<float*>(base + (addr)), (val))
#define X86_STORE_NTPS(addr, val) _mm_stream_ps(reinterpret_cast<float*>(base + (addr)), (val))
#define X86_STORE_NTQ(addr, val) \
    _mm_stream_si64(reinterpret_cast<long long*>(base + (addr)), \
                    static_cast<long long>(val))

// Register Operations
#define X86_MOVAPS_REG(dest, src) \
    ctx.xmm[dest].reg = ctx.xmm[src].reg
#define X86_MOVLHPS(dest, src) \
    ctx.xmm[dest].reg = _mm_movelh_ps(ctx.xmm[dest].reg, ctx.xmm[src].reg)
#define X86_MOVHLPS(dest, src) \
    ctx.xmm[dest].reg = _mm_movehl_ps(ctx.xmm[dest].reg, ctx.xmm[src].reg)

// Arithmetic Operations
#define X86_ADDPS(dest, src) \
    ctx.xmm[dest].reg = _mm_add_ps(ctx.xmm[dest].reg, ctx.xmm[src].reg)
#define X86_MULPS(dest, src) \
    ctx.xmm[dest].reg = _mm_mul_ps(ctx.xmm[dest].reg, ctx.xmm[src].reg)
#define X86_SHUFPS(dest, src, imm) \
    ctx.xmm[dest].reg = _mm_shuffle_ps(ctx.xmm[dest].reg, ctx.xmm[src].reg, imm)

// MMX Load/Store
#define X86_MMX_LOAD(addr) (*reinterpret_cast<uint64_t*>(base + addr))
#define X86_MMX_STORE(addr, value) (*reinterpret_cast<uint64_t*>(base + addr) = value)
#define MMX_REG(reg) (ctx.fpu.mmx[(reg)]) 

#define X86_ATOMIC_XCHG_U8(addr, value)  std::atomic_exchange(reinterpret_cast<std::atomic<uint8_t>*>(base + (addr)), static_cast<uint8_t>(value))
#define X86_ATOMIC_XCHG_U16(addr, value) std::atomic_exchange(reinterpret_cast<std::atomic<uint16_t>*>(base + (addr)), static_cast<uint16_t>(value))
#define X86_ATOMIC_XCHG_U32(addr, value) std::atomic_exchange(reinterpret_cast<std::atomic<uint32_t>*>(base + (addr)), static_cast<uint32_t>(value))

#define X86_ATOMIC_XADD_U8(addr, value)  std::atomic_fetch_add(reinterpret_cast<std::atomic<uint8_t>*>(base + (addr)), static_cast<uint8_t>(value))
#define X86_ATOMIC_XADD_U16(addr, value) std::atomic_fetch_add(reinterpret_cast<std::atomic<uint16_t>*>(base + (addr)), static_cast<uint16_t>(value))
#define X86_ATOMIC_XADD_U32(addr, value) std::atomic_fetch_add(reinterpret_cast<std::atomic<uint32_t>*>(base + (addr)), static_cast<uint32_t>(value))


#ifndef X86_CALL_FUNC
#define X86_CALL_FUNC(x) x(ctx, base)
#endif

#define X86_MEMORY_SIZE 0x100000000ull

#define X86_LOOKUP_FUNC(x, y) *(X86Func**)(x + X86_IMAGE_BASE + X86_IMAGE_SIZE + (uint64_t(uint32_t(y) - X86_CODE_BASE) * 2))

#ifndef X86_CALL_INDIRECT_FUNC
#define X86_CALL_INDIRECT_FUNC(x) (X86_LOOKUP_FUNC(base, x))(ctx, base)
#endif



extern uint8_t g_mmio[];
extern uint8_t* g_nv2aPtr;
extern uint32_t XboxSignatureKey[];

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

    //Clear all flags
    void clear_eflags()
    {
        //value &= ~(CF | PF | ZF | SF | OF);
        value &= ~(CF | PF | AF | ZF | SF | OF);
    }

    void update_compare_flags_U32(uint32_t lhs, uint32_t rhs) {
        clear_eflags();

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


    void update_compare_flags_U16(uint16_t lhs, uint16_t rhs) {
        clear_eflags();

        uint16_t result = lhs - rhs;
        bool carry = lhs < rhs;

        if (result == 0)
            value |= ZF;

        if (result & 0x8000)
            value |= SF;

        if ((__builtin_popcount(result & 0xFF) % 2) == 0)
            value |= PF;

        if (carry)
            value |= CF;

        bool overflow = ((lhs ^ rhs) & (lhs ^ result)) & 0x8000;
        if (overflow)
            value |= OF;
    }

    void update_compare_flags_U8(uint8_t lhs, uint8_t rhs) {
        clear_eflags();

        uint8_t result = lhs - rhs;
        bool carry = lhs < rhs;

        if (result == 0)
            value |= ZF;

        if (result & 0x80)
            value |= SF;

        if ((__builtin_popcount(result) % 2) == 0)
            value |= PF;

        if (carry)
            value |= CF;

        // 8-bit signed overflow check
        bool overflow = ((lhs ^ rhs) & (lhs ^ result)) & 0x80;
        if (overflow)
            value |= OF;
    }

    void update_compare_flags_sse(float lhs, float rhs)
    {
        clear_eflags();
        const bool unordered = std::isnan(lhs) || std::isnan(rhs);

        if (unordered) {
            // Unordered: set PF, CF, ZF
            value |= (PF | CF | ZF);
        }
        else
        {

            if (lhs == rhs)
                value |= ZF;
            else if (lhs < rhs)
                value |= CF;
        }

        value &= ~OF;
    }

    void update_test_flags_U8(uint8_t result)
    {
        clear_eflags();
        if (result == 0)
            value |= ZF;
        if (result & 0x80)  // Check bit 7 for 8-bit
            value |= SF;
        if (!(__builtin_popcount(result & 0xFF) & 1))
            value |= PF;
    }

    void update_test_flags_U16(uint16_t result)
    {
        clear_eflags();
        if (result == 0)
            value |= ZF;
        if (result & 0x8000)  //Check bit 15 for 16-bit
            value |= SF;
        if (!(__builtin_popcount(result & 0xFF) & 1))
            value |= PF;
    }

    void update_test_flags_U32(uint32_t result)
    {
        clear_eflags();
        if (result == 0)
            value |= ZF;
        if (result & 0x80000000)  // Check bit 31 for 32-bit
            value |= SF;
        if (!(__builtin_popcount(result & 0xFF) & 1))
            value |= PF;
    }

    //and, or, xor etc.
    void update_flags_logic(uint32_t result)
    {
        clear_eflags();

        value |= (result == 0) ? ZF : 0;
        value |= (result & 0x80000000) ? SF : 0;

        uint8_t lsb = result & 0xFF;
        value |= (__builtin_popcount(lsb) % 2 == 0) ? PF : 0;
    }

    void update_flags_logic(uint16_t result)
    {
        clear_eflags();
        value |= (result == 0) ? ZF : 0;
        value |= (result & 0x8000) ? SF : 0;
        value |= (__builtin_popcount(result & 0xFF) % 2 == 0) ? PF : 0;
    }

    void update_flags_logic(uint8_t result)
    {
        clear_eflags();
        value |= (result == 0) ? ZF : 0;
        value |= (result & 0x80) ? SF : 0;
        value |= (__builtin_popcount(result) % 2 == 0) ? PF : 0;
    }

    void update_flags_adc(uint32_t lhs, uint32_t rhs, uint32_t carry, uint32_t result, uint8_t operand_size = 4)
    {
        clear_eflags();
        uint32_t sign_bit = operand_size * 8 - 1;
        value |= ((result < lhs) || (result == lhs && carry == 1)) ? CF : 0;
        value |= (result == 0) ? ZF : 0;
        value |= ((result >> sign_bit) & 1) ? SF : 0;
        value |= ((((lhs ^ result) & (rhs ^ result)) >> sign_bit) & 1) ? OF : 0;
        uint8_t lsb = result & 0xFF;
        value |= (__builtin_popcount(lsb) % 2 == 0) ? PF : 0;
        value |= (((lhs & 0xF) + (rhs & 0xF) + carry) > 0xF) ? AF : 0;
    }


    void update_flags_sbb(uint32_t lhs, uint32_t rhs, uint32_t borrow, uint32_t result, uint8_t operand_size)
    {
        clear_eflags();
        uint32_t sign_bit = operand_size * 8 - 1;
        value |= ((uint64_t)lhs < (uint64_t)rhs + borrow) ? CF : 0;
        value |= (result == 0) ? ZF : 0;
        value |= ((result >> sign_bit) & 1) ? SF : 0;
        value |= ((((lhs ^ rhs) & (lhs ^ result)) >> sign_bit) & 1) ? OF : 0;
        value |= (__builtin_popcount(result & 0xFF) % 2 == 0) ? PF : 0;
        value |= ((lhs ^ rhs ^ result) & 0x10) ? AF : 0;
    }

    void update_flags_add_U32(uint32_t lhs, uint32_t rhs, uint32_t result)
    {
        clear_eflags();
        value |= (result < lhs) ? CF : 0;
        value |= (result == 0) ? ZF : 0;


        value |= (result & 0x80000000) ? SF : 0;

        // Overflow Flag: Set if signed overflow occurs (same sign inputs, different sign output)
        value |= ((((lhs ^ result) & (rhs ^ result)) >> 31) != 0) ? OF : 0;

        // Parity Flag: Set if result has even number of set bits in lowest byte
        uint8_t lsb = result & 0xFF;
        value |= (__builtin_popcount(lsb) % 2 == 0) ? PF : 0;

        // Auxiliary Flag: Set if carry from bit 3 to bit 4
        value |= (((lhs & 0xF) + (rhs & 0xF)) > 0xF) ? AF : 0;
    }

    void update_flags_add_U16(uint16_t lhs, uint16_t rhs, uint16_t result)
    {
        clear_eflags();

        uint32_t full_result = (uint32_t)lhs + (uint32_t)rhs;
        value |= (full_result > 0xFFFF) ? CF : 0;

        value |= (result == 0) ? ZF : 0;

        value |= (result & 0x8000) ? SF : 0;

        // Overflow Flag: Set if signed overflow occurs
        // For 16-bit: check if both operands have same sign but result has different sign
        bool lhs_sign = (lhs & 0x8000) != 0;
        bool rhs_sign = (rhs & 0x8000) != 0;
        bool result_sign = (result & 0x8000) != 0;
        value |= (lhs_sign == rhs_sign && lhs_sign != result_sign) ? OF : 0;

        // Parity Flag: Set if result has even number of set bits in lowest byte
        uint8_t lsb = result & 0xFF;
        value |= (__builtin_popcount(lsb) % 2 == 0) ? PF : 0;

        // Auxiliary Flag: Set if carry from bit 3 to bit 4
        value |= (((lhs & 0xF) + (rhs & 0xF)) > 0xF) ? AF : 0;
    }

    void update_flags_add_U8(uint8_t lhs, uint8_t rhs, uint8_t result)
    {
        clear_eflags();

        uint16_t full_result = (uint16_t)lhs + (uint16_t)rhs;
        value |= (full_result > 0xFF) ? CF : 0;

        value |= (result == 0) ? ZF : 0;

        value |= (result & 0x80) ? SF : 0;

        // Overflow Flag: Set if signed overflow occurs
        // For 8-bit: check if both operands have same sign but result has different sign
        bool lhs_sign = (lhs & 0x80) != 0;
        bool rhs_sign = (rhs & 0x80) != 0;
        bool result_sign = (result & 0x80) != 0;
        value |= (lhs_sign == rhs_sign && lhs_sign != result_sign) ? OF : 0;

        // Parity Flag: Set if result has even number of set bits
        value |= (__builtin_popcount(result) % 2 == 0) ? PF : 0;

        // Auxiliary Flag: Set if carry from bit 3 to bit 4
        value |= (((lhs & 0xF) + (rhs & 0xF)) > 0xF) ? AF : 0;
    }

    void update_flags_sub_U32(uint32_t lhs, uint32_t rhs, uint32_t result)
    {
        clear_eflags();

        // Special case: SUB X,0 is identical to TEST X,X (only affects SF/ZF/PF)
        if (rhs == 0)
        {
            value |= (result == 0) ? ZF : 0;
            value |= (result & 0x80000000) ? SF : 0;
            uint8_t lsb = result & 0xFF;
            value |= (__builtin_popcount(lsb) % 2 == 0) ? PF : 0;
            return;  // Skip CF/OF/AF for this case!
        }

        // For unsigned comparison, CF is set if rhs > lhs (borrow needed)
        value |= (lhs < rhs) ? CF : 0;
        value |= (result == 0) ? ZF : 0;
        value |= (result & 0x80000000) ? SF : 0;
        value |= ((((lhs ^ rhs) & (lhs ^ result)) >> 31) != 0) ? OF : 0;
        uint8_t lsb = result & 0xFF;
        value |= (__builtin_popcount(lsb) % 2 == 0) ? PF : 0;
        value |= ((lhs ^ rhs ^ result) & 0x10) ? AF : 0;
    }

    void update_flags_sub_U16(uint16_t lhs, uint16_t rhs, uint16_t result)
    {
        clear_eflags();

        if (rhs == 0) {
            value |= (result == 0) ? ZF : 0;
            value |= (result & 0x8000) ? SF : 0;
            uint8_t lsb = result & 0xFF;
            value |= (__builtin_popcount(lsb) % 2 == 0) ? PF : 0;
            return;  // Skip CF/OF/AF for this case!
        }


        value |= (lhs < rhs) ? CF : 0;
        value |= (result == 0) ? ZF : 0;
        value |= (result & 0x8000) ? SF : 0;

        // Overflow Flag: Set if signed overflow occurs in subtraction
        bool lhs_sign = (lhs & 0x8000) != 0;
        bool rhs_sign = (rhs & 0x8000) != 0;
        bool result_sign = (result & 0x8000) != 0;
        value |= (lhs_sign != rhs_sign && lhs_sign != result_sign) ? OF : 0;

        uint8_t lsb = result & 0xFF;
        value |= (__builtin_popcount(lsb) % 2 == 0) ? PF : 0;
        value |= ((lhs ^ rhs ^ result) & 0x10) ? AF : 0;
    }

    void update_flags_sub_U8(uint8_t lhs, uint8_t rhs, uint8_t result)
    {
        clear_eflags();

        // Special case: SUB X,0 is identical to TEST X,X (only affects SF/ZF/PF)
        if (rhs == 0)
        {
            value |= (result == 0) ? ZF : 0;
            value |= (result & 0x80) ? SF : 0;
            value |= (__builtin_popcount(result) % 2 == 0) ? PF : 0;
            return;  // Skip CF/OF/AF for this case!
        }

        value |= (lhs < rhs) ? CF : 0;
        value |= (result == 0) ? ZF : 0;
        value |= (result & 0x80) ? SF : 0;

        // Overflow Flag: Set if signed overflow occurs in subtraction
        bool lhs_sign = (lhs & 0x80) != 0;
        bool rhs_sign = (rhs & 0x80) != 0;
        bool result_sign = (result & 0x80) != 0;
        value |= (lhs_sign != rhs_sign && lhs_sign != result_sign) ? OF : 0;

        value |= (__builtin_popcount(result) % 2 == 0) ? PF : 0;
        value |= ((lhs ^ rhs ^ result) & 0x10) ? AF : 0;
    }

    void update_flags_mul(bool overflow)
    {
        clear_eflags();

        if (overflow)
            value |= (CF | OF);
    }

    void update_flags_inc_U32(uint32_t old_val, uint32_t result)
    {
        // Preserve Carry Flag
        uint32_t saved_cf = value & CF;
        clear_eflags();
        value |= saved_cf;
        value |= (result == 0) ? ZF : 0;
        value |= (result & 0x80000000) ? SF : 0;
        // Overflow Flag (only if 0x7FFFFFFF -> 0x80000000)
        value |= (old_val == 0x7FFFFFFF) ? OF : 0;
        uint8_t lsb = result & 0xFF;
        value |= (__builtin_popcount(lsb) % 2 == 0) ? PF : 0;
        value |= ((old_val & 0x0F) == 0x0F) ? AF : 0;
    }

    void update_flags_inc_U16(uint16_t old_val, uint16_t result)
    {

        uint32_t saved_cf = value & CF;
        clear_eflags();
        value |= saved_cf;
        value |= (result == 0) ? ZF : 0;
        value |= (result & 0x8000) ? SF : 0;
        // Overflow Flag (only if 0x7FFF -> 0x8000)
        value |= (old_val == 0x7FFF) ? OF : 0;
        uint8_t lsb = result & 0xFF;
        value |= (__builtin_popcount(lsb) % 2 == 0) ? PF : 0;
        value |= ((old_val & 0x0F) == 0x0F) ? AF : 0;
    }

    void update_flags_inc_U8(uint8_t old_val, uint8_t result)
    {
        // Preserve Carry Flag
        uint32_t saved_cf = value & CF;
        clear_eflags();
        value |= saved_cf;
        value |= (result == 0) ? ZF : 0;
        value |= (result & 0x80) ? SF : 0;  // Sign flag for 8-bit (bit 7)
        // Overflow Flag (only if 0x7F -> 0x80)
        value |= (old_val == 0x7F) ? OF : 0;
        uint8_t lsb = result & 0xFF;
        value |= (__builtin_popcount(lsb) % 2 == 0) ? PF : 0;
        value |= ((old_val & 0x0F) == 0x0F) ? AF : 0;
    }

    void update_flags_dec_U32(uint32_t old_val, uint32_t result)
    {
        // Preserve Carry Flag
        uint32_t saved_cf = value & CF;
        clear_eflags();
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
        value |= ((old_val & 0x0F) == 0x0) ? AF : 0;
    }

    void update_flags_dec_U16(uint16_t old_val, uint16_t result)
    {
        // Preserve Carry Flag
        uint32_t saved_cf = value & CF;
        clear_eflags();
        value |= saved_cf;


        value |= (result == 0) ? ZF : 0;
        value |= (result & 0x8000) ? SF : 0;

        value |= (old_val == 0x8000) ? OF : 0;

        // Parity Flag (still based on lowest 8 bits)
        uint8_t lsb = result & 0xFF;
        value |= (__builtin_popcount(lsb) % 2 == 0) ? PF : 0;

        // Auxiliary Flag
        value |= ((old_val & 0x0F) == 0x0) ? AF : 0;
    }

    void update_flags_dec_U8(uint8_t old_val, uint8_t result)
    {
        uint32_t saved_cf = value & CF;
        clear_eflags();
        value |= saved_cf;

        value |= (result == 0) ? ZF : 0;

        // Sign Flag - check the highest bit (bit 7 for 8-bit)
        value |= (result & 0x80) ? SF : 0;

        // Overflow Flag (only if 0x80 -> 0x7F)
        value |= (old_val == 0x80) ? OF : 0;

        // Parity Flag
        value |= (__builtin_popcount(result) % 2 == 0) ? PF : 0;

        // Auxiliary Flag
        value |= ((old_val & 0x0F) == 0x0) ? AF : 0;
    }

    void update_flags_neg_U32(uint32_t original_value, uint32_t result)
    {
        clear_eflags();

        value |= (original_value != 0) ? X86EFlags::CF : 0;

        value |= (original_value == 0x80000000) ? X86EFlags::OF : 0;

        // Other flags
        value |= (result == 0) ? X86EFlags::ZF : 0;
        value |= (result & 0x80000000) ? X86EFlags::SF : 0;

        uint8_t lsb = result & 0xFF;
        value |= (__builtin_popcount(lsb) % 2 == 0) ? X86EFlags::PF : 0;
        value |= ((original_value ^ result) & 0x10) ? X86EFlags::AF : 0;
    }

    void update_flags_neg_U16(uint16_t original_value, uint16_t result)
    {
        clear_eflags();

        value |= (original_value != 0) ? CF : 0;

        value |= (original_value == 0x8000) ? OF : 0;

        // Other flags
        value |= (result == 0) ? ZF : 0;
        value |= (result & 0x8000) ? SF : 0;  // Sign flag for 16-bit

        uint8_t lsb = result & 0xFF;
        value |= (__builtin_popcount(lsb) % 2 == 0) ? PF : 0;
        value |= ((original_value ^ result) & 0x10) ? AF : 0;
    }


    void update_flags_neg_U8(uint8_t original_value, uint8_t result)
    {
        clear_eflags();

        value |= (original_value != 0) ? CF : 0;
        value |= (original_value == 0x80) ? OF : 0;

        // Other flags
        value |= (result == 0) ? ZF : 0;
        value |= (result & 0x80) ? SF : 0;  // Sign flag for 8-bit

        value |= (__builtin_popcount(result) % 2 == 0) ? PF : 0;
        value |= ((original_value ^ result) & 0x10) ? AF : 0;
    }

    // Updates flags after SHL (Shift Left)
    void update_flags_shl(uint32_t value_before, uint32_t shift_count, uint32_t result, uint8_t operand_size)
    {
        // x86 masks the count to 5 bits
        shift_count &= 0x1F;
        
        if (shift_count == 0)
            return;

        clear_eflags();
        uint32_t bit_width = operand_size * 8;

        // CF = last bit shifted out (MSB side)
        if (shift_count > 0 && shift_count <= bit_width)
        {
            uint32_t last_shifted_out = (value_before >> (bit_width - shift_count)) & 1;
            value |= last_shifted_out ? CF : 0;
        }
        // OF = sign bit changed (1-bit shifts only)
        if (shift_count == 1)
        {
            uint32_t sign_bit = bit_width - 1;
            bool sign_before = (value_before >> sign_bit) & 1;
            bool sign_after = (result >> sign_bit) & 1;
            value |= (sign_before != sign_after) ? OF : 0;
        }
        // SF = MSB of result
        uint32_t sign_bit = bit_width - 1;
        value |= (result >> sign_bit) & 1 ? SF : 0;
        // ZF
        value |= (result == 0) ? ZF : 0;
        // PF
        uint8_t lsb = result & 0xFF;
        value |= (__builtin_popcount(lsb) % 2 == 0) ? PF : 0;
    }

    // Updates flags after SHR (Shift Right)
    void update_flags_shr(uint32_t value_before, uint32_t shift_count, uint32_t result, uint8_t operand_size)
    {
        // x86 masks the count to 5 bits
        shift_count &= 0x1F;

        if (shift_count == 0)
            return;

        clear_eflags();
        if (shift_count > 0)
        {
            uint32_t last_shifted_out = (value_before >> (shift_count - 1)) & 1;
            value |= last_shifted_out ? CF : 0;
        }
        if (shift_count == 1)
        {
            // OF = MSB of original value, based on operand size
            uint32_t msb_pos = (operand_size * 8) - 1;
            bool msb_before = (value_before >> msb_pos) & 1;
            value |= msb_before ? OF : 0;
        }

        // SF = MSB of result, based on operand size
        uint32_t sign_bit = (operand_size * 8) - 1;
        value |= (result >> sign_bit) & 1 ? SF : 0;

        value |= (result == 0) ? ZF : 0;
        uint8_t lsb = result & 0xFF;
        value |= (__builtin_popcount(lsb) % 2 == 0) ? PF : 0;
    }

    void update_flags_shld(uint32_t value_before, uint32_t shift_count, uint32_t result, uint32_t operand_size) {

        if (shift_count == 0) return; // No flags affected if shift count is 0

        clear_eflags();

        // Normalize shift count based on operand size
        uint32_t mask_bits = (operand_size == 16) ? 16 : 32;
        shift_count = shift_count & (mask_bits - 1);

        if (shift_count == 0) return;

        // CF = Last bit shifted out
        if (shift_count <= mask_bits) {
            uint32_t last_shifted_out = (value_before >> (mask_bits - shift_count)) & 1;
            value |= last_shifted_out ? CF : 0;
        }

        // OF = Set if sign bit changed (only for 1-bit shifts)
        if (shift_count == 1) {
            uint32_t sign_bit = mask_bits - 1;
            bool sign_before = (value_before >> sign_bit) & 1;
            bool sign_after = (result >> sign_bit) & 1;
            value |= (sign_before != sign_after) ? OF : 0;
        }

        // SF = MSB of result
        value |= (result >> (mask_bits - 1)) ? SF : 0;

        // ZF = Result is zero
        uint32_t mask = (operand_size == 16) ? 0xFFFF : 0xFFFFFFFF;
        value |= ((result & mask) == 0) ? ZF : 0;

        // PF = Parity of LSB
        uint8_t lsb = result & 0xFF;
        value |= (__builtin_popcount(lsb) % 2 == 0) ? PF : 0;
    }

    // Updates flags after SHRD (Shift Right Double)
    void update_flags_shrd(uint32_t value_before, uint32_t shift_count, uint32_t result, uint32_t operand_size) {
        if (shift_count == 0) return; // No flags affected if shift count is 0

        clear_eflags();

        // Normalize shift count based on operand size
        uint32_t mask_bits = (operand_size == 16) ? 16 : 32;
        shift_count = shift_count & (mask_bits - 1);

        if (shift_count == 0) return;

        // CF = Last bit shifted out
        if (shift_count <= mask_bits) {
            uint32_t last_shifted_out = (value_before >> (shift_count - 1)) & 1;
            value |= last_shifted_out ? CF : 0;
        }

        // OF = sign bit changed (only for 1-bit shifts)
        if (shift_count == 1) {
            uint32_t sign_bit = mask_bits - 1;
            bool msb_before = (value_before >> sign_bit) & 1;
            bool msb_after = (result >> sign_bit) & 1;
            value |= (msb_before != msb_after) ? OF : 0;
        }

        // SF = MSB of result
        value |= (result >> (mask_bits - 1)) ? SF : 0;

        // ZF = Result is zero
        uint32_t mask = (operand_size == 16) ? 0xFFFF : 0xFFFFFFFF;
        value |= ((result & mask) == 0) ? ZF : 0;

        // PF = Parity of LSB
        uint8_t lsb = result & 0xFF;
        value |= (__builtin_popcount(lsb) % 2 == 0) ? PF : 0;
    }

    // Updates flags after SAR (Shift Arithmetic Right)
    void update_flags_sar(uint32_t value_before, uint32_t shift_count, uint32_t result, uint8_t operand_size)
    {
        // x86 masks the count to 5 bits
        shift_count &= 0x1F;
        
        if (shift_count == 0)
            return;

        uint32_t bit_width = operand_size * 8;

        clear_eflags();

        // CF = last bit shifted out (LSB side for SAR)
        if (shift_count > 0 && shift_count <= bit_width)
        {
            uint32_t last_shifted_out = (value_before >> (shift_count - 1)) & 1;
            value |= last_shifted_out ? CF : 0;
        }

        value |= (result == 0) ? ZF : 0;
        uint32_t sign_bit = bit_width - 1;
        value |= (result >> sign_bit) & 1 ? SF : 0;
        uint8_t lsb = result & 0xFF;
        value |= (__builtin_popcount(lsb) % 2 == 0) ? PF : 0;
    }

    // Updates flags after ROL (Rotate Left)
    void update_flags_rol(uint32_t result, uint32_t masked_count, uint8_t operand_size)
    {
        if (masked_count == 0)
            return;

        uint32_t sign_bit = operand_size * 8 - 1;
        bool new_cf = result & 1;
        value &= ~(CF | OF);
        value |= new_cf ? CF : 0;

        if (masked_count == 1)
            value |= (((result >> sign_bit) & 1) != new_cf) ? OF : 0;
        }
    // Updates flags after ROR (Rotate Right)
    void update_flags_ror(uint32_t result, uint32_t masked_count, uint8_t operand_size)
    {
        if (masked_count == 0)
            return;

        uint32_t sign_bit = operand_size * 8 - 1;
        bool msb = (result >> sign_bit) & 1;
        bool msb_minus_1 = (result >> (sign_bit - 1)) & 1;
        value &= ~(CF | OF);
        value |= msb ? CF : 0;

        if (masked_count == 1)
            value |= (msb != msb_minus_1) ? OF : 0;
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
    union {
        x87_float st[8];    // 8-register FPU stack (ST0-ST7)
        uint64_t mmx[8];    // MMX registers (MM0-MM7) - share physical space with FPU
    };
    uint16_t top = 0; //Stack pointer (0-7)
    uint16_t cw = 0x037F; //Control word (default: round-to-nearest, 64-bit precision)
    uint16_t sw = 0;  //Status word tells what's currently happening inside the FPU
    enum : uint16_t {
        C0 = (1 << 8),  // Condition bit 0
        C1 = (1 << 9),  // Condition bit 1
        C2 = (1 << 10), // Condition bit 2 (for FCOS range reduction)
        C3 = (1 << 14)  // Condition bit 3
    };
    uint16_t tw = 0xFFFF; //Tag word (all empty by default) describe the "type" of the data in one of the 8 STx registers.



    void push(x87_float value)
    {
        top = (top - 1) & 7;

        // Update TOP bits in SW (bits 11-13)
        sw = (sw & ~0x3800) | (top << 11);

        int tag_pos = top * 2;  // 2 bits per register

        // Check for stack overflow - use 2-bit tag check
        int current_tag = (tw >> tag_pos) & 3;
        if (current_tag != 3) {  // Register not empty (tag != 11)
            sw |= 0x41;
        }

        st[top] = value;

        // Clear both bits for this register (set to 00 = valid)
        tw &= ~(3 << tag_pos);
    }

    x87_float pop()
    {
        // Check for stack underflow using 2-bit tags
        int tag_pos = top * 2;
        int current_tag = (tw >> tag_pos) & 3;

        if (current_tag == 3)
        {  // Register is already empty
            sw |= 0x41;  // Set IE and C1 for stack fault
            return std::numeric_limits<x87_float>::quiet_NaN();
        }
        x87_float val = st[top];

        // Mark register as empty (tag = 11)
        tw |= (3 << tag_pos);

        // Update top
        top = (top + 1) & 7;

        // Update TOP bits in SW (bits 11-13)
        sw = (sw & ~0x3800) | (top << 11);

        return val;
    }

    void ffree(int8_t i)
    {
        int physical_reg = (top + i) & 7;
        int tag_pos = physical_reg * 2;
        tw = (tw & ~(3 << tag_pos)) | ((0b11 & 3) << tag_pos);
    }

    x87_float& st0() { return st[top]; }
    x87_float& st1() { return st[(top + 1) & 7]; }
    x87_float& st2() { return st[(top + 2) & 7]; }
    x87_float& st3() { return st[(top + 3) & 7]; }
    x87_float& st4() { return st[(top + 4) & 7]; }
    x87_float& st5() { return st[(top + 5) & 7]; }
    x87_float& st6() { return st[(top + 6) & 7]; }
    x87_float& st7() { return st[(top + 7) & 7]; }

    x87_float& getST(uint8_t index)
    {
        switch (index)
        {
        case 0:
        default:
            return st0();
        case 1:
            return st1();
        case 2:
            return st2();
        case 3:
            return st3();
        case 4:
            return st4();
        case 5:
            return st5();
        case 6:
            return st6();
        case 7:
            return st7();
        }
    }


    void init()
    {
        cw = 0x37F;
        tw = 0xFFFF;
        sw = 0;
    }

    void save(uint32_t addr, uint8_t* base, bool is32bits)
    {
        if (is32bits)
        {
            X86_STORE_U16(addr, cw);
            X86_STORE_U16(addr + 4, sw);
            X86_STORE_U16(addr + 8, tw);

            // Save registers in physical order (ST(0) is at position 'top')
            for (int i = 0; i < 8; i++)
            {
                // Convert long double to 80-bit extended precision
                X86_STORE_F80(addr + 28 + i * 10, st[i]);
            }
        }
        else
        {
            X86_STORE_U16(addr, cw);
            X86_STORE_U16(addr + 2, sw);
            X86_STORE_U16(addr + 4, tw);

            // Save registers in physical order (ST(0) is at position 'top')
            for (int i = 0; i < 8; i++)
            {
                // Convert long double to 80-bit extended precision
                X86_STORE_F80(addr + 14 + i * 10, st[i]);
            }
        }
    }

    void load(uint32_t addr, uint8_t* base, bool is32bits)
    {
        if (is32bits)
        {
            cw = X86_LOAD_U16(addr);
            sw = X86_LOAD_U16(addr + 4);
            tw = X86_LOAD_U16(addr + 8);

            // Save registers in physical order (ST(0) is at position 'top')
            for (int i = 0; i < 8; i++)
            {
                // Convert long double to 80-bit extended precision
                st[i] = X86_LOAD_F80(addr + 28 + i * 10);
            }
        }
        else
        {
            cw = X86_LOAD_U16(addr);
            sw = X86_LOAD_U16(addr + 2);
            tw = X86_LOAD_U16(addr + 4);

            // Save registers in physical order (ST(0) is at position 'top')
            for (int i = 0; i < 8; i++)
            {
                // Convert long double to 80-bit extended precision
                st[i] = X86_LOAD_F80(addr + 14 + i * 10);
            }
        }
    }

    void flag_invalid() { sw |= C0 | C2; }  // For NaN/Invalid ops
    void flag_divzero() { sw |= C0 | C3; }  // For x/0 cases
    void flag_stackfault() { sw |= C0 | C1; }  // Stack overflow/underflow

    void clear_flags()
    {
        sw &= ~(C0 | C1 | C2 | C3);
    }

    void set_unordered() {
        sw |= C0 | C2 | C3; // Set for NaN comparisons
    }

    void set_compare_flags(bool less, bool equal)
    {
        clear_flags();

        if (less)
            sw |= C0;
        else if (equal)
            sw |= C3;
    }

    void set_precision_flag()
    {
        sw |= (1 << 5); // PE
    }

    void set_exception_flags(x87_float result)
    {
        // Finite input (not NaN or Inf) sets no flags below; PE (inexact)
        // is set by callers via set_precision_flag(). Xbox titles keep all
        // FPU exceptions masked, so the skipped ES update never applies.
        if (result == result && result != std::numeric_limits<x87_float>::infinity() && result != -std::numeric_limits<x87_float>::infinity())
            return;
        constexpr uint16_t FLAGS_INVALID = 0x01;   // IE bit (bit 0)
        constexpr uint16_t FLAGS_OVERFLOW = 0x08;  // OE bit (bit 3)
        constexpr uint16_t FLAGS_PRECISION = 0x20; // PE bit (bit 5)

        uint8_t exception_type = 0;

        if (std::isnan(result))
            exception_type = 1;
        else if (std::isinf(result))
            exception_type = 3;


        switch (exception_type)
        {
        case 1: sw |= FLAGS_INVALID;   break;
        case 3: sw |= FLAGS_OVERFLOW;  break;
        case 4: sw |= FLAGS_PRECISION; break;
            // default: sw |= FLAGS_PRECISION; break; //Default to precision
        }

        // Set ES (Exception Summary) bit if any unmasked exceptions
        uint16_t unmasked = (sw & 0x3F) & ~(cw & 0x3F);
        if (unmasked) {
            sw |= 0x80;
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
    }

    x87_float round_to_control(x87_float value) const
    {
        switch ((cw >> 8) & 0x3)
        {
        case 0x0: // 24-bit single precision (float)
            value = static_cast<x87_float>(static_cast<float>(value));
            break;
        case 0x2: // 53-bit double precision (double)
            value = static_cast<x87_float>(static_cast<double>(value));
            break;
            // case 0x3: 64-bit extended precision (long double) - no truncation
        }


        return value;
    }

    x87_float apply_rounding(x87_float value) const
    {
        switch ((cw >> 10) & 0x3) {
        case 0x0: return std::nearbyint(value);
        case 0x1: return std::floor(value);
        case 0x2: return std::ceil(value);
        case 0x3: return std::trunc(value);
        }
        return value;
    }

    void compare_and_pop(x87_float rhs, int pops = 0, bool ordered = true)
    {
        clear_flags();
        bool st0_nan = std::isnan(st0());
        bool rhs_nan = std::isnan(rhs);

        if (st0_nan || rhs_nan)
        {
            sw |= X87FPU::C0 | X87FPU::C2 | X87FPU::C3;

            // For ordered comparisons (FCOM/FCOMP), set Invalid Operation
            if (ordered)
                sw |= 0x01; // IE flag
        }
        else if (st0() < rhs)
        {
            sw |= X87FPU::C0;  // ST0 < rhs
        }
        else if (st0() > rhs)
        {
            // ST0 > rhs: no flags set (C3=0, C2=0, C0=0)
        }
        else  // fpu.st0() == rhs
        {
            sw |= X87FPU::C3;  // ST0 == rhs
        }

        while (pops--)
            pop();
    }

    void compare_and_set_eflags(x87_float lhs, x87_float rhs, X86EFlags& eflags)
    {
        if (std::isnan(lhs) || std::isnan(rhs)) //is unordered
        {
            eflags.value |= X86EFlags::ZF | X86EFlags::PF | X86EFlags::CF;
        }
        else if (lhs > rhs)
        {
            eflags.value &= ~(X86EFlags::ZF | X86EFlags::CF | X86EFlags::PF);
        }
        else if (lhs < rhs)
        {
            eflags.value |= X86EFlags::CF;
            eflags.value &= ~(X86EFlags::ZF | X86EFlags::PF);
        }
        else  //equals
        {
            eflags.value |= X86EFlags::ZF;
            eflags.value &= ~(X86EFlags::CF | X86EFlags::PF);
        }
    }

};


union XmmRegister {
    __m128 reg;
    float f32[4];
    uint32_t u32[4];
    uint64_t u64[2];
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

    XmmRegister xmm[8];

    uint32_t mxcsr = 0x1F80;
    X87FPU fpu;

    void AddEsp(uint8_t count)
    {
        esp.u32 += (4 * count);
    }

    void SubEsp(uint8_t count)
    {
        esp.u32 -= (4 * count);
    }

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

// CONDITION CODE HELPER
inline bool X86_CC_O(const X86Context& ctx) { return (ctx.eflags.value & X86EFlags::OF) != 0; }
inline bool X86_CC_NO(const X86Context& ctx) { return (ctx.eflags.value & X86EFlags::OF) == 0; }
inline bool X86_CC_B(const X86Context& ctx) { return (ctx.eflags.value & X86EFlags::CF) != 0; }
inline bool X86_CC_NB(const X86Context& ctx) { return (ctx.eflags.value & X86EFlags::CF) == 0; }
inline bool X86_CC_Z(const X86Context& ctx) { return (ctx.eflags.value & X86EFlags::ZF) != 0; }
inline bool X86_CC_NZ(const X86Context& ctx) { return (ctx.eflags.value & X86EFlags::ZF) == 0; }
inline bool X86_CC_BE(const X86Context& ctx) { return (ctx.eflags.value & (X86EFlags::CF | X86EFlags::ZF)) != 0; }
inline bool X86_CC_NBE(const X86Context& ctx) { return (ctx.eflags.value & (X86EFlags::CF | X86EFlags::ZF)) == 0; }
inline bool X86_CC_S(const X86Context& ctx) { return (ctx.eflags.value & X86EFlags::SF) != 0; }
inline bool X86_CC_NS(const X86Context& ctx) { return (ctx.eflags.value & X86EFlags::SF) == 0; }
inline bool X86_CC_P(const X86Context& ctx) { return (ctx.eflags.value & X86EFlags::PF) != 0; }
inline bool X86_CC_NP(const X86Context& ctx) { return (ctx.eflags.value & X86EFlags::PF) == 0; }
inline bool X86_CC_L(const X86Context& ctx)
{
    return ((ctx.eflags.value & X86EFlags::SF) != 0) != ((ctx.eflags.value & X86EFlags::OF) != 0);
}
inline bool X86_CC_NL(const X86Context& ctx)
{
    return ((ctx.eflags.value & X86EFlags::SF) != 0) == ((ctx.eflags.value & X86EFlags::OF) != 0);
}
inline bool X86_CC_LE(const X86Context& ctx)
{
    return (ctx.eflags.value & X86EFlags::ZF) != 0 || X86_CC_L(ctx);
}
inline bool X86_CC_NLE(const X86Context& ctx)
{
    return (ctx.eflags.value & X86EFlags::ZF) == 0 && X86_CC_NL(ctx);
}
// end CC HELPER

inline bool X86_ATOMIC_CMPXCHG_U32(uint8_t* base, uint32_t addr, uint32_t& eax_val, uint32_t desired_val)
{
    auto* ptr = reinterpret_cast<std::atomic<uint32_t>*>(base + addr);
    return std::atomic_compare_exchange_strong(ptr, &eax_val, desired_val);
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

//todo check if all these functions and their instructions are correct
inline uint64_t X86_PADDW(uint64_t src_val, uint64_t dst_val)
{
    uint64_t result = 0;

    for (int i = 0; i < 4; i++)
    {
        uint16_t src_word = (src_val >> (i * 16)) & 0xFFFF;
        uint16_t dst_word = (dst_val >> (i * 16)) & 0xFFFF;
        uint16_t res_word = src_word + dst_word;
        result |= (static_cast<uint64_t>(res_word) << (i * 16));
    }

    return result;
}

inline uint64_t X86_PSRAW(uint64_t shift_val, uint64_t dst_val)
{
    uint64_t result = 0;

    for (int i = 0; i < 4; i++)
    {
        int16_t word = (dst_val >> (i * 16)) & 0xFFFF;
        int16_t shifted = word >> shift_val;
        result |= (static_cast<uint64_t>(shifted & 0xFFFF) << (i * 16));
    }

    return result;
}

inline uint64_t X86_PACKUSWB(uint64_t dst_val, uint64_t src_val)
{
    uint64_t result = 0;
    for (int i = 0; i < 4; i++) {

        int16_t word = (dst_val >> (i * 16)) & 0xFFFF;
        uint8_t byte = (word < 0) ? 0 : ((word > 255) ? 255 : static_cast<uint8_t>(word));
        result |= static_cast<uint64_t>(byte) << (i * 8);
    }

    for (int i = 0; i < 4; i++)
    {
        int16_t word = (src_val >> (i * 16)) & 0xFFFF;
        uint8_t byte = (word < 0) ? 0 : ((word > 255) ? 255 : static_cast<uint8_t>(word));
        result |= static_cast<uint64_t>(byte) << ((i + 4) * 8);
    }

    return result;
}

inline uint64_t X86_PAVGB(uint64_t dst_val, uint64_t src_val)
{
    uint64_t result = 0;

    for (size_t i = 0; i < 8; i++)
    {
        uint8_t dst_byte = (dst_val >> (i * 8)) & 0xFF;
        uint8_t src_byte = (src_val >> (i * 8)) & 0xFF;
        uint8_t avg = (dst_byte + src_byte + 1) >> 1;
        result |= (uint64_t(avg) << (i * 8));
    }

    return result;
}



inline void X87_FPREM(X87FPU& fpu)
{
    x87_float dividend = fpu.st0();
    x87_float divisor = fpu.st1();
    fpu.clear_flags();

    if (divisor == 0.0L) {
        fpu.sw |= X87FPU::C0;  // invalid
        return;
    }

    x87_float quotient = std::trunc(dividend / divisor);
    x87_float remainder = dividend - (quotient * divisor);
    fpu.st0() = remainder;

    if (std::fabs(quotient) < 4.0) {

        int q_bits = static_cast<int>(quotient) & 0x7;
        if (q_bits & 1) fpu.sw |= X87FPU::C1;
        if (q_bits & 2) fpu.sw |= X87FPU::C3;
        if (q_bits & 4) fpu.sw |= X87FPU::C0;
    }
    else
    {
        fpu.sw |= X87FPU::C2;
    }
}

inline void X87_FXAM(X87FPU& fpu, int32_t top)
{
    fpu.clear_flags();

    x87_float v = fpu.st[top];

    //Get the 2-bit tag for the current register
    int tag = (fpu.tw >> (top * 2)) & 3;

    if (tag == 3) {  //Empty
        fpu.sw |= X87FPU::C3;
        return;
    }

    //is negative
    if (std::signbit(v)) {
        fpu.sw |= X87FPU::C1;
    }

    //Classify based on value
    if (std::isnan(v))
    {
        fpu.sw |= X87FPU::C0;
    }
    else if (std::isinf(v))
    {
        fpu.sw |= X87FPU::C2;
    }
    else if (v == 0.0L)
    {
        fpu.sw |= X87FPU::C2;
    }
    else if (std::fpclassify(v) == FP_SUBNORMAL)
    {
        fpu.sw |= X87FPU::C3 | X87FPU::C2;  //Denormal
    }
    else
    {
        fpu.sw |= X87FPU::C2; //normal
    }
}

inline void X87_FDIVP(X87FPU& fpu, uint32_t addr)
{
    // FDIVP always: ST(1) = ST(1) / ST(0), then pop ST(0)
    x87_float& st1 = fpu.st1();
    x87_float& st0 = fpu.st0();

    if (st0 == 0.0L)
    {
        // printf("WARNING, DIVIDE PER 0!!!\n%x", addr);

        if (st1 == 0.0L) {
            fpu.sw |= 0x01;  // IE flag - 0/0
        }
        else {
            fpu.sw |= 0x04;  // ZE flag - non-zero/0
        }

        st1 = std::numeric_limits<x87_float>::quiet_NaN();

        // Update tag for ST(1) to "special" (tag=2)
        int tag_pos = ((fpu.top + 1) & 7) * 2;
        fpu.tw = (fpu.tw & ~(3 << tag_pos)) | (2 << tag_pos);
    }
    else
    {
        x87_float result = st1 / st0;

        // Check for overflow/underflow
        if (std::fpclassify(result) == FP_SUBNORMAL) {
            fpu.sw |= 0x10;  // UE flag - Underflow
        }
        else if (std::isinf(result)) {
            printf("WARNING, INF NUMBER !!!\n%x", addr);
            fpu.sw |= 0x08;  // OE flag - Overflow
        }

        st1 = result;
        fpu.set_precision_flag();
    }

    fpu.pop();
}

inline void X87_ISDIV_VALID(x87_float A, x87_float B, uint32_t addr)
{
    x87_float& st0 = A;
    x87_float& st1 = B;


    if (st0 == 0.0L || st1 == 0.0L)
    {
        //printf("WARNING, DIVIDE PER 0!!! (%Lf / %Lf) %x\n", A, B, addr);
    }
    else
    {
        x87_float result = st0 / st1;

        // Check for overflow/underflow
        if (std::isinf(result))
        {
            printf("WARNING, DIVISION RESULT IS INF!!! (%Lf / %Lf) %x\n", A, B, addr);
        }

    }
}

inline x87_float X87_FDIVR(x87_float res, x87_float A, x87_float B, uint32_t addr)
{
    X87_ISDIV_VALID(A, B, addr);

    res = A / B;

    return res;
}

inline x87_float X87_FIDIV_16(x87_float st0, int16_t B, uint32_t addr)
{
    if (st0 == 0.0L || B == 0)
    {
        //printf("WARNING, DIVIDE PER 0!!! (%Lf / %d) %x\n", st0, B, addr);
    }

    return (st0 / (x87_float)B);
}

inline x87_float X87_FIDIV_32(x87_float st0, int32_t B, uint32_t addr)
{
    if (st0 == 0.0L || B == 0)
    {
        //printf("WARNING, DIVIDE PER 0!!! (%Lf / %d) %x\n", st0, B, addr);
    }

    return (st0 / (x87_float)B);
}

inline x87_float X87_FIDIV_REG(x87_float st0, x87_float B, uint32_t addr)
{
    if (st0 == 0.0L || B == 0)
    {
        //printf("WARNING, DIVIDE PER 0!!! (%Lf / %d) %x\n", st0, B, addr);
    }

    return (st0 / B);
}

inline uint32_t X86_RCR32(uint32_t val, uint8_t shift, X86EFlags& eflags)
{
    if (shift == 0) return val;
    shift %= 33;

    uint8_t old_cf = (eflags.value & X86EFlags::CF) ? 1 : 0;

    uint64_t wide = ((uint64_t)old_cf << 32) | val;
    wide = (wide >> shift) | (wide << (33 - shift));
    wide &= 0x1FFFFFFFFULL;

    uint32_t result = static_cast<uint32_t>(wide);
    uint8_t new_cf = (wide >> 32) & 1;

    // Update CF
    if (new_cf)
        eflags.value |= X86EFlags::CF;
    else
        eflags.value &= ~X86EFlags::CF;


    if (shift == 1)
    {
        uint8_t of = ((result >> 31) & 1) ^ old_cf;
        if (of)
            eflags.value |= X86EFlags::OF;
        else
            eflags.value &= ~X86EFlags::OF;
    }

    return result;
}

inline void X86_DIV8(uint32_t divisor, X86Context& ctx)
{

    if (__builtin_expect(divisor == 0, 0))
        return;

    uint16_t dividend_ = ctx.eax.u16;
    uint8_t divisor_ = static_cast<uint8_t>(divisor);

    uint16_t temp_quotient_ = dividend_ / divisor_;

    if (__builtin_expect(temp_quotient_ > UINT8_MAX, 0))
    {
        return;
    }

    uint8_t quotient_var = static_cast<uint8_t>(temp_quotient_);
    uint8_t remainder_var = static_cast<uint8_t>(dividend_ % divisor_);

    ctx.eax.u8_lo = quotient_var;
    ctx.eax.u8_hi = remainder_var;
}

inline void X86_DIV16(uint32_t divisor, X86Context& ctx)
{
    if (__builtin_expect(divisor == 0, 0))
        return;

    uint32_t dividend_ = (static_cast<uint32_t>(ctx.edx.u16) << 16) | ctx.eax.u16;
    uint16_t divisor_ = static_cast<uint16_t>(divisor);
    uint32_t quotient_ = dividend_ / divisor_;
    uint32_t remainder_ = dividend_ % divisor_;

    if (__builtin_expect(quotient_ > UINT16_MAX, 0))
        return;

    ctx.eax.u16 = static_cast<uint16_t>(quotient_);
    ctx.edx.u16 = static_cast<uint16_t>(remainder_);
}

inline void X86_DIV32(uint32_t divisor, X86Context& ctx)
{
    if (__builtin_expect(divisor == 0, 0))
        return;

    uint64_t dividend_ = (static_cast<uint64_t>(ctx.edx.u32) << 32) | ctx.eax.u32;
    uint32_t divisor_ = static_cast<uint32_t>(divisor);
    uint64_t quotient_ = dividend_ / divisor_;
    uint64_t remainder_ = dividend_ % divisor_;

    if (__builtin_expect(quotient_ > UINT32_MAX, 0))
        return;

    ctx.eax.u32 = static_cast<uint32_t>(quotient_);
    ctx.edx.u32 = static_cast<uint32_t>(remainder_);
}

inline void X86_IDIV8(uint32_t divisor, X86Context& ctx)
{
    if (__builtin_expect(divisor == 0, 0))
        return;

    int16_t dividend = static_cast<int16_t>(ctx.eax.u16);
    int8_t  divisor_ = static_cast<int8_t>(divisor);
    int16_t quotient = dividend / divisor_;

    if (__builtin_expect(quotient > INT8_MAX || quotient < INT8_MIN, 0))
        return;
    ctx.eax.u8_lo = static_cast<uint8_t>(static_cast<int8_t>(quotient));
    ctx.eax.u8_hi = static_cast<uint8_t>(static_cast<int8_t>(dividend % divisor_));
}

inline void X86_IDIV16(uint32_t divisor, X86Context& ctx)
{
    if (__builtin_expect(divisor == 0, 0))
        return;

    // DX sign-extended to form high word, AX is raw bits for low word

    int32_t dividend = (static_cast<int32_t>(static_cast<int16_t>(ctx.edx.u16)) << 16) | static_cast<uint32_t>(ctx.eax.u16);
    int16_t divisor_ = static_cast<int16_t>(divisor);
    int32_t quotient = dividend / divisor_;
    int32_t remainder = dividend % divisor_;

    if (__builtin_expect(quotient > INT16_MAX || quotient < INT16_MIN, 0))
        return;

    ctx.eax.u16 = static_cast<uint16_t>(static_cast<int16_t>(quotient));
    ctx.edx.u16 = static_cast<uint16_t>(static_cast<int16_t>(remainder));
}

inline void X86_IDIV32(uint32_t divisor, X86Context& ctx)
{
    if (__builtin_expect(divisor == 0, 0))
        return;

    // EDX sign-extended to form high dword, EAX is raw bits for low dword
    int64_t dividend = (static_cast<int64_t>(static_cast<int32_t>(ctx.edx.u32)) << 32) | static_cast<uint64_t>(ctx.eax.u32);
    int32_t divisor_ = static_cast<int32_t>(divisor);
    int64_t quotient = dividend / divisor_;
    int64_t remainder = dividend % divisor_;

    if (__builtin_expect(quotient > INT32_MAX || quotient < INT32_MIN, 0))
        return;

    ctx.eax.u32 = static_cast<uint32_t>(static_cast<int32_t>(quotient));
    ctx.edx.u32 = static_cast<uint32_t>(static_cast<int32_t>(remainder));
}

inline void X86_SAR8(uint8_t& dst, const uint8_t count, X86Context& ctx)
{
    uint8_t orig = dst;
    dst = static_cast<uint8_t>(static_cast<int8_t>(dst) >> (count & 0x1F));
    ctx.eflags.update_flags_sar(orig, count, dst, 1);
}

inline void X86_SAR16(uint16_t& dst, const uint8_t count, X86Context& ctx)
{
    uint16_t orig = dst;
    dst = static_cast<uint16_t>(static_cast<int16_t>(dst) >> (count & 0x1F));
    ctx.eflags.update_flags_sar(orig, count, dst, 2);
}

inline void X86_SAR32(uint32_t& dst, const uint8_t count, X86Context& ctx)
{
    uint32_t orig = dst;
    dst = static_cast<uint32_t>(static_cast<int32_t>(dst) >> (count & 0x1F));
    ctx.eflags.update_flags_sar(orig, count, dst, 4);
}

inline void X86_SAR8_MEM(uint32_t addr, const uint8_t count, X86Context& ctx, uint8_t* base)
{
    uint8_t orig = X86_LOAD_U8(addr);
    uint8_t res = static_cast<uint8_t>(static_cast<int8_t>(orig) >> (count & 0x1F));
    X86_STORE_U8(addr, res);
    ctx.eflags.update_flags_sar(orig, count, res, 1);
}

inline void X86_SAR16_MEM(uint32_t addr, const uint8_t count, X86Context& ctx, uint8_t* base)
{
    uint16_t orig = X86_LOAD_U16(addr);
    uint16_t res = static_cast<uint16_t>(static_cast<int16_t>(orig) >> (count & 0x1F));
    X86_STORE_U16(addr, res);
    ctx.eflags.update_flags_sar(orig, count, res, 2);
}

inline void X86_SAR32_MEM(uint32_t addr, const uint8_t count, X86Context& ctx, uint8_t* base)
{
    uint32_t orig = X86_LOAD_U32(addr);
    uint32_t res = static_cast<uint32_t>(static_cast<int32_t>(orig) >> (count & 0x1F));
    X86_STORE_U32(addr, res);
    ctx.eflags.update_flags_sar(orig, count, res, 4);
}

inline void X86_SHR8(uint8_t& dst, const uint8_t count, X86Context& ctx)
{
    uint8_t temp = dst;
    dst >>= count;
    ctx.eflags.update_flags_shr(temp, count, dst, 1);
}

inline void X86_SHR8_MEM(uint32_t addr, const uint8_t count, X86Context& ctx, uint8_t* base)
{
    uint8_t orig = X86_LOAD_U8(addr);
    uint8_t res = orig >> count;
    X86_STORE_U8(addr, res);
    ctx.eflags.update_flags_shr(orig, count, res, 1);
}


inline void X86_SHR16(uint16_t& dst, const uint8_t count, X86Context& ctx)
{
    uint16_t temp = dst;
    dst >>= count;
    ctx.eflags.update_flags_shr(temp, count, dst, 2);
}

inline void X86_SHR16_MEM(uint32_t addr, const uint8_t count, X86Context& ctx, uint8_t* base)
{
    uint16_t orig = X86_LOAD_U16(addr);
    uint16_t res = orig >> count;
    X86_STORE_U16(addr, res);
    ctx.eflags.update_flags_shr(orig, count, res, 2);
}

inline void X86_SHR32(uint32_t& dst, const uint8_t count, X86Context& ctx)
{
    uint32_t temp = dst;
    dst >>= count;
    ctx.eflags.update_flags_shr(temp, count, dst, 4);
}

inline void X86_SHR32_MEM(uint32_t addr, const uint8_t count, X86Context& ctx, uint8_t* base)
{
    uint32_t orig = X86_LOAD_U32(addr);
    uint32_t res = orig >> count;
    X86_STORE_U32(addr, res);
    ctx.eflags.update_flags_shr(orig, count, res, 4);
}

inline void X86_SHL8(uint8_t& dst, const uint8_t count, X86Context& ctx)
{
    uint8_t temp = dst;
    dst <<= count;
    ctx.eflags.update_flags_shl(temp, count, dst, 1);
}

inline void X86_SHL8_MEM(uint32_t addr, const uint8_t count, X86Context& ctx, uint8_t* base)
{
    uint8_t orig = X86_LOAD_U8(addr);
    uint8_t res = orig << count;
    X86_STORE_U8(addr, res);
    ctx.eflags.update_flags_shr(orig, count, res, 1);
}

inline void X86_SHL16(uint16_t& dst, const uint8_t count, X86Context& ctx)
{
    uint16_t temp = dst;
    dst <<= count;
    ctx.eflags.update_flags_shl(temp, count, dst, 2);
}

inline void X86_SHL16_MEM(uint32_t addr, const uint8_t count, X86Context& ctx, uint8_t* base)
{
    uint16_t orig = X86_LOAD_U16(addr);
    uint16_t res = orig << count;
    X86_STORE_U16(addr, res);
    ctx.eflags.update_flags_shr(orig, count, res, 2);
}

inline void X86_SHL32(uint32_t& dst, const uint8_t count, X86Context& ctx)
{
    uint32_t temp = dst;
    dst <<= count;
    ctx.eflags.update_flags_shl(temp, count, dst, 4);
}

inline void X86_SHL32_MEM(uint32_t addr, const uint8_t count, X86Context& ctx, uint8_t* base)
{
    uint32_t orig = X86_LOAD_U32(addr);
    uint32_t res = orig << count;
    X86_STORE_U32(addr, res);
    ctx.eflags.update_flags_shr(orig, count, res, 4);
}

// reg destination, address type must match union type of CTX
inline void X86_SUB32(uint32_t& dst, uint32_t src, X86Context& ctx)
{
    uint32_t orig = dst;
    dst = orig - src;
    ctx.eflags.update_flags_sub_U32(orig, src, dst);
}

// mem destination, need base parameter for store macro.
inline void X86_SUB32_MEM(uint32_t addr, uint32_t src, X86Context& ctx, uint8_t* base)
{
    uint32_t orig = X86_LOAD_U32(addr);
    uint32_t res = orig - src;
    X86_STORE_U32(addr, res);
    ctx.eflags.update_flags_sub_U32(orig, src, res);
}

inline void X86_SUB16(uint16_t& dst, uint16_t src, X86Context& ctx)
{
    uint16_t orig = dst;
    dst = orig - src;
    ctx.eflags.update_flags_sub_U16(orig, src, dst);
}

// mem destination, need base parameter for store macro.
inline void X86_SUB16_MEM(uint32_t addr, uint16_t src, X86Context& ctx, uint8_t* base)
{
    uint16_t orig = X86_LOAD_U16(addr);
    uint16_t res = orig - src;
    X86_STORE_U16(addr, res);
    ctx.eflags.update_flags_sub_U16(orig, src, res);
}

inline void X86_SUB8(uint8_t& dst, uint8_t src, X86Context& ctx)
{
    uint8_t orig = dst;
    dst = orig - src;
    ctx.eflags.update_flags_sub_U8(orig, src, dst);
}

// mem destination, need base parameter for store macro.
inline void X86_SUB8_MEM(uint32_t addr, uint8_t src, X86Context& ctx, uint8_t* base)
{
    uint8_t orig = X86_LOAD_U8(addr);
    uint8_t res = orig - src;
    X86_STORE_U8(addr, res);
    ctx.eflags.update_flags_sub_U8(orig, src, res);
}

inline void X86_ADD32(uint32_t& dst, uint32_t src, X86Context& ctx)
{
    uint32_t orig = dst;
    dst = orig + src;
    ctx.eflags.update_flags_add_U32(orig, src, dst);
}

// mem destination, need base parameter for store macro.
inline void X86_ADD32_MEM(uint32_t addr, uint32_t src, X86Context& ctx, uint8_t* base)
{
    uint32_t orig = X86_LOAD_U32(addr);
    uint32_t res = orig + src;
    X86_STORE_U32(addr, res);
    ctx.eflags.update_flags_add_U32(orig, src, res);
}

inline void X86_ADD16(uint16_t& dst, uint16_t src, X86Context& ctx)
{
    uint16_t orig = dst;
    dst = orig + src;
    ctx.eflags.update_flags_add_U16(orig, src, dst);
}

// mem destination, need base parameter for store macro.
inline void X86_ADD16_MEM(uint32_t addr, uint16_t src, X86Context& ctx, uint8_t* base)
{
    uint16_t orig = X86_LOAD_U16(addr);
    uint16_t res = orig + src;
    X86_STORE_U16(addr, res);
    ctx.eflags.update_flags_add_U16(orig, src, res);
}

inline void X86_ADD8(uint8_t& dst, uint8_t src, X86Context& ctx)
{
    uint8_t orig = dst;
    dst = orig + src;
    ctx.eflags.update_flags_add_U8(orig, src, dst);
}

// mem destination, need base parameter for store macro.
inline void X86_ADD8_MEM(uint32_t addr, uint8_t src, X86Context& ctx, uint8_t* base)
{
    uint8_t orig = X86_LOAD_U8(addr);
    uint8_t res = orig + src;
    X86_STORE_U8(addr, res);
    ctx.eflags.update_flags_add_U8(orig, src, res);
}

inline void X86_INC32(uint32_t& dst, X86Context& ctx)
{
    uint32_t orig = dst;
    dst = orig + 1;
    ctx.eflags.update_flags_inc_U32(orig, dst);
}

inline void X86_INC32_MEM(uint32_t addr, X86Context& ctx, uint8_t* base)
{
    uint32_t orig = X86_LOAD_U32(addr);
    uint32_t res = orig + 1;
    X86_STORE_U32(addr, res);
    ctx.eflags.update_flags_inc_U32(orig, res);
}

inline void X86_INC16(uint16_t& dst, X86Context& ctx)
{
    uint16_t orig = dst;
    dst = orig + 1;
    ctx.eflags.update_flags_inc_U16(orig, dst);
}

inline void X86_INC16_MEM(uint32_t addr, X86Context& ctx, uint8_t* base)
{
    uint16_t orig = X86_LOAD_U16(addr);
    uint16_t res = orig + 1;
    X86_STORE_U16(addr, res);
    ctx.eflags.update_flags_inc_U16(orig, res);
}

inline void X86_INC8(uint8_t& dst, X86Context& ctx)
{
    uint8_t orig = dst;
    dst = orig + 1;
    ctx.eflags.update_flags_inc_U8(orig, dst);
}

inline void X86_INC8_MEM(uint32_t addr, X86Context& ctx, uint8_t* base)
{
    uint8_t orig = X86_LOAD_U8(addr);
    uint8_t res = orig + 1;
    X86_STORE_U8(addr, res);
    ctx.eflags.update_flags_inc_U8(orig, res);
}

inline void X86_DEC32(uint32_t& dst, X86Context& ctx)
{
    uint32_t orig = dst;
    dst = orig - 1;
    ctx.eflags.update_flags_dec_U32(orig, dst);
}

inline void X86_DEC32_MEM(uint32_t addr, X86Context& ctx, uint8_t* base)
{
    uint32_t orig = X86_LOAD_U32(addr);
    uint32_t res = orig - 1;
    X86_STORE_U32(addr, res);
    ctx.eflags.update_flags_dec_U32(orig, res);
}

inline void X86_DEC16(uint16_t& dst, X86Context& ctx)
{
    uint16_t orig = dst;
    dst = orig - 1;
    ctx.eflags.update_flags_dec_U16(orig, dst);
}

inline void X86_DEC16_MEM(uint32_t addr, X86Context& ctx, uint8_t* base)
{
    uint16_t orig = X86_LOAD_U16(addr);
    uint16_t res = orig - 1;
    X86_STORE_U16(addr, res);
    ctx.eflags.update_flags_dec_U16(orig, res);
}

inline void X86_DEC8(uint8_t& dst, X86Context& ctx)
{
    uint8_t orig = dst;
    dst = orig - 1;
    ctx.eflags.update_flags_dec_U8(orig, dst);
}

inline void X86_DEC8_MEM(uint32_t addr, X86Context& ctx, uint8_t* base)
{
    uint8_t orig = X86_LOAD_U8(addr);
    uint8_t res = orig - 1;
    X86_STORE_U8(addr, res);
    ctx.eflags.update_flags_dec_U8(orig, res);
}

inline void X86_NEG_U32(uint32_t& dst, X86Context& ctx)
{
    uint32_t orig = dst;
    dst = -orig;
    ctx.eflags.update_flags_neg_U32(orig, dst);
}

inline void X86_NEG_U32_MEM(uint32_t addr, X86Context& ctx, uint8_t* base)
{
    uint32_t orig = X86_LOAD_U32(addr);
    uint32_t res = -orig;
    X86_STORE_U32(addr, res);
    ctx.eflags.update_flags_neg_U16(orig, res);
}

inline void X86_NEG_U16(uint16_t &dst, X86Context& ctx)
{
    uint16_t orig = dst;
    dst = -orig;
    ctx.eflags.update_flags_neg_U16(orig, dst);
}

inline void X86_NEG_U16_MEM(uint32_t addr, X86Context& ctx, uint8_t* base)
{
    uint16_t orig = X86_LOAD_U16(addr);
    uint16_t res = -orig;
    X86_STORE_U16(addr, res);
    ctx.eflags.update_flags_neg_U16(orig, res);
}

inline void X86_NEG_U8(uint8_t& dst, X86Context& ctx)
{
    uint8_t orig = dst;
    dst = -orig;
    ctx.eflags.update_flags_neg_U8(orig, dst);
}

inline void X86_NEG_U8_MEM(uint32_t addr, X86Context& ctx, uint8_t* base)
{
    uint8_t orig = X86_LOAD_U8(addr);
    uint8_t res = -orig;
    X86_STORE_U8(addr, res);
    ctx.eflags.update_flags_neg_U8(orig, res);
}


inline void X86_IMUL_EAX_U8(uint8_t src, X86Context& ctx)
{
    int16_t result = static_cast<int16_t>(static_cast<int8_t>(ctx.eax.u8_lo))
        * static_cast<int16_t>(static_cast<int8_t>(src));
    ctx.eax.u16 = static_cast<uint16_t>(result);
    // OF/CF set if result doesn't fit in 8 bits
    const bool overflow = (result < INT8_MIN || result > INT8_MAX);
    ctx.eflags.value = (ctx.eflags.value & ~(X86EFlags::CF | X86EFlags::OF))
        | (overflow ? (X86EFlags::CF | X86EFlags::OF) : 0);
}

inline void X86_IMUL_EAX_U16(uint16_t src, X86Context& ctx)
{
    int32_t result = static_cast<int32_t>(static_cast<int16_t>(ctx.eax.u16))
        * static_cast<int32_t>(static_cast<int16_t>(src));
    ctx.eax.u16 = static_cast<uint16_t>(result & 0xFFFF);
    ctx.edx.u16 = static_cast<uint16_t>(static_cast<uint32_t>(result) >> 16);
    const bool overflow = (static_cast<int16_t>(ctx.edx.u16) != (static_cast<int16_t>(ctx.eax.u16) >> 15));
    ctx.eflags.value = (ctx.eflags.value & ~(X86EFlags::CF | X86EFlags::OF))
        | (overflow ? (X86EFlags::CF | X86EFlags::OF) : 0);
}

inline void X86_IMUL_EAX_U32(uint32_t src, X86Context& ctx)
{
    int64_t result = static_cast<int64_t>(static_cast<int32_t>(ctx.eax.u32))
        * static_cast<int64_t>(static_cast<int32_t>(src));
    ctx.eax.u32 = static_cast<uint32_t>(result & 0xFFFFFFFFULL);
    ctx.edx.u32 = static_cast<uint32_t>(static_cast<uint64_t>(result) >> 32);
    const bool overflow = (static_cast<int32_t>(ctx.edx.u32) != (static_cast<int32_t>(ctx.eax.u32) >> 31));
    ctx.eflags.value = (ctx.eflags.value & ~(X86EFlags::CF | X86EFlags::OF))
        | (overflow ? (X86EFlags::CF | X86EFlags::OF) : 0);
}


inline void X86_IMUL_U8(uint8_t& dst, uint8_t lhs, uint8_t rhs, X86Context& ctx)
{
    int16_t result = static_cast<int16_t>(static_cast<int8_t>(lhs))
        * static_cast<int16_t>(static_cast<int8_t>(rhs));
    dst = static_cast<uint8_t>(result);
    const bool overflow = (result < INT8_MIN || result > INT8_MAX);
    ctx.eflags.value = (ctx.eflags.value & ~(X86EFlags::CF | X86EFlags::OF))
        | (overflow ? (X86EFlags::CF | X86EFlags::OF) : 0);
}

inline void X86_IMUL_U16(uint16_t& dst, uint16_t lhs, uint16_t rhs, X86Context& ctx)
{
    int32_t result = static_cast<int32_t>(static_cast<int16_t>(lhs))
        * static_cast<int32_t>(static_cast<int16_t>(rhs));
    dst = static_cast<uint16_t>(result);
    const bool overflow = (result < INT16_MIN || result > INT16_MAX);
    ctx.eflags.value = (ctx.eflags.value & ~(X86EFlags::CF | X86EFlags::OF))
        | (overflow ? (X86EFlags::CF | X86EFlags::OF) : 0);
}

inline void X86_IMUL_U32(uint32_t& dst, uint32_t lhs, uint32_t rhs, X86Context& ctx)
{
    int64_t result = static_cast<int64_t>(static_cast<int32_t>(lhs))
        * static_cast<int64_t>(static_cast<int32_t>(rhs));

    dst = static_cast<uint32_t>(result);
    const bool overflow = (result < INT32_MIN || result > INT32_MAX);
    ctx.eflags.value = (ctx.eflags.value & ~(X86EFlags::CF | X86EFlags::OF))
        | (overflow ? (X86EFlags::CF | X86EFlags::OF) : 0);
}

inline void X86_MINPS(XmmRegister &dst, __m128 src)
{
    dst.reg = _mm_min_ps(dst.reg, src);
}

inline void X86_MAXPS(XmmRegister &dst, __m128 src)
{
    dst.reg = _mm_max_ps(dst.reg, src);
}

inline void X86_CVTSS2SI_MEM(uint32_t addr, uint32_t &dst, uint8_t* base, bool mm_cvttss_si32)
{
    float valOrigin = X86_LOAD_F32(addr);
    const float* val = &valOrigin;
    if (mm_cvttss_si32)
        dst = static_cast<uint32_t>(static_cast<int32_t>(_mm_cvttss_si32((_mm_load_ss(val)))));
    else
        dst = static_cast<uint32_t>(static_cast<int32_t>(_mm_cvtss_si32((_mm_load_ss(val)))));
}

// --- Bitwise MEM helpers ---

inline void X86_AND32_MEM(uint32_t addr, uint32_t src, X86Context& ctx, uint8_t* base)
{
    uint32_t temp = X86_LOAD_U32(addr);
    temp &= src;
    X86_STORE_U32(addr, temp);
    ctx.eflags.update_flags_logic(temp);
}

inline void X86_AND16_MEM(uint32_t addr, uint16_t src, X86Context& ctx, uint8_t* base)
{
    uint16_t temp = X86_LOAD_U16(addr);
    temp &= src;
    X86_STORE_U16(addr, temp);
    ctx.eflags.update_flags_logic(temp);
}

inline void X86_AND8_MEM(uint32_t addr, uint8_t src, X86Context& ctx, uint8_t* base)
{
    uint8_t temp = X86_LOAD_U8(addr);
    temp &= src;
    X86_STORE_U8(addr, temp);
    ctx.eflags.update_flags_logic(temp);
}

inline void X86_OR32_MEM(uint32_t addr, uint32_t src, X86Context& ctx, uint8_t* base)
{
    uint32_t temp = X86_LOAD_U32(addr);
    temp |= src;
    X86_STORE_U32(addr, temp);
    ctx.eflags.update_flags_logic(temp);
}

inline void X86_OR16_MEM(uint32_t addr, uint16_t src, X86Context& ctx, uint8_t* base)
{
    uint16_t temp = X86_LOAD_U16(addr);
    temp |= src;
    X86_STORE_U16(addr, temp);
    ctx.eflags.update_flags_logic(temp);
}

inline void X86_OR8_MEM(uint32_t addr, uint8_t src, X86Context& ctx, uint8_t* base)
{
    uint8_t temp = X86_LOAD_U8(addr);
    temp |= src;
    X86_STORE_U8(addr, temp);
    ctx.eflags.update_flags_logic(temp);
}

inline void X86_XOR32_MEM(uint32_t addr, uint32_t src, X86Context& ctx, uint8_t* base)
{
    uint32_t temp = X86_LOAD_U32(addr);
    temp ^= src;
    X86_STORE_U32(addr, temp);
    ctx.eflags.update_flags_logic(temp);
}

inline void X86_XOR16_MEM(uint32_t addr, uint16_t src, X86Context& ctx, uint8_t* base)
{
    uint16_t temp = X86_LOAD_U16(addr);
    temp ^= src;
    X86_STORE_U16(addr, temp);
    ctx.eflags.update_flags_logic(temp);
}

inline void X86_XOR8_MEM(uint32_t addr, uint8_t src, X86Context& ctx, uint8_t* base)
{
    uint8_t temp = X86_LOAD_U8(addr);
    temp ^= src;
    X86_STORE_U8(addr, temp);
    ctx.eflags.update_flags_logic(temp);
}

// --- ADC helpers ---

inline void X86_ADC32(uint32_t& dst, uint32_t src, X86Context& ctx)
{
    uint32_t carry = (ctx.eflags.value & X86EFlags::CF) ? 1 : 0;
    uint32_t orig = dst;
    uint32_t result = orig + src + carry;
    dst = result;
    ctx.eflags.update_flags_adc(orig, src, carry, result);
}

inline void X86_ADC32_MEM(uint32_t addr, uint32_t src, X86Context& ctx, uint8_t* base)
{
    uint32_t carry = (ctx.eflags.value & X86EFlags::CF) ? 1 : 0;
    uint32_t orig = X86_LOAD_U32(addr);
    uint32_t result = orig + src + carry;
    X86_STORE_U32(addr, result);
    ctx.eflags.update_flags_adc(orig, src, carry, result);
}

inline void X86_ADC16(uint16_t& dst, uint16_t src, X86Context& ctx)
{
    uint32_t carry = (ctx.eflags.value & X86EFlags::CF) ? 1 : 0;
    uint16_t orig = dst;
    uint16_t result = orig + src + (uint16_t)carry;
    dst = result;
    ctx.eflags.update_flags_adc(orig, src, carry, result);
}

inline void X86_ADC16_MEM(uint32_t addr, uint16_t src, X86Context& ctx, uint8_t* base)
{
    uint32_t carry = (ctx.eflags.value & X86EFlags::CF) ? 1 : 0;
    uint16_t orig = X86_LOAD_U16(addr);
    uint16_t result = orig + src + (uint16_t)carry;
    X86_STORE_U16(addr, result);
    ctx.eflags.update_flags_adc(orig, src, carry, result);
}

inline void X86_ADC8(uint8_t& dst, uint8_t src, X86Context& ctx)
{
    uint32_t carry = (ctx.eflags.value & X86EFlags::CF) ? 1 : 0;
    uint8_t orig = dst;
    uint8_t result = orig + src + (uint8_t)carry;
    dst = result;
    ctx.eflags.update_flags_adc(orig, src, carry, result);
}

inline void X86_ADC8_MEM(uint32_t addr, uint8_t src, X86Context& ctx, uint8_t* base)
{
    uint32_t carry = (ctx.eflags.value & X86EFlags::CF) ? 1 : 0;
    uint8_t orig = X86_LOAD_U8(addr);
    uint8_t result = orig + src + (uint8_t)carry;
    X86_STORE_U8(addr, result);
    ctx.eflags.update_flags_adc(orig, src, carry, result);
}

// --- SBB helpers ---

inline void X86_SBB32(uint32_t& dst, uint32_t src, X86Context& ctx)
{
    uint32_t carry = (ctx.eflags.value & X86EFlags::CF) ? 1 : 0;
    uint32_t orig = dst;
    uint32_t result = orig - (src + carry);
    dst = result;
    ctx.eflags.update_flags_sub_U32(orig, src + carry, result);
}

inline void X86_SBB32_MEM(uint32_t addr, uint32_t src, X86Context& ctx, uint8_t* base)
{
    uint32_t carry = (ctx.eflags.value & X86EFlags::CF) ? 1 : 0;
    uint32_t orig = X86_LOAD_U32(addr);
    uint32_t result = orig - (src + carry);
    X86_STORE_U32(addr, result);
    ctx.eflags.update_flags_sub_U32(orig, src + carry, result);
}

inline void X86_SBB16(uint16_t& dst, uint16_t src, X86Context& ctx)
{
    uint32_t carry = (ctx.eflags.value & X86EFlags::CF) ? 1 : 0;
    uint16_t orig = dst;
    uint16_t result = orig - (uint16_t)(src + carry);
    dst = result;
    ctx.eflags.update_flags_sub_U16(orig, src + carry, result);
}

inline void X86_SBB16_MEM(uint32_t addr, uint16_t src, X86Context& ctx, uint8_t* base)
{
    uint32_t carry = (ctx.eflags.value & X86EFlags::CF) ? 1 : 0;
    uint16_t orig = X86_LOAD_U16(addr);
    uint16_t result = orig - (uint16_t)(src + carry);
    X86_STORE_U16(addr, result);
    ctx.eflags.update_flags_sub_U16(orig, src + carry, result);
}

inline void X86_SBB8(uint8_t& dst, uint8_t src, X86Context& ctx)
{
    uint32_t carry = (ctx.eflags.value & X86EFlags::CF) ? 1 : 0;
    uint8_t orig = dst;
    uint8_t result = orig - (uint8_t)(src + carry);
    dst = result;
    ctx.eflags.update_flags_sub_U8(orig, src + carry, result);
}

inline void X86_SBB8_MEM(uint32_t addr, uint8_t src, X86Context& ctx, uint8_t* base)
{
    uint32_t carry = (ctx.eflags.value & X86EFlags::CF) ? 1 : 0;
    uint8_t orig = X86_LOAD_U8(addr);
    uint8_t result = orig - (uint8_t)(src + carry);
    X86_STORE_U8(addr, result);
    ctx.eflags.update_flags_sub_U8(orig, src + carry, result);
}

// --- BSF helpers ---

inline void X86_BSF32(uint32_t& dst, uint32_t src, X86Context& ctx)
{
    if (src == 0) {
        ctx.eflags.value |= X86EFlags::ZF;
    } else {
        ctx.eflags.value &= ~X86EFlags::ZF;
        dst = __builtin_ctz(src);
    }
}

inline void X86_BSF16(uint16_t& dst, uint16_t src, X86Context& ctx)
{
    if (src == 0) {
        ctx.eflags.value |= X86EFlags::ZF;
    } else {
        ctx.eflags.value &= ~X86EFlags::ZF;
        dst = (uint16_t)__builtin_ctz(src);
    }
}

// --- FPATAN helper ---

inline void X86_FPATAN(X87FPU& fpu)
{
    x87_float st1Temp = fpu.st1();
    x87_float st0Temp = fpu.st0();
    fpu.set_precision_flag();
    fpu.pop();
    fpu.st0() = std::atan2(st1Temp, st0Temp);
}

// --- FXCH helper ---

inline void X86_FXCH(X87FPU& fpu, int index = 1)
{
    x87_float tmp = fpu.st0();
    fpu.st0() = fpu.getST(index);
    fpu.getST(index) = tmp;
}

// --- XCHG reg-reg helper ---

template<typename T>
inline void X86_XCHG_REG(T& a, T& b)
{
    T tmp = a;
    a = b;
    b = tmp;
}

// --- RCR MEM helpers ---

inline void X86_RCR32_MEM(uint32_t addr, uint8_t shift, X86Context& ctx, uint8_t* base)
{
    uint32_t temp = X86_LOAD_U32(addr);
    X86_STORE_U32(addr, X86_RCR32(temp, shift, ctx.eflags));
}

// --- ROL helpers ---

inline void X86_ROL32(uint32_t& dst, uint32_t count, X86Context& ctx)
{
    uint32_t orig = dst;
    dst = (orig << count) | (orig >> (32 - count));
    ctx.eflags.update_flags_rol(orig, count, dst);
}

inline void X86_ROL32_MEM(uint32_t addr, uint32_t count, X86Context& ctx, uint8_t* base)
{
    uint32_t orig = X86_LOAD_U32(addr);
    uint32_t result = (orig << count) | (orig >> (32 - count));
    X86_STORE_U32(addr, result);
    ctx.eflags.update_flags_rol(orig, count, result);
}

inline void X86_ROL16(uint16_t& dst, uint32_t count, X86Context& ctx)
{
    uint16_t orig = dst;
    dst = (uint16_t)((orig << count) | (orig >> (32 - count)));
    ctx.eflags.update_flags_rol(orig, count, dst);
}

inline void X86_ROL16_MEM(uint32_t addr, uint32_t count, X86Context& ctx, uint8_t* base)
{
    uint16_t orig = X86_LOAD_U16(addr);
    uint16_t result = (uint16_t)((orig << count) | (orig >> (32 - count)));
    X86_STORE_U16(addr, result);
    ctx.eflags.update_flags_rol(orig, count, result);
}

inline void X86_ROL8(uint8_t& dst, uint32_t count, X86Context& ctx)
{
    uint8_t orig = dst;
    dst = (uint8_t)((orig << count) | (orig >> (32 - count)));
    ctx.eflags.update_flags_rol(orig, count, dst);
}

inline void X86_ROL8_MEM(uint32_t addr, uint32_t count, X86Context& ctx, uint8_t* base)
{
    uint8_t orig = X86_LOAD_U8(addr);
    uint8_t result = (uint8_t)((orig << count) | (orig >> (32 - count)));
    X86_STORE_U8(addr, result);
    ctx.eflags.update_flags_rol(orig, count, result);
}

// --- ROR helpers ---

inline void X86_ROR32(uint32_t& dst, uint32_t count, X86Context& ctx)
{
    uint32_t orig = dst;
    dst = (orig >> count) | (orig << (32 - count));
    ctx.eflags.update_flags_ror(orig, count, dst);
}

inline void X86_ROR32_MEM(uint32_t addr, uint32_t count, X86Context& ctx, uint8_t* base)
{
    uint32_t orig = X86_LOAD_U32(addr);
    uint32_t result = (orig >> count) | (orig << (32 - count));
    X86_STORE_U32(addr, result);
    ctx.eflags.update_flags_ror(orig, count, result);
}

inline void X86_ROR16(uint16_t& dst, uint32_t count, X86Context& ctx)
{
    uint16_t orig = dst;
    dst = (uint16_t)((orig >> count) | (orig << (32 - count)));
    ctx.eflags.update_flags_ror(orig, count, dst);
}

inline void X86_ROR16_MEM(uint32_t addr, uint32_t count, X86Context& ctx, uint8_t* base)
{
    uint16_t orig = X86_LOAD_U16(addr);
    uint16_t result = (uint16_t)((orig >> count) | (orig << (32 - count)));
    X86_STORE_U16(addr, result);
    ctx.eflags.update_flags_ror(orig, count, result);
}

inline void X86_ROR8(uint8_t& dst, uint32_t count, X86Context& ctx)
{
    uint8_t orig = dst;
    dst = (uint8_t)((orig >> count) | (orig << (32 - count)));
    ctx.eflags.update_flags_ror(orig, count, dst);
}

inline void X86_ROR8_MEM(uint32_t addr, uint32_t count, X86Context& ctx, uint8_t* base)
{
    uint8_t orig = X86_LOAD_U8(addr);
    uint8_t result = (uint8_t)((orig >> count) | (orig << (32 - count)));
    X86_STORE_U8(addr, result);
    ctx.eflags.update_flags_ror(orig, count, result);
}

// --- SHLD helpers ---

inline void X86_SHLD32(uint32_t& dst, uint32_t src, uint32_t raw_count, X86Context& ctx)
{
    uint32_t count = raw_count & 0x1F;
    uint32_t orig = dst;
    uint32_t result = (orig << count) | (src >> (32 - count));
    dst = result;
    ctx.eflags.update_flags_shld(orig, count, result, 32);
}

inline void X86_SHLD32_MEM(uint32_t addr, uint32_t src, uint32_t raw_count, X86Context& ctx, uint8_t* base)
{
    uint32_t count = raw_count & 0x1F;
    uint32_t orig = X86_LOAD_U32(addr);
    uint32_t result = (orig << count) | (src >> (32 - count));
    X86_STORE_U32(addr, result);
    ctx.eflags.update_flags_shld(orig, count, result, 32);
}

inline void X86_SHLD16(uint16_t& dst, uint16_t src, uint32_t raw_count, X86Context& ctx)
{
    uint32_t count = raw_count & 0xF;
    uint32_t orig = dst;
    uint32_t result = ((orig << count) | (src >> (16 - count))) & 0xFFFF;
    dst = (uint16_t)result;
    ctx.eflags.update_flags_shld(orig, count, result, 16);
}

inline void X86_SHLD16_MEM(uint32_t addr, uint16_t src, uint32_t raw_count, X86Context& ctx, uint8_t* base)
{
    uint32_t count = raw_count & 0xF;
    uint16_t orig = X86_LOAD_U16(addr);
    uint32_t result = ((orig << count) | (src >> (16 - count))) & 0xFFFF;
    X86_STORE_U16(addr, (uint16_t)result);
    ctx.eflags.update_flags_shld(orig, count, result, 16);
}

// --- SHRD helpers ---

inline void X86_SHRD32(uint32_t& dst, uint32_t src, uint32_t raw_count, X86Context& ctx)
{
    uint32_t count = raw_count & 0x1F;
    uint32_t orig = dst;
    uint32_t result = (orig >> count) | (src << (32 - count));
    dst = result;
    ctx.eflags.update_flags_shrd(orig, count, result, 32);
}

inline void X86_SHRD32_MEM(uint32_t addr, uint32_t src, uint32_t raw_count, X86Context& ctx, uint8_t* base)
{
    uint32_t count = raw_count & 0x1F;
    uint32_t orig = X86_LOAD_U32(addr);
    uint32_t result = (orig >> count) | (src << (32 - count));
    X86_STORE_U32(addr, result);
    ctx.eflags.update_flags_shrd(orig, count, result, 32);
}

inline void X86_SHRD16(uint16_t& dst, uint16_t src, uint32_t raw_count, X86Context& ctx)
{
    uint32_t count = raw_count & 0xF;
    uint32_t orig = dst;
    uint32_t result = ((orig >> count) | (src << (16 - count))) & 0xFFFF;
    dst = (uint16_t)result;
    ctx.eflags.update_flags_shrd(orig, count, result, 16);
}

inline void X86_SHRD16_MEM(uint32_t addr, uint16_t src, uint32_t raw_count, X86Context& ctx, uint8_t* base)
{
    uint32_t count = raw_count & 0xF;
    uint16_t orig = X86_LOAD_U16(addr);
    uint32_t result = ((orig >> count) | (src << (16 - count))) & 0xFFFF;
    X86_STORE_U16(addr, (uint16_t)result);
    ctx.eflags.update_flags_shrd(orig, count, result, 16);
}

// --- CMPXCHG helpers ---

inline void X86_CMPXCHG32_MEM(uint32_t addr, uint32_t src_val, X86Context& ctx, uint8_t* base)
{
    uint32_t expected = ctx.eax.u32;
    bool success = X86_ATOMIC_CMPXCHG_U32(base, addr, expected, src_val);
    if (success) {
        ctx.eflags.value |= X86EFlags::ZF;
    } else {
        ctx.eax.u32 = expected;
        ctx.eflags.value &= ~X86EFlags::ZF;
    }
}

inline void X86_CMPXCHG32(uint32_t& current, uint32_t src_val, X86Context& ctx)
{
    uint32_t expected = ctx.eax.u32;
    if (expected == current) {
        current = src_val;
        ctx.eflags.value |= X86EFlags::ZF;
    } else {
        ctx.eax.u32 = current;
        ctx.eflags.value &= ~X86EFlags::ZF;
    }
}

inline void X86_CMPXCHG16_MEM(uint32_t addr, uint16_t src_val, X86Context& ctx, uint8_t* base)
{
    uint16_t expected = ctx.eax.u16;
    bool success = X86_ATOMIC_CMPXCHG_U32(base, addr, (uint32_t&)expected, src_val);
    if (success) {
        ctx.eflags.value |= X86EFlags::ZF;
    } else {
        ctx.eax.u16 = expected;
        ctx.eflags.value &= ~X86EFlags::ZF;
    }
}

inline void X86_CMPXCHG16(uint16_t& current, uint16_t src_val, X86Context& ctx)
{
    uint16_t expected = ctx.eax.u16;
    if (expected == current) {
        current = src_val;
        ctx.eflags.value |= X86EFlags::ZF;
    } else {
        ctx.eax.u16 = current;
        ctx.eflags.value &= ~X86EFlags::ZF;
    }
}

inline void X86_CMPXCHG8_MEM(uint32_t addr, uint8_t src_val, X86Context& ctx, uint8_t* base)
{
    uint8_t expected = ctx.eax.u8_lo;
    bool success = X86_ATOMIC_CMPXCHG_U32(base, addr, (uint32_t&)expected, src_val);
    if (success) {
        ctx.eflags.value |= X86EFlags::ZF;
    } else {
        ctx.eax.u8_lo = expected;
        ctx.eflags.value &= ~X86EFlags::ZF;
    }
}

inline void X86_CMPXCHG8(uint8_t& current, uint8_t src_val, X86Context& ctx)
{
    uint8_t expected = ctx.eax.u8_lo;
    if (expected == current) {
        current = src_val;
        ctx.eflags.value |= X86EFlags::ZF;
    } else {
        ctx.eax.u8_lo = current;
        ctx.eflags.value &= ~X86EFlags::ZF;
    }
}

// --- XADD helpers ---

inline void X86_XADD32_ATOMIC(uint32_t addr, uint32_t& src, uint8_t* base)
{
    src = X86_ATOMIC_XADD_U32(addr, src);
}

inline void X86_XADD32_MEM(uint32_t addr, uint32_t& src, uint8_t* base)
{
    uint32_t tmp = *reinterpret_cast<volatile uint32_t*>(base + addr);
    *reinterpret_cast<volatile uint32_t*>(base + addr) += src;
    src = tmp;
}

inline void X86_XADD16_ATOMIC(uint32_t addr, uint16_t& src, uint8_t* base)
{
    src = X86_ATOMIC_XADD_U16(addr, src);
}

inline void X86_XADD16_MEM(uint32_t addr, uint16_t& src, uint8_t* base)
{
    uint16_t tmp = *reinterpret_cast<volatile uint16_t*>(base + addr);
    *reinterpret_cast<volatile uint16_t*>(base + addr) += src;
    src = tmp;
}

inline void X86_XADD8_ATOMIC(uint32_t addr, uint8_t& src, uint8_t* base)
{
    src = X86_ATOMIC_XADD_U8(addr, src);
}

inline void X86_XADD8_MEM(uint32_t addr, uint8_t& src, uint8_t* base)
{
    uint8_t tmp = *reinterpret_cast<volatile uint8_t*>(base + addr);
    *reinterpret_cast<volatile uint8_t*>(base + addr) += src;
    src = tmp;
}

template<typename T>
inline void X86_XADD_REG(T& dst, T& src)
{
    T tmp = dst;
    dst += src;
    src = tmp;
}

inline void X86_MUL32(uint32_t rhs, X86Context& ctx)
{
    uint64_t result = static_cast<uint64_t>(ctx.eax.u32) * static_cast<uint64_t>(rhs);
    ctx.eax.u32 = static_cast<uint32_t>(result & 0xFFFFFFFF);
    ctx.edx.u32 = static_cast<uint32_t>(result >> 32);
    ctx.eflags.update_flags_mul(ctx.edx.u32 != 0);
}

#endif // X86_CONTEXT_H_INCLUDED
