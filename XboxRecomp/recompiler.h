#pragma once

#include "pch.h"
#include "recompiler_config.h"
#include "Zydis/DecoderTypes.h"
#include <functional>
#include <algorithm>
#include <iterator>
#include <util.h>

const static ZydisMnemonic FloatOP[] =
{
    ZYDIS_MNEMONIC_FADD, ZYDIS_MNEMONIC_FSUB, ZYDIS_MNEMONIC_FMUL, ZYDIS_MNEMONIC_FDIV,
    ZYDIS_MNEMONIC_FIADD,
    ZYDIS_MNEMONIC_FSIN, ZYDIS_MNEMONIC_FCOMP, ZYDIS_MNEMONIC_FCOM, ZYDIS_MNEMONIC_FCOMPP,
    ZYDIS_MNEMONIC_FCOS, ZYDIS_MNEMONIC_FSINCOS, ZYDIS_MNEMONIC_FXAM, ZYDIS_MNEMONIC_FUCOMIP, 
    ZYDIS_MNEMONIC_FCOMIP, ZYDIS_MNEMONIC_F2XM1, ZYDIS_MNEMONIC_FSCALE, ZYDIS_MNEMONIC_SQRTSS
};

const static ZydisMnemonic U64OP[] =
{
    ZYDIS_MNEMONIC_PUNPCKLDQ, ZYDIS_MNEMONIC_PUNPCKHDQ
};

const static ZydisMnemonic U32OP[] =
{
    ZYDIS_MNEMONIC_ADC, ZYDIS_MNEMONIC_MOVSB, ZYDIS_MNEMONIC_MOVSW,
    ZYDIS_MNEMONIC_CMPSD
};

struct RecompilerLocalVariables
{
    bool r[8]{};   //General-purpose registers (EAX, EBX, ECX, EDX, ESI, EDI, EBP, ESP)
    bool xmm[16]{}; //SIMD registers (XMM0-XMM15)
    bool flags{};   //EFLAGS register
    bool st[8]{}; //x87 FPU stack registers (ST(0)-ST(7)) - Optional, if x87 is used
    bool temp{};
    bool fs{};

    //temp to avoid variable redundancy 
    bool valDouble[3]{};
    bool valUint32[2]{};
    bool valUint64[2]{};

    bool isUint64OP(const ZydisMnemonic op)
    {
        for (int i = 0; i < LengthOfArray(U64OP); i++)
        {
            if (U64OP[i] == op)
                return true;
        }

        return false;
    }    
    
    bool isUint32OP(const ZydisMnemonic op)
    {
        for (int i = 0; i < LengthOfArray(U32OP); i++)
        {
            if (U32OP[i] == op)
                return true;
        }

        return false;
    }

    bool isFloatOP(const ZydisMnemonic op)
    {
        for (int i = 0; i < LengthOfArray(FloatOP); i++)
        {
            if (FloatOP[i] == op)
                return true;
        }

        return false;
    }
};

struct RecompilerFuncConfig
{
    bool isFS{};
    bool isLastInst{};
    std::string RegisterStackBaseAddr;
    bool isRegKernelAddr{};
    uint32_t RegisterKernelAddr;
};

enum class CSRState {
    Unknown,  
    FPU,  //x87 FPU mode (flush-to-zero for x87)
    SSE  //SSE/AVX mode (flush-to-zero for MXCSR)
};

struct x86_insn
{
    ZydisDecodedInstruction insn;
    ZydisDecodedOperand* operands;
};



struct Recompiler
{
    // Enforce In-order Execution of I/O constant for quick comparison
    static constexpr uint32_t c_eieio = 0xAC06007C;
    Image image;
    std::vector<Function> functions;
    std::string out;
    size_t cppFileIndex = 0;
    RecompilerConfig config;

    bool LoadConfig(const std::string_view& configFilePath);

    template<class... Args>
    void print(fmt::format_string<Args...> fmt, Args&&... args)
    {
        fmt::vformat_to(std::back_inserter(out), fmt.get(), fmt::make_format_args(args...));
    }

    template<class... Args>
    void println(fmt::format_string<Args...> fmt, Args&&... args)
    {
        fmt::vformat_to(std::back_inserter(out), fmt.get(), fmt::make_format_args(args...));
        out += '\n';
    }

    void Analyse();


    bool Recompile(
        const Function& fn,
        uint32_t base,
        const x86_insn& insn,
        const uint8_t* data,
        std::unordered_map<uint32_t, RecompilerSwitchTable>::iterator& switchTable,
        RecompilerLocalVariables& localVariables,
        CSRState& csrState, RecompilerFuncConfig &funcConfig);

    bool Recompile(const Function& fn);

    void Recompile(const std::filesystem::path& headerFilePath);

    void SaveCurrentOutData(const std::string_view& name = std::string_view());

    void HandleSseScalarInstruction(const x86_insn& insn,
        const std::function<std::string(size_t)>& xmm,
        const std::function<std::string(const ZydisDecodedOperandMem&)>& decode_memory_operand,
        const char* op_symbol, size_t base);
};
