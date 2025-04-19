#pragma once

#include "pch.h"
#include "recompiler_config.h"
#include "Zydis/DecoderTypes.h"
#include <functional>


struct RecompilerLocalVariables
{
    bool r[8]{};   //General-purpose registers (EAX, EBX, ECX, EDX, ESI, EDI, EBP, ESP)
    bool xmm[16]{}; //SIMD registers (XMM0-XMM15)
    bool flags{};   //EFLAGS register
    bool st[8]{}; //x87 FPU stack registers (ST(0)-ST(7)) - Optional, if x87 is used
    bool temp{};
    bool fs{};
};

struct RecompilerFuncConfig
{
    bool isFS{};
    bool isLastInst{};
    std::string RegisterStackBaseAddr;
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


    bool Recompiler::Recompile(
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

    void Recompiler::HandleSseScalarInstruction(const x86_insn& insn, const std::function<std::string(size_t)>& xmm,
        const std::function<std::string(const ZydisDecodedOperandMem&)>& decode_memory_operand, const char* op_symbol);
};
