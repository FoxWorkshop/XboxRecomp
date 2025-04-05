#include "pch.h"
#include <functional>
#include "recompiler.h"
#include "image.h"
#include <fmt/core.h>
#include <fmt/format.h>
#include <Zydis/Zydis.h>
#include <iostream>
#include <array>
#include <xbe.h>


//will get identified when parsing XBE file.
size_t textBaseAddr = 0x11000;
size_t endHeader = textBaseAddr;

std::string decode_memory_operand_NoParentheses(const ZydisDecodedOperandMem& mem);


inline const char* GetOperandSizeName(uint16_t size)
{
    switch (size) {
    case 8:
        return "U8";
    case 16:
        return "U16";
    case 32:
        return "U32";
    default:
        throw std::runtime_error("Unsupported operand size");
    }
}

namespace std {
    template <typename T, size_t N>
    struct hash<std::array<T, N>> {
        size_t operator()(const std::array<T, N>& arr) const {
            size_t hash_value = 0;
            for (size_t i = 0; i < N; ++i) {
                hash_value ^= std::hash<T>{}(arr[i]) + 0x9e3779b9 + (hash_value << 6) + (hash_value >> 2);
            }
            return hash_value;
        }
    };
}

void Recompiler::HandleSseScalarInstruction(const x86_insn& insn,
    const std::function<std::string(size_t)>& xmm,
    const std::function<std::string(const ZydisDecodedOperandMem&)>& decode_memory_operand,
    const char* op_symbol)
{
    if (insn.insn.operand_count != 2) {
        println("// ERROR: Expected 2 operands");
        return;
    }

    // Validate Operand 0 (must be XMM register)
    if (insn.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
        insn.operands[0].reg.value < ZYDIS_REGISTER_XMM0 ||
        insn.operands[0].reg.value > ZYDIS_REGISTER_XMM7)
    {
        println("// ERROR: Operand 0 is not XMM0-XMM7");
        return;
    }

    const size_t xmm_idx = insn.operands[0].reg.value - ZYDIS_REGISTER_XMM0;
    const std::string dest = fmt::format("ctx.vec[{}].f32[0]", xmm_idx);

    // Handle Operand 1 (XMM or memory)
    std::string src;
    if (insn.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        if (insn.operands[1].reg.value < ZYDIS_REGISTER_XMM0 ||
            insn.operands[1].reg.value > ZYDIS_REGISTER_XMM7) {
            println("// ERROR: Operand 1 is not XMM0-XMM7");
            return;
        }
        src = fmt::format("ctx.vec[{}].f32[0]",
            insn.operands[1].reg.value - ZYDIS_REGISTER_XMM0);
    }
    else if (insn.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
    {
        std::string mem_addr = decode_memory_operand_NoParentheses(insn.operands[1].mem);

        // Ensure memory operand includes ctx reference and proper sub-component
        if (mem_addr.find("ctx.") == std::string::npos)
        {
            if (mem_addr.find("eax") != std::string::npos) {
                mem_addr = "ctx.eax.u32" + mem_addr.substr(3);
            }
            else if (mem_addr.find("ebx") != std::string::npos) {
                mem_addr = "ctx.ebx.u32" + mem_addr.substr(3);
            }
            else if (mem_addr.find("ecx") != std::string::npos) {
                mem_addr = "ctx.ecx.u32" + mem_addr.substr(3);
            }
            else if (mem_addr.find("edx") != std::string::npos) {
                mem_addr = "ctx.edx.u32" + mem_addr.substr(3);
            }
            else if (mem_addr.find("esi") != std::string::npos) {
                mem_addr = "ctx.esi.u32" + mem_addr.substr(3);
            }
            else if (mem_addr.find("edi") != std::string::npos) {
                mem_addr = "ctx.edi.u32" + mem_addr.substr(3);
            }
            else if (mem_addr.find("ebp") != std::string::npos) {
                mem_addr = "ctx.ebp.u32" + mem_addr.substr(3);
            }
            else if (mem_addr.find("esp") != std::string::npos) {
                mem_addr = "ctx.esp.u32" + mem_addr.substr(3);
            }
        }

        src = fmt::format("X86_LOAD_F32({})", mem_addr);
    }
    else {
        println("// ERROR: Operand 1 must be XMM register or memory");
        return;
    }

    // Generate the operation
    println("\t{} {} {};", dest, op_symbol, src);
}

struct ImmWrapper {
    ZydisDecodedOperandImm_ imm;

    friend std::ostream& operator<<(std::ostream& os, const ImmWrapper& wrapper) {
        return os << "0x" << std::hex << wrapper.imm.value.u;
    }
};

// Specialize fmt::formatter for ImmWrapper
template <>
struct fmt::formatter<ImmWrapper> {
    constexpr auto parse(fmt::format_parse_context& ctx) {
        return ctx.begin(); // No format specifiers needed
    }

    template <typename FormatContext>
    auto format(const ImmWrapper& wrapper, FormatContext& ctx) const {
        // Formatting the immediate value
        return fmt::format_to(ctx.out(), "{}", wrapper.imm.value.u);
    }
};


bool Recompiler::LoadConfig(const std::string_view& configFilePath)
{
    printf("Init...\n");
    printf("Loading config file...\n");
    config.Load(configFilePath);

    std::vector<uint8_t> file;

    if (file.empty())
    {
        file = LoadFile((config.directoryPath + config.filePath).c_str());
    }

    image = Image::ParseImage(file.data(), file.size());
    return true;
}

struct jmpInst
{
    size_t instAddr;    // Address of the `jmp` instruction
    size_t targetAddr;  // Destination address
    bool isExternal;    // Initially false; resolved later
};


bool isCodeSection(const size_t addr, const std::set<Section, SectionComparer>& sections)
{
    for (const auto& section : sections)
    {
        if (addr >= section.base && addr <= section.size + section.base)
        {
            return (section.flags & SectionFlags_Code);
        }
    }

    return false;
}


Section GetSectionPerName(const std::set<Section, SectionComparer>& sections, std::string name)
{
    for (const auto& section : sections)
    {
        if (section.name == name)
        {
            return section;
        }
    }

    // If not found, return an empty section
    return { "", NULL, 0, (SectionFlags)0, 0 };
}


void ExtractFunctionsAddresses(const Section& rdata_section, const Section& text_section, std::vector<size_t>* funcsTable, std::vector<size_t>& out, std::unordered_set<size_t>& dupliCheck)
{
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    ZydisDecodedInstruction instruction;

    for (auto& func : *funcsTable)
    {
        uint32_t func_ptr = func;

        // Calculate the offset within the .rdata section
        uint8_t* funcTable_data = rdata_section.data + (func_ptr - rdata_section.base);
        uint8_t* vftable_end = rdata_section.data + rdata_section.size;


        // Extract function pointers from the vftable / func arrays
        while (funcTable_data + sizeof(uint32_t) <= vftable_end)
        {
            uint32_t potential_func;
            memcpy(&potential_func, funcTable_data, sizeof(uint32_t));

            if (dupliCheck.count(potential_func) == 0 && potential_func >= text_section.base && potential_func < text_section.base + text_section.size)
            {
                //function in .text section tend to end with 0
                if ((potential_func & 0xF) != 0)
                {
                    break;
                }

                uint8_t* func_start = text_section.data + (potential_func - text_section.base);


                if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, func_start, text_section.size, &instruction, operands)))
                {
                    if (1)
                        out.push_back(potential_func);

                    dupliCheck.insert(potential_func);
                    funcTable_data += sizeof(uint32_t);

                }

            }
            else {
                // End 
                break;
            }

        }
    }
}

bool IsPossibleFunctionPointer(uint32_t address, const Image& image) {
    for (const auto& section : image.sections) {
        if (section.flags & SectionFlags_Code)
        {
            if (address >= section.base && address < section.base + section.size)
                return (address & 0xF) == 0x0;
        }
    }
    return false;
}


void CheckForVftableRef(ZydisDecodedInstruction instruction, ZydisDecodedOperand_* operands, std::unordered_set<size_t>& duplicateCheck, std::vector<size_t>& vftables, const Image& image)
{
    bool isPush = instruction.mnemonic == ZYDIS_MNEMONIC_PUSH;
    bool isMov = instruction.mnemonic == ZYDIS_MNEMONIC_MOV;

    if (isMov || isPush)
    {
        uint32_t vftable_pointer = 0;

        if (isPush && instruction.operand_count >= 1 && operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
        {
            vftable_pointer = static_cast<uint32_t>(operands[0].imm.value.u);
        }

        if (isMov && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
        {
            vftable_pointer = static_cast<uint32_t>(operands[1].imm.value.u);
        }

        if (vftable_pointer < image.base)
            return;

        // 1. Check alignment (VFTables are typically 4-byte aligned)
        if ((vftable_pointer & 0x3) != 0)
        {
            return;
        }


        //Check if the vftable pointer is within the .rdata section
        for (const auto& data_section : image.sections)
        {
            if (data_section.flags & SectionFlags_Data &&
                vftable_pointer >= data_section.base &&
                vftable_pointer < data_section.base + data_section.size)
            {

                if (duplicateCheck.count(vftable_pointer) == 0)
                {
                    //store first vftable ref address.
                    //note this will also store false positive address, but those will be resolved when extracting function address after.
                    vftables.push_back(vftable_pointer);
                    duplicateCheck.insert(vftable_pointer);
                }

                break;
            }
        }

    }
}

bool IsSuspiciousAddress(uint32_t address) {
    // Check for small or unaligned addresses
    if (address < 0x1000 || (address & 0x3) != 0) {
        return true;
    }
    return false;
}

void CheckForFunctionPtrRef(std::ofstream& outfileFunc, ZydisDecoder decoder, ZydisDecodedInstruction instruction, ZydisDecodedOperand_* operands, std::unordered_set<size_t>& duplicateCheck, std::vector<size_t>& extraFuncPtr, Section section, const Image& image)
{
    //we don't check for push instruction because it's too generic and grab a lot of false positive
    //it also only get SEH type function (at least for Shadow) so it's not really worth
    bool isMov = instruction.mnemonic == ZYDIS_MNEMONIC_MOV;
    bool isLea = instruction.mnemonic == ZYDIS_MNEMONIC_LEA;

    if (isMov || isLea)
    {
        uint32_t function_address = 0;

        if (isLea)
        {
            if (instruction.operand_count >= 2 &&
                operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                //Case 1: Direct function address loading (lea reg, offset)
                if (operands[1].mem.base == ZYDIS_REGISTER_NONE &&
                    operands[1].mem.index == ZYDIS_REGISTER_NONE)
                {
                    function_address = static_cast<uint32_t>(operands[1].mem.disp.value);
                }
                else if (operands[1].mem.index != ZYDIS_REGISTER_NONE && operands[1].mem.scale == 4)
                {
                    //Case 2: Indexed memory access (lea reg, [base + index*scale + disp])
                    function_address = static_cast<uint32_t>(operands[1].mem.disp.value);
                }
            }
        }

        if (isMov)
        {
            // Handle `mov reg, offset <function>`
            if (instruction.operand_count >= 2 &&
                operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                function_address = static_cast<uint32_t>(operands[1].imm.value.u);
            }

            // Handle `mov [mem], offset <function>`
            if (instruction.operand_count >= 2 &&
                operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                function_address = static_cast<uint32_t>(operands[1].imm.value.u);
            }

            // MOV Case 3: Indexed Memory Access (mov [base + index*scale], function)
            if (instruction.operand_count >= 2 && operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && operands[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                if (operands[0].mem.index != ZYDIS_REGISTER_NONE && operands[0].mem.scale == 4)
                {
                    function_address = static_cast<uint32_t>(operands[0].mem.disp.value);
                }
            }
        }

        if (function_address < image.base || function_address >= endHeader || !isCodeSection(function_address, image.sections) || IsSuspiciousAddress(function_address))
            return;

        auto code = section.data + (function_address - section.base);
        auto size = section.base + section.size - function_address;

        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, code, size, &instruction, operands)))
        {
            function_address = function_address;
            return;
        }


        if (duplicateCheck.count(function_address) == 0)
        {
            extraFuncPtr.push_back(function_address);
            outfileFunc << std::hex << function_address << std::endl;
            duplicateCheck.insert(function_address);
        }
    }
}

bool isNextBytesRet(uint8_t* data)
{
    for (int i = 0; i < 4; i++)
    {
        if (data[i] == 0xC3 || data[i] == 0xC2 && data[i + 2] == 00)
            return true;
    }

    return false;
}


bool isRetFunc(uint8_t* data, const uint32_t i)
{
    if (i < 16) //prevent crash if used on very first instruction and function
        return false;

    return data[-1] == 0xC3 || data[-1] == 0xC2 && data[-3] == 0x0;
}

size_t getLastAddress(const Image& image) {
    size_t lastAddress = 0;

    for (const auto& section : image.sections)
    {
        size_t sectionEnd = section.base + section.size;

        if (sectionEnd > lastAddress)
            lastAddress = sectionEnd;

    }

    return lastAddress - 10;
}



bool isPadding(uint8_t* data, const uint32_t i)
{
    if (i < 16) //prevent crash if used on very first instruction and function
        return false;

    bool isValid = false;
    for (int i = 0; i > -3; i--)
    {
        isValid = data[i] == 0xCC;
    }

    if (isValid == false)
    {
        for (int i = 0; i > -3; i--)
        {
            isValid = data[i] == 0x90;
        }
    }

    return isValid;
}

void CheckTailJmp(const Image& image, std::unordered_set<size_t>& duplicateCheck, std::vector<size_t>& funcsTable)
{

    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    for (const auto& section : image.sections)
    {
        bool isCode = (section.flags & SectionFlags_Code);

        if (!isCode)
            continue;

        size_t headerSectionBase = section.base;
        uint8_t* headerSectionData = section.data;
        uint8_t* headerSectionDataEnd = section.data + section.size;

        while (headerSectionData < headerSectionDataEnd)
        {
            // Disassemble x86 instruction
            ZydisDecodedInstruction instruction;
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, headerSectionData, headerSectionDataEnd - headerSectionData, &instruction, operands))) {
                headerSectionData++; // Skip invalid instruction
                continue;
            }

            const bool isJmp = instruction.mnemonic == ZYDIS_MNEMONIC_JMP;

            if (isJmp)
            {
                size_t jmpTargetAddress = 0;

                if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                {
                    int32_t imm = (int32_t)operands[0].imm.value.s;
                    jmpTargetAddress = headerSectionBase + (headerSectionData - section.data) + instruction.length + imm;
                    size_t instAddr = headerSectionBase + (headerSectionData - section.data);

                    if (duplicateCheck.count(jmpTargetAddress))
                    {
                        headerSectionData += instruction.length;
                        continue;
                    }

                    // Check if the target address is within the current section
                    if (isCodeSection(jmpTargetAddress, image.sections) &&
                        image.symbols.find(jmpTargetAddress) == image.symbols.end())
                    {
                        for (size_t i = 0; i < funcsTable.size() - 1; i++)
                        {
                            if (duplicateCheck.count(jmpTargetAddress) != 0)
                                break;

                            if (instAddr >= funcsTable[i] && instAddr < funcsTable[i + 1])
                            {
                                if (jmpTargetAddress >= funcsTable[i + 1] || jmpTargetAddress < funcsTable[i])
                                {
                                    auto nextData = headerSectionData + instruction.length;
                                    if (isNextBytesRet(nextData) == false)
                                    {
                                        funcsTable.push_back(jmpTargetAddress);
                                        duplicateCheck.insert(jmpTargetAddress);
                                    }
                                }
                            }
                        }
                    }

                }
            }

            headerSectionData += instruction.length;
        }
    }
}

bool isAddressRangeBanned(std::unordered_map<uint32_t, uint32_t>* banned, uint32_t addr)
{
    for (auto& ban : *banned)
    {
        if (addr >= ban.first && addr <= ban.second)
        {
            return true;
        }
    }

    return false;
}

void ProcessEntryPoint(const Image& image, const Section section, std::vector<size_t>& funcsTable, std::unordered_set<size_t>& duplicateCheck)
{
    funcsTable.push_back(image.entry_point);
    duplicateCheck.insert(image.entry_point);

    auto* data = static_cast<const uint8_t*>(image.Find(image.entry_point));
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
    ZydisDecodedInstruction insn;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    size_t addr = image.entry_point;


    // Process code sections to identify functions
    size_t headerSectionBase = section.base;
    uint8_t* headerSectionDataEnd = section.data + section.size;
    size_t offset = addr - image.entry_point;
    while (data + offset < headerSectionDataEnd)
    {

        //failsafe but shouldn't be needed
        if (addr > image.entry_point + 0x1000)
            break;

        offset = addr - image.entry_point;
        ZydisDecodedInstruction instruction;
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, data + offset, headerSectionDataEnd - data, &instruction, operands)))
        {
            addr++;
            continue;
        }

        const bool isCall = instruction.mnemonic == ZYDIS_MNEMONIC_CALL;
        const bool isDone = instruction.mnemonic == ZYDIS_MNEMONIC_NOT || instruction.mnemonic == ZYDIS_MNEMONIC_RET;

        if (isDone)
        {
            break;
        }

        if (isCall)
        {
            size_t target_address = 0;

            if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                int32_t imm = (int32_t)operands[0].imm.value.s;
                target_address = headerSectionBase + (data + offset - section.data) + instruction.length + imm;

                if (duplicateCheck.count(target_address))
                {
                    addr += instruction.length;
                    continue;
                }

                // Check if the target address is within the current section
                if (isCodeSection(target_address, image.sections) &&
                    image.symbols.find(target_address) == image.symbols.end())
                {
                    funcsTable.push_back(target_address);
                    duplicateCheck.insert(target_address);
                }
            }
        }

        addr += instruction.length;
    }
}


void Recompiler::Analyse()
{

    auto data = GetSectionPerName(image.sections, ".data");
    auto rdata = GetSectionPerName(image.sections, ".rdata");
    auto text = GetSectionPerName(image.sections, ".text");


    if (text.name == "")
    {
        //handle error;
        exit(-1);
        return;
    }


    printf("\nSearching for functions...\n");

    std::unordered_set<size_t> duplicateCheck;
    std::vector<size_t> vftablesRef, funcArrayRef, funcsTable; //used to detect virtual function, array of function pointer and functions from "push" and "mov" instruction


    // Process manual functions from config (if any)
    for (auto& [address, size] : config.functions)
    {
        functions.emplace_back(address, size);
        image.symbols.emplace(fmt::format("sub_{:X}", address), address, size, Symbol_Function);
        duplicateCheck.insert(address);
    }


    ProcessEntryPoint(image, text, funcsTable, duplicateCheck);

    textBaseAddr = text.base;
    endHeader = getLastAddress(image);
    // Initialize Zydis decoder for x86
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    std::ofstream outfileFunc("functions.txt");



    // Process code sections to identify functions
    for (const auto& section : image.sections)
    {
        bool isCode = (section.flags & SectionFlags_Code);

        if (!isCode)
            continue;

        size_t headerSectionBase = section.base;
        uint8_t* headerSectionData = section.data;
        uint8_t* headerSectionDataEnd = section.data + section.size;

        while (headerSectionData < headerSectionDataEnd)
        {

            ZydisDecodedInstruction instruction;
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, headerSectionData, headerSectionDataEnd - headerSectionData, &instruction, operands)))
            {
                headerSectionData++;
                continue;
            }

            //Check for call instructions
            const bool isCall = instruction.mnemonic == ZYDIS_MNEMONIC_CALL;
            auto nextData = headerSectionData + instruction.length;
            const bool isRet = nextData[0] == 0xC3 || nextData[0] == 0xC2;

            if (isCall)
            {
                size_t target_address = 0;

                if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                {
                    int32_t imm = (int32_t)operands[0].imm.value.s;
                    target_address = headerSectionBase + (headerSectionData - section.data) + instruction.length + imm;
                    size_t instAddr = headerSectionBase + (headerSectionData - section.data);

                    if (duplicateCheck.count(target_address))
                    {
                        headerSectionData += instruction.length;
                        continue;
                    }


                    // Check if the target address is within the current section
                    if (isCodeSection(target_address, image.sections) &&
                        image.symbols.find(target_address) == image.symbols.end())
                    {
                        funcsTable.push_back(target_address);
                        duplicateCheck.insert(target_address);
                    }


                }
                else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
                {
                    // Handle indirect jumps/calls (e.g., "jmp [eax]" or "call [ebx+4]")
                    // For now, we'll skip these since we can't resolve the target address statically.
                    // Will need logic to handle these dynamically during recompilation

                    const auto& op = operands[0];
                    size_t baseAddress = headerSectionBase + (headerSectionData - section.data);
                    size_t tableAddress = op.mem.disp.value;

                    // Detect function pointer array (e.g., funcs_3DA8D[eax*4])
                    if (op.mem.scale == 4 && op.mem.disp.size > 0)
                    {
                        for (const auto& data_section : image.sections)
                        {

                            if (data_section.flags & SectionFlags_Data &&
                                tableAddress >= data_section.base &&
                                tableAddress < data_section.base + data_section.size)
                            {

                                if (duplicateCheck.count(tableAddress) == 0)
                                {
                                    //store potential function array ref address.
                                    //note this will also store false positive address, but those will be resolved when extracting function address after.
                                    funcArrayRef.push_back(tableAddress);
                                    duplicateCheck.insert(tableAddress);
                                }
                                break;
                            }
                        }
                    }

                    headerSectionData += instruction.length;
                    continue;
                }
            }

            /** if (isRet == false)
                 CheckForFunctionPtrRef(outfileFuncPush, decoder, instruction, operands, duplicateCheck, funcsTable, section, image);*/

            CheckForVftableRef(instruction, operands, duplicateCheck, vftablesRef, image);

            headerSectionData += instruction.length;
        }
    }


    // Sort func ref address by base address
    std::sort(funcsTable.begin(), funcsTable.end());
    std::sort(vftablesRef.begin(), vftablesRef.end());

    ExtractFunctionsAddresses(rdata, text, &vftablesRef, funcsTable, duplicateCheck);

    ExtractFunctionsAddresses(data, text, &funcArrayRef, funcsTable, duplicateCheck);

    //final pass, browse manually to find any missed functions
    for (const auto& section : image.sections)
    {
        bool isCode = (section.flags & SectionFlags_Code);

        if (!isCode)
            continue;

        uint8_t* data = section.data;
        size_t size = section.base + section.size;

        const size_t ALIGNMENT = 16;
        size_t i = 0;
        for (; i < size; i += ALIGNMENT)
        {
            uint32_t currentAddr = section.base + i;


            if (duplicateCheck.count(currentAddr))
                continue;

            if (currentAddr > size)
                break;

            auto code = section.data + (currentAddr - section.base);
            if (!i || isPadding(data, i))
            {
                currentAddr = section.base + i;

                if (currentAddr >= section.base && currentAddr < section.base + section.size &&
                    image.symbols.find(currentAddr) == image.symbols.end())
                {
                    if (duplicateCheck.count(currentAddr) == 0)
                    {
                        funcsTable.push_back(currentAddr);
                        duplicateCheck.insert(currentAddr);
                    }

                }
            }
        }
    }


    CheckTailJmp(image, duplicateCheck, funcsTable);
    std::stable_sort(funcsTable.begin(), funcsTable.end());

    printf("Now analysing functions please wait...\n");

    //finally, analyse all functions that we found to extract their block data and prepare recompilation.
    for (int i = 0; i < funcsTable.size(); i++)
    {
        for (const auto& section : image.sections)
        {
            bool isCode = (section.flags & SectionFlags_Code);

            if (!isCode)
                continue;

            auto funcPtr = funcsTable[i];
            if (funcPtr >= section.base && funcPtr < section.base + section.size && image.symbols.find(funcPtr) == image.symbols.end())
            {

                auto code = section.data + (funcPtr - section.base);
                auto size = section.base + section.size - funcPtr;
                auto potentialSize = size;

                if (i + 1 < funcsTable.size())
                    potentialSize = (funcsTable[i + 1] - funcPtr) + funcPtr;

                bool banned = isAddressRangeBanned(&config.bannedAddresses, funcPtr);

                if (banned)
                    continue;

                auto invalidInstr = config.invalidInstructions.find(funcPtr);
                if (invalidInstr != config.invalidInstructions.end())
                {
                    continue;
                }

                auto& fn = functions.emplace_back(Function::Analyze(code, potentialSize, funcPtr, config.switchTables));
                image.symbols.emplace(fmt::format("sub_{:X}", fn.base), fn.base, fn.size, Symbol_Function);
            }
        }

    }

    std::sort(functions.begin(), functions.end(), [](auto& lhs, auto& rhs) { return lhs.base < rhs.base; });
    //std::sort(globalJumps.begin(), globalJumps.end(), [](auto& lhs, auto& rhs) { return lhs.instAddr < rhs.instAddr; });

    functions.erase(std::unique(functions.begin(), functions.end()), functions.end());
    printf("Analysed %d functions.\n", functions.size());

    for (auto& fn : functions)
    {
        outfileFunc << std::hex << fn.base << std::endl;
    }

    outfileFunc.close();
}

uint32_t getOperandValue(const ZydisDecodedOperand& operand)
{
    switch (operand.type)
    {
    case ZYDIS_OPERAND_TYPE_IMMEDIATE:
        return static_cast<uint32_t>(operand.imm.value.u);
    default:
        return 0; // Unsupported operand type
    }
}

std::string decode_memory_operand(const ZydisDecodedOperandMem& mem)
{
    std::string result;

    // Base register (e.g., ESP, EBP)
    if (mem.base != ZYDIS_REGISTER_NONE)
    {
        result += ZydisRegisterGetString(mem.base); // e.g., "esp"
    }

    // Index register (e.g., ESI in [EAX+ESI*4])
    if (mem.index != ZYDIS_REGISTER_NONE) {
        if (!result.empty()) result += " + ";
        result += ZydisRegisterGetString(mem.index); // e.g., "esi"
        if (mem.scale != 1) {
            result += " * " + std::to_string(mem.scale); // e.g., " * 4"
        }
    }

    // Displacement (e.g., +0x40, -0x34)
    if (mem.disp.value != 0) {
        if (!result.empty()) {
            result += (mem.disp.value > 0) ? " + " : " - ";
            result += "0x" + std::to_string(abs(mem.disp.value));
        }
        else {
            result += "0x" + std::to_string(mem.disp.value);
        }
    }

    // Handle cases like [EAX] (no displacement)
    if (result.empty())
        result = "0";

    return "(" + result + ")";
}

std::string get_register_name(ZydisRegister reg) {

    switch (reg)
    {
    case ZYDIS_REGISTER_EAX:
        return "eax";
    case ZYDIS_REGISTER_EBX:
        return "ebx";
    case ZYDIS_REGISTER_ECX:
        return "ecx";
    case ZYDIS_REGISTER_EDX:
        return "edx";
    case ZYDIS_REGISTER_ESI:
        return "esi";
    case ZYDIS_REGISTER_EDI:
        return "edi";
    case ZYDIS_REGISTER_EBP:
        return "ebp";
    case ZYDIS_REGISTER_ESP:
        return "esp";

    default: throw std::runtime_error("Unsupported register");
    }
}

std::string decode_memory_operand_NoParentheses(const ZydisDecodedOperandMem& mem) {
    std::string result;

    // Base register
    if (mem.base != ZYDIS_REGISTER_NONE)
        result += fmt::format("ctx.{}.u32", get_register_name(mem.base));


    // Index register with scale
    if (mem.index != ZYDIS_REGISTER_NONE)
    {
        if (!result.empty()) result += " + ";
        result += fmt::format("ctx.{}.u32", get_register_name(mem.index));
        if (mem.scale > 1) {
            result += " * " + std::to_string(mem.scale);
        }
    }

    // Displacement
    if (mem.disp.value != 0) {
        if (!result.empty()) {
            result += (mem.disp.value > 0) ? " + " : " - ";
            result += std::to_string(abs(mem.disp.value));
        }
        else {
            result += std::to_string(mem.disp.value);
        }
    }

    return result.empty() ? "0" : result;
}


bool Recompiler::Recompile(
    const Function& fn,
    uint32_t base,
    const x86_insn& insn,
    const uint8_t* data,
    std::unordered_map<uint32_t, RecompilerSwitchTable>::iterator& switchTable,
    RecompilerLocalVariables& localVariables,
    CSRState& csrState)
{

    char buffer[256];
    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    ZydisFormatterFormatInstruction(&formatter, &insn.insn, insn.operands, insn.insn.operand_count, buffer, sizeof(buffer), base, &data);

    println("\t// {}", buffer);


    //println("\t// {} {}", , insn.op_str);

    auto get_x86_reg = [&](ZydisRegister reg, bool isFloat = false, bool with_size = true, bool for_address = false) -> std::string
        {

            if (isFloat)
            {
                // Handle XMM registers (OG Xbox only uses XMM0-XMM7)
                if (reg >= ZYDIS_REGISTER_XMM0 && reg <= ZYDIS_REGISTER_XMM7)
                {
                    return fmt::format("ctx.xmm[{}]", reg - ZYDIS_REGISTER_XMM0);
                }
                // Handle x87 FPU stack
                if (reg >= ZYDIS_REGISTER_ST0 && reg <= ZYDIS_REGISTER_ST7)
                {
                    return fmt::format("ctx.fpu.st{}()", reg - ZYDIS_REGISTER_ST0);
                }
                // Handle control registers
                if (reg == ZYDIS_REGISTER_MXCSR)
                {
                    return "ctx.mxcsr";
                }

                throw std::runtime_error("Unsupported FP/SIMD register");
            }

            //Handle segment registers
            if (reg >= ZYDIS_REGISTER_ES && reg <= ZYDIS_REGISTER_GS) {
                static constexpr std::array<const char*, 6> seg_names = {
                    "es", "cs", "ss", "ds", "fs", "gs"
                };
                return fmt::format("ctx.{}", seg_names[reg - ZYDIS_REGISTER_ES]);
            }
            const char* reg_name = nullptr;
            const char* suffix = "";

            const ZydisRegisterClass reg_class = ZydisRegisterGetClass(reg);
            const ZydisRegister parent_reg = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_COMPAT_32, reg);

            // Special handling for ESP/EBP/ESI/EDI first
            switch (parent_reg)
            {
            case ZYDIS_REGISTER_ESP: reg_name = "esp"; break;
            case ZYDIS_REGISTER_EBP: reg_name = "ebp"; break;
            case ZYDIS_REGISTER_ESI: reg_name = "esi"; break;
            case ZYDIS_REGISTER_EDI: reg_name = "edi"; break;
            case ZYDIS_REGISTER_EAX: reg_name = "eax"; break;
            case ZYDIS_REGISTER_EBX: reg_name = "ebx"; break;
            case ZYDIS_REGISTER_ECX: reg_name = "ecx"; break;
            case ZYDIS_REGISTER_EDX: reg_name = "edx"; break;
            default:
                throw std::runtime_error(fmt::format("Unsupported base register: {}", ZydisRegisterGetString(parent_reg)));
            }

            if (for_address) {
                return fmt::format("ctx.{}.u32", reg_name);
            }

            if (!with_size)
                return fmt::format("ctx.{}", reg_name);

            // Handle sub-registers
            switch (ZydisRegisterGetWidth(ZYDIS_MACHINE_MODE_LONG_COMPAT_32, reg))
            {
            case 8:
                return reg >= ZYDIS_REGISTER_AH ? fmt::format("ctx.{}.u8_hi", reg_name) : fmt::format("ctx.{}.u8_lo", reg_name);
            case 16:
                return fmt::format("ctx.{}.u16", reg_name);
            case 32:
                return fmt::format("ctx.{}.u32", reg_name);
            default: throw std::runtime_error("Unsupported size");
            }

            // Special case: EIP/RIP needs different handling
            if (reg == ZYDIS_REGISTER_EIP || reg == ZYDIS_REGISTER_RIP) {
                return "ctx.eip";
            }

            return fmt::format("ctx.{}{}", reg_name, suffix);
        };

    auto GetJmpTableRegister = [&](size_t index) {
        static constexpr std::array<const char*, 8> reg_names =
        {
            "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"
        };

        if (index >= reg_names.size())
        {
            throw std::runtime_error("Invalid x86 register index");
        }


        return fmt::format("ctx.{}", reg_names[index]);
        };



    // SIMD registers (XMM0-XMM7)
    auto xmm = [&](size_t index) {
        if (index >= 8) {
            throw std::out_of_range("Invalid XMM index");
        }

        if (config.floatingPointRegistersAsLocalVariables) {
            localVariables.xmm[index] = true;
            return fmt::format("xmm[{}]", index);
        }
        return fmt::format("ctx.xmm[{}]", index);
        };

    auto ea = [&](const ZydisDecodedOperand& memOp, bool address_mode = false) -> std::string {
        std::string result;

        // Helper to get address-ready register string (always .u32)
        auto get_addr_reg = [&](ZydisRegister reg) -> std::string {
            switch (ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_COMPAT_32, reg)) {
            case ZYDIS_REGISTER_EAX:
                return "ctx.eax.u32";
            case ZYDIS_REGISTER_EBX:
                return "ctx.ebx.u32";
            case ZYDIS_REGISTER_ECX:
                return "ctx.ecx.u32";
            case ZYDIS_REGISTER_EDX:
                return "ctx.edx.u32";
            case ZYDIS_REGISTER_ESI:
                return "ctx.esi.u32";
            case ZYDIS_REGISTER_EDI:
                return "ctx.edi.u32";
            case ZYDIS_REGISTER_EBP:
                return "ctx.ebp.u32";
            case ZYDIS_REGISTER_ESP:
                return "ctx.esp.u32";

            default: throw std::runtime_error("Unsupported address register");
            }
            };

        // Add base register (if present)
        if (memOp.mem.base != ZYDIS_REGISTER_NONE)
            result += get_addr_reg(memOp.mem.base);

        // Add index register (if present)
        if (memOp.mem.index != ZYDIS_REGISTER_NONE)
        {
            if (!result.empty()) result += " + ";
            result += get_addr_reg(memOp.mem.index);
            if (memOp.mem.scale > 1) {
                result += " * " + std::to_string(memOp.mem.scale);
            }
        }

        // Add displacement
        if (memOp.mem.disp.value != 0)
        {
            if (!result.empty()) {
                result += (memOp.mem.disp.value > 0) ? " + " : " - ";
                result += std::to_string(abs(memOp.mem.disp.value));
            }
            else {
                result = std::to_string(memOp.mem.disp.value);
            }
        }

        return result.empty() ? "0" : result;
        };



    auto eflags = [&]() {
        return "ctx.eflags";
        };


    auto printSetFlushMode = [&](bool enable)
        {
            auto newState = enable ? CSRState::SSE : CSRState::FPU;
            if (csrState != newState) {
                if (newState == CSRState::SSE) {
                    // Enable flush-to-zero for SSE/AVX (MXCSR)
                    println("\t_mm_setcsr(_mm_getcsr() | 0x8000); // Set flush-to-zero bit in MXCSR");
                }
                else {
                    // Enable flush-to-zero for x87 FPU
                    println("\t_controlfp(_controlfp(0, 0) | 0x8000, 0xFFFF); // Set flush-to-zero bit in x87 control word");
                }

                csrState = newState;
            }
        };

    auto HandleFsValue = [&](uint8_t offset, std::string reg)
        {
            switch (offset)
            {
            case 0x20:
                println("\t{} = GetCurrentThreadId(ctx, base);", reg);
                break;
            case 0x24:
                println("\t{} = GetXboxThreadFlags(ctx, base);", reg);
                break;
            case 0x28:
                println("\t{} = GetActiveRpcHandle(ctx, base);", reg);
                break;
            default:
                println("\t{} = 0; //Unknown FS offset: 0x{:X}", reg, offset);
                break;
            }
        };


    auto printFunctionCallAddr = [&](uint32_t address)
        {

            auto targetSymbol = image.symbols.find(address & 0xFFFFFFFF);

            if (targetSymbol != image.symbols.end() && targetSymbol->address == address && targetSymbol->type == Symbol_Function)
            {
                if (config.nonVolatileRegistersAsLocalVariables && (targetSymbol->name.find("__rest") == 0 || targetSymbol->name.find("__save") == 0))
                {
                    // Skip non-volatile register save/restore functions
                }
                else {
                    // Call the function directly
                    println("\t{}(ctx, base);", targetSymbol->name);
                }
            }
            else {
                // Log an error for unknown functions
                println("\t// ERROR: Unknown function at 0x{:X}", address);
            }

        };



    auto printConditionalBranch = [&](bool not_, const std::string_view& cond, uint32_t base, const x86_insn& insn) {
        uint32_t targetAddress = base + insn.insn.length;


        if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
        {
            targetAddress += insn.operands[0].imm.value.s;  // Signed displacement
        }
        else if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
            insn.operands[0].mem.disp.value) {
            targetAddress += insn.operands[0].mem.disp.value;
        }


        // Always use hex for addresses
        std::string targetStr = fmt::format("0x{:X}", targetAddress);

        if (targetAddress == 0)
        {
            println("\t// WARNING: Branch target resolves to 0x0 (possible analysis error)");
            println("\tif ({}{}) goto invalid_target;", not_ ? "!" : "", cond);
        }
        else if (targetAddress < fn.base || targetAddress >= fn.base + fn.size)
        {
            // External function call
            println("\tif ({}{}) {{", not_ ? "!" : "", cond);
            printFunctionCallAddr(targetAddress);
            println("\t}}");
        }
        else
        {
            if (targetAddress == fn.base)
            {
                printFunctionCallAddr(targetAddress);
                println("\treturn;");
            }
            else
            {
                // Internal jump
                println("\tif ({}{}) goto loc_{:X};",
                    not_ ? "!" : "", cond, targetAddress);
            }
        }
        };

    auto compare_and_pop = [&](const std::string& rhs) {
        println("\tctx.fpu.sw &= ~(X87FPU::C0 | X87FPU::C1 | X87FPU::C2 | X87FPU::C3);");
        println("\tif (std::isnan(ctx.fpu.st0()) || std::isnan({})) {{", rhs);
        println("\t\tctx.fpu.sw |= X87FPU::C0 | X87FPU::C2 | X87FPU::C3;");
        println("\t}} else if (ctx.fpu.st0() < {}) {{", rhs);
        println("\t\tctx.fpu.sw |= X87FPU::C0;");
        println("\t}} else if (ctx.fpu.st0() > {}) {{", rhs);
        println("\t\tctx.fpu.sw &= ~X87FPU::C0;");
        println("\t}} else {{ // equal");
        println("\t\tctx.fpu.sw |= X87FPU::C3;");
        println("\t}}");
        println("\tctx.fpu.pop();");
        };


    // Handle x86 instructions
    switch (insn.insn.mnemonic)
    {
    case ZYDIS_MNEMONIC_AAA:
        println("\tif ((ctx.eax.u8_lo > 9) || (ctx.eflags.value & X86EFlags::AF)) {{");
        println("\t    ctx.eax.u8_lo += 6;");
        println("\t    ctx.eax.u8_hi += 1;");
        println("\t    ctx.eflags.value |= X86EFlags::AF | X86EFlags::CF;");
        println("\t}} else {{");
        println("\t    ctx.eflags.value &= ~(X86EFlags::AF | X86EFlags::CF);");
        println("\t}}");
        println("\tctx.eax.u8_lo &= 0x0F;");
        break;
    case ZYDIS_MNEMONIC_PUSH:

        //xbox kernel stuff
        if (insn.operands[0].mem.segment == ZYDIS_REGISTER_FS) 
        {
            uint32_t offset = insn.operands[0].mem.disp.value;
            println("\t// PUSH FS:[0x{:X}]", offset);
            HandleFsValue(offset, "tmp_value"); 
            println("\tX86_PUSH(ctx, base, tmp_value);");
            break;
        }

        if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {

            //PUSH reg
            println("\tX86_PUSH(ctx, base, {});", get_x86_reg(insn.operands[0].reg.value));
        }
        else if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
        {
            //PUSH imm
            ImmWrapper immWrapper{ insn.operands[0].imm }; // Wrap the immediate value
            uint32_t imm_value = static_cast<uint32_t>(insn.operands[0].imm.value.u);
            println("\tX86_PUSH(ctx, base, 0x{:X});", imm_value);
        }
        else if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            //PUSH [mem]
            println("\tX86_PUSH(ctx, base, X86_LOAD_{}({}));",
                GetOperandSizeName(insn.operands[0].size),
                ea(insn.operands[0]));
        }

        break;
    case ZYDIS_MNEMONIC_MOV:
        if (insn.insn.operand_count >= 2) 
        {
            const auto& dst = insn.operands[0];
            const auto& src = insn.operands[1];
            const char* sizeSuffix = GetOperandSizeName(dst.size);

            //handle FS register (kernel and xbox memory stuff, e.g "FS:[0x20]")
            if (src.type == ZYDIS_OPERAND_TYPE_MEMORY && src.mem.segment == ZYDIS_REGISTER_FS) 
            {
                uint32_t offset = src.mem.disp.value;
                println("\t//FS read at offset 0x{:X}", offset);
                HandleFsValue(offset, get_x86_reg(dst.reg.value));
                break;
            }

            // MOV reg, imm
            if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) 
            {
                println("\t{} = {};",
                    get_x86_reg(dst.reg.value),  // Automatically includes .u8/.u16/.u32
                    src.imm.value.u);
            }
            // MOV reg, reg
            else if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                src.type == ZYDIS_OPERAND_TYPE_REGISTER) 
            {
                println("\t{} = {};",
                    get_x86_reg(dst.reg.value),
                    get_x86_reg(src.reg.value));
            }
            // MOV reg, [mem]
            else if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                src.type == ZYDIS_OPERAND_TYPE_MEMORY) 
            {
                println("\t{} = X86_LOAD_{}({});",
                    get_x86_reg(dst.reg.value),
                    sizeSuffix,
                    ea(src, true));
            }
            // MOV [mem], reg
            else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                src.type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                println("\tX86_STORE_{}({}, {});",
                    sizeSuffix,
                    ea(dst, true),
                    get_x86_reg(src.reg.value));
            }
            // MOV [mem], imm
            else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                println("\tX86_STORE_{}({}, {});",
                    sizeSuffix,
                    ea(dst, true),
                    src.imm.value.u);
            }
        }
        break;
    case ZYDIS_MNEMONIC_MOVSX:

        if (insn.insn.operand_count >= 2)
        {
            const auto& dst = insn.operands[0];
            const auto& src = insn.operands[1];
            const char* srcSizeSuffix = GetOperandSizeName(src.size);
            const char* dstSizeSuffix = GetOperandSizeName(dst.size);

            //handle FS register (kernel and xbox memory stuff, e.g "FS:[0x20]")
            if (src.type == ZYDIS_OPERAND_TYPE_MEMORY && src.mem.segment == ZYDIS_REGISTER_FS)
            {
                uint32_t offset = src.mem.disp.value;
                println("\t// Sign-extended FS read at offset 0x{:X}", offset);
                std::string tempVar = "tmp_value_" + std::to_string(base);
                HandleFsValue(offset, tempVar);
                println("\t{} = static_cast<{}>(tmp_value);", get_x86_reg(dst.reg.value), (dst.size == 16) ? "int16_t" : "int32_t");
                break;
            }

            if (src.type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                //Handle sign extension from smaller to larger register
                if (src.size == 8) {
                    println("\t{} = static_cast<{}>(static_cast<int8_t>({}));",
                        get_x86_reg(dst.reg.value),
                        (dst.size == 16) ? "int16_t" : "int32_t",  // destination type
                        get_x86_reg(src.reg.value));
                }
                else if (src.size == 16) {
                    println("\t{} = static_cast<int32_t>(static_cast<int16_t>({}));",
                        get_x86_reg(dst.reg.value),
                        get_x86_reg(src.reg.value));
                }
            }
            else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                //Handle memory source with sign extension
                if (src.size == 8) {
                    println("\t{} = static_cast<{}>(static_cast<int8_t>(X86_LOAD_{}({})));",
                        get_x86_reg(dst.reg.value),
                        (dst.size == 16) ? "int16_t" : "int32_t",  //destination type
                        srcSizeSuffix,
                        ea(src));
                }
                else if (src.size == 16) {
                    println("\t{} = static_cast<int32_t>(static_cast<int16_t>(X86_LOAD_{}({})));",
                        get_x86_reg(dst.reg.value),
                        srcSizeSuffix,
                        ea(src));
                }
            }
        }
        break;
    case ZYDIS_MNEMONIC_CMP:
        if (insn.insn.operand_count >= 2)
        {
            // Handle both operands simply
            auto get_operand = [&](const ZydisDecodedOperand& op) -> std::string
                {
                    if (op.type == ZYDIS_OPERAND_TYPE_REGISTER)
                    {
                        return get_x86_reg(op.reg.value);
                    }
                    else if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                    {
                        return std::to_string(op.imm.value.u);
                    }
                    else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY)
                    {
                        return "X86_LOAD_U32(" + ea(op) + ")";
                    }
                    return "";
                };

            std::string lhs = get_operand(insn.operands[0]);
            std::string rhs = get_operand(insn.operands[1]);

            if (!lhs.empty() && !rhs.empty()) {
                // Default to 32-bit comparison (covers most cases)
                println("\tctx.eflags.update_compare_flags<uint32_t>({}, {});", lhs, rhs);
            }

        }
        break;
    case ZYDIS_MNEMONIC_COMISS:
        if (insn.insn.operand_count >= 2)
        {
            // COMISS xmm1, xmm2/m32
            const std::string xmm1 = get_x86_reg(insn.operands[0].reg.value, true);

            if (insn.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                // Register comparison
                const std::string xmm2 = get_x86_reg(insn.operands[1].reg.value, true);
                println("\tctx.eflags.update_compare_flags_sse(_mm_cvtss_f32({}), _mm_cvtss_f32({}));",
                    xmm1, xmm2);
            }
            else if (insn.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                // Memory comparison - use address-based unique temp name
                println("\talignas(16) float comiss_temp_{:X} = X86_LOAD_F32({});",
                    base, ea(insn.operands[1]));
                println("\tctx.eflags.update_compare_flags_sse(_mm_cvtss_f32({}), comiss_temp_{:X});",
                    xmm1, base);
            }
            else {
                throw std::runtime_error("Unsupported COMISS operand");
            }
        }
        break;
    case ZYDIS_MNEMONIC_CALL:
        if (insn.insn.operand_count >= 1)
        {
            // Direct call (relative offset)
            if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                uint32_t targetAddress = base + insn.insn.length + insn.operands[0].imm.value.s;
                printFunctionCallAddr(targetAddress);
            }
            else if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {

                uint32_t targetAddress = insn.operands[0].mem.disp.value;
                const auto callDst = ResolveKernelCall(targetAddress);
                if (callDst)
                {
                    printFunctionCallAddr(targetAddress);
                }
                else
                {
                    // Indirect call (memory operand)
                    println("\tX86_CALL_INDIRECT_FUNC({});", ea(insn.operands[0]));
                }
            }
            else if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                // Register indirect (call eax)
                println("\tX86_CALL_INDIRECT_FUNC({});", get_x86_reg(insn.operands[0].reg.value));
            }
        }
        break;
    case ZYDIS_MNEMONIC_CLD:
        println("\tctx.eflags.set_df(false);  // Set forward direction");
        break;
    case ZYDIS_MNEMONIC_CMOVB:
        if (insn.insn.operand_count >= 2)
        {
            println("\tif (ctx.eflags.CF) {} = {};",
                get_x86_reg(insn.operands[0].reg.value),
                get_x86_reg(insn.operands[1].reg.value));
        }
        break;
    case ZYDIS_MNEMONIC_CMOVNB:
        if (insn.insn.operand_count >= 2)
        {
            println("\tif (!ctx.eflags.CF) {} = {};", get_x86_reg(insn.operands[0].reg.value), get_x86_reg(insn.operands[1].reg.value));
        }
        break;
    case ZYDIS_MNEMONIC_CWDE:
        println("\tctx.eax.u32 = (int32_t)(int16_t)ctx.eax.u16;");
        break;
    case ZYDIS_MNEMONIC_FILD:
        if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            println("\tctx.fpu.push(static_cast<double>(X86_LOAD_U32({})));",
                ea(insn.operands[0]));
        }
        break;

    case ZYDIS_MNEMONIC_FADD:
        if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
            println("\tctx.fpu.st0() += ctx.fpu.st{}();", insn.operands[0].reg.value - ZYDIS_REGISTER_ST0);
        else
            println("\tctx.fpu.st0() += X86_LOAD_F64({});", ea(insn.operands[0]));
        break;
    case ZYDIS_MNEMONIC_FABS:
        println("\tctx.fpu.st0() = fabs(ctx.fpu.st0());");
        break;
    case ZYDIS_MNEMONIC_FCOS:
        println("\t// FCOS");
        println("\tdouble fcos_angle_{:X} = ctx.fpu.st0();", base);
        println("\tctx.fpu.sw &= ~X87FPU::C2;");
        println("\tif (fabs(fcos_angle_{:X}) > 9223372036854775808.0) {{", base);
        println("\t    ctx.fpu.sw |= X87FPU::C2;");
        println("\t}}");
        println("\tctx.fpu.st0() = cos(fcos_angle_{:X});", base);
        break;
    case ZYDIS_MNEMONIC_FPATAN:
        println("\tdouble st1Temp_{:X} = ctx.fpu.st1();", base);
        println("\tdouble st0Temp_{:X} = ctx.fpu.st0();", base);
        println("\tctx.fpu.pop();");
        println("\tctx.fpu.st0() = atan2(st1Temp_{:X}, st0Temp_{:X});", base, base);
        break;
    case ZYDIS_MNEMONIC_FSIN:
        println("\tctx.fpu.st0() = sin(ctx.fpu.st0());");
        break;
    case ZYDIS_MNEMONIC_FSINCOS:
        println("\tdouble sin_val = sin(ctx.fpu.st0());");
        println("\tdouble cos_val = cos(ctx.fpu.st0());");
        println("\tctx.fpu.st0() = sin_val;");
        println("\tctx.fpu.push(cos_val);");  // x87pushes cosine after sine
        break;
    case ZYDIS_MNEMONIC_FSQRT:
        println("\tctx.fpu.st0() = sqrt(ctx.fpu.st0());");
        break;
    case ZYDIS_MNEMONIC_FST:
        if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            // FST ST(i)
            println("\tctx.fpu.st{}() = ctx.fpu.st0();",
                insn.operands[0].reg.value - ZYDIS_REGISTER_ST0);
        }
        else {
            // FST m32/m64
            println("\tX86_STORE_F64({}, ctx.fpu.st0());",
                ea(insn.operands[0]));
        }
        break;
    case ZYDIS_MNEMONIC_FMUL:
        if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
            println("\tctx.fpu.st0() *= ctx.fpu.st{}();", insn.operands[0].reg.value - ZYDIS_REGISTER_ST0);
        else
            println("\tctx.fpu.st0() *= X86_LOAD_F64({});", ea(insn.operands[0]));
        break;

    case ZYDIS_MNEMONIC_FSUB:
        if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
            println("\tctx.fpu.st0() -= ctx.fpu.st{}();", insn.operands[0].reg.value - ZYDIS_REGISTER_ST0);
        else
            println("\tctx.fpu.st0() -= X86_LOAD_F64({});", ea(insn.operands[0]));
        break;
    case ZYDIS_MNEMONIC_FSUBP:
        println("\tctx.fpu.st1() -= ctx.fpu.st0();");
        println("\tctx.fpu.pop();");
        break;
    case ZYDIS_MNEMONIC_FMULP:
        println("\tctx.fpu.st1() *= ctx.fpu.st0();");
        println("\tctx.fpu.pop();");
        break;
    case ZYDIS_MNEMONIC_FSTP:
        if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            println("\tctx.fpu.st{}() = ctx.fpu.st0();", insn.operands[0].reg.value - ZYDIS_REGISTER_ST0);
            println("\tctx.fpu.pop();");
        }
        else
        {
            println("\tX86_STORE_F64({}, ctx.fpu.st0());", ea(insn.operands[0]));
            println("\tctx.fpu.pop();");
        }
        break;

    case ZYDIS_MNEMONIC_FLD:
        if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            // Load float/double and push onto the x87 stack
            if (insn.operands[0].size == 32) {
                println("\tctx.fpu.push(X86_LOAD_F32({}));", ea(insn.operands[0]));
            }
            else {
                println("\tctx.fpu.push(X86_LOAD_F64({}));", ea(insn.operands[0]));
            }
        }
        else if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            // FLD ST(i) - Duplicates a register onto the stack
            println("\tctx.fpu.push(ctx.fpu.st{}());",
                insn.operands[0].reg.value - ZYDIS_REGISTER_ST0);
        }
        break;
    case ZYDIS_MNEMONIC_FDIV:
        if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            println("\tctx.fpu.st0() /= ctx.fpu.st{}();",
                insn.operands[0].reg.value - ZYDIS_REGISTER_ST0);
        }
        else
        {
            //FDIV m32/m64
            println("\tctx.fpu.st0() /= X86_LOAD_F64({});",
                ea(insn.operands[0]));
        }
        break;
    case ZYDIS_MNEMONIC_FDIVR:
        if (insn.insn.operand_count == 2)
        {
            // Case 1: FDIVR ST(1), ST(0) → ST(1) = ST(0) / ST(1)
            if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                insn.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                insn.operands[0].reg.value >= ZYDIS_REGISTER_ST0 &&
                insn.operands[0].reg.value <= ZYDIS_REGISTER_ST7 &&
                insn.operands[1].reg.value == ZYDIS_REGISTER_ST0)
            {
                int st_idx = insn.operands[0].reg.value - ZYDIS_REGISTER_ST0;
                println("\tctx.fpu.st%d() = ctx.fpu.st0() / ctx.fpu.st%d();", st_idx, st_idx);
            }
            // Case 2: FDIVR m32/m64 → ST(0) = [mem] / ST(0)
            else if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                std::string memAddr = decode_memory_operand(insn.operands[0].mem);
                if (insn.operands[0].size == 32) {
                    println("\tctx.fpu.st0() = *(float*)%s / ctx.fpu.st0();", memAddr);
                }
                else { // 64-bit double
                    println("\tctx.fpu.st0() = *(double*)%s / ctx.fpu.st0();", memAddr);
                }
            }
            else
            {
                println("// ERROR: Unsupported FDIVR operand combination");
            }
        }
        break;
    case ZYDIS_MNEMONIC_FCHS:
        println("\tctx.fpu.st0() = -ctx.fpu.st0();");
        break;
    case ZYDIS_MNEMONIC_FCOMP:
        if (insn.insn.operand_count > 0)
        {
            if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                compare_and_pop(fmt::format("ctx.fpu.st{}()",
                    insn.operands[0].reg.value - ZYDIS_REGISTER_ST0));
            }
            else if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                println("\t{{");
                if (insn.operands[0].size == 32)
                {
                    println("\t\tfloat val_{:X} = X86_LOAD_F32({});",
                        base, ea(insn.operands[0]));
                    compare_and_pop(fmt::format("val_{:X}", base));
                }
                else
                {
                    println("\t\tdouble val_{:X} = X86_LOAD_F64({});",
                        base, ea(insn.operands[0]));
                    compare_and_pop(fmt::format("val_{:X}", base));
                }
                println("\t}}");
            }
        }
        else
        {
            // FCOMPP (compare ST0 and ST1, then pop twice)
            println("\t// FCOMPP (implied operands)");
            compare_and_pop("ctx.fpu.st1()");
            println("\tctx.fpu.pop(); // Second pop for FCOMPP");
        }
        break;
    case ZYDIS_MNEMONIC_FCOMIP:
        if (insn.insn.operand_count >= 1 && insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            println("\t // fcomip");
            println("\tctx.eflags.clear_compare_flags();");
            println("\tif (std::isnan(ctx.fpu.st0()) || std::isnan(ctx.fpu.st{}())) {{",
                insn.operands[0].reg.value - ZYDIS_REGISTER_ST0);
            println("\t    ctx.eflags.value |= X86EFlags::CF | X86EFlags::PF | X86EFlags::ZF;");
            println("\t}} else if (ctx.fpu.st0() < ctx.fpu.st{}()) {{",
                insn.operands[0].reg.value - ZYDIS_REGISTER_ST0);
            println("\t    ctx.eflags.value |= X86EFlags::CF;");
            println("\t}} else if (ctx.fpu.st0() == ctx.fpu.st{}()) {{",
                insn.operands[0].reg.value - ZYDIS_REGISTER_ST0);
            println("\t    ctx.eflags.value |= X86EFlags::ZF;");
            println("\t}}");
            println("\tctx.fpu.pop();");  //FCOMIP always pops the stack
        }
        break;
    case ZYDIS_MNEMONIC_FXCH:
        if (insn.insn.operand_count == 0)
        {
            println("\tdouble tmp_{:X} = ctx.fpu.st0();", base);
            println("\tctx.fpu.st0() = ctx.fpu.st1();");
            println("\tctx.fpu.st1() = tmp_{:X};", base);
        }
        else if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            const int st_index = insn.operands[0].reg.value - ZYDIS_REGISTER_ST0;
            println("\tdouble tmp_{:X} = ctx.fpu.st0();", base);
            println("\tctx.fpu.st0() = ctx.fpu.st{}();", st_index);
            println("\tctx.fpu.st{}() = tmp_{:X};", st_index, base);
        }
        break;
    case ZYDIS_MNEMONIC_JZ:
    case ZYDIS_MNEMONIC_JNZ:
        if (insn.insn.operand_count >= 2)
        {
            printConditionalBranch(false, "ctx.eflags.ZF", base, insn);
        }
        break;
    case ZYDIS_MNEMONIC_JBE:
        if (insn.insn.operand_count >= 1) {
            //printConditionalBranch(false, "ctx.eflags.value & (X86EFlags::CF | X86EFlags::ZF)", base, insn);
            printConditionalBranch(false,
                "(ctx.eflags.value & X86EFlags::CF) || "
                "(ctx.eflags.value & X86EFlags::ZF)",
                base, insn);
        }
        break;
    case ZYDIS_MNEMONIC_JNBE:
        if (insn.insn.operand_count >= 1) {
            //printConditionalBranch(false, "!(ctx.eflags.value & (X86EFlags::CF | X86EFlags::ZF))", base, insn);
            printConditionalBranch(false,
                "!(ctx.eflags.value & X86EFlags::CF) && "
                "!(ctx.eflags.value & X86EFlags::ZF)",
                base, insn);
        }
        break;
    case ZYDIS_MNEMONIC_JB:
        if (insn.insn.operand_count >= 1) {
            //printConditionalBranch(false, "ctx.eflags.CF", base, insn);
            printConditionalBranch(false, "(ctx.eflags.value & 0x1)", base, insn); 
        }
        break;
    case ZYDIS_MNEMONIC_JNB:
        if (insn.insn.operand_count >= 1) {
            printConditionalBranch(false, "!ctx.eflags.CF", base, insn);
        }
        break;
    case ZYDIS_MNEMONIC_JL:
        if (insn.insn.operand_count >= 1) 
        {
            printConditionalBranch(false, "((ctx.eflags.value >> 7) & 1) != ((ctx.eflags.value >> 11) & 1)", base, insn);
        }
        break;
    case ZYDIS_MNEMONIC_JLE:
        if (insn.insn.operand_count >= 1) {
            printConditionalBranch(false, "(ctx.eflags.value & X86EFlags::ZF) || "
                "((ctx.eflags.value & X86EFlags::SF) != (ctx.eflags.value & X86EFlags::OF))", base, insn);
        }
        break;
    case ZYDIS_MNEMONIC_JNLE:  //Jump if ZF=0 AND SF=OF
        printConditionalBranch(false,
            "(!(ctx.eflags.value & X86EFlags::ZF) && ((ctx.eflags.value & X86EFlags::SF) == (ctx.eflags.value & X86EFlags::OF)))",
            base, insn);
        break;
    case ZYDIS_MNEMONIC_JNL:  //Jump if SF == OF (not less)
        printConditionalBranch(false,
            "((ctx.eflags.value & X86EFlags::SF) == (ctx.eflags.value & X86EFlags::OF))",
            base, insn);
        break;
    case ZYDIS_MNEMONIC_JNS:
       // printConditionalBranch(false, "(ctx.eflags.value & X86EFlags::SF)", base, insn);
        printConditionalBranch(false, "!(ctx.eflags.value & X86EFlags::SF)", base, insn);
        break;
    case ZYDIS_MNEMONIC_JS:
        //printConditionalBranch(true, "(ctx.eflags.value & X86EFlags::SF)", base, insn);
        printConditionalBranch(false, "(ctx.eflags.value & X86EFlags::SF)", base, insn);
        break;
    case ZYDIS_MNEMONIC_JP:
        if (insn.insn.operand_count >= 1) {
            printConditionalBranch(false, "ctx.eflags.PF", base, insn);
        }
        break;
    case ZYDIS_MNEMONIC_JO:
        if (insn.insn.operand_count >= 1) {
            printConditionalBranch(false, "ctx.eflags.OF", base, insn);
        }
        break;
    case ZYDIS_MNEMONIC_POP:
        //xbox kernel stuff
        if (insn.operands[0].mem.segment == ZYDIS_REGISTER_FS) 
        {
            uint32_t offset = insn.operands[0].mem.disp.value;
            println("\t//POP FS:[0x{:X}] (skipped)", offset);
            println("\t(void)X86_POP(ctx, base);  // Discard value");
            break;
        }

        if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            println("\t{} = X86_POP(ctx, base);", get_x86_reg(insn.operands[0].reg.value));
        }
        else if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            const auto& dst = insn.operands[0];
            const char* size_suffix = GetOperandSizeName(dst.size);
            println("\tX86_STORE_{}({}, X86_POP(ctx, base));", size_suffix, ea(dst));
        }
        break;
    case ZYDIS_MNEMONIC_RET:
        println("\treturn;");
        break;
    case ZYDIS_MNEMONIC_STD:
        println("\tctx.eflags.set_df(true);  // Set backward direction");
        break;
    case ZYDIS_MNEMONIC_ADD:
        if (insn.insn.operand_count >= 2)
        {
            const auto& dst = insn.operands[0];
            const auto& src = insn.operands[1];
            const char* size_suffix = GetOperandSizeName(dst.size);

            // ADD reg, imm
            if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                println("\t{} += {};",
                    get_x86_reg(dst.reg.value),
                    src.imm.value.u);
            }
            // ADD reg, reg
            else if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                println("\t{} += {};",
                    get_x86_reg(dst.reg.value),
                    get_x86_reg(src.reg.value));
            }
            // ADD reg, [mem]
            else if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                println("\t{} += X86_LOAD_{}({});",
                    get_x86_reg(dst.reg.value),
                    size_suffix,
                    ea(src));
            }
            // ADD [mem], reg
            else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                println("\tX86_STORE_{}({}, X86_LOAD_{}({}) + {});",
                    size_suffix,
                    ea(dst),
                    size_suffix,
                    ea(dst),
                    get_x86_reg(src.reg.value));
            }
            // ADD [mem], imm
            else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                println("\tX86_STORE_{}({}, X86_LOAD_{}({}) + {});",
                    size_suffix,
                    ea(dst),
                    size_suffix,
                    ea(dst),
                    src.imm.value.u);
            }
        }
        break;
    case ZYDIS_MNEMONIC_ADDSS:  //float
        HandleSseScalarInstruction(insn, xmm, decode_memory_operand, "+=");
        break;
    case ZYDIS_MNEMONIC_SUB:
        if (insn.insn.operand_count >= 2)
        {
            const auto& dst = insn.operands[0];
            const auto& src = insn.operands[1];
            const char* size_suffix = GetOperandSizeName(dst.size);

            //SUB reg, imm
            if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                println("\t{} -= {};",
                    get_x86_reg(dst.reg.value),
                    src.imm.value.u);
            }
            else if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                println("\t{} -= {};",
                    get_x86_reg(dst.reg.value),
                    get_x86_reg(src.reg.value));
            }
            else if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                println("\t{} -= X86_LOAD_{}({});",
                    get_x86_reg(dst.reg.value),
                    size_suffix,
                    ea(src));
            }
            else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                println("\tX86_STORE_{}({}, X86_LOAD_{}({}) - {});",
                    size_suffix,
                    ea(dst),
                    size_suffix,
                    ea(dst),
                    get_x86_reg(src.reg.value));
            }
            else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                println("\tX86_STORE_{}({}, X86_LOAD_{}({}) - {});",
                    size_suffix,
                    ea(dst),
                    size_suffix,
                    ea(dst),
                    src.imm.value.u);
            }
        }
        break;
    case ZYDIS_MNEMONIC_SUBSS:
        HandleSseScalarInstruction(insn, xmm, decode_memory_operand, "-=");
        break;
    case ZYDIS_MNEMONIC_JMP:
        if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            if (switchTable != config.switchTables.end())
            {
                //Generate a switch statement for the jump table
                println("\tswitch ({}) {{", GetJmpTableRegister(switchTable->second.r) + ".u32");

                for (size_t i = 0; i < switchTable->second.labels.size(); i++)
                {
                    println("\tcase {}:", i);
                    auto label = switchTable->second.labels[i];
                    if (label < fn.base || label >= fn.base + fn.size)
                    {
                        println("\t\t// ERROR: 0x{:X}", label);
                        fmt::println("ERROR: Switch case at {:X} is trying to jump outside function: {:X}", base, label);
                        println("\t\treturn;");
                    }
                    else
                    {
                        if (label == fn.base)
                            printFunctionCallAddr(label);
                        else
                            println("\t\tgoto loc_{:X};", label);
                    }
                }

                println("\tdefault:");
                println("\t\t__builtin_unreachable();");
                println("\t}}");

                // Mark this jump table as handled
                switchTable = config.switchTables.end();
            }
            else
            {
                //Handle regular indirect jump
                 // Handle regular indirect jump dynamically
                //println("\tX86_CALL_INDIRECT_FUNC({}.u32);", ea(insn.operands[0]));

                uint32_t targetAddress = insn.operands[0].mem.disp.value;
                const auto callDst = ResolveKernelCall(targetAddress);
                if (callDst)
                {
                    printFunctionCallAddr(targetAddress);
                }
                else
                {
                    println("\tX86_CALL_INDIRECT_FUNC(X86_LOAD_U32({}));", ea(insn.operands[0]));
                }
                println("\treturn;");
            }
        }
        else if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
        {
            // Handle direct jumps (JMP imm)
            uint32_t targetAddress = base + insn.insn.length + insn.operands[0].imm.value.s;
            if (targetAddress < fn.base || targetAddress >= fn.base + fn.size)
            {
                // Target is outside the current function: call the function
                printFunctionCallAddr(targetAddress);
                println("\treturn;");
            }
            else
            {

                if (targetAddress == fn.base)
                {
                    printFunctionCallAddr(targetAddress);
                    println("\treturn;");
                }
                else
                {   //Target is within the current function: generate a goto statement
                    println("\tgoto loc_{:X};", targetAddress);
                }
            }
        }
        else if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            println("\tX86_CALL_INDIRECT_FUNC({});", get_x86_reg(insn.operands[0].reg.value));
            println("\treturn;");
        }
        break;
    case ZYDIS_MNEMONIC_IMUL:
        if (insn.insn.operand_count >= 2)
        {
            if (insn.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                println("\t{} *= {};", get_x86_reg(insn.operands[0].reg.value), insn.operands[1].imm.value.s);
            }
            else if (insn.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                println("\t{} *= {};", get_x86_reg(insn.operands[0].reg.value), get_x86_reg(insn.operands[1].reg.value));
            }
        }
        break;
    case ZYDIS_MNEMONIC_SHL:
        if (insn.insn.operand_count >= 2)
        {
            if (insn.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                println("\t{} <<= {};", get_x86_reg(insn.operands[0].reg.value), insn.operands[1].imm.value.u);
            }
            else if (insn.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                println("\t{} <<= {};", get_x86_reg(insn.operands[0].reg.value), get_x86_reg(insn.operands[1].reg.value));
            }
        }
        break;
    case ZYDIS_MNEMONIC_INC:
        if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            //INC reg
            println("\t{}++;", get_x86_reg(insn.operands[0].reg.value));
        }
        else if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            const auto& op = insn.operands[0];
            const char* size_suffix = GetOperandSizeName(op.size);

            //INC [mem]
            println("\tX86_STORE_{}({}, X86_LOAD_{}({}) + 1);", size_suffix, ea(op), size_suffix, ea(op));
        }
        break;
    case ZYDIS_MNEMONIC_DIVSS:
        HandleSseScalarInstruction(insn, xmm, decode_memory_operand, "/=");
        break;
    case ZYDIS_MNEMONIC_DEC:
        if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            //DEC reg
            println("\t{}--;", get_x86_reg(insn.operands[0].reg.value));
        }
        else if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            const auto& op = insn.operands[0];
            const char* size_suffix = GetOperandSizeName(op.size);

            //DEC [mem]
            println("\tX86_STORE_{}({}, X86_LOAD_{}({}) - 1);", size_suffix, ea(op), size_suffix, ea(op));
        }
        break;

    case ZYDIS_MNEMONIC_OR:
        if (insn.insn.operand_count >= 2)
        {
            const auto& dst = insn.operands[0];
            const auto& src = insn.operands[1];
            const char* size_suffix = GetOperandSizeName(dst.size);

            if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                insn.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                uint64_t imm_value = src.imm.value.u;
                ImmWrapper immWrapper{ insn.operands[1].imm };
                println("\t{} |= {};", get_x86_reg(insn.operands[0].reg.value), immWrapper);
            }

            else if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                insn.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                //OR reg, reg
                println("\t{} |= {};", get_x86_reg(insn.operands[0].reg.value), get_x86_reg(insn.operands[1].reg.value));
            }
            else if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                insn.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                //OR reg, [mem] -> reg |= [mem]
                println("\t{} |= X86_LOAD_{}({});", get_x86_reg(dst.reg.value), size_suffix, ea(src));
            }
            else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                println("\tX86_STORE_{}({}, X86_LOAD_{}({}) | {});", size_suffix, ea(dst), size_suffix,
                    ea(dst), get_x86_reg(src.reg.value));
            }
            else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                println("\tX86_STORE_{}({}, X86_LOAD_{}({}) | 0x{:X});", size_suffix, ea(dst),
                    size_suffix, ea(dst), src.imm.value.u);
            }
        }
        break;
    case ZYDIS_MNEMONIC_AND:
        if (insn.insn.operand_count >= 2 &&
            insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            insn.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
        {
            //AND reg, imm
            ImmWrapper immWrapper{ insn.operands[1].imm };
            println("\t{} &= {};", get_x86_reg(insn.operands[0].reg.value), immWrapper);
        }
        else if (insn.insn.operand_count >= 2 &&
            insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            insn.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            //AND reg, reg
            println("\t{} &= {};", get_x86_reg(insn.operands[0].reg.value), get_x86_reg(insn.operands[1].reg.value));
        }
        else if (insn.insn.operand_count >= 2 &&
            insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            insn.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            // AND reg, [mem] -> reg &= [mem]
            const char* size_suffix = GetOperandSizeName(insn.operands[0].size);
            println("\t{} &= X86_LOAD_{}({});", get_x86_reg(insn.operands[0].reg.value), size_suffix,
                ea(insn.operands[1]));
        }
        else if (insn.insn.operand_count >= 2 &&
            insn.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
            insn.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            //AND [mem], reg -> [mem] &= reg
            const char* size_suffix = GetOperandSizeName(insn.operands[0].size);
            println("\tX86_STORE_{}({}, X86_LOAD_{}({}) & {});", size_suffix, ea(insn.operands[0]),
                size_suffix, ea(insn.operands[0]), get_x86_reg(insn.operands[1].reg.value));
        }
        break;
    case ZYDIS_MNEMONIC_TEST:
        if (insn.insn.operand_count >= 2)
        {
            const auto& dst = insn.operands[0];
            const char* size_suffix = GetOperandSizeName(dst.size);

            if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                insn.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                println("\tctx.eflags.update_test_flags({} & {});", get_x86_reg(dst.reg.value),
                    get_x86_reg(insn.operands[1].reg.value));
            }
            else if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                insn.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                println("\tctx.eflags.update_test_flags({} & {});", get_x86_reg(dst.reg.value),
                    insn.operands[1].imm.value.u);
            }
            else if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                insn.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                println("\tctx.eflags.update_test_flags({} & X86_LOAD_{}({}));", get_x86_reg(dst.reg.value),
                    size_suffix, ea(insn.operands[1]));
            }
            else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                insn.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                println("\tctx.eflags.update_test_flags(X86_LOAD_{}({}) & {});",
                    size_suffix, ea(dst), get_x86_reg(insn.operands[1].reg.value));
            }
            // TEST [mem], imm
            else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                insn.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                println("\tctx.eflags.update_test_flags(X86_LOAD_{}({}) & {});", size_suffix,
                    ea(dst), insn.operands[1].imm.value.u);
            }
        }
        break;
    case ZYDIS_MNEMONIC_LEA:
        if (insn.insn.operand_count >= 2 &&
            insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            insn.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            // LEA reg, [mem] -> reg = address calculation only
            println("\t{} = {};",
                get_x86_reg(insn.operands[0].reg.value),
                ea(insn.operands[1], true));  // true = address mode
        }
        break;
    case ZYDIS_MNEMONIC_LEAVE:
        //Equivalent to: mov esp,ebp; pop ebp
        println("\tctx.esp.u32 = ctx.ebp.u32;");
        println("\tctx.ebp.u32 = X86_POP(ctx, base);");
        break;
    case ZYDIS_MNEMONIC_STOSD:
        if (insn.insn.attributes & ZYDIS_ATTRIB_HAS_REP)
        {
            println("\tfor (uint32_t i = 0; i < ctx.ecx.u32; ++i) {{");
            println("\t    X86_STORE_U32(static_cast<uintptr_t>(ctx.edi.u32) + i * 4, ctx.eax.u32);");
            println("\t}}");
            println("\tctx.edi.u32 += ctx.ecx.u32 * 4;");
            println("\tctx.ecx.u32 = 0;");
        }
        else
        { //rare
            println("\tX86_STORE_U32(static_cast<uintptr_t>(ctx.edi.u32), ctx.eax.u32);");
            println("\tctx.edi.u32 += 4;");
        }
        break;
    case ZYDIS_MNEMONIC_STOSB:
        if (insn.insn.attributes & ZYDIS_ATTRIB_HAS_REP)
        {
            //REP STOSB: Safe type handling for fmt
            println("\tfor (uint32_t i = 0; i < ctx.ecx.u32; ++i) {{");
            println("\t    X86_STORE_U8(static_cast<uintptr_t>(ctx.edi.u32) + i, static_cast<uint8_t>(ctx.eax.u8_lo));");
            println("\t}}");
            println("\tctx.edi.u32 += ctx.ecx.u32;");
            println("\tctx.ecx.u32 = 0;");
        }
        else {
            // Single STOSB
            println("\tX86_STORE_U8(static_cast<uintptr_t>(ctx.edi.u32), static_cast<uint8_t>(ctx.eax.u8_lo));");
            println("\tctx.edi.u32 += 1;");
        }
        break;
    case ZYDIS_MNEMONIC_MOVSD:
        println("\tfor (; ctx.ecx.u32 > 0; ctx.ecx.u32--, ctx.esi.u32 += 4, ctx.edi.u32 += 4) {{");
        println("\t\tX86_STORE_U32(ctx.edi.u32, X86_LOAD_U32(ctx.esi.u32));");
        println("\t}}");
        break;
    case ZYDIS_MNEMONIC_MOVAPS:
        if (insn.insn.operand_count == 2) {
            // Register-to-register move (MOVAPS XMM1, XMM2)
            if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                insn.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                println("\t{} = {};",
                    xmm(insn.operands[0].reg.value - ZYDIS_REGISTER_XMM0),
                    xmm(insn.operands[1].reg.value - ZYDIS_REGISTER_XMM0));
            }
            // Register-to-memory move (MOVAPS [mem], XMM)
            else if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                insn.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                std::string mem_addr = ea(insn.operands[0]);
                println("\t_mm_store_ps(reinterpret_cast<float*>({}), {});",
                    mem_addr,
                    xmm(insn.operands[1].reg.value - ZYDIS_REGISTER_XMM0));
            }
            // Memory-to-register move (MOVAPS XMM, [mem])
            else if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                insn.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                std::string mem_addr = ea(insn.operands[1]);
                println("\t{} = _mm_load_ps(reinterpret_cast<const float*>({}));",
                    xmm(insn.operands[0].reg.value - ZYDIS_REGISTER_XMM0),
                    mem_addr);
            }
            else {
                println("// ERROR: Unsupported MOVAPS operand combination");
            }
        }
        break;
    case ZYDIS_MNEMONIC_MOVSB:
        /**println("\tfor (; ctx.ecx.u32 > 0; ctx.ecx.u32--, ctx.esi.u32++, ctx.edi.u32++) {{");
        println("\t\tX86_STORE_U32(ctx.edi.u32, X86_LOAD_U32(ctx.esi.u32));");
        println("\t}}");*/
        println("\tX86_STORE_U8(ctx.edi.u32, X86_LOAD_U8(ctx.esi.u32));");
        println("\tctx.eflags.update_string_pointer(ctx.esi.u32);");
        println("\tctx.eflags.update_string_pointer(ctx.edi.u32);");
        break;
    case ZYDIS_MNEMONIC_MUL:
        if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {

            println("\tuint64_t result_{:X} = static_cast<uint64_t>(ctx.eax.u32) * static_cast<uint64_t>({});",
                base, get_x86_reg(insn.operands[0].reg.value));
            println("\tctx.eax.u32 = static_cast<uint32_t>(result_{:X} & 0xFFFFFFFF);", base);
            println("\tctx.edx.u32 = static_cast<uint32_t>(result_{:X} >> 32);", base);
        }
        else if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            println("\tuint64_t result_{:X} = static_cast<uint64_t>(ctx.eax.u32) * static_cast<uint64_t>(X86_LOAD_U32({}));",
                base, ea(insn.operands[0]));
            println("\tctx.eax.u32 = static_cast<uint32_t>(result_{:X} & 0xFFFFFFFF);", base);
            println("\tctx.edx.u32 = static_cast<uint32_t>(result_{:X} >> 32);", base);
        }
        break;
    case ZYDIS_MNEMONIC_MULSS:
        HandleSseScalarInstruction(insn, xmm, decode_memory_operand, "*=");
        break;
    case ZYDIS_MNEMONIC_SAR:
        if (insn.insn.operand_count >= 2)
        {
            if (insn.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                //SAR reg, imm
                println("\t{} >>= {};", get_x86_reg(insn.operands[0].reg.value), insn.operands[1].imm.value.u);
            }
            else if (insn.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                println("\t{} >>= {};",
                    get_x86_reg(insn.operands[1].reg.value),
                    insn.operands[1].imm.value.u);
            }
        }
        break;
    case ZYDIS_MNEMONIC_SBB:
        if (insn.insn.operand_count >= 2)
        {
            const auto& dst = insn.operands[0];
            const auto& src = insn.operands[1];
            const char* sizeSuffix = GetOperandSizeName(dst.size);
            const char* cf = "(ctx.eflags.value & X86EFlags::CF) ? 1 : 0";

            // SBB reg, imm
            if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                println("\t{} -= {} + {};", get_x86_reg(dst.reg.value), src.imm.value.u, cf);
            }
            // SBB reg, reg
            else if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                src.type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                println("\t{} -= {} + {};", get_x86_reg(dst.reg.value), get_x86_reg(src.reg.value), cf);
            }
            // SBB reg, [mem]
            else if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                src.type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                println("\t{} -= X86_LOAD_U{}({}) + {};", get_x86_reg(dst.reg.value),
                    dst.size, ea(src), cf);
            }
            else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                src.type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                println("\tX86_STORE_U{}({}, X86_LOAD_U{}({}) - {} - {});", dst.size,
                    ea(dst), dst.size, ea(dst), get_x86_reg(src.reg.value), cf);
            }
            else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                println("\tX86_STORE_U{}({}, X86_LOAD_U{}({}) - {} - {});",
                    dst.size, ea(dst), dst.size, ea(dst), src.imm.value.u, cf);
            }

            println("\tctx.eflags.update_sub_flags(0, 0, {});", cf);
        }
        break;
    case ZYDIS_MNEMONIC_PUSHFD:
        println("\tX86_PUSH(ctx, base, ctx.eflags.value);");
        break;
    case ZYDIS_MNEMONIC_XCHG:
        if (insn.insn.operand_count >= 2)
        {
            const auto& op1 = insn.operands[0];
            const auto& op2 = insn.operands[1];
            const char* size_suffix = GetOperandSizeName(op1.size);

            // Generate unique temp name based on instruction address
            const std::string tmp_var = fmt::format("xchg_tmp_{:x}", base);

            // XCHG reg, reg
            if (op1.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                op2.type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                println("\tauto {} = {};", tmp_var, get_x86_reg(op1.reg.value));
                println("\t{} = {};", get_x86_reg(op1.reg.value), get_x86_reg(op2.reg.value));
                println("\t{} = {};", get_x86_reg(op2.reg.value), tmp_var);
            }
            // XCHG reg, [mem]
            else if (op1.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                op2.type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                println("\tauto {} = {};", tmp_var, get_x86_reg(op1.reg.value));
                println("\t{} = X86_LOAD_{}({});", get_x86_reg(op1.reg.value), size_suffix, ea(op2));
                println("\tX86_STORE_{}({}, {});", size_suffix, ea(op2), tmp_var);
            }
            // XCHG [mem], reg
            else if (op1.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                op2.type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                println("\tauto {} = X86_LOAD_{}({});", tmp_var, size_suffix, ea(op1));
                println("\tX86_STORE_{}({}, {});", size_suffix, ea(op1), get_x86_reg(op2.reg.value));
                println("\t{} = {};", get_x86_reg(op2.reg.value), tmp_var);
            }
        }
        break;
    case ZYDIS_MNEMONIC_XOR:
        if (insn.insn.operand_count >= 2)
        {
            const auto& dst = insn.operands[0];
            const auto& src = insn.operands[1];
            const char* size_suffix = GetOperandSizeName(dst.size);

            // XOR reg, reg
            if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                println("\t{} ^= {};",
                    get_x86_reg(dst.reg.value),
                    get_x86_reg(src.reg.value));
            }
            // XOR reg, [mem]
            else if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                println("\t{} ^= X86_LOAD_{}({});",
                    get_x86_reg(dst.reg.value),
                    size_suffix,
                    ea(src));
            }
            // XOR [mem], reg
            else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                println("\tX86_STORE_{}({}, X86_LOAD_{}({}) ^ {});",
                    size_suffix,
                    ea(dst),
                    size_suffix,
                    ea(dst),
                    get_x86_reg(src.reg.value));
            }
            // XOR [mem], imm
            else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                println("\tX86_STORE_{}({}, X86_LOAD_{}({}) ^ {});",
                    size_suffix,
                    ea(dst),
                    size_suffix,
                    ea(dst),
                    src.imm.value.u);
            }
        }
        break;
    case ZYDIS_MNEMONIC_XORPS:
        if (insn.insn.operand_count >= 2)
        {
            // XORPS xmm, xmm
            if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                insn.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                println("\t{} = _mm_xor_ps({}, {});",
                    get_x86_reg(insn.operands[0].reg.value, true),
                    get_x86_reg(insn.operands[0].reg.value, true),
                    get_x86_reg(insn.operands[1].reg.value, true));
            }
            // XORPS xmm, [mem]
            else if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                insn.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                println("\t{} = _mm_xor_ps({}, _mm_load_ps(reinterpret_cast<const float*>({})));",
                    get_x86_reg(insn.operands[0].reg.value, true),
                    get_x86_reg(insn.operands[0].reg.value, true),
                    ea(insn.operands[1]));
            }
        }
        break;
    case ZYDIS_MNEMONIC_MOVSS:
        if (insn.insn.operand_count == 2)
        {
            const auto& dst = insn.operands[0];
            const auto& src = insn.operands[1];

            if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                src.type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                int reg_idx = dst.reg.value - ZYDIS_REGISTER_XMM0;
                println("\tXMM_F32({}, 0) = X86_LOAD_F32({});", reg_idx, ea(src, true));
            }
            else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                src.type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                int reg_idx = src.reg.value - ZYDIS_REGISTER_XMM0;
                println("\tX86_STORE_F32({}, XMM_F32({}, 0));", ea(dst, true), reg_idx);
            }
            else if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                src.type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                int dst_idx = dst.reg.value - ZYDIS_REGISTER_XMM0;
                int src_idx = src.reg.value - ZYDIS_REGISTER_XMM0;
                println("\tXMM_F32({}, 0) = XMM_F32({}, 0);", dst_idx, src_idx);
            }
        }
        break;
    case ZYDIS_MNEMONIC_SHR:
        if (insn.insn.operand_count >= 2)
        {
            const auto& dst = insn.operands[0];
            const char* size_suffix = GetOperandSizeName(dst.size);

            // SHR reg/mem, imm
            if (insn.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER)
                {
                    println("\t{} >>= {};",
                        get_x86_reg(dst.reg.value),
                        insn.operands[1].imm.value.u);
                }
                else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY)
                {
                    println("\tX86_STORE_{}({}, X86_LOAD_{}({}) >> {});",
                        size_suffix, ea(dst), size_suffix,
                        ea(dst), insn.operands[1].imm.value.u);
                }
            }
            else if (insn.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                insn.operands[1].reg.value == ZYDIS_REGISTER_CL)
            {
                if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER)
                {
                    println("\t{} >>= ctx.ecx.u8_lo;", get_x86_reg(dst.reg.value));
                }
                else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY)
                {
                    println("\tX86_STORE_{}({}, X86_LOAD_{}({}) >> ctx.ecx.u8_lo);", size_suffix,
                        ea(dst), size_suffix, ea(dst));
                }
            }
        }
        break;
    case ZYDIS_MNEMONIC_MOVZX:
        if (insn.insn.operand_count >= 2)
        {
            const auto& dst = insn.operands[0];
            const auto& src = insn.operands[1];

            if (src.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                src.mem.segment == ZYDIS_REGISTER_FS) {
                uint32_t offset = src.mem.disp.value;
                auto dst_reg = get_x86_reg(dst.reg.value);

                println("\t// movzx {}, byte ptr fs:[0x{:X}]", dst_reg, offset);
                println("\t{} = GetXboxThreadFlags(ctx, base);", dst_reg);
                break;
            }

            //MOVZX reg, reg
            if (insn.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                if (insn.operands[0].size == 4)
                {
                    if (insn.operands[1].size == 1)
                    {
                        println("\t{}.u32 = (uint32_t){}.u8;",
                            get_x86_reg(insn.operands[0].reg.value), get_x86_reg(insn.operands[1].reg.value));
                    }
                    else if (insn.operands[1].size == 2) //16-bit
                    {
                        println("\t{}.u32 = (uint32_t){}.u16;",
                            get_x86_reg(insn.operands[0].reg.value), get_x86_reg(insn.operands[1].reg.value));
                    }
                }
                else if (insn.operands[0].size == 2) //16-bit
                {
                    println("\t{}.u16 = (uint16_t){}.u8;",
                        get_x86_reg(insn.operands[0].reg.value), get_x86_reg(insn.operands[1].reg.value));
                }
            }
            // MOVZX reg, mem
            else if (insn.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                if (insn.operands[0].size == 4) // 32-bit
                {
                    if (insn.operands[1].size == 1) // 8-bit
                    {
                        println("\t{}.u32 = (uint32_t)X86_LOAD_U8({});",
                            get_x86_reg(insn.operands[0].reg.value), ea(insn.operands[1]));
                    }
                    else if (insn.operands[1].size == 2) // 16-bit
                    {
                        println("\t{}.u32 = (uint32_t)X86_LOAD_U16({});",
                            get_x86_reg(insn.operands[0].reg.value), ea(insn.operands[1]));
                    }
                }
                else if (insn.operands[0].size == 2) // 16-bit destination
                {
                    println("\t{}.u16 = (uint16_t)X86_LOAD_U8({});",
                        get_x86_reg(insn.operands[0].reg.value), ea(insn.operands[1]));
                }
            }
        }
        break;
    case ZYDIS_MNEMONIC_NEG:
        if (insn.insn.operand_count >= 1)
        {
            const auto& op = insn.operands[0];

            // NEG reg
            if (op.type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                println("\t{} = -{};", get_x86_reg(op.reg.value),
                    get_x86_reg(op.reg.value));
            }
            // NEG [mem]
            else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                println("\tX86_STORE_U32({}, -X86_LOAD_U32({}));  // NEG (32-bit)",
                    ea(op),
                    ea(op));
            }
        }
        break;
    case ZYDIS_MNEMONIC_NOT:
        if (insn.insn.operand_count >= 1)
        {
            const auto& op = insn.operands[0];
            if (op.type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                println("\t{} = static_cast<uint32_t>(~{});",
                    get_x86_reg(op.reg.value),
                    get_x86_reg(op.reg.value));
            }
            else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                println("\tX86_STORE_U32({}, static_cast<uint32_t>(~X86_LOAD_U32({})));",
                    ea(op),
                    ea(op));
            }
        }
        break;
    case ZYDIS_MNEMONIC_CMPSB:
        println("\tctx.eflags.update_compare_flags(");
        println("\t    X86_LOAD_U8(ctx.esi.u32),");
        println("\t    X86_LOAD_U8(ctx.edi.u32)");
        println("\t);");
        println("\tctx.eflags.update_string_pointer(ctx.esi.u32);");
        println("\tctx.eflags.update_string_pointer(ctx.edi.u32);");
        break;
    case ZYDIS_MNEMONIC_SETL:
        if (insn.insn.operand_count >= 1)
        {
            const auto& op = insn.operands[0];
            if (op.type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                println("\t{} = ((ctx.eflags.value & X86EFlags::SF) != "
                    "(ctx.eflags.value & X86EFlags::OF)) ? 1 : 0;",
                    get_x86_reg(op.reg.value));
            }
            else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                println("\tX86_STORE_U8({}, ((ctx.eflags.value & X86EFlags::SF) != "
                    "(ctx.eflags.value & X86EFlags::OF)) ? 1 : 0);",
                    ea(op));
            }
        }
        break;
    case ZYDIS_MNEMONIC_SETZ:
        if (insn.insn.operand_count >= 1)
        {
            const auto& op = insn.operands[0];
            if (op.type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                //SETZ reg (explicit uint8_t)
                println("\t{} = static_cast<uint8_t>((ctx.eflags.value & X86EFlags::ZF) ? 1 : 0);",
                    get_x86_reg(op.reg.value));
            }
            else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                //SETZ [mem]
                println("\tX86_STORE_U8({}, static_cast<uint8_t>((ctx.eflags.value & X86EFlags::ZF) ? 1 : 0));",
                    ea(op));
            }
        }
        break;
    case ZYDIS_MNEMONIC_SETNZ:
        if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
            println("\t{} = (ctx.eflags.value & X86EFlags::ZF) ? 0 : 1;",
                get_x86_reg(insn.operands[0].reg.value));
        }
        else if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            //SETNZ byte [mem]
            println("\tX86_STORE_U8({}, (ctx.eflags.value & X86EFlags::ZF) ? 0 : 1);",
                ea(insn.operands[0]));
        }
        break;
    case ZYDIS_MNEMONIC_SETNS:
        println("\t{} = !ctx.eflags.SF;", get_x86_reg(insn.operands[0].reg.value));
        break;
    case ZYDIS_MNEMONIC_SETNLE:
        println("\t{} = !ctx.eflags.ZF && (ctx.eflags.SF == ctx.eflags.OF);",
            get_x86_reg(insn.operands[0].reg.value));
        break;
    case ZYDIS_MNEMONIC_UCOMISS:
    {
        const auto& op2 = insn.operands[1];
        std::string src;

        if (op2.type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            if (op2.reg.value < ZYDIS_REGISTER_XMM0 || op2.reg.value > ZYDIS_REGISTER_XMM15)
            {
                throw std::runtime_error("UCOMISS second operand must be XMM or memory");
            }
            src = fmt::format("_mm_cvtss_f32({})", get_x86_reg(op2.reg.value, true));
        }
        else if (op2.type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            src = fmt::format("(float)X86_LOAD_F32({})", ea(op2));
        }
    }
    break;
    case ZYDIS_MNEMONIC_LAHF:
        println("\tctx.eax.u8_hi = ctx.eflags.value & 0xFF;");
        break;
    case ZYDIS_MNEMONIC_SLDT: //unused ?
        //println("\tX86_STORE_U16({}, ctx.ldtr);", ea(insn.operands[0]));
        break;
    case ZYDIS_MNEMONIC_SGDT:
        println("\tX86_STORE_U16({}, ctx.gdtr.limit);", ea(insn.operands[0]));
        println("\tX86_STORE_U32({}+2, ctx.gdtr.base);", ea(insn.operands[0]));
        break;
    case ZYDIS_MNEMONIC_NOP:
    case ZYDIS_MNEMONIC_INT3:
        break;
    default:
        return false;
    }


    return true;
}

std::unordered_set<std::string> instMissing;
bool Recompiler::Recompile(const Function& fn)
{
    auto base = fn.base;
    auto end = base + fn.size;
    auto* data = static_cast<const uint8_t*>(image.Find(base));

    static std::unordered_set<size_t> labels;
    labels.clear();

    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
    ZydisDecodedInstruction insn;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    //Collect labels from jumps and mid-assembly hooks
    for (size_t addr = base; addr < end; addr += insn.length)
    {
        size_t offset = addr - base;
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, data + offset, end, &insn, operands)))
        {
            addr++;
            continue;
        }

        auto invalidInstr = config.invalidInstructions.find(addr);
        if (invalidInstr != config.invalidInstructions.end())
        {
            continue;
        }

        if (isAddressRangeBanned(&config.bannedAddresses, addr))
        {
            continue;
        }

        auto switchTable = config.switchTables.find(addr);
        if (switchTable != config.switchTables.end())
        {
            for (auto label : switchTable->second.labels)
                labels.emplace(label);
        }

        // Handle jumps
        if (insn.mnemonic >= ZYDIS_MNEMONIC_JB && insn.mnemonic <= ZYDIS_MNEMONIC_JZ)
        {
            if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                size_t targetAddr = addr + insn.length + operands[0].imm.value.s;

                if (targetAddr > fn.base && targetAddr < fn.base + fn.size)
                    labels.emplace(targetAddr);
            }
        }

        // Handle mid-assembly hooks
        auto midAsmHook = config.midAsmHooks.find(addr);
        if (midAsmHook != config.midAsmHooks.end()) {
            if (midAsmHook->second.returnOnFalse || midAsmHook->second.returnOnTrue ||
                midAsmHook->second.jumpAddressOnFalse != NULL || midAsmHook->second.jumpAddressOnTrue != NULL)
            {
                print("extern bool ");
            }
            else {
                print("extern void ");
            }

            print("{}(", midAsmHook->second.name);
            for (auto& reg : midAsmHook->second.registers)
            {
                if (out.back() != '(')
                    out += ", ";
                print("uint32_t& {}", reg); // Map x86 registers to uint32_t
            }
            println(");\n");

            if (midAsmHook->second.jumpAddress != NULL)
                labels.emplace(midAsmHook->second.jumpAddress);
            if (midAsmHook->second.jumpAddressOnTrue != NULL)
                labels.emplace(midAsmHook->second.jumpAddressOnTrue);
            if (midAsmHook->second.jumpAddressOnFalse != NULL)
                labels.emplace(midAsmHook->second.jumpAddressOnFalse);
        }
    }

    // Generate function signature
    auto symbol = image.symbols.find(fn.base);
    std::string name;
    if (symbol != image.symbols.end()) {
        name = symbol->name;
    }
    else {
        name = fmt::format("sub_{:X}", fn.base);
    }

#ifdef XBOX_RECOMP_USE_ALIAS
    println("__attribute__((alias(\"__imp__{}\"))) X86_WEAK_FUNC({});", name, name);
#endif

    println("X86_FUNC_IMPL(__imp__{}) {{", name);
    //println("\tX86_FUNC_PROLOGUE();");

    auto switchTable = config.switchTables.end();
    bool allRecompiled = true;

    static std::string tempString;
    tempString.clear();
    std::swap(out, tempString);

    while (base < end)
    {


        if (isAddressRangeBanned(&config.bannedAddresses, base))
        {
            base += 1;
            continue;
        }

        // Handle labels
        if (labels.find(base) != labels.end())
        {
            println("loc_{:X}:", base);
        }

        if (switchTable == config.switchTables.end())
            switchTable = config.switchTables.find(base);


        size_t offset = base - fn.base;
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, data + offset, end, &insn, operands)))
        {
            fmt::println("Failed to decode instruction at 0x{:X}", base);
            allRecompiled = false;
            base += 1; // Skip to the next byte
            continue;
        }

        x86_insn ins = { insn, operands };
        RecompilerLocalVariables localvariables;
        CSRState csrState = CSRState::Unknown;

        // Recompile instruction
        if (!Recompile(fn, base, ins, data, switchTable, localvariables, csrState))
        {
            if (instMissing.count(ZydisMnemonicGetString(insn.mnemonic)) == 0)
            {
                instMissing.insert(ZydisMnemonicGetString(insn.mnemonic));
            }
            fmt::println("Unrecognized instruction at 0x{:X}: {}", base, ZydisMnemonicGetString(insn.mnemonic));


            allRecompiled = false;
        }

        base += insn.length;
    }

    println("}}\n");

#ifndef XBOX_RECOMP_USE_ALIAS
    println("X86_WEAK_FUNC({}) {{", name);
    println("\t__imp__{}(ctx, base);", name);
    println("}}\n");
#endif

    std::swap(out, tempString);
    out += tempString;

    return allRecompiled;
}

void Recompiler::Recompile(const std::filesystem::path& headerFilePath)
{
    out.reserve(10 * 1024 * 1024);

    {
        println("#pragma once");

        println("#ifndef X86_CONFIG_H_INCLUDED");
        println("#define X86_CONFIG_H_INCLUDED\n");

        //if we ever add x86 optmisation through config, add them here

        println("");

        println("#define X86_IMAGE_BASE 0x{:X}ull", image.base);
        println("#define X86_IMAGE_SIZE 0x{:X}ull", image.size);

        // Extract the address of the minimum code segment to store the function table at.
        size_t codeMin = ~0;
        size_t codeMax = 0;

        for (auto& section : image.sections)
        {
            if ((section.flags & SectionFlags_Code) != 0)
            {
                if (section.base < codeMin)
                    codeMin = section.base;

                if ((section.base + section.size) > codeMax)
                    codeMax = (section.base + section.size);
            }
        }

        println("#define X86_CODE_BASE 0x{:X}ull", codeMin);
        println("#define X86_CODE_SIZE 0x{:X}ull", codeMax - codeMin);

        println("");

        println("#ifdef X86_INCLUDE_DETAIL");
        println("#include \"x86_detail.h\"");
        println("#endif");

        println("\n#endif");

        SaveCurrentOutData("x86_config.h");
    }

    {
        println("#pragma once");

        println("#include \"x86_config.h\"\n");

        std::ifstream stream(headerFilePath);
        if (stream.good())
        {
            std::stringstream ss;
            ss << stream.rdbuf();
            out += ss.str();
        }

        SaveCurrentOutData("x86_context.h");
    }

    {
        println("#pragma once\n");
        println("#include \"x86_config.h\"");
        println("#include \"x86_context.h\"\n");

        for (auto& symbol : image.symbols)
            println("X86_EXTERN_FUNC({});", symbol.name);

        SaveCurrentOutData("x86_recomp_shared.h");
    }

    {
        println("#include \"x86_recomp_shared.h\"\n");

        println("X86FuncMapping X86FuncMappings[] = {{");
        for (auto& symbol : image.symbols)
            println("\t{{ 0x{:X}, {} }},", symbol.address, symbol.name);

        println("\t{{ 0, nullptr }}");
        println("}};");

        SaveCurrentOutData("x86_func_mapping.cpp");
    }

    int count = 0;
    for (size_t i = 0; i < functions.size(); i++)
    {
        if ((i % 256) == 0)
        {
            SaveCurrentOutData();
            println("#include \"x86_recomp_shared.h\"\n");
        }

        if ((i % 60) == 0 || (i == (functions.size() - 1)))
            fmt::println("Recompiling functions... {}%", static_cast<float>(i + 1) / functions.size() * 100.0f);

        if (functions[i].base >= 0x80000000)
        {
            printf("hi\n");
        }

        Recompile(functions[i]);
    }

    if (instMissing.size() > 0)
    {
        printf("missing following instructions:\n");
    }
    for (auto s : instMissing)
    {
        printf("%s\n", s.c_str());
    }
    SaveCurrentOutData();
}

void Recompiler::SaveCurrentOutData(const std::string_view& name)
{
    if (!out.empty())
    {
        std::string cppName;

        if (name.empty())
        {
            cppName = fmt::format("x86_recomp.{}.cpp", cppFileIndex);
            ++cppFileIndex;
        }

        bool shouldWrite = true;

        // Check if an identical file already exists first to not trigger recompilation
        std::string directoryPath = config.directoryPath;
        if (!directoryPath.empty())
            directoryPath += "/";

        std::string filePath = fmt::format("{}{}/{}", directoryPath, config.outDirectoryPath, name.empty() ? cppName : name);
        FILE* f = fopen(filePath.c_str(), "rb");
        if (f)
        {
            static std::vector<uint8_t> temp;

            fseek(f, 0, SEEK_END);
            long fileSize = ftell(f);
            if (fileSize == out.size())
            {
                fseek(f, 0, SEEK_SET);
                temp.resize(fileSize);
                fread(temp.data(), 1, fileSize, f);

                shouldWrite = !XXH128_isEqual(XXH3_128bits(temp.data(), temp.size()), XXH3_128bits(out.data(), out.size()));
            }
            fclose(f);
        }

        if (shouldWrite)
        {
            f = fopen(filePath.c_str(), "wb");
            fwrite(out.data(), 1, out.size(), f);
            fclose(f);
        }

        out.clear();
    }
}
