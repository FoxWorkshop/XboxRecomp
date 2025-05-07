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
#include <util.h>


//will get identified when parsing XBE file.
size_t textBaseAddr = 0x11000;
size_t endHeader = textBaseAddr;



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


    return data[i + -1] == 0xCC && (data[i + -2] == 0xCC || data[i + -2] == 0xC3);
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

void remove_overlapping_functions(std::vector<Function>& functions)
{
    if (functions.empty())
        return;


    for (auto it = functions.begin(); it != functions.end(); )
    {
        // Find the next function that doesn't completely overlap with this one
        auto next_it = std::next(it);
        if (next_it == functions.end())
            break;

        const size_t current_end = it->base + it->size;
        const size_t next_end = next_it->base + next_it->size;

        // Check if functions overlap
        if (next_it->base < current_end)
        {
            // They overlap - keep the larger one
            if (it->size >= next_it->size)
            {
                // Current function is larger or equal - remove next
                next_it = functions.erase(next_it);
            }
            else
            {
                // Next function is larger - merge and remove next one
                it->size = (next_it->base + next_it->size) - it->base;
                next_it = functions.erase(next_it);
            }
        }
        else {
            // No overlap - move to next
            ++it;
        }
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

        if (!isCode || section.name != ".text")
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
                auto max = section.base + section.size - funcPtr;
                auto potentialEnd = max;

                if (i + 1 < funcsTable.size())
                    potentialEnd = (funcsTable[i + 1] - funcPtr) + funcPtr;
                else
                    potentialEnd = section.base + section.size; //if last function of the list, put size of the image as maximum length

                bool banned = isAddressRangeBanned(&config.bannedAddresses, funcPtr);

                if (banned)
                    continue;

                auto invalidInstr = config.invalidInstructions.find(funcPtr);
                if (invalidInstr != config.invalidInstructions.end())
                {
                    continue;
                }

                functions.emplace_back(Function::Analyze(code, potentialEnd, funcPtr, config.switchTables));

            }
        }

    }

    std::sort(functions.begin(), functions.end(), [](auto& lhs, auto& rhs) { return lhs.base < rhs.base; });
    functions.erase(std::unique(functions.begin(), functions.end()), functions.end());
    //std::sort(globalJumps.begin(), globalJumps.end(), [](auto& lhs, auto& rhs) { return lhs.instAddr < rhs.instAddr; });
    remove_overlapping_functions(functions);


    // Process manual functions from config (if any)
    for (auto& [address, size] : config.functions)
    {
        for (auto it = functions.begin(); it != functions.end(); )
        {
            auto funcEnd = it->base + it->size;

            if (address == it->base || (funcEnd > address && funcEnd <= address + size))
            {
                it = functions.erase(it);
            }
            else
            {
                ++it;
            }
        }

        functions.emplace_back(address, size);
    }

    std::sort(functions.begin(), functions.end(), [](auto& lhs, auto& rhs) { return lhs.base < rhs.base; });

    printf("Analysed %d functions.\n", functions.size());

    for (auto& fn : functions)
    {
        image.symbols.emplace(fmt::format("sub_{:X}", fn.base), fn.base, fn.size, Symbol_Function);
        outfileFunc << "{ address = 0x" << std::hex << fn.base << ", size = 0x" << std::hex << fn.size << " }," << std::endl;
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

inline const char* GetOperandTypeName(uint16_t size)
{
    switch (size) {
    case 8:
        return "uint8_t";
    case 16:
        return "uint16_t";
    case 32:
        return "uint32_t";
    default: throw std::runtime_error("Unsupported operand size");
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
};


template <>
struct fmt::formatter<ImmWrapper> {
    constexpr auto parse(fmt::format_parse_context& ctx)
    {
        return ctx.begin();
    }

    template <typename FormatContext>
    auto format(const ImmWrapper& wrapper, FormatContext& ctx) const
    {
        // Format as hex with "0x" prefix
        return fmt::format_to(ctx.out(), "0x{:x}", wrapper.imm.value.u);
    }
};


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
    case ZYDIS_REGISTER_AX:
    case ZYDIS_REGISTER_AL:
    case ZYDIS_REGISTER_AH:
        return "eax";
    case ZYDIS_REGISTER_EBX:
    case ZYDIS_REGISTER_BX:
    case ZYDIS_REGISTER_BL:
    case ZYDIS_REGISTER_BH:
        return "ebx";
    case ZYDIS_REGISTER_ECX:
    case ZYDIS_REGISTER_CX:
    case ZYDIS_REGISTER_CL:
    case ZYDIS_REGISTER_CH:
        return "ecx";
    case ZYDIS_REGISTER_EDX:
    case ZYDIS_REGISTER_DX:
    case ZYDIS_REGISTER_DL:
    case ZYDIS_REGISTER_DH:
        return "edx";
    case ZYDIS_REGISTER_ESI:
    case ZYDIS_REGISTER_SI:
        return "esi";
    case ZYDIS_REGISTER_EDI:
    case ZYDIS_REGISTER_DI:
        return "edi";
    case ZYDIS_REGISTER_EBP:
    case ZYDIS_REGISTER_BP:
        return "ebp";
    case ZYDIS_REGISTER_ESP:
    case ZYDIS_REGISTER_SP:
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

std::string format_fp_operand(const ZydisDecodedOperand& op, bool isDouble)
{
    if (op.type != ZYDIS_OPERAND_TYPE_IMMEDIATE)
        return "/* not an immediate */";

    std::ostringstream ss;

    if (isDouble)
    {
        double val;
        std::memcpy(&val, &op.imm.value.u, sizeof(double));
        ss << val;
    }
    else
    {
        float val;
        std::uint32_t temp = static_cast<std::uint32_t>(op.imm.value.u);
        std::memcpy(&val, &temp, sizeof(float));
        ss << val;
    }

    return ss.str();
}


bool Recompiler::Recompile(
    const Function& fn,
    uint32_t base,
    const x86_insn& insn,
    const uint8_t* data,
    std::unordered_map<uint32_t, RecompilerSwitchTable>::iterator& switchTable,
    RecompilerLocalVariables& localVariables,
    CSRState& csrState, RecompilerFuncConfig& funcConfig)
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
                if (reg >= ZYDIS_REGISTER_MM0 && reg <= ZYDIS_REGISTER_MM7)
                {
                    return fmt::format("ctx.mmx[{}]", reg - ZYDIS_REGISTER_MM0);
                }

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

            if (reg == ZYDIS_REGISTER_EFLAGS)
            {
                return "ctx.eflags.value";  // Return the value stored in eflags
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
                switch (reg)
                {
                case ZYDIS_REGISTER_AL:
                case ZYDIS_REGISTER_BL:
                case ZYDIS_REGISTER_CL:
                case ZYDIS_REGISTER_DL:
                    return fmt::format("ctx.{}.u8_lo", reg_name);

                case ZYDIS_REGISTER_AH:
                case ZYDIS_REGISTER_BH:
                case ZYDIS_REGISTER_CH:
                case ZYDIS_REGISTER_DH:
                    return fmt::format("ctx.{}.u8_hi", reg_name);

                default:
                    throw std::runtime_error("Unsupported 8-bit subregister");
                }
                break;
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

    auto get_fp_reg = [&](ZydisRegister reg) -> std::string
        {
            if (reg >= ZYDIS_REGISTER_XMM0 && reg <= ZYDIS_REGISTER_XMM7)
                return fmt::format("ctx.xmm[{}]", reg - ZYDIS_REGISTER_XMM0);

            if (reg >= ZYDIS_REGISTER_ST0 && reg <= ZYDIS_REGISTER_ST7)
                return fmt::format("ctx.fpu.st{}()", reg - ZYDIS_REGISTER_ST0);

            if (reg == ZYDIS_REGISTER_MXCSR)
                return "ctx.mxcsr";

            throw std::runtime_error(fmt::format("Unsupported floating-point register: {}", ZydisRegisterGetString(reg)));
        };

    enum class FPBackend {
        X87,
        SSE
    };

    // SIMD registers (XMM0-XMM7)
    auto xmm = [&](size_t index) {
        if (index >= 8) {
            throw std::out_of_range("Invalid XMM index");
        }

        if (config.floatingPointRegistersAsLocalVariables)
        {
            localVariables.xmm[index] = true;
            return fmt::format("xmm[{}]", index);
        }
        return fmt::format("ctx.xmm[{}]", index);
        };

    auto ea = [&](const ZydisDecodedOperand& memOp, bool address_mode = false) -> std::string {
        std::string result;

        // Helper to get address-ready register string (always .u32)
        auto get_addr_reg = [&](ZydisRegister reg) -> std::string
            {
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


    auto HandleFsValue = [&](uint8_t offset, std::string reg, bool is_write = false)
        {
            // Host-side TEB/KPCR structure (kpcr_ptr points to this)

            std::string kpcr_access = fmt::format("X86_LOAD_U32(ctx.kpcr_ptr + 0x{:X})", offset);

            if (is_write)
                kpcr_access = fmt::format("X86_STORE_U32(ctx.kpcr_ptr + 0x{:X})", offset);


            switch (offset)
            {
            case 0x00:  // NT_TIB.ExceptionList (SEH Chain)
            case 0x1C:  // NT_TIB.Self 
            case 0x20:  // KPCR->Prcb
            case 0x24:  // KPCR->Irql
            case 0x28:  // KPCR->PrcbData
                if (is_write) {
                    println("\t{} = {};  // Host write to FS:[0x{:X}]", kpcr_access, reg, offset);
                }
                else {
                    println("\t{} = {};  // Host read from FS:[0x{:X}]", reg, kpcr_access, offset);
                }
                break;

            case 0x04:  // FS:[4] = StackBase
                if (is_write) {
                    println("\t{} = {};  // Guest write to FS:[4] (TLS mid-array)", kpcr_access, reg);
                }
                else {
                    println("\t{} = {};  // Guest read from FS:[4] (TLS mid-array)", reg, kpcr_access);
                }
                break;

                // --- Default: Unknown offsets ---
            default:
                if (is_write) {
                    println("\t{} = {};  // WARNING: Unknown FS write at 0x{:X}", kpcr_access, reg, offset);
                }
                else {
                    println("\t{} = 0;  // WARNING: Unknown FS read at 0x{:X}", reg, offset);
                }
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
                    return 1;
                }
            }
            else {
                // Log an error for unknown functions
                println("\tprintf(\"WARNING UNKNOWN FUNCTION REACHED {:X} at: {:X}\\n\");", address, base);
                println("\t// ERROR: Unknown function at 0x{:X}", address);
            }

            return 0;
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


        std::string targetStr = fmt::format("0x{:X}", targetAddress);

        if (targetAddress == 0)
        {
            println("\tprintf(\"WARNING: Branch target resolves to 0x0 (possible analysis error) - {:X}\n\");", base);
            println("\t// WARNING: Branch target resolves to 0x0 (possible analysis error)");
            println("\tif ({}{}) goto invalid_target;", not_ ? "!" : "", cond);
        }
        else if (targetAddress < fn.base || targetAddress >= fn.base + fn.size)
        {
            // External function call
            println("\tif ({}{}) {{", not_ ? "!" : "", cond);
            printFunctionCallAddr(targetAddress);
            println("\treturn;");
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

    auto floatOperations = [&](std::string sign)
        {
            println("\tctx.fpu.clear_flags();");

            if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                println("\tvalDouble0 = ctx.fpu.st0() {} ctx.fpu.st{}();",
                    sign, insn.operands[0].reg.value - ZYDIS_REGISTER_ST0);
            }
            else {
                println("\tvalDouble0 = ctx.fpu.st0() {} X86_LOAD_F64({});",
                    sign, ea(insn.operands[0]));
            }

            println("\tctx.fpu.st0() = ctx.fpu.round_to_control(valDouble0);");
            println("\tctx.fpu.set_exception_flags(ctx.fpu.st0());");

            if (sign == "/")
            {
                println("\tif (!std::isfinite(valDouble0) && valDouble0 == ctx.fpu.st0() {} 0.0) {{", sign);
                println("\t    ctx.fpu.sw |= X87FPU::C3; //DIVZERO flag");
                println("\t}}");
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

    auto format_operand = [&](const ZydisDecodedOperand& op, const char* size_suffix = "U32") -> std::string {
        if (op.type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            return get_x86_reg(op.reg.value);
        }
        else if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            return fmt::format("0x{:X}u", static_cast<uint32_t>(op.imm.value.u));
        }
        else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            return fmt::format("X86_LOAD_{}({})", size_suffix, ea(op));
        }
        return "";
        };

    auto get_temp_reg = [&](ZyanU16 size)
        {
            return fmt::format("temp_{:X}_{}", base, GetOperandSizeName(size));
        };

    auto handle_bitwise = [&](const char* op, const char* flag_updater = "update_flags_logic") {
        if (insn.insn.operand_count >= 2) {
            const auto& dst = insn.operands[0];
            const auto& src = insn.operands[1];
            const char* size_suffix = GetOperandSizeName(dst.size);

            auto mask_imm = [size_suffix](uint64_t imm) -> uint64_t {
                if (strcmp(size_suffix, "U8") == 0) return imm & 0xFF;
                if (strcmp(size_suffix, "U16") == 0) return imm & 0xFFFF;
                return imm & 0xFFFFFFFF; // Default 32-bit
                };

            if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                std::string temp_res = get_temp_reg(dst.size);
                println("\tauto {} = X86_LOAD_{}({});", temp_res, size_suffix, ea(dst));

                if (src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    println("\t{} {} {:#x};", temp_res, op, mask_imm(src.imm.value.u));
                }
                else {
                    println("\t{} {} {};", temp_res, op, format_operand(src, size_suffix));
                }

                println("\tX86_STORE_{}({}, {});", size_suffix, ea(dst), temp_res);
                println("\tctx.eflags.{}({});", flag_updater, temp_res);
            }
            else {
                if (src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    println("\t{} {} {:#x};",
                        format_operand(dst, size_suffix),
                        op,
                        mask_imm(src.imm.value.u));
                }
                else {
                    println("\t{} {} {};",
                        format_operand(dst, size_suffix),
                        op,
                        format_operand(src, size_suffix));
                }
                println("\tctx.eflags.{}({});", flag_updater, format_operand(dst, size_suffix));
            }
        }
        };

    auto get_st_index = [](ZydisRegister reg) {
        constexpr uint8_t ST0_ID = ZYDIS_REGISTER_ST0;
        uint8_t index = reg - ST0_ID;
        assert(index < 8); // Safety check
        return index;
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
    case ZYDIS_MNEMONIC_ADC:
        if (insn.insn.operand_count >= 2) 
        {
            const auto& dst = insn.operands[0];
            const auto& src = insn.operands[1];
            const char* size_suffix = GetOperandSizeName(dst.size);

            // Save the CF value before operation
            println("\tvalUint320 = ctx.eflags.value & X86EFlags::CF ? 1 : 0;");

            if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                std::string temp_old = get_temp_reg(dst.size) + "_OLD";
                std::string temp_src = get_temp_reg(dst.size) + "_SRC";
                std::string temp_res = get_temp_reg(dst.size) + "_RES";

                // Load destination value
                println("\tauto {} = X86_LOAD_{}({});", temp_old, size_suffix, ea(dst));

                // Load source value into a temporary variable
                if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    println("\tauto {} = {};", temp_src, get_x86_reg(src.reg.value));
                }
                else if (src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    println("\tauto {} = {};", temp_src, src.imm.value.u);
                }
                else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                    println("\tauto {} = X86_LOAD_{}({});", temp_src, size_suffix, ea(src));
                }

                // Calculate result
                println("\tauto {} = {} + {} + valUint320;", temp_res, temp_old, temp_src);
                println("\tX86_STORE_{}({}, {});", size_suffix, ea(dst), temp_res);
                println("\tctx.eflags.update_flags_adc({}, {}, valUint320, {});", temp_old, temp_src, temp_res);
            }
            else { // Register destination
                std::string dst_reg = get_x86_reg(dst.reg.value);
                std::string temp_old = get_temp_reg(dst.size) + "_OLD";
                std::string temp_src = get_temp_reg(dst.size) + "_SRC";

                // Save original destination value
                println("\tauto {} = {};", temp_old, dst_reg);

                // Get source value
                if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    println("\tauto {} = {};", temp_src, get_x86_reg(src.reg.value));
                }
                else if (src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    println("\tauto {} = {};", temp_src, src.imm.value.u);
                }
                else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                    println("\tauto {} = X86_LOAD_{}({});", temp_src, size_suffix, ea(src));
                }

                println("\t{} = {} + {} + valUint320;", dst_reg, temp_old, temp_src);
                println("\tctx.eflags.update_flags_adc({}, {}, valUint320, {});", temp_old, temp_src, dst_reg);
            }
        }
        break;
    case ZYDIS_MNEMONIC_ADDPS:
        if (insn.insn.operand_count >= 2)
        {
            const auto& dst = insn.operands[0];
            const auto& src = insn.operands[1];

            if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                src.type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                println("\tX86_ADDPS({}, {});", static_cast<unsigned>(dst.reg.value - ZYDIS_REGISTER_XMM0),
                    static_cast<unsigned>(src.reg.value - ZYDIS_REGISTER_XMM0));
            }
        }
        break;
    case ZYDIS_MNEMONIC_BSF:
        if (insn.insn.operand_count >= 2)
        {
            const auto& dst = insn.operands[0];
            const auto& src = insn.operands[1];
            const char* size_suffix = GetOperandSizeName(src.size);

            // Load source operand into a temporary
            std::string temp_src = get_temp_reg(src.size);
            println("\tauto {} = {};", temp_src, format_operand(src, size_suffix));

            // Check for zero and update ZF accordingly
            println("\tif ({} == 0) {{", temp_src);
            println("\t\tctx.eflags.value |= X86EFlags::ZF;");
            println("\t}} else {{");
            println("\t\tctx.eflags.value &= ~X86EFlags::ZF;");

            // Use built-in compiler function to find first set bit
            println("\t\t{} = __builtin_ctz({});", format_operand(dst, size_suffix), temp_src);
            println("\t}}");
        }
        break;
    case ZYDIS_MNEMONIC_PUSH:

        //xbox kernel stuff
        if (insn.operands[0].mem.segment == ZYDIS_REGISTER_FS)
        {
            uint32_t offset = insn.operands[0].mem.disp.value;
            std::string tempVar = "tmp_value_" + std::to_string(base);
            println("\tuint32_t {};", tempVar);
            HandleFsValue(offset, tempVar);
            println("\tX86_PUSH(ctx, base, {});", tempVar);
            break;
        }

        if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
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
    case ZYDIS_MNEMONIC_PSHUFW:
        if (insn.insn.operand_count >= 3) {
            const auto& dst = insn.operands[0];
            const auto& src = insn.operands[1];
            const auto& imm = insn.operands[2];

            const std::string dst_reg = fmt::format("ctx.mmx[{}]",
                dst.reg.value - ZYDIS_REGISTER_MM0);

            if (src.type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                println("\t{} = X86_PSHUFW(ctx.mmx[{}], 0x{:02X});", dst_reg, src.reg.value - ZYDIS_REGISTER_MM0, imm.imm.value.u & 0xFF);
            }
            else
            {
                println("\t{} = X86_PSHUFW(X86_LOAD_U64({}), 0x{:02X});", dst_reg, ea(src), imm.imm.value.u & 0xFF);
            }
        }
        break;
    case ZYDIS_MNEMONIC_MOV:
        if (insn.insn.operand_count >= 2)
        {
            const auto& dst = insn.operands[0];
            const auto& src = insn.operands[1];
            const char* srcSizeSuffix = GetOperandSizeName(src.size);
            uint32_t size = dst.size;

            //FS is Xbox kernel stuff
            //handle FS register (kernel and xbox memory stuff, e.g "FS:[0x20]")
            if (src.type == ZYDIS_OPERAND_TYPE_MEMORY && src.mem.segment == ZYDIS_REGISTER_FS)
            {
                // MOV reg, FS:[offset]
                uint32_t offset = (uint32_t)src.mem.disp.value;

                if (offset == 0x4) //stackbase
                {
                    funcConfig.isFS = true; //next mov instruction will adjust the ptr we will need to resolve it
                    funcConfig.RegisterStackBaseAddr = get_x86_reg(dst.reg.value);
                    println("\t{} = (ctx.kpcr_ptr + 0x4);  //Read FS Stack Base", get_x86_reg(dst.reg.value));
                }
                // Special case: FS:[0x24] is 8-bit IRQL
                else if (offset == 0x24)
                {
                    println("\t{} = X86_LOAD_U8(ctx.kpcr_ptr + 0x24);  //Read IRQL",
                        get_x86_reg(dst.reg.value));
                    if (size > 8) println("\t{} = (uint8_t)({});  //Truncate to 8-bit",
                        get_x86_reg(dst.reg.value), get_x86_reg(dst.reg.value));
                }
                // Default: Host pointer read
                else
                {
                    println("\t{} = (ctx.kpcr_ptr + 0x{:X});", get_x86_reg(dst.reg.value), offset);
                }
                break;
            }
            else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY && dst.mem.segment == ZYDIS_REGISTER_FS)
            {
                // MOV FS:[offset], reg
                uint32_t offset = (uint32_t)dst.mem.disp.value;

                // Special case: FS:[4] expects a guest virtual address
                if (offset == 0x4)
                {
                    println("\tX86_STORE_U32((ctx.kpcr_ptr + 0x4), {});", get_x86_reg(src.reg.value));
                }
                // Special case: FS:[0x24] is 8-bit IRQL
                else if (offset == 0x24) {
                    println("\tX86_STORE_U8((ctx.kpcr_ptr + 0x24), (uint8_t)({}));  // Write IRQL",
                        get_x86_reg(src.reg.value));
                }
                // Default: Host pointer write
                else
                {
                    println("\tX86_STORE_U32((ctx.kpcr_ptr + 0x{:X}), {});", offset, get_x86_reg(src.reg.value));
                }
                break;
            }

            const char* size_suffix = GetOperandSizeName(dst.size);
            std::string src_str = format_operand(src, size_suffix);
            std::string dst_str = get_x86_reg(dst.reg.value); // Always a register for MOV

            if (!src_str.empty())
            {
                // Special case for memory destinations
                if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY)
                {
                    println("\tX86_STORE_{}({}, {});",
                        size_suffix, ea(dst), src_str);
                }
                else
                {
                    if (funcConfig.isFS == true)
                    {
                        src_str = src_str;
                    }
                    if (funcConfig.isFS == true && src_str.find(funcConfig.RegisterStackBaseAddr) != std::string::npos)
                    {
                        //hacky fix to handle FS 0x4 ptr shenanigans
                        if (src_str.find("X86_LOAD") != std::string::npos)
                        {
                            auto index = src_str.find("(");
                            if (index != std::string::npos)
                                src_str = src_str.substr(index); //Keep everything from '(' onward

                            funcConfig.isFS = false;
                        }

                    }
                    println("\t{} = {};", dst_str, src_str);
                }
            }
        }
        break;
    case ZYDIS_MNEMONIC_MOVQ:
        if (insn.insn.operand_count >= 2) {
            const auto& dst = insn.operands[0];
            const auto& src = insn.operands[1];

            if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                src.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                ZydisRegisterGetClass(dst.reg.value) == ZYDIS_REGCLASS_MMX &&
                ZydisRegisterGetClass(src.reg.value) == ZYDIS_REGCLASS_MMX)
            {
                println("\tctx.mmx[{}] = ctx.mmx[{}];",
                    static_cast<unsigned>(dst.reg.value - ZYDIS_REGISTER_MM0),
                    static_cast<unsigned>(src.reg.value - ZYDIS_REGISTER_MM0));
            }
            // 2. MMX to memory
            else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                src.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                ZydisRegisterGetClass(src.reg.value) == ZYDIS_REGCLASS_MMX)
            {
                println("\tX86_STORE_U64({}, ctx.mmx[{}]);",
                    ea(dst),
                    static_cast<unsigned>(src.reg.value - ZYDIS_REGISTER_MM0));
            }
            // 3. Memory to MMX
            else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                ZydisRegisterGetClass(dst.reg.value) == ZYDIS_REGCLASS_MMX)
            {
                println("\tctx.mmx[{}] = X86_LOAD_U64({});",
                    static_cast<unsigned>(dst.reg.value - ZYDIS_REGISTER_MM0),
                    ea(src));
            }
            else
            {

                // Handle XMM register to memory/register
                if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                    src.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    ZydisRegisterGetClass(src.reg.value) == ZYDIS_REGCLASS_XMM) {

                    // Extract lower 64-bits from XMM and store to memory
                    println("\tX86_STORE_U64({}, *reinterpret_cast<uint64_t*>(&ctx.vec[{}].u32[0]));",
                        ea(dst), src.reg.value - ZYDIS_REGISTER_XMM0);
                }
                // Handle memory/register to XMM register
                else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                    dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    ZydisRegisterGetClass(dst.reg.value) == ZYDIS_REGCLASS_XMM) {

                    // Load 64-bits from memory to XMM (zeroing upper 64-bits)
                    println("\t*reinterpret_cast<uint64_t*>(&ctx.vec[{}].u32[0]) = X86_LOAD_U64({});",
                        dst.reg.value - ZYDIS_REGISTER_XMM0, ea(src));
                    println("\tctx.vec[{}].u32[2] = 0;", dst.reg.value - ZYDIS_REGISTER_XMM0);
                    println("\tctx.vec[{}].u32[3] = 0;", dst.reg.value - ZYDIS_REGISTER_XMM0);
                }
                // Handle XMM to XMM transfer
                else if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    src.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    ZydisRegisterGetClass(dst.reg.value) == ZYDIS_REGCLASS_XMM &&
                    ZydisRegisterGetClass(src.reg.value) == ZYDIS_REGCLASS_XMM) {

                    println("\tctx.vec[{}].u32[0] = ctx.vec[{}].u32[0];",
                        dst.reg.value - ZYDIS_REGISTER_XMM0,
                        src.reg.value - ZYDIS_REGISTER_XMM0);
                    println("\tctx.vec[{}].u32[1] = ctx.vec[{}].u32[1];",
                        dst.reg.value - ZYDIS_REGISTER_XMM0,
                        src.reg.value - ZYDIS_REGISTER_XMM0);
                    println("\tctx.vec[{}].u32[2] = 0;", dst.reg.value - ZYDIS_REGISTER_XMM0);
                    println("\tctx.vec[{}].u32[3] = 0;", dst.reg.value - ZYDIS_REGISTER_XMM0);
                }
                else if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    ZydisRegisterGetClass(dst.reg.value) == ZYDIS_REGCLASS_XMM &&
                    src.type == ZYDIS_OPERAND_TYPE_REGISTER) {

                    println("\t*reinterpret_cast<uint64_t*>(&ctx.vec[{}].u32[0]) = {};",
                        dst.reg.value - ZYDIS_REGISTER_XMM0,
                        format_operand(src, "U64"));
                    println("\tctx.vec[{}].u32[2] = 0;", dst.reg.value - ZYDIS_REGISTER_XMM0);
                    println("\tctx.vec[{}].u32[3] = 0;", dst.reg.value - ZYDIS_REGISTER_XMM0);
                }
                // XMM to general purpose register
                else if (src.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    ZydisRegisterGetClass(src.reg.value) == ZYDIS_REGCLASS_XMM &&
                    dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {

                    println("\t{} = *reinterpret_cast<uint64_t*>(&ctx.vec[{}].u32[0]);",
                        format_operand(dst, "U64"),
                        src.reg.value - ZYDIS_REGISTER_XMM0);
                }
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
    case ZYDIS_MNEMONIC_MOVUPS:
        if (insn.insn.operand_count >= 2)
        {
            const auto& dst = insn.operands[0];
            const auto& src = insn.operands[1];

            // MOVUPS xmm1, xmm2 (XMM ← XMM)
            if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                src.type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                println("\tX86_MOVAPS_REG({}, {});", static_cast<unsigned>(dst.reg.value - ZYDIS_REGISTER_XMM0), static_cast<unsigned>(src.reg.value - ZYDIS_REGISTER_XMM0));
            }
            // MOVUPS xmm1, [mem] (XMM ← memory)
            else if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                src.type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                println("\tX86_MOVUPS({}, {});", static_cast<unsigned>(dst.reg.value - ZYDIS_REGISTER_XMM0), ea(src));
            }
            // MOVUPS [mem], xmm1 (memory ← XMM)
            else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                src.type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                println("\tX86_MOVUPS_STORE({}, {});", ea(dst), static_cast<unsigned>(src.reg.value - ZYDIS_REGISTER_XMM0));
            }
        }
        break;
    case ZYDIS_MNEMONIC_MOVLHPS:
        if (insn.insn.operand_count >= 2)
        {
            const auto& dst = insn.operands[0];
            const auto& src = insn.operands[1];

            if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                src.type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                println("\tX86_MOVLHPS({}, {});",
                    dst.reg.value - ZYDIS_REGISTER_XMM0,
                    src.reg.value - ZYDIS_REGISTER_XMM0);
            }
            else
            {
                println("\t// ERROR: Invalid MOVLHPS operands");
            }
        }
        break;

    case ZYDIS_MNEMONIC_MOVHLPS:
        if (insn.insn.operand_count >= 2)
        {
            const auto& dst = insn.operands[0];
            const auto& src = insn.operands[1];

            if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                src.type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                println("\tX86_MOVHLPS({}, {});",
                    dst.reg.value - ZYDIS_REGISTER_XMM0,
                    src.reg.value - ZYDIS_REGISTER_XMM0);
            }
        }
        break;

    case ZYDIS_MNEMONIC_MOVNTPS:
        if (insn.insn.operand_count >= 2)
        {
            const auto& dst = insn.operands[0];
            const auto& src = insn.operands[1];

            if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                src.type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                println("\tX86_MOVNTPS({}, {});",
                    ea(dst),
                    src.reg.value - ZYDIS_REGISTER_XMM0);
            }
        }
        break;
    case ZYDIS_MNEMONIC_CMP:
        if (insn.insn.operand_count >= 2)
        {
            auto size = insn.operands[0].size;
            const char* size_suffix = GetOperandSizeName(insn.operands[0].size);
            const char* type_name = GetOperandTypeName(insn.operands[0].size);
            // Handle memory-to-register compares (e.g., `cmp [eax], eax`)
            if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                std::string lhs = fmt::format("X86_LOAD_{}({})", size_suffix, ea(insn.operands[0]));
                std::string rhs;

                if (insn.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
                {
                    // Register operand (e.g., EAX)
                    rhs = fmt::format("ctx.{}.u32", get_register_name(insn.operands[1].reg.value), size_suffix == "U8" ? "u8" :
                        size_suffix == "U16" ? "u16" : "u32");
                }
                else if (insn.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) 
                {
                    // Immediate operand (e.g., `cmp [eax], 0x42`)
                    const char* cast_type = size_suffix == "U8" ? "uint8_t" :
                        size_suffix == "U16" ? "uint16_t" : "uint32_t";
                    rhs = fmt::format("static_cast<{}>({:#x}u)", cast_type,
                        insn.operands[1].imm.value.u);
                }
                else {
                    throw std::runtime_error("Unsupported CMP operand type");
                }

                println("\tctx.eflags.update_compare_flags<{}>({}, {});", type_name, lhs, rhs);
            }
            else 
            {
                // Default handling for non-memory operands
                std::string lhs = format_operand(insn.operands[0], size_suffix);
                std::string rhs = format_operand(insn.operands[1], size_suffix);
                println("\tctx.eflags.update_compare_flags<{}>({}, {});", type_name, lhs, rhs);
            }
        }
        break;
    case ZYDIS_MNEMONIC_CMOVNZ:
        if (insn.insn.operand_count >= 2)
        {
            const auto& dst = insn.operands[0];
            const auto& src = insn.operands[1];

            println("\tif ((ctx.eflags.value & X86EFlags::ZF) == 0) {{");

            if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                println("\t    {} = {};", get_x86_reg(dst.reg.value),
                    src.type == ZYDIS_OPERAND_TYPE_REGISTER ?
                    get_x86_reg(src.reg.value) :
                    fmt::format("X86_LOAD_{}({})", GetOperandSizeName(dst.size), ea(src)));
            }
            else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                println("\t    X86_STORE_{}({}, {});", GetOperandSizeName(dst.size), ea(dst),
                    src.type == ZYDIS_OPERAND_TYPE_REGISTER ?
                    get_x86_reg(src.reg.value) :
                    fmt::format("X86_LOAD_{}({})", GetOperandSizeName(dst.size), ea(src)));
            }
            println("\t}}");
        }
        break;

    case ZYDIS_MNEMONIC_CMOVNLE:
        if (insn.insn.operand_count >= 2)
        {
            const auto& dst = insn.operands[0];
            const auto& src = insn.operands[1];


            println("\tif (((ctx.eflags.value & X86EFlags::ZF) == 0) && (((ctx.eflags.value & X86EFlags::SF) != 0) == ((ctx.eflags.value & X86EFlags::OF) != 0))) {{");

            if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                println("\t    {} = {};", get_x86_reg(dst.reg.value),
                    src.type == ZYDIS_OPERAND_TYPE_REGISTER ?
                    get_x86_reg(src.reg.value) :
                    fmt::format("X86_LOAD_U{}({})", GetOperandSizeName(dst.size), ea(src)));
            }
            else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                println("\t    X86_STORE_{}({}, {});", GetOperandSizeName(dst.size), ea(dst),
                    src.type == ZYDIS_OPERAND_TYPE_REGISTER ?
                    get_x86_reg(src.reg.value) :
                    fmt::format("X86_LOAD_U{}({})", GetOperandSizeName(dst.size), ea(src)));
            }
            println("\t}}");
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
    {

        if (insn.insn.operand_count >= 1)
        {
            // Direct call (relative offset)
            if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                println("\tctx.esp.u32 -= 0x4; //Adjust stack pointer"); //in x86, the cpu always adjust the stack pointer by 4 bytes regardless of call convention
                uint32_t targetAddress = base + insn.insn.length + insn.operands[0].imm.value.s;
                int res = printFunctionCallAddr(targetAddress);

                if (!res)
                {
                    println("\tctx.esp.u32 += 0x4; //function wasn't found, reAdjust stack pointer TODO FIX!!!!!");
                    println("\tprintf(\"MISSING FUNCTION CALL: {:X} at {:X}\\n\");", targetAddress, base);
                }
            }
            else if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {

                uint32_t targetAddress = insn.operands[0].mem.disp.value;
                const auto callDst = ResolveKernelCall(targetAddress);
                if (callDst)
                {
                    println("\tctx.esp.u32 -= 0x4; //Adjust stack pointer");
                    int res = printFunctionCallAddr(targetAddress);
                    if (!res)
                        println("\tctx.esp.u32 += 0x4; //function wasn't found, reAdjust stack pointer TODO FIX!!!!!");
                }
                else
                {
                    // Indirect call (memory operand)
                    println("\tauto ptr_{} = *(uint32_t*)(base + " + ea(insn.operands[0]) + ");", base);
                    println("\tctx.esp.u32 -= 0x4; //Adjust stack pointer");
                    println("\tX86_CALL_INDIRECT_FUNC(ptr_{});", base);
                }
            }
            else if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                // Register indirect (call eax)
                println("\tauto ptr_{} = " + get_x86_reg(insn.operands[0].reg.value) + ";", base);
                println("\tctx.esp.u32 -= 0x4; //Adjust stack pointer");
                println("\tX86_CALL_INDIRECT_FUNC(ptr_{});", base);
            }
        }
    }
    break;
    case ZYDIS_MNEMONIC_CDQ:
        println("\tctx.edx.u32 = (ctx.eax.i32 >> 31) * 0xFFFFFFFFu;");
        break;
    case ZYDIS_MNEMONIC_CLD:
        println("\tctx.eflags.set_df(false);  // Set forward direction");
        break;
    case ZYDIS_MNEMONIC_CMOVB:
        if (insn.insn.operand_count >= 2)
        {
            println("\tif ( (ctx.eflags.value & X86EFlags::CF)) {} = {};",
                get_x86_reg(insn.operands[0].reg.value),
                get_x86_reg(insn.operands[1].reg.value));
        }
        break;
    case ZYDIS_MNEMONIC_CMOVNB:
        if (insn.insn.operand_count >= 2)
        {
            println("\tif ( (ctx.eflags.value & X86EFlags::CF) == 0) {} = {};", get_x86_reg(insn.operands[0].reg.value), get_x86_reg(insn.operands[1].reg.value));
        }
        break;
    case ZYDIS_MNEMONIC_CVTTSS2SI:
        if (insn.insn.operand_count >= 2)
        {
            const auto& dst = insn.operands[0];
            const auto& src = insn.operands[1];

            // CVTTSS2SI reg32, xmm/m32
            if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                src.type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                println("\t{} = (int32_t)_mm_cvttss_si32({});",
                    get_x86_reg(dst.reg.value),
                    get_x86_reg(src.reg.value, true));         // XMM reg ('true')
            }
            else if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                src.type == ZYDIS_OPERAND_TYPE_MEMORY)
            {

                println("\t{} = (int32_t)_mm_cvttss_si32(_mm_load_ss((const float*)(&X86_LOAD_F32({}))));", get_x86_reg(dst.reg.value), ea(src));
            }
        }
        break;
    case ZYDIS_MNEMONIC_CVTSI2SS:
        if (insn.insn.operand_count >= 2)
        {
            const auto& dst = insn.operands[0];
            const auto& src = insn.operands[1];

            // CVTSI2SS xmm, reg32/m32
            if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                src.type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                println("\t{} = _mm_cvtsi32_ss({}, {});",
                    get_x86_reg(dst.reg.value, true),  
                    get_x86_reg(dst.reg.value, true),  
                    get_x86_reg(src.reg.value));      
            }
            else if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                src.type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                println("\t{} = _mm_cvtsi32_ss({}, (int32_t)X86_LOAD_U32({}));",
                    get_x86_reg(dst.reg.value, true),  
                    get_x86_reg(dst.reg.value, true),  
                    ea(src));
            }
        }
        break;
    case ZYDIS_MNEMONIC_CWDE:
        println("\tctx.eax.u32 = (int32_t)(int16_t)ctx.eax.u16;");
        break;
    case ZYDIS_MNEMONIC_FILD:
        if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            println("\tctx.fpu.clear_flags();");
            println("\tctx.fpu.push(static_cast<double>(X86_LOAD_U32({})));",
                ea(insn.operands[0]));
        }
        break;

    case ZYDIS_MNEMONIC_FADD:
        floatOperations("+");
        break;
    case ZYDIS_MNEMONIC_FADDP:
        if (insn.insn.operand_count == 0) 
        {
            // Implicit ST(1) = ST(0) + ST(1), then pop
            println("\tctx.fpu.st1() += ctx.fpu.st0();");
            println("\tctx.fpu.pop();");
            println("\tctx.fpu.set_exception_flags(ctx.fpu.st0());");
        }
        else if (insn.insn.operand_count >= 2) {
            const auto& dest = insn.operands[0];
            const auto& src = insn.operands[1];

            if (dest.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                src.type == ZYDIS_OPERAND_TYPE_REGISTER) 
            {

                println("\tctx.fpu.st{}() += ctx.fpu.st{}();",
                    dest.reg.value - ZYDIS_REGISTER_ST0,
                    src.reg.value - ZYDIS_REGISTER_ST0);
                println("\tctx.fpu.pop();");
                println("\tctx.fpu.set_exception_flags(ctx.fpu.st0());");
            }
        }
        break;
    case ZYDIS_MNEMONIC_FABS:
        println("\tctx.fpu.st0() = fabs(ctx.fpu.st0());");
        break;
    case ZYDIS_MNEMONIC_FCOS:
        println("\tvalDouble0 = ctx.fpu.st0();");
        println("\tctx.fpu.sw &= ~X87FPU::C2;");
        println("\tif (fabs(valDouble0) > 9223372036854775808.0) {{ // 2^63");
        println("\t    ctx.fpu.sw |= X87FPU::C2; // Set C2 if out of range");
        println("\t    ctx.fpu.st0() = std::numeric_limits<double>::quiet_NaN();");
        println("\t}} else {{");
        println("\t    ctx.fpu.st0() = cos(valDouble0);");
        println("\t}}");
        break;
    case ZYDIS_MNEMONIC_FLDLG2:
        println("\tctx.fpu.push(std::log2(10.0L));");
        println("\tctx.fpu.set_exception_flags(ctx.fpu.st0());");
        break;
    case ZYDIS_MNEMONIC_FNCLEX:
        println("\tctx.fpu.sw &= ~0x3F; //Clear all exception flags (bits 0-5)");
        break;

    case ZYDIS_MNEMONIC_FPATAN:
        println("\tdouble st1Temp_{:X} = ctx.fpu.st1();", base);
        println("\tdouble st0Temp_{:X} = ctx.fpu.st0();", base);
        println("\tctx.fpu.pop();");
        println("\tctx.fpu.st0() = atan2(st1Temp_{:X}, st0Temp_{:X});", base, base);
        break;
    case ZYDIS_MNEMONIC_FSIN:
        println("\tctx.fpu.clear_flags();");
        println("\tvalDouble0 = ctx.fpu.st0();");
        println("\tif (fabs(valDouble0) > 9223372036854775808.0) {{"); // 2^63
        println("\t    ctx.fpu.set_unordered();");
        println("\t    ctx.fpu.st0() = std::numeric_limits<double>::quiet_NaN();");
        println("\t}} else {{");
        println("\t    ctx.fpu.st0() = ctx.fpu.round_to_control(sin(valDouble0));");
        println("\t}}");
        break;
    case ZYDIS_MNEMONIC_FSINCOS:
        println("\tctx.fpu.clear_flags();");
        println("\tvalDouble2 = ctx.fpu.st0();");
        println("\tif (fabs(valDouble2) > 9223372036854775808.0) {{");
        println("\t    ctx.fpu.set_unordered();");
        println("\t    ctx.fpu.st0() = std::numeric_limits<double>::quiet_NaN();");
        println("\t    ctx.fpu.push(std::numeric_limits<double>::quiet_NaN());");
        println("\t}} else {{");
        println("\t    valDouble0 = sin(valDouble2);");
        println("\t    valDouble1 = cos(valDouble2);");
        println("\t    ctx.fpu.st0() = ctx.fpu.round_to_control(valDouble0);");
        println("\t    ctx.fpu.push(ctx.fpu.round_to_control(valDouble1));");
        println("\t}}");
        break;
    case ZYDIS_MNEMONIC_FSQRT:
        println("\tctx.fpu.clear_flags();");
        println("\tif (ctx.fpu.st0() < 0.0) {{");
        println("\t    ctx.fpu.flag_invalid();");
        println("\t    ctx.fpu.st0() = std::numeric_limits<double>::quiet_NaN();");
        println("\t}} else {{");
        println("\t    ctx.fpu.st0() = sqrt(ctx.fpu.st0());");
        println("\t}}");
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
        floatOperations("*");
        break;
    case ZYDIS_MNEMONIC_FIMUL:
        if (insn.insn.operand_count >= 1) 
        {
            const auto& src = insn.operands[0];

            if (src.type == ZYDIS_OPERAND_TYPE_MEMORY) 
            {
                switch (src.size) 
                {
                case 16:
                    println("\tctx.fpu.st0() *= (int16_t)X86_LOAD_U16({});", ea(src));
                    break;
                case 32:
                    println("\tctx.fpu.st0() *= (int32_t)X86_LOAD_U32({});", ea(src));
                    break;
                default:
                    println("\tassert(false && \"Invalid operand size for FIMUL\");");
                }
            }
            else if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) 
            {
                println("\tctx.fpu.st0() *= {};", get_x86_reg(src.reg.value));
            }
            println("\tctx.fpu.set_exception_flags(ctx.fpu.st0());");
        }
        break;
    case ZYDIS_MNEMONIC_FSUB:
        floatOperations("-");
        break;
    case ZYDIS_MNEMONIC_FSUBP:
        println("\tctx.fpu.st1() -= ctx.fpu.st0();");
        println("\tctx.fpu.pop();");
        break;
    case ZYDIS_MNEMONIC_FSUBR:
        if (insn.insn.operand_count >= 1) 
        {
            const auto& src = insn.operands[0];

            if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) 
            {
                if (ZydisRegisterGetClass(src.reg.value) == ZYDIS_REGCLASS_X87) 
                {
                    println("\tctx.fpu.st0() = ctx.fpu.st{}() - ctx.fpu.st0();", src.reg.value - ZYDIS_REGISTER_ST0);
                }
                else 
                {
                    // Register contains integer value
                    println("\tctx.fpu.st0() = {} - ctx.fpu.st0();", get_x86_reg(src.reg.value));
                }
            }
            else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                switch (src.size) 
                {
                case 32:
                    println("\tctx.fpu.st0() = X86_LOAD_F32({}) - ctx.fpu.st0();", ea(src));
                    break;
                case 64:
                    println("\tctx.fpu.st0() = X86_LOAD_F64({}) - ctx.fpu.st0();", ea(src));
                    break;
                default:
                    println("\tassert(false && \"Invalid operand size for FSUBR\");");
                }
            }
            println("\tctx.fpu.set_exception_flags(ctx.fpu.st0());");
        }
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
            println("\tctx.fpu.clear_flags();");
            if (insn.operands[0].size == 32) {
                println("\tctx.fpu.push(X86_LOAD_F32({}));",
                    ea(insn.operands[0]));
            }
            else {
                println("\tctx.fpu.push(X86_LOAD_F64({}));",
                    ea(insn.operands[0]));
            }
        }
        else if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
            println("\tctx.fpu.clear_flags();");
            println("\tctx.fpu.push(ctx.fpu.st{}());",
                insn.operands[0].reg.value - ZYDIS_REGISTER_ST0);
        }
        break;
    case ZYDIS_MNEMONIC_FLDZ: // Load +0.0
        println("\tctx.fpu.push(0.0L);");
        break;

    case ZYDIS_MNEMONIC_FNSTSW: // Store FPU Status Word
        if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            insn.operands[0].reg.value == ZYDIS_REGISTER_AX) {
            println("\tctx.eax.u16 = ctx.fpu.sw;");
        }
        else if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
            println("\tX86_STORE_U16({}, ctx.fpu.sw);", ea(insn.operands[0]));
        }
        break;

    case ZYDIS_MNEMONIC_FUCOMPP: // Unordered Compare and Pop Twice
        println("\t\tctx.fpu.compare_and_pop(ctx.fpu.st1());");
        println("\t\tctx.fpu.pop();");
        break;
    case ZYDIS_MNEMONIC_FDIV:
        floatOperations("/");
        break;
    case ZYDIS_MNEMONIC_FIDIV:
        if (insn.insn.operand_count >= 1) 
        {
            const auto& src = insn.operands[0];

            if (src.type == ZYDIS_OPERAND_TYPE_MEMORY) 
            {
                switch (src.size) {

                case 16:
                    println("\tctx.fpu.st0() /= (int16_t)X86_LOAD_U16({});", ea(src));
                    break;
                case 32:
                    println("\tctx.fpu.st0() /= (int32_t)X86_LOAD_U32({});", ea(src));
                    break;
                default:
                    println("\tassert(false && \"Invalid operand size for FIDIV\");");
                }
            }
            else if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                println("\tctx.fpu.st0() /= {};", get_x86_reg(src.reg.value));
            }
            println("\tctx.fpu.set_exception_flags(ctx.fpu.st0());");
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
                println("\tctx.fpu.st{}() = ctx.fpu.st0() / ctx.fpu.st{}();", st_idx, st_idx);
            }
            // Case 2: FDIVR m32/m64 → ST(0) = [mem] / ST(0)
            else if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                std::string memAddr = decode_memory_operand(insn.operands[0].mem);
                if (insn.operands[0].size == 32) {
                    println("\tctx.fpu.st0() = *(float*){} / ctx.fpu.st0();", memAddr);
                }
                else { // 64-bit double
                    println("\tctx.fpu.st0() = *(double*){} / ctx.fpu.st0();", memAddr);
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
    case ZYDIS_MNEMONIC_FCOM:
        if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            println("\tctx.fpu.compare_and_pop(X86_LOAD_F64({}), 0);", ea(insn.operands[0]));
        }
        else if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            println("\tctx.fpu.compare_and_pop(ctx.fpu.st{}(), 0);", get_st_index(insn.operands[0].reg.value));
        }
        break;
    case ZYDIS_MNEMONIC_FCOMP:
        if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            println("\tctx.fpu.compare_and_pop(X86_LOAD_F64({}), 1);", ea(insn.operands[0]));
        }
        else if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            println("\tctx.fpu.compare_and_pop(ctx.fpu.st{}(), 1);", get_st_index(insn.operands[0].reg.value));
        }
        break;
    case ZYDIS_MNEMONIC_FCOMIP:
        if (insn.insn.operand_count >= 1)
        {
            const auto& src = insn.operands[0];
            int st_idx = src.reg.value - ZYDIS_REGISTER_ST0;
            //Compare ST(0) with ST(i), set EFLAGS, and pop ST(0)
            println("\t// Compare ST(0) with ST({})", st_idx);
            println("\tctx.fpu.clear_flags();");
            println("\tctx.eflags.clear_compare_flags();");

            //Handle the different comparison cases
            println("\tif (std::isnan(ctx.fpu.st0()) || std::isnan(ctx.fpu.st{}())) {{", st_idx);
            println("\t\tctx.eflags.value |= X86EFlags::ZF | X86EFlags::PF | X86EFlags::CF;");
            println("\t}} else if (ctx.fpu.st0() > ctx.fpu.st{}()) {{", st_idx);
            println("\t\tctx.eflags.value &= ~(X86EFlags::ZF | X86EFlags::CF);");
            println("\t}} else if (ctx.fpu.st0() < ctx.fpu.st{}()) {{", st_idx);
            println("\t\tctx.eflags.value |= X86EFlags::CF;");
            println("\t\tctx.eflags.value &= ~X86EFlags::ZF;");
            println("\t}} else {{");
            println("\t\tctx.eflags.value |= X86EFlags::ZF;");
            println("\t\tctx.eflags.value &= ~X86EFlags::CF;");
            println("\t}}");

            // Pop ST(0)
            println("\tctx.fpu.pop();");
        }
        break;
    case ZYDIS_MNEMONIC_FCOMPP:
        if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            println("\tctx.fpu.compare_and_pop(X86_LOAD_F64({}), 2);", ea(insn.operands[0]));
        }
        else if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            println("\tctx.fpu.compare_and_pop(ctx.fpu.st{}(), 2);", get_st_index(insn.operands[0].reg.value));
        }
        break;
    case ZYDIS_MNEMONIC_FISTP:
        if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            switch (insn.operands[0].size)
            {
            case 16:
                println("\tX86_STORE_U16({}, (int16_t)ctx.fpu.round_to_control(ctx.fpu.st0()));",
                    ea(insn.operands[0]));
                break;
            case 32:
                println("\tX86_STORE_U32({}, (int32_t)ctx.fpu.round_to_control(ctx.fpu.st0()));",
                    ea(insn.operands[0]));
                break;
            case 64:
                println("\tX86_STORE_U64({}, (int64_t)ctx.fpu.round_to_control(ctx.fpu.st0()));",
                    ea(insn.operands[0]));
                break;
            default:
                assert(false && "Unsupported FISTP size");
            }
            println("\tctx.fpu.pop();");
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
    case ZYDIS_MNEMONIC_FNSTCW:
        if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) 
        {
            println("\tX86_STORE_U16({}, ctx.fpu.cw);", ea(insn.operands[0]));
        }
        break;
    case ZYDIS_MNEMONIC_FLDCW:
        if (insn.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) 
        {
            println("\tctx.fpu.cw = X86_LOAD_U16({});", ea(insn.operands[0]));
            println("\t_MM_SET_ROUNDING_MODE((ctx.fpu.cw >> 10) & 0x3);");
        }
        break;
    case ZYDIS_MNEMONIC_FRNDINT:
        println("\tswitch ((ctx.fpu.cw >> 10) & 0x3) {{");  // Check rounding mode
        println("\tcase 0: //Round to nearest");
        println("\t    ctx.fpu.st0() = std::nearbyint(ctx.fpu.st0()); break;");
        println("\tcase 1: //Round down");
        println("\t    ctx.fpu.st0() = std::floor(ctx.fpu.st0()); break;");
        println("\tcase 2: //Round up");
        println("\t    ctx.fpu.st0() = std::ceil(ctx.fpu.st0()); break;");
        println("\tcase 3: //Truncate");
        println("\t    ctx.fpu.st0() = std::trunc(ctx.fpu.st0()); break;");
        println("\t}}");
        println("\tctx.fpu.set_exception_flags(ctx.fpu.st0());");
        break;
    case ZYDIS_MNEMONIC_FYL2X:
        println("\tctx.fpu.st1() = ctx.fpu.st1() * std::log2(ctx.fpu.st0());");
        println("\tctx.fpu.pop();");
        println("\tctx.fpu.set_exception_flags(ctx.fpu.st0());");
        break;
    case ZYDIS_MNEMONIC_FWAIT:
        println("\tif (ctx.fpu.sw & 0x3F) {{");  // Check exception flags
        println("\t    ctx.fpu.handle_exceptions();");  
        println("\t}}");
        break;
    case ZYDIS_MNEMONIC_JZ:
        if (insn.insn.operand_count >= 1) {
            printConditionalBranch(false, "(ctx.eflags.value & X86EFlags::ZF) != 0", base, insn);
        }
        break;

        // For JNZ (Jump if Not Zero)
    case ZYDIS_MNEMONIC_JNZ:
        if (insn.insn.operand_count >= 1) {
            printConditionalBranch(false, "(ctx.eflags.value & X86EFlags::ZF) == 0", base, insn);
        }
        break;
    case ZYDIS_MNEMONIC_JBE:
        if (insn.insn.operand_count >= 1) {
            printConditionalBranch(false,
                "((ctx.eflags.value & X86EFlags::CF) != 0) || ((ctx.eflags.value & X86EFlags::ZF) != 0)",
                base, insn);
        }
        break;
    case ZYDIS_MNEMONIC_JNBE:
        if (insn.insn.operand_count >= 1) {
            printConditionalBranch(false,
                "((ctx.eflags.value & X86EFlags::CF) == 0) && ((ctx.eflags.value & X86EFlags::ZF) == 0)",
                base, insn);
        }
        break;
    case ZYDIS_MNEMONIC_JB:
        if (insn.insn.operand_count >= 1) {
            printConditionalBranch(false, "(ctx.eflags.value & X86EFlags::CF) != 0", base, insn);
        }
        break;
    case ZYDIS_MNEMONIC_JNB:
        if (insn.insn.operand_count >= 1) {
            printConditionalBranch(false, "(ctx.eflags.value & X86EFlags::CF) == 0", base, insn);
        }
        break;
    case ZYDIS_MNEMONIC_JL:
        if (insn.insn.operand_count >= 1) {
            printConditionalBranch(false,
                "(((ctx.eflags.value & X86EFlags::SF) != 0) != ((ctx.eflags.value & X86EFlags::OF) != 0))",
                base, insn);
        }
        break;
    case ZYDIS_MNEMONIC_JLE:
        if (insn.insn.operand_count >= 1) {
            printConditionalBranch(false,
                "((ctx.eflags.value & X86EFlags::ZF) != 0) || (((ctx.eflags.value & X86EFlags::SF) != 0) != ((ctx.eflags.value & X86EFlags::OF) != 0))",
                base, insn);
        }
        break;
    case ZYDIS_MNEMONIC_JNLE:
        if (insn.insn.operand_count >= 1) {
            printConditionalBranch(false,
                "((ctx.eflags.value & X86EFlags::ZF) == 0) && (((ctx.eflags.value & X86EFlags::SF) != 0) == ((ctx.eflags.value & X86EFlags::OF) != 0))",
                base, insn);
        }
        break;
    case ZYDIS_MNEMONIC_JNL:
        if (insn.insn.operand_count >= 1) {
            printConditionalBranch(false,
                "(((ctx.eflags.value & X86EFlags::SF) != 0) == ((ctx.eflags.value & X86EFlags::OF) != 0))",
                base, insn);
        }
        break;
    case ZYDIS_MNEMONIC_JNS:
        if (insn.insn.operand_count >= 1) {
            printConditionalBranch(false, "(ctx.eflags.value & X86EFlags::SF) == 0", base, insn);
        }
        break;
    case ZYDIS_MNEMONIC_JS:
        if (insn.insn.operand_count >= 1) {
            printConditionalBranch(false, "(ctx.eflags.value & X86EFlags::SF) != 0", base, insn);
        }
        break;
    case ZYDIS_MNEMONIC_JP:
        if (insn.insn.operand_count >= 1) {
            printConditionalBranch(false, "(ctx.eflags.value & X86EFlags::PF) != 0", base, insn);
        }
        break;
    case ZYDIS_MNEMONIC_JNP:
        if (insn.insn.operand_count >= 1) {
            printConditionalBranch(false, "(ctx.eflags.value & X86EFlags::PF) == 0", base, insn);
        }
        break;
    case ZYDIS_MNEMONIC_JO:
        if (insn.insn.operand_count >= 1) {
            printConditionalBranch(false, "(ctx.eflags.value & X86EFlags::OF) != 0", base, insn);
        }
        break;
    case ZYDIS_MNEMONIC_JNO:
        if (insn.insn.operand_count >= 1) {
            printConditionalBranch(false, "(ctx.eflags.value & X86EFlags::OF) == 0", base, insn);
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
        if (insn.insn.operand_count > 0 && insn.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
        {
            uint16_t stack_adjust = insn.operands[0].imm.value.u;
            if (stack_adjust > 0)
                println("\tctx.esp.u32 += 0x{:X};  //Adjust stack pointer", stack_adjust);
        }
        println("\tctx.esp.u32 += 0x{:X};  //Adjust stack pointer", 4); //in x86, the cpu always adjust the stack pointer by 4 bytes regardless of call convention
        println("\treturn;");
        break;
    case ZYDIS_MNEMONIC_STD:
        println("\tctx.eflags.set_df(true);  //Set backward direction");
        break;
    case ZYDIS_MNEMONIC_ADD:
        if (insn.insn.operand_count >= 2) 
        {
            const auto& dst = insn.operands[0];
            const auto& src = insn.operands[1];
            const char* size_suffix = GetOperandSizeName(dst.size);

            if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY) 
            {
                std::string temp_old = get_temp_reg(dst.size) + "_OLD";
                std::string temp_src = get_temp_reg(dst.size) + "_SRC";
                std::string temp_res = get_temp_reg(dst.size) + "_RES";

                // Load destination value
                println("\tauto {} = X86_LOAD_{}({});", temp_old, size_suffix, ea(dst));

                // Load source value into a temporary variable
                if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    println("\tauto {} = {};", temp_src, get_x86_reg(src.reg.value));
                }
                else if (src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    println("\tauto {} = {};", temp_src, src.imm.value.u);
                }
                else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                    println("\tauto {} = X86_LOAD_{}({});", temp_src, size_suffix, ea(src));
                }

 
                println("\tauto {} = {} + {};", temp_res, temp_old, temp_src);
                println("\tX86_STORE_{}({}, {});", size_suffix, ea(dst), temp_res);
                println("\tctx.eflags.update_flags_add({}, {}, {});", temp_old, temp_src, temp_res);
            }
            else 
            { // Register destination
                std::string dst_reg = get_x86_reg(dst.reg.value);
                std::string temp_old = get_temp_reg(dst.size) + "_OLD";
                std::string temp_src = get_temp_reg(dst.size) + "_SRC";

                // Save original destination value
                println("\tauto {} = {};", temp_old, dst_reg);

                // Get source value
                if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    println("\tauto {} = {};", temp_src, get_x86_reg(src.reg.value));
                }
                else if (src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    println("\tauto {} = {};", temp_src, src.imm.value.u);
                }
                else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                    println("\tauto {} = X86_LOAD_{}({});", temp_src, size_suffix, ea(src));
                }

                // Perform the addition
                println("\t{} = {} + {};", dst_reg, temp_old, temp_src);
                println("\tctx.eflags.update_flags_add({}, {}, {});", temp_old, temp_src, dst_reg);
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

            if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                std::string temp_old = get_temp_reg(dst.size) + "_OLD";
                std::string temp_src = get_temp_reg(dst.size) + "_SRC";
                std::string temp_res = get_temp_reg(dst.size) + "_RES";

                // Load destination value
                println("\tauto {} = X86_LOAD_{}({});", temp_old, size_suffix, ea(dst));

                // Load source value into a temporary variable
                if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    println("\tauto {} = {};", temp_src, get_x86_reg(src.reg.value));
                }
                else if (src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    println("\tauto {} = {};", temp_src, src.imm.value.u);
                }
                else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                    println("\tauto {} = X86_LOAD_{}({});", temp_src, size_suffix, ea(src));
                }

                // Calculate result
                println("\tauto {} = {} - {};", temp_res, temp_old, temp_src);

                // Store result
                println("\tX86_STORE_{}({}, {});", size_suffix, ea(dst), temp_res);

                // Update flags properly
                println("\tctx.eflags.update_flags_sub({}, {}, {});", temp_old, temp_src, temp_res);
            }
            else { // Register destination
                std::string dst_reg = get_x86_reg(dst.reg.value);
                std::string temp_old = get_temp_reg(dst.size) + "_OLD";
                std::string temp_src = get_temp_reg(dst.size) + "_SRC";

                // Save original destination value
                println("\tauto {} = {};", temp_old, dst_reg);

                // Get source value
                if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    println("\tauto {} = {};", temp_src, get_x86_reg(src.reg.value));
                }
                else if (src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    println("\tauto {} = {};", temp_src, src.imm.value.u);
                }
                else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                    println("\tauto {} = X86_LOAD_{}({});", temp_src, size_suffix, ea(src));
                }

                // Perform the subtraction
                println("\t{} = {} - {};", dst_reg, temp_old, temp_src);

                // Update flags properly
                println("\tctx.eflags.update_flags_sub({}, {}, {});", temp_old, temp_src, dst_reg);
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
    case ZYDIS_MNEMONIC_DIV:
    case ZYDIS_MNEMONIC_IDIV:
    {
        if (insn.insn.operand_count < 1)
            break;

        const auto& op = insn.operands[0];
        const char* size_suffix = GetOperandSizeName(op.size);
        std::string divisor = (op.type == ZYDIS_OPERAND_TYPE_REGISTER)
            ? get_x86_reg(op.reg.value) : fmt::format("X86_LOAD_{}({})", size_suffix, ea(op));

        println("\tif ({} == 0) {{", divisor);
        println("\t\t// Handle division by zero ERROR");
        println("\t}} else {{");

        std::string divdiend = "dividend_" + std::to_string(base);
        std::string quotient = "quotient_" + std::to_string(base);
        std::string remainder = "remainder_" + std::to_string(base);

        if (op.size == 8)
        {
            if (insn.insn.mnemonic == ZYDIS_MNEMONIC_IDIV) {
                println("\t\tint16_t {} = static_cast<int16_t>(ctx.ax.u16);", divdiend);
                println("\t\tint8_t {} = {} / static_cast<int8_t>({});", quotient, divdiend, divisor);
                println("\t\tint8_t {} = {} % static_cast<int8_t>({});", remainder, divdiend, divisor);
            }
            else {
                println("\t\tuint16_t {} = ctx.ax.u16;", divdiend);
                println("\t\tuint8_t {} = {} / static_cast<uint8_t>({});", quotient, divdiend, divisor);
                println("\t\tuint8_t {} = {} % static_cast<uint8_t>({});", remainder, divdiend, divisor);
            }
            println("\t\tctx.al.u8 = {};", quotient);
            println("\t\tctx.ah.u8 = {};", remainder);
        }
        else if (op.size == 16) {
            if (insn.insn.mnemonic == ZYDIS_MNEMONIC_IDIV)
            {
                println("\t\tint32_t {} = (static_cast<int32_t>(ctx.dx.u16) << 16) | ctx.ax.u16;", divdiend);
                println("\t\tint16_t {} = {} / static_cast<int16_t>({});", quotient, divdiend, divisor);
                println("\t\tint16_t {} = {} % static_cast<int16_t>({});", remainder, divdiend, divisor);
            }
            else {
                println("\t\tuint32_t {} = (static_cast<uint32_t>(ctx.dx.u16) << 16) | ctx.ax.u16;", divdiend);
                println("\t\tuint16_t {} = {} / static_cast<uint16_t>({});", quotient, divdiend, divisor);
                println("\t\tuint16_t {} = {} % static_cast<uint16_t>({});", remainder, divdiend, divisor);
            }
            println("\t\tctx.ax.u16 = {};", quotient);
            println("\t\tctx.dx.u16 = {};", remainder);
        }
        else if (op.size == 32)
        {
            std::string dividend = fmt::format("dividend_{:X}", base);

            if (insn.insn.mnemonic == ZYDIS_MNEMONIC_IDIV)
            {
                println("\t\tint64_t {} = (static_cast<int64_t>(static_cast<int32_t>(ctx.edx.u32)) << 32) | ctx.eax.u32;", dividend);
                println("\t\tint32_t {} = static_cast<int32_t>({} / static_cast<int32_t>({}));", quotient, dividend, divisor);
                println("\t\tint32_t {} = static_cast<int32_t>({} % static_cast<int32_t>({}));", remainder, dividend, divisor);
            }
            else {
                println("\t\tuint64_t {} = (static_cast<uint64_t>(ctx.edx.u32) << 32) | ctx.eax.u32;", dividend);
                println("\t\tuint32_t {} = static_cast<uint32_t>({} / {});", quotient, dividend, divisor);
                println("\t\tuint32_t {} = static_cast<uint32_t>({} % {});", remainder, dividend, divisor);
            }
            println("\t\tctx.eax.u32 = {};", quotient);
            println("\t\tctx.edx.u32 = {};", remainder);
        }
        else {
            println("\t\t//Unsupported operand size: {}", op.size);
        }

        println("\t\tctx.eflags.value = 0; // Flags undefined after DIV/IDIV");
        println("\t}}");
        break;
    }
    case ZYDIS_MNEMONIC_IMUL:
    {
        auto get_operand_str = [&](const ZydisDecodedOperand& op) -> std::string
            {
                if (op.type == ZYDIS_OPERAND_TYPE_REGISTER)
                    return get_x86_reg(op.reg.value);
                else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY)
                    return fmt::format("X86_LOAD_{}({})", GetOperandSizeName(op.size), ea(op));
                else if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                    return fmt::format("{}", static_cast<int32_t>(op.imm.value.s));
                else
                    throw std::runtime_error("Unsupported operand in IMUL");
            };

        // First, classify the actual IMUL form we're dealing with
        enum ImulForm {
            IMUL_UNKNOWN,
            IMUL_EAX_EDX,      // Single operand: EDX:EAX = EAX * op
            IMUL_REG_REG,      // Two operands: reg1 = reg1 * reg2/mem
            IMUL_REG_IMM,      // Two operands: reg1 = reg1 * imm
            IMUL_REG_REG_IMM    // Three operands: reg1 = reg2/mem * imm
        } form = IMUL_UNKNOWN;

        // Count actual meaningful operands (ignore implicit ones)
        //fix a bug with zydis detecting more than 3 operands
        int explicit_operands = 0;
        for (size_t i = 0; i < insn.insn.operand_count; ++i)
        {
            if (insn.operands[i].visibility == ZYDIS_OPERAND_VISIBILITY_EXPLICIT)
                explicit_operands++;
        }

        if (explicit_operands == 1)
        {
            form = IMUL_EAX_EDX;
        }
        else if (explicit_operands == 2)
        {
            if (insn.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                form = IMUL_REG_IMM;
            }
            else {
                form = IMUL_REG_REG;
            }
        }
        else if (explicit_operands == 3)
        {
            form = IMUL_REG_REG_IMM;
        }

        // Now handle each form
        switch (form)
        {
        case IMUL_EAX_EDX:
        {
            // IMUL r/m - EDX:EAX = EAX * r/m
            const auto& src = insn.operands[0];
            std::string rhs = get_operand_str(src);
            std::string temp_result = fmt::format("imul_result_{:X}", base);

            println("\tint64_t {} = static_cast<int64_t>(static_cast<int32_t>(ctx.eax.u32)) * "
                "static_cast<int64_t>(static_cast<int32_t>({}));", temp_result, rhs);
            println("\tctx.eax.u32 = static_cast<uint32_t>({} & 0xFFFFFFFF);", temp_result);
            println("\tctx.edx.u32 = static_cast<uint32_t>(static_cast<uint64_t>({}) >> 32);", temp_result);
            println("\tctx.eflags.value = (ctx.eflags.value & ~(X86EFlags::CF | X86EFlags::OF)) | "
                "((({} >> 31) != ctx.edx.u32) ? (X86EFlags::CF | X86EFlags::OF) : 0);", temp_result);
            break;
        }
        case IMUL_REG_REG:
        {
            // IMUL r, r/m - r1 = r1 * r2/mem
            const auto& dst = insn.operands[0];
            const auto& src = insn.operands[1];
            std::string lhs = get_x86_reg(dst.reg.value);
            std::string rhs = get_operand_str(src);
            std::string temp_result = fmt::format("imul_result_{:X}", base);

            println("\tint64_t {} = static_cast<int64_t>(static_cast<int32_t>({})) * "
                "static_cast<int64_t>(static_cast<int32_t>({}));", temp_result, lhs, rhs);
            println("\t{} = static_cast<uint32_t>({});", lhs, temp_result);
            println("\tctx.eflags.value = (ctx.eflags.value & ~(X86EFlags::CF | X86EFlags::OF)) | "
                "((static_cast<int64_t>(static_cast<int32_t>({})) != {}) ? "
                "(X86EFlags::CF | X86EFlags::OF) : 0);", lhs, temp_result);
            break;
        }

        case IMUL_REG_IMM: {
            // IMUL r, imm - r = r * imm
            const auto& dst = insn.operands[0];
            const auto& imm = insn.operands[1];
            std::string lhs = get_x86_reg(dst.reg.value);
            std::string imm_str = get_operand_str(imm);
            std::string temp_result = fmt::format("imul_result_{:X}", base);

            println("\tint64_t {} = static_cast<int64_t>(static_cast<int32_t>({})) * "
                "static_cast<int64_t>({});", temp_result, lhs, imm_str);
            println("\t{} = static_cast<uint32_t>({});", lhs, temp_result);
            println("\tctx.eflags.value = (ctx.eflags.value & ~(X86EFlags::CF | X86EFlags::OF)) | "
                "((static_cast<int64_t>(static_cast<int32_t>({})) != {}) ? "
                "(X86EFlags::CF | X86EFlags::OF) : 0);", lhs, temp_result);
            break;
        }

        case IMUL_REG_REG_IMM: {
            // IMUL r, r/m, imm - r = r/m * imm
            const auto& dst = insn.operands[0];
            const auto& src = insn.operands[1];
            const auto& imm = insn.operands[2];
            std::string lhs = get_x86_reg(dst.reg.value);
            std::string rhs = get_operand_str(src);
            std::string imm_str = get_operand_str(imm);
            std::string temp_result = fmt::format("imul_result_{:X}", base);

            println("\tint64_t {} = static_cast<int64_t>(static_cast<int32_t>({})) * "
                "static_cast<int64_t>({});", temp_result, rhs, imm_str);
            println("\t{} = static_cast<uint32_t>({});", lhs, temp_result);
            println("\tctx.eflags.value = (ctx.eflags.value & ~(X86EFlags::CF | X86EFlags::OF)) | "
                "((static_cast<int64_t>(static_cast<int32_t>({})) != {}) ? "
                "(X86EFlags::CF | X86EFlags::OF) : 0);", lhs, temp_result);
            break;
        }

        default:
            throw std::runtime_error(fmt::format("Unsupported IMUL form with {} explicit operands",
                explicit_operands));
        }
    }
    break;
    case ZYDIS_MNEMONIC_LDMXCSR:
    {
        // Operand 0: memory source
        const std::string src = ea(insn.operands[0]);
        println("\tctx.mxcsr = X86_LOAD_U32({});", src);
    }
    break;
    case ZYDIS_MNEMONIC_SHL:
        if (insn.insn.operand_count >= 2)
        {
            const auto& dst = insn.operands[0];
            const char* size_suffix = GetOperandSizeName(dst.size);

            std::string temp = "temp_" + std::to_string(base);

            // SHR reg/mem, imm
            if (insn.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                //backup value before shifting
                uint32_t shift_count = insn.operands[1].imm.value.u;

                if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER)
                {
                    println("\tauto {} = {};", temp, get_x86_reg(dst.reg.value));
                    println("\t{} <<= {};", get_x86_reg(dst.reg.value), shift_count);
                    println("\tctx.eflags.update_flags_shl({}, {}, {});", temp, shift_count,
                        get_x86_reg(dst.reg.value));
                }
                else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY)
                {
                    // Load original value
                    println("\tauto {} = X86_LOAD_{}({});", temp, size_suffix, ea(dst));

                    // Perform shift and store
                    println("\tX86_STORE_{}({}, {} << {});", size_suffix, ea(dst), temp, shift_count);

                    println("\tctx.eflags.update_flags_shl({}, {}, X86_LOAD_{}({}));",
                        temp, shift_count, size_suffix, ea(dst));
                }
            }
            else if (insn.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                insn.operands[1].reg.value == ZYDIS_REGISTER_CL)
            {
                if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER)
                {
                    println("\tauto {} = {};", temp, get_x86_reg(dst.reg.value));
                    println("\t{} <<= ctx.ecx.u8_lo;", get_x86_reg(dst.reg.value));
                    println("\tctx.eflags.update_flags_shl({}, ctx.ecx.u8_lo, {});",
                        temp, get_x86_reg(dst.reg.value));
                }
                else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY)
                {
                    println("\tauto {} = X86_LOAD_{}({});", temp, size_suffix, ea(dst));

                    // Perform shift and store
                    println("\tX86_STORE_{}({}, {} << ctx.ecx.u8_lo);", size_suffix, ea(dst), temp);

                    //Update flags (original value, shift count, result)
                    println("\tctx.eflags.update_flags_shl({}, ctx.ecx.u8_lo, X86_LOAD_{}({}));", temp, size_suffix, ea(dst));
                }
            }
        }
        break;
    case ZYDIS_MNEMONIC_SHUFPS:
        if (insn.insn.operand_count >= 3)
        {
            const auto& dst = insn.operands[0];
            const auto& src = insn.operands[1];
            const auto& imm = insn.operands[2];

            if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                src.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                imm.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                println("\tX86_SHUFPS({}, {}, {});", static_cast<unsigned>(dst.reg.value - ZYDIS_REGISTER_XMM0),
                    static_cast<unsigned>(src.reg.value - ZYDIS_REGISTER_XMM0),
                    imm.imm.value.u);
            }
        }
        break;
    case ZYDIS_MNEMONIC_INC:
        if (insn.insn.operand_count >= 1) {
            const auto& op = insn.operands[0];
            const char* size_suffix = GetOperandSizeName(op.size);

            if (op.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                std::string oldval = get_temp_reg(op.size);
                println("\tauto {} = {};", oldval, get_x86_reg(op.reg.value));
                println("\t{}++;", get_x86_reg(op.reg.value));
                println("\tctx.eflags.update_flags_inc({}, {});", oldval, get_x86_reg(op.reg.value));
            }
            else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                std::string temp_old = get_temp_reg(op.size) + "_OLD";
                std::string temp_res = get_temp_reg(op.size) + "_RES";

                println("\tauto {} = X86_LOAD_{}({});", temp_old, size_suffix, ea(op));
                println("\tauto {} = {};", temp_res, temp_old);
                println("\t{}++;", temp_res);
                println("\tX86_STORE_{}({}, {});", size_suffix, ea(op), temp_res);
                println("\tctx.eflags.update_flags_inc({}, {});", temp_old, temp_res);
            }
        }
        break;
    case ZYDIS_MNEMONIC_DIVSS:
        HandleSseScalarInstruction(insn, xmm, decode_memory_operand, "/=");
        break;
    case ZYDIS_MNEMONIC_DEC:
        if (insn.insn.operand_count >= 1) {
            const auto& op = insn.operands[0];
            const char* size_suffix = GetOperandSizeName(op.size);

            if (op.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                std::string oldval = get_temp_reg(op.size);
                println("\tauto {} = {};", oldval, get_x86_reg(op.reg.value));
                println("\t{}--;", get_x86_reg(op.reg.value));
                println("\tctx.eflags.update_flags_dec({}, {});", oldval, get_x86_reg(op.reg.value));
            }
            else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                std::string temp_old = get_temp_reg(op.size) + "_OLD";
                std::string temp_res = get_temp_reg(op.size) + "_RES";

                println("\tauto {} = X86_LOAD_{}({});", temp_old, size_suffix, ea(op));
                println("\tauto {} = {};", temp_res, temp_old);
                println("\t{}--;", temp_res);
                println("\tX86_STORE_{}({}, {});", size_suffix, ea(op), temp_res);
                println("\tctx.eflags.update_flags_dec({}, {});", temp_old, temp_res);
            }
        }
        break;
    case ZYDIS_MNEMONIC_OR:
        handle_bitwise("|=", "update_flags_logic");
        break;
    case ZYDIS_MNEMONIC_AND:
        handle_bitwise("&=", "update_flags_logic");
        break;
    case ZYDIS_MNEMONIC_TEST:
        if (insn.insn.operand_count >= 2)
        {
            const char* size_suffix = GetOperandSizeName(insn.operands[0].size);
            std::string lhs = format_operand(insn.operands[0], size_suffix);
            std::string rhs = format_operand(insn.operands[1], size_suffix);
            if (!lhs.empty() && !rhs.empty())
            {
                println("\tctx.eflags.update_test_flags({} & {});", lhs, rhs);
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
    case ZYDIS_MNEMONIC_RDTSC:
        //println("\tctx.eax.u64 = static_cast<uint32_t>(__rdtsc());");
        break;
    case ZYDIS_MNEMONIC_STOSD:
        if (insn.insn.attributes & ZYDIS_ATTRIB_HAS_REP)
        {
            println("\tif (ctx.eflags.value & X86EFlags::DF) {{");
            println("\t    for (uint32_t i = 0; i < ctx.ecx.u32; ++i) {{");
            println("\t        X86_STORE_U32(static_cast<uintptr_t>(ctx.edi.u32) - i * 4, ctx.eax.u32);");
            println("\t    }}");
            println("\t    ctx.edi.u32 -= ctx.ecx.u32 * 4;");
            println("\t}} else {{");
            println("\t    for (uint32_t i = 0; i < ctx.ecx.u32; ++i) {{");
            println("\t        X86_STORE_U32(static_cast<uintptr_t>(ctx.edi.u32) + i * 4, ctx.eax.u32);");
            println("\t    }}");
            println("\t    ctx.edi.u32 += ctx.ecx.u32 * 4;");
            println("\t}}");
            println("\tctx.ecx.u32 = 0;");
        }
        else
        {
            println("\tX86_STORE_U32(static_cast<uintptr_t>(ctx.edi.u32), ctx.eax.u32);");
            println("\tctx.edi.u32 += (ctx.eflags.value & X86EFlags::DF) ? -4 : 4;");
        }
        break;

    case ZYDIS_MNEMONIC_STOSB:
        if (insn.insn.attributes & ZYDIS_ATTRIB_HAS_REP)
        {
            println("\tif (ctx.eflags.value & X86EFlags::DF) {{");
            println("\t    for (uint32_t i = 0; i < ctx.ecx.u32; ++i) {{");
            println("\t        X86_STORE_U8(static_cast<uintptr_t>(ctx.edi.u32) - i, static_cast<uint8_t>(ctx.eax.u8_lo));");
            println("\t    }}");
            println("\t    ctx.edi.u32 -= ctx.ecx.u32;");
            println("\t}} else {{");
            println("\t    for (uint32_t i = 0; i < ctx.ecx.u32; ++i) {{");
            println("\t        X86_STORE_U8(static_cast<uintptr_t>(ctx.edi.u32) + i, static_cast<uint8_t>(ctx.eax.u8_lo));");
            println("\t    }}");
            println("\t    ctx.edi.u32 += ctx.ecx.u32;");
            println("\t}}");
            println("\tctx.ecx.u32 = 0;");
        }
        else
        {
            println("\tX86_STORE_U8(static_cast<uintptr_t>(ctx.edi.u32), static_cast<uint8_t>(ctx.eax.u8_lo));");
            println("\tctx.edi.u32 += (ctx.eflags.value & X86EFlags::DF) ? -1 : 1;");
        }
        break;
    case ZYDIS_MNEMONIC_STOSW:
        if (insn.insn.attributes & ZYDIS_ATTRIB_HAS_REP)
        {
            println("\tif (ctx.eflags.value & X86EFlags::DF) {{");
            println("\t    for (uint32_t i = 0; i < ctx.ecx.u32; ++i) {{");
            println("\t        X86_STORE_U16(static_cast<uintptr_t>(ctx.edi.u32) - i * 2, ctx.eax.u16);");
            println("\t    }}");
            println("\t    ctx.edi.u32 -= ctx.ecx.u32 * 2;");
            println("\t}} else {{");
            println("\t    for (uint32_t i = 0; i < ctx.ecx.u32; ++i) {{");
            println("\t        X86_STORE_U16(static_cast<uintptr_t>(ctx.edi.u32) + i * 2, ctx.eax.u16);");
            println("\t    }}");
            println("\t    ctx.edi.u32 += ctx.ecx.u32 * 2;");
            println("\t}}");
            println("\tctx.ecx.u32 = 0;");
        }
        else
        {
            println("\tX86_STORE_U16(static_cast<uintptr_t>(ctx.edi.u32), ctx.eax.u16);");
            println("\tctx.edi.u32 += (ctx.eflags.value & X86EFlags::DF) ? -2 : 2;");
        }
        break;
    case ZYDIS_MNEMONIC_STMXCSR:
    {

        const std::string dst = ea(insn.operands[0]);
        println("\tX86_STORE_U32({}, ctx.mxcsr);", dst);
        break;
    }

    case ZYDIS_MNEMONIC_MOVSD:
        if (insn.insn.attributes & ZYDIS_ATTRIB_HAS_REP) 
        {
            println("\tfor (; ctx.ecx.u32 > 0; ctx.ecx.u32--, ctx.esi.u32 += 4, ctx.edi.u32 += 4) {{");
            println("\t\tX86_STORE_U32(ctx.edi.u32, X86_LOAD_U32(ctx.esi.u32));");
            println("\t}}");
        }
        else {
            println("\tX86_STORE_U32(ctx.edi.u32, X86_LOAD_U32(ctx.esi.u32));");
            println("\tctx.esi.u32 += 4;");
            println("\tctx.edi.u32 += 4;");
        }
        break;
    case ZYDIS_MNEMONIC_MOVAPS:
        if (insn.insn.operand_count >= 2)
        {
            const auto& dst = insn.operands[0];
            const auto& src = insn.operands[1];

            // MOVAPS xmm1, xmm2 (XMM ← XMM)
            if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                src.type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                println("\tX86_MOVAPS_REG({}, {});",
                    static_cast<unsigned>(dst.reg.value - ZYDIS_REGISTER_XMM0),
                    static_cast<unsigned>(src.reg.value - ZYDIS_REGISTER_XMM0));
            }
            // MOVAPS xmm1, [mem] (XMM ← memory)
            else if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                src.type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                println("\tX86_MOVAPS({}, {});",
                    static_cast<unsigned>(dst.reg.value - ZYDIS_REGISTER_XMM0),
                    ea(src));
            }
            // MOVAPS [mem], xmm1 (memory ← XMM)
            else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                src.type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                println("\tX86_MOVAPS_STORE({}, {});",
                    ea(dst),
                    static_cast<unsigned>(src.reg.value - ZYDIS_REGISTER_XMM0));
            }
        }
        break;
    case ZYDIS_MNEMONIC_MOVSB:
        if (insn.insn.attributes & ZYDIS_ATTRIB_HAS_REP)
        {
            println("\tvalUint320 = ctx.ecx.u32;");
            println("\tint direction_{} = (ctx.eflags.value & X86EFlags::DF) ? -1 : 1;", base);
            println("\tfor (; valUint320 > 0; valUint320--) {{");
            println("\t\tX86_STORE_U8(ctx.edi.u32, X86_LOAD_U8(ctx.esi.u32));");
            println("\t\tctx.esi.u32 += direction_{};", base);
            println("\t\tctx.edi.u32 += direction_{};", base);
            println("\t\tctx.ecx.u32--;");
            println("\t}}");
        }
        else
        {
            println("\tX86_STORE_U8(ctx.edi.u32, X86_LOAD_U8(ctx.esi.u32));");
            println("\tctx.eflags.update_string_pointer(ctx.esi.u32);");
            println("\tctx.eflags.update_string_pointer(ctx.edi.u32);");
        }
        break;
    case ZYDIS_MNEMONIC_MOVSW:
        if (insn.insn.attributes & ZYDIS_ATTRIB_HAS_REP)
        {
            println("\tvalUint320 = ctx.ecx.u32;");
            println("\tint direction_{} = (ctx.eflags.value & X86EFlags::DF) ? -2 : 2;", base);
            println("\tfor (; valUint320 > 0; valUint320--) {{");
            println("\t\tX86_STORE_U16(ctx.edi.u32, X86_LOAD_U16(ctx.esi.u32));");
            println("\t\tctx.esi.u32 += direction_{};", base);
            println("\t\tctx.edi.u32 += direction_{};", base);
            println("\t\tctx.ecx.u32--;");
            println("\t}}");
        }
        else
        {
            println("\tX86_STORE_U16(ctx.edi.u32, X86_LOAD_U16(ctx.esi.u32));");
            println("\tctx.eflags.update_string_pointer_word(ctx.esi.u32);");
            println("\tctx.eflags.update_string_pointer_word(ctx.esi.u32);");
        }
        break;
    case ZYDIS_MNEMONIC_MUL:
        if (insn.insn.operand_count >= 1)
        {
            const auto& op = insn.operands[0];
            const char* size_suffix = GetOperandSizeName(op.size);
            std::string rhs;

            if (op.type == ZYDIS_OPERAND_TYPE_REGISTER)
                rhs = get_x86_reg(op.reg.value);
            else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY)
                rhs = fmt::format("X86_LOAD_{}({})", size_suffix, ea(op));

            if (!rhs.empty())
            {
                std::string temp_result = fmt::format("mul_result_{:X}", base);
                println("\tuint64_t {} = static_cast<uint64_t>(ctx.eax.u32) * static_cast<uint64_t>({});", temp_result, rhs);
                println("\tctx.eax.u32 = static_cast<uint32_t>({} & 0xFFFFFFFF);", temp_result);
                println("\tctx.edx.u32 = static_cast<uint32_t>({} >> 32);", temp_result);
                println("\tctx.eflags.update_flags_mul(ctx.edx.u32 != 0);");
            }
        }
        break;
    case ZYDIS_MNEMONIC_MULPS:
        if (insn.insn.operand_count >= 2)
        {
            const auto& dst = insn.operands[0];
            const auto& src = insn.operands[1];

            if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                src.type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                println("\tX86_MULPS({}, {});", static_cast<unsigned>(dst.reg.value - ZYDIS_REGISTER_XMM0),
                    static_cast<unsigned>(src.reg.value - ZYDIS_REGISTER_XMM0));
            }
        }
        break;
    case ZYDIS_MNEMONIC_MULSS:
        HandleSseScalarInstruction(insn, xmm, decode_memory_operand, "*=");
        break;
    case ZYDIS_MNEMONIC_SAR:
        if (insn.insn.operand_count >= 2)
        {
            const auto& dst = insn.operands[0];
            const char* size_suffix = GetOperandSizeName(dst.size);
            std::string temp = "temp_" + std::to_string(base);

            // SAR reg/mem, imm
            if (insn.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                uint32_t shift_count = insn.operands[1].imm.value.u;

                if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER)
                {
                    // Store original value before shift
                    println("\tauto {} = {};", temp, get_x86_reg(dst.reg.value));

                    // Perform arithmetic right shift (>> preserves sign)
                    println("\t{} >>= {};", get_x86_reg(dst.reg.value), shift_count);

                    // Update flags (original value, shift count, result)
                    println("\tctx.eflags.update_flags_sar({}, {}, {});", temp, shift_count, get_x86_reg(dst.reg.value));
                }
                else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY)
                {
                    // Load original value
                    println("\tauto {} = X86_LOAD_{}({});", temp, size_suffix, ea(dst));

                    // Perform shift and store
                    println("\tX86_STORE_{}({}, {} >> {});", size_suffix, ea(dst), temp, shift_count);

                    // Update flags (original value, shift count, result)
                    println("\tctx.eflags.update_flags_sar({}, {}, X86_LOAD_{}({}));",
                        temp, shift_count, size_suffix, ea(dst));
                }
            }
            // SAR reg/mem, CL
            else if (insn.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                insn.operands[1].reg.value == ZYDIS_REGISTER_CL)
            {
                if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER)
                {
                    // Store original value before shift
                    println("\tauto {} = {};", temp, get_x86_reg(dst.reg.value));

                    // Perform shift
                    println("\t{} >>= ctx.ecx.u8_lo;", get_x86_reg(dst.reg.value));

                    // Update flags (original value, shift count, result)
                    println("\tctx.eflags.update_flags_sar({}, ctx.ecx.u8_lo, {});", temp, get_x86_reg(dst.reg.value));
                }
                else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY)
                {
                    // Load original value
                    println("\tauto {} = X86_LOAD_{}({});", temp, size_suffix, ea(dst));

                    // Perform shift and store
                    println("\tX86_STORE_{}({}, {} >> ctx.ecx.u8_lo);", size_suffix, ea(dst), temp);

                    // Update flags (original value, shift count, result)
                    println("\tctx.eflags.update_flags_sar({}, ctx.ecx.u8_lo, X86_LOAD_{}({}));", temp, size_suffix, ea(dst));
                }
            }
        }
        break;
    case ZYDIS_MNEMONIC_SBB:
        if (insn.insn.operand_count >= 2) {
            const auto& dst = insn.operands[0];
            const auto& src = insn.operands[1];
            const char* size_suffix = GetOperandSizeName(dst.size);

            // Save the CF value before operation
            println("\tuint32_t cf_value_{} = (ctx.eflags.value & X86EFlags::CF) ? 1 : 0;", base);

            if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY) 
            {
                std::string temp_old = get_temp_reg(dst.size) + "_OLD";
                std::string temp_src = get_temp_reg(dst.size) + "_SRC";
                std::string temp_res = get_temp_reg(dst.size) + "_RES";

                println("\tauto {} = X86_LOAD_{}({});", temp_old, size_suffix, ea(dst));

                // Load source value into a temporary variable
                if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    println("\tauto {} = {};", temp_src, get_x86_reg(src.reg.value));
                }
                else if (src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    println("\tauto {} = {};", temp_src, src.imm.value.u);
                }
                else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                    println("\tauto {} = X86_LOAD_{}({});", temp_src, size_suffix, ea(src));
                }


                println("\tauto {} = {} - ({} + cf_value_{});", temp_res, temp_old, temp_src, base);

                println("\tX86_STORE_{}({}, {});", size_suffix, ea(dst), temp_res);

                println("\tctx.eflags.update_flags_sub({}, {} + cf_value_{}, {});", temp_old, temp_src, base, temp_res);
            }
            else { // Register destination
                std::string dst_reg = get_x86_reg(dst.reg.value);
                std::string temp_old = get_temp_reg(dst.size) + "_OLD";
                std::string temp_src = get_temp_reg(dst.size) + "_SRC";

                // Save original destination value
                println("\tauto {} = {};", temp_old, dst_reg);

                // Get source value
                if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) 
                {
                    println("\tauto {} = {};", temp_src, get_x86_reg(src.reg.value));
                }
                else if (src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    println("\tauto {} = {};", temp_src, src.imm.value.u);
                }
                else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                    println("\tauto {} = X86_LOAD_{}({});", temp_src, size_suffix, ea(src));
                }

                // Perform the subtraction with borrow
                println("\t{} = {} - ({} + cf_value_{});", dst_reg, temp_old, temp_src, base);
                println("\tctx.eflags.update_flags_sub({}, {} + cf_value_{}, {});", temp_old, temp_src, base, dst_reg);
            }
        }
        break;
    case ZYDIS_MNEMONIC_PUSHFD:
        println("\tX86_PUSH(ctx, base, ctx.eflags.value);");
        break;
    case ZYDIS_MNEMONIC_PUNPCKHDQ: // Parallel Unpack High Doubleword
        if (insn.insn.operand_count >= 2) {
            const auto& dst = insn.operands[0];
            const auto& src = insn.operands[1];

            println("\t\tvalUint640 = MMX_REG({}, {});", dst.reg.value - ZYDIS_REGISTER_MM0, (int)ZYDIS_REGISTER_MM0);
            if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                println("\t\tvalUint641 = MMX_REG({}, {});", src.reg.value - ZYDIS_REGISTER_MM0, (int)ZYDIS_REGISTER_MM0);
            }
            else {
                println("\t\tvalUint641 = X86_LOAD_U64({});", ea(src));
            }
            println("\t\tMMX_REG({}, {}) = ((valUint640 >> 32) & 0xFFFFFFFF) | ((valUint641 & 0xFFFFFFFF) << 32);",
                dst.reg.value - ZYDIS_REGISTER_MM0, (int)ZYDIS_REGISTER_MM0);
        }
        break;
    case ZYDIS_MNEMONIC_PUNPCKLDQ: // Parallel Unpack Low Doubleword
        if (insn.insn.operand_count >= 2) {
            const auto& dst = insn.operands[0];
            const auto& src = insn.operands[1];

            println("\t\tvalUint640 = MMX_REG({}, {});", dst.reg.value - ZYDIS_REGISTER_MM0, (int)ZYDIS_REGISTER_MM0);
            if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                println("\t\tvalUint641 = MMX_REG({}, {});", src.reg.value - ZYDIS_REGISTER_MM0, (int)ZYDIS_REGISTER_MM0);
            }
            else {
                println("\t\tvalUint641 = X86_LOAD_U64({});", ea(src));
            }
            println("\t\tMMX_REG({}, {}) = (valUint640 & 0xFFFFFFFF) | ((valUint641 & 0xFFFFFFFF) << 32);",
                dst.reg.value - ZYDIS_REGISTER_MM0, (int)ZYDIS_REGISTER_MM0);
        }
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
    case ZYDIS_MNEMONIC_XADD:

        if (insn.insn.operand_count >= 2)
        {
            const auto& dst = insn.operands[0];
            const auto& src = insn.operands[1];

            if (insn.insn.attributes & ZYDIS_ATTRIB_HAS_LOCK)
            {
                println("\tauto old_val_{} = X86_LOAD_U32({});", base, ea(dst));
                println("\tX86_STORE_U32({}, old_val_{} + {});", ea(dst), base, format_operand(src));
                println("\t{} = old_val_{};", format_operand(src), base);
                println("\tstd::atomic_thread_fence(std::memory_order_seq_cst);");
            }
            else 
            {
                println("\tauto temp_{} = {};", base, format_operand(src));
                println("\t{} += {};", format_operand(src), format_operand(dst));
                println("\t{} = temp_{};", format_operand(dst), base);
            }
        }
        break;
    case ZYDIS_MNEMONIC_XOR:
        handle_bitwise("^=", "update_flags_logic");
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

            std::string temp = "temp_" + std::to_string(base);

            // SHR reg/mem, imm
            if (insn.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                //backup value before shifting
                uint32_t shift_count = insn.operands[1].imm.value.u;

                if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER)
                {
                    println("\tauto {} = {};", temp, get_x86_reg(dst.reg.value));
                    println("\t{} >>= {};", get_x86_reg(dst.reg.value), shift_count);
                    println("\tctx.eflags.update_flags_shr({}, {}, {});", temp, shift_count,
                        get_x86_reg(dst.reg.value));
                }
                else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY)
                {
                    // Load original value
                    println("\tauto {} = X86_LOAD_{}({});", temp, size_suffix, ea(dst));

                    // Perform shift and store
                    println("\tX86_STORE_{}({}, {} >> {});", size_suffix, ea(dst), temp, shift_count);

                    println("\tctx.eflags.update_flags_shr({}, {}, X86_LOAD_{}({}));",
                        temp, shift_count, size_suffix, ea(dst));
                }
            }
            else if (insn.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                insn.operands[1].reg.value == ZYDIS_REGISTER_CL)
            {
                if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER)
                {
                    println("\tauto {} = {};", temp, get_x86_reg(dst.reg.value));
                    println("\t{} >>= ctx.ecx.u8_lo;", get_x86_reg(dst.reg.value));
                    println("\tctx.eflags.update_flags_shr({}, ctx.ecx.u8_lo, {});",
                        temp, get_x86_reg(dst.reg.value));
                }
                else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY)
                {
                    println("\tauto {} = X86_LOAD_{}({});", temp, size_suffix, ea(dst));

                    // Perform shift and store
                    println("\tX86_STORE_{}({}, {} >> ctx.ecx.u8_lo);", size_suffix, ea(dst), temp);

                    //Update flags (original value, shift count, result)
                    println("\tctx.eflags.update_flags_shr({}, ctx.ecx.u8_lo, X86_LOAD_{}({}));", temp, size_suffix, ea(dst));
                }
            }
        }
        break;
    case ZYDIS_MNEMONIC_MOVZX:
        if (insn.insn.operand_count >= 2)
        {
            const auto& dst = insn.operands[0];
            const auto& src = insn.operands[1];

            if (src.type == ZYDIS_OPERAND_TYPE_MEMORY && src.mem.segment == ZYDIS_REGISTER_FS)
            {
                uint32_t offset = src.mem.disp.value;
                auto dst_reg = get_x86_reg(dst.reg.value);

                switch (offset)
                {
                case 0x24:
                    println("\t{} = X86_LOAD_U32(ctx.kpcr_ptr + 0x24);",
                        dst_reg);
                    break;
                case 0x28:  // RPC Handle (byte access)
                    println("\t{} = X86_LOAD_U8(ctx.kpcr_ptr + 0x28);",
                        dst_reg);
                    break;
                default:
                    println("\t{} = 0; // Unknown FS byte offset: 0x{:X}", dst_reg, offset);
                    break;
                }
            }
            else if (src.type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                std::string dst_reg = get_x86_reg(dst.reg.value);
                std::string src_reg = get_x86_reg(src.reg.value);


                if (dst.size == 32)
                {
                    if (src.size == 8)
                    {
                        if (src.reg.value >= ZYDIS_REGISTER_AH && src.reg.value <= ZYDIS_REGISTER_BH)
                        {
                            // High byte register (AH, CH, DH, BH)
                            ZydisRegister base_reg = static_cast<ZydisRegister>(
                                ZYDIS_REGISTER_EAX + (src.reg.value - ZYDIS_REGISTER_AH));
                            println("\t{} = (uint8_t)({} >> 8);", dst_reg, get_x86_reg(base_reg));
                        }
                        else
                        {
                            // Low byte register (AL, CL, DL, BL)
                            println("\t{} = (uint8_t){};", dst_reg, src_reg);
                        }
                    }
                    else if (src.size == 16)
                    {
                        println("\t{} = {} & 0xFFFF;", dst_reg, src_reg);
                    }
                }
                else if (dst.size == 16)
                {
                    // 16-bit destination
                    if (src.size == 8)
                    {
                        // 8-bit source
                        if (src.reg.value >= ZYDIS_REGISTER_AH && src.reg.value <= ZYDIS_REGISTER_BH)
                        {
                            // High byte register (AH, CH, DH, BH)
                            ZydisRegister base_reg = static_cast<ZydisRegister>(
                                ZYDIS_REGISTER_EAX + (src.reg.value - ZYDIS_REGISTER_AH));
                            println("\t{} = (uint8_t)({} >> 8);", dst_reg, get_x86_reg(base_reg));
                        }
                        else {
                            // Low byte register (AL, CL, DL, BL)
                            println("\t{} = (uint8_t){};", dst_reg, src_reg);
                        }
                    }
                }
            }
            else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                const char* load_op = nullptr;

                // Determine load size from SOURCE operand
                switch (src.size)
                {
                case 8:  load_op = "X86_LOAD_U8";
                    break;
                case 16: load_op = "X86_LOAD_U16";
                    break;
                default:
                    throw std::runtime_error("Unsupported MOVZX source size");
                }

                if (src.mem.base == ZYDIS_REGISTER_ECX && src.mem.disp.value == 4)
                {
                    println("\t// Optimized Xbox kernel version read");
                    println("\t{} = (uint32_t){}(ctx.ecx.u32 + 4);", get_x86_reg(dst.reg.value), load_op);
                }
                else
                {
                    println("\t{} = (uint32_t){}({});", get_x86_reg(dst.reg.value), load_op, ea(src));
                }
            }
        }
        break;
    case ZYDIS_MNEMONIC_NEG:
        if (insn.insn.operand_count >= 1)
        {
            const auto& op = insn.operands[0];
            const char* size_suffix = GetOperandSizeName(op.size);

            if (op.type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                std::string reg = get_x86_reg(op.reg.value);
                std::string temp_old = get_temp_reg(op.size) + "_OLD";

                println("\tauto {} = {};", temp_old, reg);
                println("\t{} = -{};", reg, reg);
                println("\tctx.eflags.update_flags_neg({}, {});", temp_old, reg);
            }
            else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                std::string temp_old = get_temp_reg(op.size) + "_OLD";
                std::string temp_res = get_temp_reg(op.size) + "_RES";

                println("\tauto {} = X86_LOAD_{}({});", temp_old, size_suffix, ea(op));
                println("\tauto {} = -{};", temp_res, temp_old);
                println("\tX86_STORE_{}({}, {});", size_suffix, ea(op), temp_res);
                println("\tctx.eflags.update_flags_neg({}, {});", temp_old, temp_res);
            }
        }
        break;
    case ZYDIS_MNEMONIC_NOT:
        if (insn.insn.operand_count >= 1)
        {
            const auto& op = insn.operands[0];
            const char* size_suffix = GetOperandSizeName(op.size);

            if (op.type == ZYDIS_OPERAND_TYPE_REGISTER)
                println("\t{} = ~{};", get_x86_reg(op.reg.value), get_x86_reg(op.reg.value));
            else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY)
                println("\tX86_STORE_{}({}, ~X86_LOAD_{}({}));",
                    size_suffix, ea(op), size_suffix, ea(op));

        }
        break;
    case ZYDIS_MNEMONIC_CMPSB:
        if (insn.insn.attributes & ZYDIS_ATTRIB_HAS_REPE)
        {
            println("\tfor (; ctx.ecx.u32 > 0; ctx.ecx.u32--, ctx.esi.u32 += 1, ctx.edi.u32 += 1) {{");
            println("\t\tuint8_t val1 = X86_LOAD_U8(ctx.esi.u32);");
            println("\t\tuint8_t val2 = X86_LOAD_U8(ctx.edi.u32);");
            println("\t\tctx.eflags.update_compare_flags<uint8_t>(val1, val2);");
            println("\t\tif (!(ctx.eflags.value & X86EFlags::ZF)) break;");
            println("\t}}");
        }
        else if (insn.insn.attributes & ZYDIS_ATTRIB_HAS_REPNE) 
        {
            println("\tfor (; ctx.ecx.u32 > 0; ctx.ecx.u32--, ctx.esi.u32 += 1, ctx.edi.u32 += 1) {{");
            println("\t\tuint8_t val1 = X86_LOAD_U8(ctx.esi.u32);");
            println("\t\tuint8_t val2 = X86_LOAD_U8(ctx.edi.u32);");
            println("\t\tctx.eflags.update_compare_flags<uint8_t>(val1, val2);");
            println("\t\tif (ctx.eflags.value & X86EFlags::ZF) break;");
            println("\t}}");
        }
        else 
        {
            println("\tuint8_t val1 = X86_LOAD_U8(ctx.esi.u32);");
            println("\tuint8_t val2 = X86_LOAD_U8(ctx.edi.u32);");
            println("\tctx.eflags.update_compare_flags<uint8_t>(val1, val2);");
            println("\tctx.esi.u32 += 1;");
            println("\tctx.edi.u32 += 1;");
        }
        break;
    case ZYDIS_MNEMONIC_CMPSD:
        if (insn.insn.attributes & ZYDIS_ATTRIB_HAS_REPE) 
        {
            println("\tfor (; ctx.ecx.u32 > 0; ctx.ecx.u32--, ctx.esi.u32 += 4, ctx.edi.u32 += 4) {{");
            println("\t\tvalUint320 = X86_LOAD_U32(ctx.esi.u32);");
            println("\t\tvalUint321 = X86_LOAD_U32(ctx.edi.u32);");
            println("\t\tctx.eflags.update_compare_flags<uint32_t>(valUint320, valUint321);");
            println("\t\tif (!(ctx.eflags.value & X86EFlags::ZF)) break;");
            println("\t}}");
        }
        else if (insn.insn.attributes & ZYDIS_ATTRIB_HAS_REPNE) 
        {
            println("\tfor (; ctx.ecx.u32 > 0; ctx.ecx.u32--, ctx.esi.u32 += 4, ctx.edi.u32 += 4) {{");
            println("\t\tvalUint320 = X86_LOAD_U32(ctx.esi.u32);");
            println("\t\tvalUint321 = X86_LOAD_U32(ctx.edi.u32);");
            println("\t\tctx.eflags.update_compare_flags<uint32_t>(valUint320, valUint321);");
            println("\t\tif (ctx.eflags.value & X86EFlags::ZF) break;");
            println("\t}}");
        }
        else 
        {
            println("\tvalUint320 = X86_LOAD_U32(ctx.esi.u32);");
            println("\tvalUint321 = X86_LOAD_U32(ctx.edi.u32);");
            println("\tctx.eflags.update_compare_flags<uint32_t>(valUint320, valUint321);");
            println("\tctx.esi.u32 += 4;");
            println("\tctx.edi.u32 += 4;");
        }
        break;
    case ZYDIS_MNEMONIC_CMPSW:
        if (insn.insn.attributes & ZYDIS_ATTRIB_HAS_REPE) {
            println("\tfor (; ctx.ecx.u32 > 0; ctx.ecx.u32--, ctx.esi.u32 += 2, ctx.edi.u32 += 2) {{");
            println("\t\tuint16_t val1 = X86_LOAD_U16(ctx.esi.u32);");
            println("\t\tuint16_t val2 = X86_LOAD_U16(ctx.edi.u32);");
            println("\t\tctx.eflags.update_compare_flags<uint16_t>(val1, val2);");
            println("\t\tif (!(ctx.eflags.value & X86EFlags::ZF)) break;");
            println("\t}}");
        }
        else if (insn.insn.attributes & ZYDIS_ATTRIB_HAS_REPNE) 
        {
            println("\tfor (; ctx.ecx.u32 > 0; ctx.ecx.u32--, ctx.esi.u32 += 2, ctx.edi.u32 += 2) {{");
            println("\t\tuint16_t val1 = X86_LOAD_U16(ctx.esi.u32);");
            println("\t\tuint16_t val2 = X86_LOAD_U16(ctx.edi.u32);");
            println("\t\tctx.eflags.update_compare_flags<uint16_t>(val1, val2);");
            println("\t\tif (ctx.eflags.value & X86EFlags::ZF) break;");
            println("\t}}");
        }
        else {
            println("\tuint16_t val1 = X86_LOAD_U16(ctx.esi.u32);");
            println("\tuint16_t val2 = X86_LOAD_U16(ctx.edi.u32);");
            println("\tctx.eflags.update_compare_flags<uint16_t>(val1, val2);");
            println("\tctx.esi.u32 += 2;");
            println("\tctx.edi.u32 += 2;");
        }
        break;
    case ZYDIS_MNEMONIC_ROL:
        if (insn.insn.operand_count >= 2)
        {
            const auto& dst = insn.operands[0];
            const char* size_suffix = GetOperandSizeName(dst.size);
            std::string temp = "temp_" + std::to_string(base);

            // ROL reg/mem, imm
            if (insn.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                uint32_t shift_count = insn.operands[1].imm.value.u;

                if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER)
                {
                    // Store original value
                    println("\tauto {} = {};", temp, get_x86_reg(dst.reg.value));

                    // Perform rotation: (x << n) | (x >> (32 - n))
                    println("\t{} = ({} << {}) | ({} >> (32 - {}));", get_x86_reg(dst.reg.value),
                        get_x86_reg(dst.reg.value), shift_count, get_x86_reg(dst.reg.value), shift_count);

                    // Update flags
                    println("\tctx.eflags.update_flags_rol({}, {}, {});",
                        temp, shift_count, get_x86_reg(dst.reg.value));
                }
                else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY)
                {
                    // Load original value
                    println("\tauto {} = X86_LOAD_{}({});", temp, size_suffix, ea(dst));

                    // Rotate and store
                    println("\tX86_STORE_{}({}, ({} << {}) | ({} >> (32 - {})));",
                        size_suffix, ea(dst), temp, shift_count, temp, shift_count);


                    println("\tctx.eflags.update_flags_rol({}, {}, X86_LOAD_{}({}));",
                        temp, shift_count, size_suffix, ea(dst));
                }
            }
            // ROL reg/mem, CL
            else if (insn.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                insn.operands[1].reg.value == ZYDIS_REGISTER_CL)
            {
                if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER)
                {
                    println("\tauto {} = {};", temp, get_x86_reg(dst.reg.value));

                    println("\t{} = ({} << ctx.ecx.u8_lo) | ({} >> (32 - ctx.ecx.u8_lo));", get_x86_reg(dst.reg.value),
                        get_x86_reg(dst.reg.value),
                        get_x86_reg(dst.reg.value));

                    println("\tctx.eflags.update_flags_rol({}, ctx.ecx.u8_lo, {});", temp, get_x86_reg(dst.reg.value));
                }
                else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY)
                {
                    println("\tauto {} = X86_LOAD_{}({});", temp, size_suffix, ea(dst));

                    println("\tX86_STORE_{}({}, ({} << ctx.ecx.u8_lo) | ({} >> (32 - ctx.ecx.u8_lo)));",
                        size_suffix, ea(dst), temp, temp);

                    println("\tctx.eflags.update_flags_rol({}, ctx.ecx.u8_lo, X86_LOAD_{}({}));",
                        temp, size_suffix, ea(dst));
                }
            }
        }
        break;
    case ZYDIS_MNEMONIC_ROR:
        if (insn.insn.operand_count >= 2)
        {
            const auto& dst = insn.operands[0];
            const char* size_suffix = GetOperandSizeName(dst.size);
            std::string temp = "temp_" + std::to_string(base);

            // ROR reg/mem, imm
            if (insn.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                uint32_t shift_count = insn.operands[1].imm.value.u;

                if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER)
                {
                    // Store original value
                    println("\tauto {} = {};", temp, get_x86_reg(dst.reg.value));

                    // Perform rotation: (x >> n) | (x << (32 - n))
                    println("\t{} = ({} >> {}) | ({} << (32 - {}));", get_x86_reg(dst.reg.value),
                        get_x86_reg(dst.reg.value), shift_count, get_x86_reg(dst.reg.value), shift_count);

                    // Update flags
                    println("\tctx.eflags.update_flags_ror({}, {}, {});",
                        temp, shift_count, get_x86_reg(dst.reg.value));
                }
                else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY)
                {
                    // Load original value
                    println("\tauto {} = X86_LOAD_{}({});", temp, size_suffix, ea(dst));

                    // Rotate and store
                    println("\tX86_STORE_{}({}, ({} >> {}) | ({} << (32 - {})));",
                        size_suffix, ea(dst), temp, shift_count, temp, shift_count);


                    println("\tctx.eflags.update_flags_ror({}, {}, X86_LOAD_{}({}));",
                        temp, shift_count, size_suffix, ea(dst));
                }
            }
            // ROR reg/mem, CL
            else if (insn.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                insn.operands[1].reg.value == ZYDIS_REGISTER_CL)
            {
                if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER)
                {
                    println("\tauto {} = {};", temp, get_x86_reg(dst.reg.value));

                    println("\t{} = ({} >> ctx.ecx.u8_lo) | ({} << (32 - ctx.ecx.u8_lo));", get_x86_reg(dst.reg.value),
                        get_x86_reg(dst.reg.value),
                        get_x86_reg(dst.reg.value));

                    println("\tctx.eflags.update_flags_ror({}, ctx.ecx.u8_lo, {});", temp, get_x86_reg(dst.reg.value));
                }
                else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY)
                {
                    println("\tauto {} = X86_LOAD_{}({});", temp, size_suffix, ea(dst));

                    println("\tX86_STORE_{}({}, ({} >> ctx.ecx.u8_lo) | ({} << (32 - ctx.ecx.u8_lo)));",
                        size_suffix, ea(dst), temp, temp);

                    println("\tctx.eflags.update_flags_ror({}, ctx.ecx.u8_lo, X86_LOAD_{}({}));",
                        temp, size_suffix, ea(dst));
                }
            }
        }
        break;
    case ZYDIS_MNEMONIC_SCASB:
        if (insn.insn.attributes & ZYDIS_ATTRIB_HAS_REPE) 
        {
            println("\tfor (; ctx.ecx.u32 > 0; ctx.ecx.u32--, ctx.edi.u32 += 1) {{");
            println("\t\tuint8_t val = X86_LOAD_U8(ctx.edi.u32);");
            println("\t\tctx.eflags.update_compare_flags<uint8_t>(ctx.eax.u8_lo, val);");
            println("\t\tif (!(ctx.eflags.value & X86EFlags::ZF)) break;");
            println("\t}}");
        }
        else if (insn.insn.attributes & ZYDIS_ATTRIB_HAS_REPNE) 
        {
            println("\t\tconst uint8_t al_val_{} = ctx.eax.u8_lo;", base);
            println("\t\tconst bool df_{} = (ctx.eflags.value & X86EFlags::DF) != 0;", base);
            println("\t\tuint32_t count_{} = ctx.ecx.u32;", base);
            println("\t\twhile (count_{} > 0) {{", base);
            println("\t\t\tctx.eflags.update_compare_flags<uint8_t>(al_val_{}, X86_LOAD_U8(ctx.edi.u32));", base);
            println("\t\t\tctx.edi.u32 += df_{} ? -1 : 1;", base);
            println("\t\t\tcount_{}--;", base);
            println("\tif ((ctx.eflags.value & X86EFlags::ZF) != 0) {{");
            println("\t\t\t\tbreak;");
            println("\t}}");
            println("\t\t}}");
            println("\t\tctx.ecx.u32 = count_{};", base);
        }
        else {
            println("\t\tuint8_t mem_val = X86_LOAD_U8(ctx.edi.u32);");
            println("\t\tctx.eflags.update_compare_flags<uint8_t>(ctx.eax.u8_lo, mem_val);");
            println("\t\tctx.edi.u32 += (ctx.eflags.value & X86EFlags::DF) ? -1 : 1;");
        }
        break;
    case ZYDIS_MNEMONIC_SETB:
        if (insn.insn.operand_count >= 1) 
        {
            const auto& dst = insn.operands[0];

            if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) 
            {
                println("\t{} = (ctx.eflags.value & X86EFlags::CF) ? 1 : 0;",
                    get_x86_reg(dst.reg.value));
            }
            else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY) 
            {
                println("\tX86_STORE_U8({}, (ctx.eflags.value & X86EFlags::CF) ? 1 : 0);",
                    ea(dst));
            }
        }
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
    case ZYDIS_MNEMONIC_SETLE:
        if (insn.insn.operand_count >= 1) {
            const auto& dst = insn.operands[0];

            println("\tconst bool condition_{} = (ctx.eflags.value & X86EFlags::ZF) || "
                "((ctx.eflags.value & X86EFlags::SF) ^ (ctx.eflags.value & X86EFlags::OF));", base);

            if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                println("\t{} = condition_{} ? 1 : 0;", get_x86_reg(dst.reg.value), base);
            }
            else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                println("\tX86_STORE_U8({}, condition_{} ? 1 : 0);", ea(dst), base);
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
    case ZYDIS_MNEMONIC_SETNL:
        if (insn.insn.operand_count >= 1)
        {
            const auto& op = insn.operands[0];
            const char* condition = "(ctx.eflags.value & (X86EFlags::SF | X86EFlags::OF)) == 0 || "
                "(ctx.eflags.value & (X86EFlags::SF | X86EFlags::OF)) == (X86EFlags::SF | X86EFlags::OF)";

            if (op.type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                // SETNL reg (explicit uint8_t)
                println("\t{} = static_cast<uint8_t>({} ? 1 : 0);", get_x86_reg(op.reg.value), condition);
            }
            else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                // SETNL [mem]
                println("\tX86_STORE_U8({}, static_cast<uint8_t>({} ? 1 : 0));", ea(op), condition);
            }
            else
            {
                println("\t//ERROR Setnl variation not handled!");
            }
        }
        break;
    case ZYDIS_MNEMONIC_SETNS:
        println("\t{} = ( (ctx.eflags.value & X86EFlags::SF) == 0);", get_x86_reg(insn.operands[0].reg.value));
        break;
    case ZYDIS_MNEMONIC_SETNLE:
        println("\t{} = ((ctx.eflags.value & X86EFlags::ZF) == 0) && "
            "((ctx.eflags.value & X86EFlags::SF) == (ctx.eflags.value & X86EFlags::OF));",
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

        println("\t//MISSING INSTRUCTION HERE TODO ADD");
        println("\tprintf(\"Missing instruction: {} - {:X}\\n\");", buffer, base);

        return false;
    }


    if (funcConfig.isLastInst && insn.insn.mnemonic != ZYDIS_MNEMONIC_JMP && insn.insn.mnemonic != ZYDIS_MNEMONIC_RET && insn.insn.mnemonic != ZYDIS_MNEMONIC_INT3)
    {
        println("\tprintf(\"WARNING Function doesn't end with JMP or RET, possible analysis error. {:x}\\n\");", base);
        println("\t//WARNING Function doesn't end with JMP or RET, possible analysis error.");
        return false;
    }

    return true;
}

std::unordered_set<std::string> instMissing;
std::unordered_map<size_t, size_t> wrongAnalyse;

bool Recompiler::Recompile(const Function& fn)
{
    auto base = fn.base;
    auto end = base + fn.size;
    auto* data = static_cast<const uint8_t*>(image.Find(base));

    static std::unordered_set<size_t> labels;
    labels.clear();


    RecompilerFuncConfig funcConfig;
    RecompilerLocalVariables localvariablesTemp;

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


    for (size_t addr = base; addr < end; addr += insn.length)
    {
        if (localvariablesTemp.valDouble[2] == true && localvariablesTemp.valUint64[2] == true)
            break;

        size_t offset = addr - fn.base;

        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, data + offset, end, &insn, operands)))
        {
            addr += 1;
            continue;
        }

        auto t = insn.mnemonic;

        if (localvariablesTemp.isUint64OP(t))
        {
            for (uint8_t i = 0; i < LengthOfArray(localvariablesTemp.valUint64); i++)
            {
                if (!localvariablesTemp.valUint64[i])
                {
                    std::string s = std::to_string(i);
                    std::string variable = "\tuint64_t valUint64" + s + " = 0;\n";
                    println(variable);
                    localvariablesTemp.valUint64[i] = true;
                    break;
                }
            }
        }

        if (localvariablesTemp.isUint32OP(t))
        {
            for (uint8_t i = 0; i < LengthOfArray(localvariablesTemp.valUint32); i++)
            {
                if (!localvariablesTemp.valUint32[i])
                {
                    if (t == ZYDIS_MNEMONIC_MOVSB || t == ZYDIS_MNEMONIC_MOVSW)
                    {
                        if ((insn.attributes & ZYDIS_ATTRIB_HAS_REP) == 0)
                        {
                            break;
                        }
                    }

                    std::string s = std::to_string(i);
                    std::string variable = "\tuint32_t valUint32" + s + " = 0;\n";
                    println(variable);
                    localvariablesTemp.valUint32[i] = true;
                    if (t == ZYDIS_MNEMONIC_CMPSD && !i)
                    {
                        s = std::to_string(1);
                        variable = "\tuint32_t valUint32" + s + " = 0;\n";
                        println(variable);
                        localvariablesTemp.valUint32[1] = true;
                    }
                    break;
                }
            }
        }

        if (localvariablesTemp.isFloatOP(t))
        {
            if (t == ZYDIS_MNEMONIC_FSINCOS)
            {
                for (uint8_t i = 0; i < LengthOfArray(localvariablesTemp.valDouble); i++)
                {
                    if (!localvariablesTemp.valDouble[i])
                    {
                        println("\tlong double valDouble{} = 0;\n", i);
                        localvariablesTemp.valDouble[i] = true;
                    }
                }
            }
            else
            {
                if (!localvariablesTemp.valDouble[0])
                {
                    println("\tlong double valDouble0 = 0;\n");
                    localvariablesTemp.valDouble[0] = true;
                }
            }
        }
    }

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


        funcConfig.isLastInst = base + insn.length >= fn.base + fn.size;

        //Recompile instruction
        if (!Recompile(fn, base, ins, data, switchTable, localvariables, csrState, funcConfig))
        {
            if (!funcConfig.isLastInst)
            {
                if (instMissing.count(ZydisMnemonicGetString(insn.mnemonic)) == 0)
                {
                    instMissing.insert(ZydisMnemonicGetString(insn.mnemonic));
                }
                fmt::println("Unrecognized instruction at 0x{:X}: {}", base, ZydisMnemonicGetString(insn.mnemonic));
            }
            else
            {
                wrongAnalyse.insert({ fn.base, base });
            }


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
        println("#define X86_IMAGE_SIZE 0x{:X}ull", image.dwsizeofImage);

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


    for (size_t i = 0; i < functions.size(); i++)
    {
        if (i > 0 && (i % 256) == 0)
        {
            SaveCurrentOutData();
            println("#include \"x86_recomp_shared.h\"\n");
        }

        if ((i % 120) == 0 || (i == (functions.size() - 1)))
            fmt::println("Recompiling functions... {}%", static_cast<float>(i + 1) / functions.size() * 100.0f);



        Recompile(functions[i]);
    }

    if (instMissing.size() > 0)
    {
        printf("\nmissing following instructions:\n");
    }

    static int countJmp = 0;
    for (auto s : instMissing)
    {
        if (countJmp >= 2)
        {
            printf("%s\n", s.c_str());
            countJmp = 0;
        }
        else
        {
            printf("%s, ", s.c_str());
            countJmp++;
        }
    }

    if (wrongAnalyse.size() > 0)
    {
        printf("\npotential wrong analyse:\n");
    }

    for (const auto& pair : wrongAnalyse)
    {
        std::cout << "Base: 0x" << std::hex << pair.first << ", Address: 0x" << pair.second << std::endl;
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
