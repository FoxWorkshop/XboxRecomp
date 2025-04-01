#include "function.h"
#include <vector>
#include <algorithm>
#include <cassert>
#include <Zydis/Zydis.h>
#include <unordered_set>
#include <unordered_map>
#include <string>
#include <switchTable.h>
#include <iostream>
#include "image.h"
#include <queue>
#include <chrono>



//x86 is very funny
static const std::unordered_set<ZydisMnemonic> ConditionalJump = {
    ZYDIS_MNEMONIC_JB,
    ZYDIS_MNEMONIC_JBE,
    ZYDIS_MNEMONIC_JCXZ,
    ZYDIS_MNEMONIC_JECXZ,
    ZYDIS_MNEMONIC_JKNZD,
    ZYDIS_MNEMONIC_JKZD,
    ZYDIS_MNEMONIC_JL,
    ZYDIS_MNEMONIC_JLE,
    ZYDIS_MNEMONIC_JNB,
    ZYDIS_MNEMONIC_JNBE,
    ZYDIS_MNEMONIC_JNL,
    ZYDIS_MNEMONIC_JNLE,
    ZYDIS_MNEMONIC_JNO,
    ZYDIS_MNEMONIC_JNP,
    ZYDIS_MNEMONIC_JNS,
    ZYDIS_MNEMONIC_JNZ,
    ZYDIS_MNEMONIC_JO,
    ZYDIS_MNEMONIC_JP,
    ZYDIS_MNEMONIC_JRCXZ,
    ZYDIS_MNEMONIC_JS,
    ZYDIS_MNEMONIC_JZ
};


inline bool IsConditionalJump(ZydisMnemonic mnemonic) {
    return ConditionalJump.find(mnemonic) != ConditionalJump.end();  // O(1) lookup
}

inline bool IsControlFlow(ZydisMnemonic mnemonic)
{
    static const std::unordered_set<ZydisMnemonic> ControlFlowSet =
    {
    ZYDIS_MNEMONIC_JMP, ZYDIS_MNEMONIC_CALL, ZYDIS_MNEMONIC_RET,
    ZYDIS_MNEMONIC_JB,
    ZYDIS_MNEMONIC_JBE,
    ZYDIS_MNEMONIC_JCXZ,
    ZYDIS_MNEMONIC_JECXZ,
    ZYDIS_MNEMONIC_JKNZD,
    ZYDIS_MNEMONIC_JKZD,
    ZYDIS_MNEMONIC_JL,
    ZYDIS_MNEMONIC_JLE,
    ZYDIS_MNEMONIC_JNB,
    ZYDIS_MNEMONIC_JNBE,
    ZYDIS_MNEMONIC_JNL,
    ZYDIS_MNEMONIC_JNLE,
    ZYDIS_MNEMONIC_JNO,
    ZYDIS_MNEMONIC_JNP,
    ZYDIS_MNEMONIC_JNS,
    ZYDIS_MNEMONIC_JNZ,
    ZYDIS_MNEMONIC_JO,
    ZYDIS_MNEMONIC_JP,
    ZYDIS_MNEMONIC_JRCXZ,
    ZYDIS_MNEMONIC_JS,
    ZYDIS_MNEMONIC_JZ
    };
    return ControlFlowSet.find(mnemonic) != ControlFlowSet.end();  // O(1) lookup
}

void Function::VfTableAnalyze(const void* code, size_t size, size_t base, Section section, std::unordered_set<size_t>& analysedFuncs, std::unordered_set<size_t>& subFunctionsFromVirtualFunc)
{
    Function fn{ base, 0 };

    // Initialize Zydis decoder
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    auto& blocks = fn.blocks;
    blocks.reserve(8);
    blocks.emplace_back(); // First block

    std::unordered_map<size_t, std::vector<size_t>> cfgEdges; // CFG adjacency list
    std::unordered_set<size_t> visited;
    std::vector<size_t> worklist{ base }; // Worklist for CFG traversal

    const auto* data = (uint8_t*)code;
    const auto* dataStart = data;
    const auto* dataEnd = data + size;

    ZydisDecodedInstruction insn{};

    while (!worklist.empty())
    {
        size_t blockStart = worklist.back();
        worklist.pop_back();

        if (visited.count(blockStart))
            continue;
        visited.insert(blockStart);

        size_t addr = blockStart;
        auto& curBlock = blocks.emplace_back(blockStart, 0);

        while (addr < base + size)
        {
            size_t offset = addr - base;
            if (offset >= size)
                break;

            // Decode instruction
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, dataStart + offset, size - offset, &insn, operands)))
                break;

            curBlock.size += insn.length;

            // Handle control flow
            if (insn.mnemonic == ZYDIS_MNEMONIC_RET)
            {
                break;
            }
            if (insn.mnemonic == ZYDIS_MNEMONIC_JMP)
            {
                if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                {
                    size_t targetAddr = addr + insn.length + operands[0].imm.value.s;
                    cfgEdges[addr].push_back(targetAddr);
                    worklist.push_back(targetAddr);
                }
                break;
            }
            else if (IsConditionalJump(insn.mnemonic))
            {
                if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                {
                    size_t targetAddr = addr + insn.length + operands[0].imm.value.s;
                    cfgEdges[addr].push_back(targetAddr);
                    worklist.push_back(targetAddr);
                }
                // Fall-through path
                cfgEdges[addr].push_back(addr + insn.length);
            }
            else if (insn.mnemonic == ZYDIS_MNEMONIC_CALL)
            {
                if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                {
                    size_t callTarget = addr + insn.length + operands[0].imm.value.s;

                    if (analysedFuncs.count(callTarget) == 0)
                    {
                        analysedFuncs.insert(callTarget);
                        subFunctionsFromVirtualFunc.insert(callTarget);
                        VfTableAnalyze(section.data + (callTarget - section.base), section.base + section.size - callTarget, callTarget, section, analysedFuncs, subFunctionsFromVirtualFunc);
                    }
                }
            }

            addr += insn.length;
        }
    }

    fn.cfg = std::move(cfgEdges);
}


#ifdef _DEBUG
#define DEBUG_LOG(...) printf(__VA_ARGS__)
#else
#define DEBUG_LOG(...)
#endif

//Blocks are sequences of instructions with a single entry and exit point.
//Branches are instructions that change the flow of execution.
//Analyse works in two steps: we collect branch target to avoid missing blocks, and then we process blocks.
Function Function::Analyze(const void* code, size_t size, size_t base, std::unordered_map<uint32_t, RecompilerSwitchTable>& switchTable)
{
    Function fn{ base, 0 };

    const auto* dataStart = static_cast<const uint8_t*>(code);
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);

    //First pass: Collect all branch targets
    std::unordered_set<size_t> branchTargets;

    for (size_t addr = base; addr < size; )
    {
        //failsafe in case we leave function boundaries
        if (addr > base + 0x1700)
            break;

        size_t offset = addr - base;

        if (offset >= size)
            break;

        auto startDecoding = std::chrono::high_resolution_clock::now();
        ZydisDecodedInstruction insn;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, dataStart + offset, size - offset, &insn, operands)))
        {
            addr++;
            continue;
        }

        if (insn.mnemonic == ZYDIS_MNEMONIC_INT3)
            break;

        // Check for control flow instructions and record targets
        if (IsControlFlow(insn.mnemonic))
        {
            if (insn.mnemonic != ZYDIS_MNEMONIC_RET)
            {
                const bool isJmp = insn.mnemonic == ZYDIS_MNEMONIC_JMP;
                if (isJmp || IsConditionalJump(insn.mnemonic))
                {
                    if (isJmp && operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
                    {
                        ZydisDecodedOperandMem mem = operands[0].mem;

                        if (mem.index != ZYDIS_REGISTER_NONE && mem.scale == 4)
                        {
                            size_t jmp_base = addr;
                            std::unordered_map<uint32_t, RecompilerSwitchTable>::iterator table;
                            auto it = switchTable.find(jmp_base);
                            if (it != switchTable.end())
                            {
                                for (size_t i = 0; i < it->second.labels.size(); i++)
                                {
                                    // Add all targets from the jump table
                                    auto label = it->second.labels[i];
                                    if (label >= fn.base || label < base + size)
                                    {
                                        branchTargets.insert(label);
                                    }
                                }
                            }
                        }
                    }
                    else if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                    {
                        size_t target = addr + insn.length + operands[0].imm.value.s;
                        branchTargets.insert(target);
                    }
                }
                else if (insn.mnemonic == ZYDIS_MNEMONIC_CALL)
                {
                    if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                        size_t target = addr + insn.length + operands[0].imm.value.s;
                        branchTargets.insert(target);
                    }
                }
            }
        }

        //Explicitly add fallthrough paths for conditional jumps
        if (IsConditionalJump(insn.mnemonic))
        {
            size_t fallthroughAddr = addr + insn.length;
            branchTargets.insert(fallthroughAddr);
        }

        addr += insn.length;
    }


    bool isCC = false;

     //Second pass: Process blocks using worklist, splitting at targets and control flow
    std::unordered_map<size_t, std::vector<size_t>> cfgEdges;
    std::unordered_set<size_t> visited;
    std::queue<size_t> worklist;
    worklist.push(base);

    while (!worklist.empty())
    {
        size_t blockStart = worklist.front();
        worklist.pop();

        if (visited.count(blockStart))
            continue;

        visited.insert(blockStart);

        size_t addr = blockStart;
        fn.blocks.emplace_back(blockStart, 0);
        auto& curBlock = fn.blocks.back();


        while (addr < size)
        {
            size_t offset = addr - base;

            if (offset >= size)
                break;

            ZydisDecodedInstruction insn;
            ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, dataStart + offset, size - offset, &insn, operands)))
                break;

            //Split if current address is a branch target (not block start)
            if (addr != blockStart && branchTargets.count(addr))
            {
                worklist.push(addr);
                break;
            }

            curBlock.size += insn.length;

            bool isControlFlow = false;
            //Check for control flow instructions

            isCC = insn.mnemonic == ZYDIS_MNEMONIC_INT3;
            if (insn.mnemonic == ZYDIS_MNEMONIC_RET || isCC)
            {
                break; //End of block
            }

            if (IsControlFlow(insn.mnemonic))
            {
                isControlFlow = true;

                // For indirect jumps, push ALL valid targets from jump table
                if (insn.mnemonic == ZYDIS_MNEMONIC_JMP && operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                    auto it = switchTable.find(addr);
                    if (it != switchTable.end())
                    {
                        for (size_t target : it->second.labels)
                        {
                            if (target >= base && target < base + size) {
                                worklist.push(target);
                            }
                        }
                    }
                }
                else
                {
                    if (insn.mnemonic == ZYDIS_MNEMONIC_JMP || IsConditionalJump(insn.mnemonic))
                    {

                        if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                        {
                            size_t target = addr + insn.length + operands[0].imm.value.s;
                            cfgEdges[addr].push_back(target);

                            if (target < base || target >= size) 
                            {
                                fn.blocks.emplace_back(target, 0);
                                break;
                            }
                            else
                            {
                                worklist.push(target);
                            }
                        }

                        //For conditional jumps, add fallthrough
                        if (IsConditionalJump(insn.mnemonic))
                        {
                            size_t fallthroughAddr = addr + insn.length;
                            cfgEdges[addr].push_back(fallthroughAddr);
                            worklist.push(fallthroughAddr);
                        }

                    }
                }
            }

            //Check if next address is a branch target
            size_t nextAddr = addr + insn.length;

            if (branchTargets.count(nextAddr))
            {
                worklist.push(nextAddr);
                break; //End of block
            }

            if (isControlFlow && (insn.mnemonic == ZYDIS_MNEMONIC_JMP || insn.mnemonic == ZYDIS_MNEMONIC_RET))
                break;


            addr += insn.length;
        }


        //printf("Block start: 0x%08X, size: %u\n", blockStart, curBlock.size);
    }

    fn.cfg = std::move(cfgEdges);
    std::sort(fn.blocks.begin(), fn.blocks.end(), [](const Block& a, const Block& b)
        {
            return a.base < b.base;
        });

#ifdef _LOG
    printf("Finished analysing function 0x%08X, blocks count: %u\n", fn.base, fn.blocks.size());
    for (int i = 0; i < fn.blocks.size(); i++)
    {
        printf("block %d, base addr: %08X, size: %08X\n", i, fn.blocks[i].base, fn.blocks[i].size);
    }
#endif


    fn.size = 0;
    for (const auto& block : fn.blocks)
    {
        fn.size += block.size; // Sum the sizes of all blocks
    }


    const Block& last_block = fn.blocks.back();
    const size_t potentialEndAddress = (last_block.base + last_block.size);
    size_t calculated_size = potentialEndAddress - fn.base;
    if (potentialEndAddress < size && fn.size < calculated_size)

    {
        if (calculated_size - fn.size > 5)
            printf("\nFunction 0x%08X, size: 0x%zX, expected: 0x%zX.\nSize adjusted, new end address: 0x%08X\n", fn.base, fn.size, calculated_size, potentialEndAddress);
        fn.size = potentialEndAddress - fn.base;
    }

    return fn;
}
