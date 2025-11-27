#include <cassert>
#include <iterator>
#include <file.h>
#include <image.h>
#include <xbox.h>
#include <fmt/core.h>
#include "function.h"
#include <Zydis/Zydis.h>
#include <switchTable.h>

#define SWITCH_ABSOLUTE 0
#define SWITCH_COMPUTED 1
#define SWITCH_BYTEOFFSET 2
#define SWITCH_SHORTOFFSET 3

uint32_t GetIndexRegister(const ZydisDecodedOperand& memOp)
{
    if (memOp.type == ZYDIS_OPERAND_TYPE_MEMORY)
    {
        switch (memOp.mem.index)
        {
        case ZYDIS_REGISTER_EAX:
            return 0;
        case ZYDIS_REGISTER_EBX:
            return 1;
        case ZYDIS_REGISTER_ECX:
            return 2;
        case ZYDIS_REGISTER_EDX:
            return 3;
        case ZYDIS_REGISTER_ESI:
            return 4;
        case ZYDIS_REGISTER_EDI:
            return 5;
        case ZYDIS_REGISTER_EBP:
            return 6;
        case ZYDIS_REGISTER_ESP:
            return 7;
        }
    }

    return (ZydisRegister)UINT8_MAX; //No register found
}


size_t DetermineJumpTableSize(const uint32_t* offsets, size_t maxSize, size_t imageBase, size_t imageSize)
{
    size_t size = 0;
    for (size_t i = 0; i < maxSize; i++)
    {
        size_t label = offsets[i];
        //Check if the label is within the valid address range
        if (label >= imageBase && label < imageBase + imageSize)
        {
            size++;
        }
        else
        {
            //Stop if we encounter an invalid address
            break;
        }
    }
    return size;
}

size_t DetermineIndirectTableSize(const uint8_t* data, size_t maxSize)
{
    size_t size = 0;
    for (size_t i = 0; i < maxSize; i++)
    {
        if (data[i] > 0x0F) // Stop if we encounter an invalid value
        {
            break;
        }
        size++;
    }
    return size;
}

bool IsAlignmentPadding(const uint8_t* data, size_t size)
{
    for (size_t i = 0; i < size; i++)
    {
        if (data[i] != 0xCC)
        {
            return false;
        }
    }
    return true;
}

size_t IsAlignmentPaddingNop(const uint8_t* data, size_t size)
{
    size_t count = 0;
    for (size_t i = 0; i < size; i++)
    {
        if (data[i] != 0x90)
        {
            continue;
        }
        else
        {
            count++;
        }
    }

    return count;
}

bool IsIndirectTable(const uint8_t* data, size_t size)
{
    for (size_t i = 0; i < size; i++)
    {
        // Indirect tables typically contain small values (e.g., 0x00 to 0x0F)
        if (data[i] > 0x0F)
        {
            return false;
        }
    }
    return true;
}



void ReadTable(Image& image, SwitchTable& table)
{
    uint32_t pOffset = 0;
    ZydisDecodedInstruction insn;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    auto* code = (uint8_t*)image.Find(table.base);

    if (!code)
    {
        printf("Failed to find code at table.base = 0x%08X.\n", table.base);
        return;
    }

    // Initialize the decoder
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);

    // Decode the first instruction to find the jump table offset
    if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, code, 16, &insn, operands)))
    {
        if (insn.operand_count > 0 && operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            // Extract the offset from the memory operand
            pOffset = operands[0].mem.disp.value;
        }
    }

    if (table.type == SWITCH_ABSOLUTE)
    {
        const auto* offsets = (uint32_t*)image.Find(pOffset);
        if (!offsets)
        {
            printf("Failed to find jump table at address 0x%08X.\n", pOffset);
            return;
        }


        table.r = GetIndexRegister(operands[0]);
        if (table.r >= UINT8_MAX) // couldn't find the jump table register
        {
            printf("No valid labels found at 0x%08X. Skipping...\n", pOffset);
            return;
        }


        // Determine the size of the jump table dynamically
        const size_t jumpTableSize = DetermineJumpTableSize(offsets, UINT8_MAX, image.base, image.size); // Arbitrary 255 value for max size
        if (jumpTableSize == 0)
        {
            printf("No valid labels found at 0x%08X. Skipping...\n", pOffset);
            return;
        }

        // table.end = pOffset + (jumpTableSize * 4);
         //Check if the data following the jump table is an indirect table
        const uint8_t* indirectTableStart = (const uint8_t*)offsets + (jumpTableSize * 4);
        if (IsIndirectTable(indirectTableStart, 16)) // Check the next 16 bytes
        {
            printf("Indirect table detected at 0x%08X. Extracting...\n", pOffset + (jumpTableSize * 4));

            //Extract the indirect table data
            size_t indirectTableSize = DetermineIndirectTableSize(indirectTableStart, 32);
            for (size_t i = 0; i < indirectTableSize; i++)
            {
                table.indirectTable.push_back(indirectTableStart[i]);
            }

            //table.end += indirectTableSize; //update end address to handle the indirect table which extend the original switch
        }        //Check if the data following the jump table is alignment padding
        else if (IsAlignmentPadding((const uint8_t*)offsets + (table.r * 4), 4)) // Check the next 4 bytes
        {
            printf("Alignment padding detected at 0x%08X. Stopping extraction.\n", pOffset + (table.r * 4));
        }


        // Read the target addresses from the jump table
        for (size_t i = 0; i < jumpTableSize; i++)
        {
            table.labels.push_back(offsets[i]);
        }
    }
    else if (table.type == SWITCH_COMPUTED)
    {



    }
}


void* SearchMask(const void* source, const uint8_t* compare, size_t compareCount, size_t size)
{

    uint8_t* src = (uint8_t*)source;

    for (size_t i = 0; i < size; i++)
    {
        size_t c = 0;
        for (c = 0; c < compareCount; c++)
        {
            if (src[i + c] != compare[c])
            {
                break;
            }
        }

        if (c == compareCount)
        {
            return &src[i];
        }
    }

    return nullptr;
}

static std::string out;

template<class... Args>
static void println(fmt::format_string<Args...> fmt, Args&&... args)
{
    fmt::vformat_to(std::back_inserter(out), fmt.get(), fmt::make_format_args(args...));
    out += '\n';
};

int main(int argc, char** argv)
{

    std::string xbePath = "";
    std::string tomlPath = "";
#ifdef _DEBUG
    if (argc < 3)
    {
        xbePath = "default.xbe";
        tomlPath = "out.toml";
    }
    else
    {
        xbePath = argv[1];
        tomlPath = argv[2];
    }
#else
    xbePath = argv[1];
    tomlPath = argv[2];

    if (argc < 3)
    {
        printf("Usage: XboxAnalyse [input XBE file path ex: default.xbe] [output jump table TOML file path ex: out.toml]");
        return EXIT_SUCCESS;
    }
#endif


    const auto file = LoadFile(xbePath);
    auto image = Image::ParseImage(file.data(), file.size());
    printf("Parse image done.\n\n");

    printf("Attempt to extract jump table...\n\n");

    auto printTable = [&](const SwitchTable& table)
        {
            println("[[switch]]");

            println("base = 0x{:X}", table.base);
            println("r = {}", table.r);
            println("default = 0x{:X}", table.defaultLabel);
            //println("end = 0x{:X}", table.end);
            println("labels = [");
            for (const auto& label : table.labels)
            {
                println("    0x{:X},", label);
            }

            println("]");
            /** if (table.indirectTable.empty() == false)
             {
                 println("indirect = [");
                 for (const auto& label : table.indirectTable)
                 {
                     println("    0x{:X},", label);
                 }
                 println("]");
             }*/
            println("");
        };

    std::vector<SwitchTable> switches{};


    println("# Generated by XboxAnalyse\n");

    auto scanPattern = [&](uint8_t* pattern, size_t count, size_t type)
        {
            ZydisDecoder decoder;
            ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
            ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

            for (const auto& section : image.sections)
            {
                if (!(section.flags & SectionFlags_Code))
                {
                    continue;
                }


                // println("# Section " + section.name + "\n");
                size_t base = section.base;
                uint8_t* data = section.data;
                uint8_t* dataStart = section.data;
                uint8_t* dataEnd = section.data + section.size;

                while (data < dataEnd && data != nullptr)
                {
                    ZydisDecodedInstruction instruction;
                    auto size = dataEnd - dataStart;

                    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, data, dataEnd - data, &instruction, operands)))
                    {
                        data++;
                        continue;
                    }

                    const bool is_jump_table = instruction.mnemonic == ZYDIS_MNEMONIC_JMP &&
                        operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                        operands[0].mem.index != ZYDIS_REGISTER_NONE &&
                        (operands[0].mem.scale == 4 || operands[0].mem.scale == 8);

                    auto addr = base + (data - section.data);
                    if (addr == 0x14A92)
                    {
                        printf("\n");
                    }

                    if (is_jump_table)
                    {

                        SwitchTable table{};
                        table.type = type;
                        // Extract the base address of the jump table
                        table.base = addr;
                        table.defaultLabel = operands[0].mem.disp.value;
        
                        if (table.base > section.base)
                        {
                            ReadTable(image, table);
                            printTable(table);
                            switches.emplace_back(std::move(table));
                        }


                    }

                    operands[0] = operands[0];
                    data += instruction.length;
                }
            }
        };

    uint8_t absoluteSwitch[] =
    {
         0xFF, 0x24, 0x85         // jmp [table + eax*4]
    };

    uint8_t computedSwitch[] =
    {
        0xFF, 0xE2              // jmp edx
    };

    uint8_t offsetSwitch[] =
    {
          0xFF, 0xE2              // jmp edx
    };

    uint8_t wordOffsetSwitch[] =
    {
        0xFF, 0xE2              // jmp edx
    };

    println("# ---- ABSOLUTE JUMPTABLE ----\n");
    scanPattern(absoluteSwitch, std::size(absoluteSwitch), SWITCH_ABSOLUTE);


    std::ofstream f(tomlPath);
    f.write(out.data(), out.size());

    printf("found %ld jump tables\n", switches.size());

    return EXIT_SUCCESS;
}
