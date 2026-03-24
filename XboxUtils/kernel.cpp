#include <algorithm>
#include <cassert>
#include <cstring>

#include "image.h"
#include <unordered_map>
#include "xbe.h"

#define DEBUG_XOR_KEY   0xEFB1F152
#define RETAIL_XOR_KEY  0x5B6D40B6
#define STRINGIFY(X) #X
#define XE_EXPORT(MODULE, ORDINAL, NAME, TYPE) { (ORDINAL), "__imp__" STRINGIFY(NAME) }


int32_t XboxSignatureAddress = -1;

bool isXboxSignatureArray(int32_t address)
{
    return XboxSignatureAddress != -1 && XboxSignatureAddress == address;
}

std::unordered_map<size_t, size_t> kernelAddrMap;

uint32_t ResolveKernelCall(const uint32_t callAddr)
{
    auto curMap = kernelAddrMap.find(callAddr);
    return (curMap != kernelAddrMap.end()) ? curMap->second : 0;
}

static uint16_t variablesID[] =
{
    0x0010,
    0x0016,
    0x001E,
    0x001F,
    0x0028,
    0x0029,
    0x002A,
    0x0040,
    0x0046,
    0x0047,
    0x0058,
    0x0059,
    0x0066,
    0x0078,
    0x009A,
    0x009C,
    0x009D,
    0x00A2,
    0x00A4,
    0x00F0,
    0x00F5,
    0x00F9,
    0x0103,
    0x0161,
    0x0162,
    0x0163,
    0x0164,
    0x0165,
    0x0141,
    0x0142,
    0x0143,
    0x0144,
    0x0145,
    0x0146,
};

std::unordered_map<size_t, const char*> XboxKernelExports =
{
    #include "xbox/xboxkrnl_table.inc"
};

uint32_t decode_kernel_thunk_addr(const uint32_t encoded_addr, const uint32_t maxSize)
{
    uint32_t debug_decoded = encoded_addr ^ DEBUG_XOR_KEY;

    if (debug_decoded < maxSize - 1000)
    {
        return debug_decoded;
    }

    uint32_t retail_decoded = encoded_addr ^ RETAIL_XOR_KEY;

    if (retail_decoded < maxSize - 1000)
    {
        return retail_decoded;
    }

    return 0;
}


void LoadKernelFunctions(Image& image)
{
    const auto* header = reinterpret_cast<const XbeHeader*>(image.data.get());

    auto kernelFuncTable = decode_kernel_thunk_addr(header->m_kernel_image_thunk_addr, image.size);

    Section rdata{};
    for (const auto& section : image.sections)
    {
        if (section.name == ".rdata")
        {
            rdata = section;
            break;
        }
    }

    uint8_t* data = rdata.data + (kernelFuncTable - rdata.base);

    if (kernelFuncTable > 0)
    {
        size_t size = rdata.base + rdata.size;
        uint16_t count = 0;

        const size_t ALIGNMENT = 4;
        const std::unordered_map<size_t, const char*>* names = &XboxKernelExports;

        for (size_t i = 0; i < size; i += ALIGNMENT)
        {
            uint32_t currentAddr = kernelFuncTable + i;
            uint32_t ordinal = *reinterpret_cast<const uint32_t*>(data + i);
            auto curPtr = data + i;

            if (count >= 366 || !curPtr[0])
                break;

            const uint32_t index = ordinal & 0xFFFF; 
            auto name = XboxKernelExports.find(index);
            if (name != names->end())
            {
                if (std::find(std::begin(variablesID), std::end(variablesID), index) == std::end(variablesID))
                {
                    kernelAddrMap.insert({ currentAddr, ordinal });
                    image.symbols.insert({ name->second, (currentAddr), 1, Symbol_Function });
                }

     
            }

            if (index == 0x145) //xbox signature address
            {
                XboxSignatureAddress = currentAddr;
            }       

            count++;
        };
    }

    if (XboxSignatureAddress == -1)
        printf("WARNING XBOX SIGNATURE NOT FOUND!\n");
}
