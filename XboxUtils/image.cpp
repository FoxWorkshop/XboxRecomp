#include "image.h"
#include "elf.h"
#include <cassert>
#include <cstring>
#include "xbe.h"
#include <unordered_map>


const std::string dataSegments[] =
{
    ".rdata", ".data", "DOLBY", ".XTILD"
};

bool isDataSection(std::string s)
{
    for (int i = 0; i < 4; i++)
    {
        if (dataSegments[i] == s)
            return true;
    }

    return false;
}

void Image::Map(const std::string_view& name, size_t base, uint32_t size, uint8_t flags, uint8_t* data)
{
    sections.insert({ std::string(name), base, size, static_cast<SectionFlags>(flags), data });
}

void PrintSections(const Image& image)
{
    for (const auto& section : image.sections)
    {
        printf("Section '%s': base = 0x%08X, size = 0x%08X\n", section.name.c_str(), section.base, section.size);
    }
}

const void* Image::Find(size_t address) const
{
    if (address >= 0x80000000)
        return nullptr;

    // Check if the address is within the bounds of the image
    if (address < base || address >= base + size)
    {
        printf("Address 0x%08X is out of bounds for the image (base = 0x%08X, size = 0x%08X).\n",
            address, base, size);
        return nullptr;
    }

    // Find the section containing the address
    auto it = sections.upper_bound(address);

    // Check if the address is before the first section
    if (it == sections.begin())
    {
        printf("Address 0x%08X is before the first section.\n", address);
        return nullptr;
    }

    // Get the previous section (the one containing the address)
    const auto& section = *std::prev(it);

    // Check if the address is within the section's bounds
    if (address < section.base || address >= section.base + section.size)
    {
        printf("Address 0x%08X is out of bounds for section '%s' (base = 0x%08X, size = 0x%08X).\n",
            address, section.name.c_str(), section.base, section.size);
        return nullptr;
    }

    // Return the pointer to the data
    return section.data + (address - section.base);
}

const Section* Image::Find(const std::string_view& name) const
{
    for (const auto& section : sections)
    {
        if (section.name == name)
        {
            return &section;
        }
    }

    return nullptr;
}

#define DEBUG_XOR_KEY   0x94859D4B
#define RETAIL_XOR_KEY  0xA8FC57AB

uint32_t decode_entry_point(const uint32_t encoded_addr, const uint32_t maxSize)
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

Image XbeLoadImage(const uint8_t* data, size_t size)
{
    const auto* header = reinterpret_cast<const XbeHeader*>(data);

    // Validate the XBE header
    if (memcmp(header->magic, "XBEH", 4) != 0)// Check the magic number
    {
        printf("Invalid XBE file: Magic number mismatch.\n");
        return {};
    }

    Image image{};
    image.size = size;
    image.data = std::make_unique<uint8_t[]>(size);
    image.entry_point = decode_entry_point(header->m_entry, size);
    image.dwsizeofImage = header->sizeOfImage;
    image.base = header->baseAddress;
    memcpy(image.data.get(), data, size);

    printf("Parsing XBE file...\n\n");

    const uint32_t sectionCertificateOffset = header->certificateAddress - header->baseAddress;
    const uint32_t sectionHeadersOffset = header->sectionHeadersAddress - header->baseAddress;

    if (sectionCertificateOffset >= size)
    {
        printf("warning Invalid section certificate offset. (out of bounds).\n");
    }
    else
    {
        const auto* sectionCertificate = reinterpret_cast<const certificate*>(data + sectionCertificateOffset);

        wprintf(L"Title: %ls\n", sectionCertificate->m_title_name);

    }

    printf("Section headers offset: 0x%08X\n", sectionHeadersOffset);

    if (sectionHeadersOffset >= size)
    {
        printf("warning Invalid section headers offset (out of bounds).\n");
        return {};
    }


    printf("Magic number: %.4s\n", header->magic);
    printf("Size of image: 0x%08X\n", header->sizeOfImage);
    printf("Number of sections: %u\n", header->numSections);

    printf("Header Base Address: 0x%08X\n", header->baseAddress);
    printf("Section Headers Address: 0x%08X\n", header->sectionHeadersAddress);
    printf("Expected Section Headers Offset: 0x%08X\n", header->sectionHeadersAddress - header->baseAddress);


    const auto* sectionHeaders = reinterpret_cast<const XbeSectionHeader*>(data + sectionHeadersOffset);

    for (uint32_t i = 0; i < header->numSections; i++)
    {
        const auto& section = sectionHeaders[i];

        if (reinterpret_cast<const uint8_t*>(&section) >= data + size)
        {
            printf("Section %u is out of bounds!\n", i);
            break;
        }

        // Validate section addresses
        if (section.rawAddress >= size || section.rawAddress + section.rawSize > size)
        {
            printf("Invalid section %u: Out of bounds (Raw Address = 0x%08X, Raw Size = 0x%08X).\n",
                i, section.rawAddress, section.rawSize);
            continue;
        }

        // Validate virtual addresses
        if (section.virtualAddress < header->baseAddress ||
            section.virtualAddress + section.virtualSize > header->baseAddress + header->sizeOfImage)
        {
            printf("Invalid section %u: Virtual address out of bounds (Virtual Address = 0x%08X, Virtual Size = 0x%08X).\n",
                i, section.virtualAddress, section.virtualSize);
            continue;
        }

        const char* name = reinterpret_cast<const char*>(data + section.sectionNameAddress - header->baseAddress);

        // Map the section
        uint8_t flags = 0;
        std::string s = name;
        if (section.m_flags.m_executable != 0x1)
        {
            flags |= SectionFlags_Data;

        }
        else // Executable flag
        {
            //skip for stuff that fire when it shouldn't for some reason
            if (!isDataSection(s))
                flags |= SectionFlags_Code;
        }

        //would be nice to have a less hardcoded way
        if (isDataSection(s))
            flags |= SectionFlags_Data;


        image.Map(name, section.virtualAddress, section.virtualSize, flags, image.data.get() + section.rawAddress);
    }

    LoadKernelFunctions(image);

    return image;
}

Image Image::ParseImage(const uint8_t* data, size_t size)
{
    if (data[0] == 'X' && data[1] == 'B' && data[2] == 'E' && data[3] == 'H')
    {
        auto res = XbeLoadImage(data, size);
        PrintSections(res); // Debug print
        return res;
    }

    return {};
}
