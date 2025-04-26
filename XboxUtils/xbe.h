// XBE Header (based on https://xboxdevwiki.net/XBE and https://xbdev.net/fileformats/xbe/NonOfficialXBEFileFormat.pdf)
#pragma pack(push, 1)
struct XbeHeader {
    char magic[4];              // "XBEH"
    uint8_t  digitalSignature[256]; // Digital signature
    uint32_t baseAddress;        // Base address of the executable
    uint32_t sizeOfHeaders;      // Size of all headers
    uint32_t sizeOfImage;        // Size of the entire image
    uint32_t sizeOfImageHeader;  // Size of the image header
    uint32_t timestamp;          // Timestamp
    uint32_t certificateAddress; // Address of the certificate
    uint32_t numSections;        // Number of sections
    uint32_t sectionHeadersAddress; // Address of section headers

    struct init_flags
    {
        uint32_t m_mount_utility_drive : 1; // mount utility drive flag
        uint32_t m_format_utility_drive : 1; // format utility drive flag
        uint32_t m_limit_64mb : 1; // limit development kit run time memory to 64mb flag
        uint32_t m_dont_setup_harddisk : 1; // don't setup hard disk flag
        uint32_t m_unused : 4; // unused (or unknown)
        uint32_t m_unused_b1 : 8; // unused (or unknown)
        uint32_t m_unused_b2 : 8; // unused (or unknown)
        uint32_t m_unused_b3 : 8; // unused (or unknown)
    }m_init_flags;

    uint32_t m_entry; // entry point addres
    uint32_t tlsAddress;         // Thread Local Storage (TLS) address
    uint32_t m_pe_stack_commit; // size of stack commit
    uint32_t m_pe_heap_reserve; // size of heap reserve
    uint32_t m_pe_heap_commit; // size of heap commit
    uint32_t m_pe_base_addr; // original base address
    uint32_t m_pe_sizeof_image; // size of original image
    uint32_t m_pe_checksum; // original checksum
    uint32_t m_pe_timedate; // original timedate stamp
    uint32_t m_debug_pathname_addr; // debug pathname address
    uint32_t m_debug_filename_addr; // debug filename address
    uint32_t m_debug_unicode_filename_addr; // debug unicode filename address
    uint32_t m_kernel_image_thunk_addr; // kernel image thunk address
    uint32_t m_nonkernel_import_dir_addr; // non kernel import directory address
    uint32_t m_library_versions; // number of library versions
    uint32_t m_library_versions_addr; // library versions address
    uint32_t m_kernel_library_version_addr; // kernel library version address
    uint32_t m_xapi_library_version_addr; // xapi library version address
};


struct XbeSectionHeader {
   
    struct flags 
    {
        uint32_t m_writable : 1; // writable flag
        uint32_t m_preload : 1; // preload flag
        uint32_t m_executable : 1; // executable flag
        uint32_t m_inserted_file : 1; // inserted file flag
        uint32_t m_head_page_ro : 1; // head page read only flag
        uint32_t m_tail_page_ro : 1; // tail page read only flag
        uint32_t m_unused_a1 : 1; // unused (or unknown)
        uint32_t m_unused_a2 : 1; // unused (or unknown)
        uint32_t m_unused_b1 : 8; // unused (or unknown)
        uint32_t m_unused_b2 : 8; // unused (or unknown)
        uint32_t m_unused_b3 : 8; // unused (or unknown)
    }m_flags;

    uint32_t virtualAddress;
    uint32_t virtualSize;
    uint32_t rawAddress;
    uint32_t rawSize;
    uint32_t sectionNameAddress;
    uint32_t sectionNameReferenceCount;
    uint32_t headSharedPageCount;
    uint32_t tailSharedPageCount;
    uint8_t sectionDigest[20]; 
};

struct certificate
{
    uint32_t m_size; // size of certificate
    uint32_t m_timedate; // timedate stamp
    uint32_t m_titleid; // title id
    uint16_t m_title_name[40]; // title name (unicode)
    uint32_t m_alt_title_id[0x10]; // alternate title ids
    uint32_t m_allowed_media; // allowed media types
    uint32_t m_game_region; // game region
    uint32_t m_game_ratings; // game ratings
    uint32_t m_disk_number; // disk number
    uint32_t m_version; // version
    uint8_t m_lan_key[16]; // lan key
    uint8_t m_sig_key[16]; // signature key
    uint8_t m_title_alt_sig_key[16][16]; // alternate signature keys
};

#pragma pack(pop)
