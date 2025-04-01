project("XboxUtils")

add_library(XboxUtils
     
    "xex.cpp" 
    "image.cpp"
    "kernel.cpp"
    "xdbf_wrapper.cpp"
    "xex_patcher.cpp"
    "memory_mapped_file.cpp"
    "${THIRDPARTY_ROOT}/libmspack/libmspack/mspack/lzxd.c"
    "${THIRDPARTY_ROOT}/tiny-AES-c/aes.c"
)

target_compile_definitions(XboxUtils
    PRIVATE
        NOMINMAX
)

target_include_directories(XboxUtils 
    PUBLIC 
        .
    PRIVATE
        "${THIRDPARTY_ROOT}/libmspack/libmspack/mspack"
        "${THIRDPARTY_ROOT}/tiny-AES-c"
        "${THIRDPARTY_ROOT}/TinySHA1"
)

target_link_libraries(XboxUtils 
    PUBLIC
		Zydis
)
