cmake_minimum_required (VERSION 3.8)

project("XboxRecomp")

add_executable(XboxRecomp 
    "main.cpp" 
    "recompiler.cpp"
    "test_recompiler.cpp" 
    "recompiler_config.cpp")

target_precompile_headers(XboxRecomp PUBLIC "pch.h")
target_compile_definitions(XboxRecomp PRIVATE LOG)


target_link_libraries(XboxRecomp PRIVATE
    LibXboxAnalyse 
    XboxUtils 
    fmt::fmt
    tomlplusplus::tomlplusplus 
    xxHash::xxhash)

if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(XboxRecomp PRIVATE -Wno-switch -Wno-unused-variable -Wno-null-arithmetic)

    # alias attribute not supported on Apple.
    if (NOT APPLE)
        target_compile_definitions(XboxRecomp PRIVATE XBOX_RECOMP_USE_ALIAS)
    endif()
endif()

target_compile_definitions(XboxRecomp PRIVATE _CRT_SECURE_NO_WARNINGS)
