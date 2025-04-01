# cmake_minimum_required (VERSION 3.16)

project("XboxAnalyse")

add_executable(XboxAnalyse 
    "main.cpp" 
    "function.cpp")

target_link_libraries(XboxAnalyse PRIVATE XboxUtils fmt::fmt)
target_compile_definitions(XboxAnalyse PRIVATE _LOG)

add_library(LibXboxAnalyse "function.cpp")
target_include_directories(LibXboxAnalyse PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(LibXboxAnalyse PUBLIC XboxUtils)

