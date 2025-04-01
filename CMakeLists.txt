cmake_minimum_required (VERSION 3.20)

set(THIRDPARTY_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/thirdparty)

set(CMAKE_CXX_STANDARD 17)
set(BUILD_SHARED_LIBS OFF)

# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_subdirectory(${THIRDPARTY_ROOT})
set(XboxANALYSE_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/XboxAnalyse)
set(XboxUTILS_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/XboxUtils)
set(XboxRECOMP_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/XboxRecomp)

project ("XboxRecomp-ALL")

add_subdirectory(${XboxANALYSE_ROOT})
add_subdirectory(${XboxRECOMP_ROOT})
add_subdirectory(${XboxUTILS_ROOT})

# Only tests if this is the top level project
if (${CMAKE_CURRENT_SOURCE_DIR} STREQUAL ${CMAKE_SOURCE_DIR})
    add_subdirectory(XboxTests)
endif()
