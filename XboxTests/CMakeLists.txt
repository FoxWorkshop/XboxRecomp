project("XboxTests")

file(GLOB TEST_FILES *.cpp)

if(TEST_FILES)
    add_executable(XboxTests 
        ${TEST_FILES}
    )
    target_link_libraries(XboxTests 
        PUBLIC 
            XboxUtils
            fmt::fmt
    )
    target_compile_options(XboxTests
        PRIVATE 
            "-march=sandybridge"
            "-Wno-unused-label"
            "-Wno-unused-variable"
    )
endif()
