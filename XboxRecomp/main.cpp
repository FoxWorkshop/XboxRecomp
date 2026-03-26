#include "pch.h"
#include "test_recompiler.h"

int main(int argc, char* argv[])
{
#ifndef XBOX_RECOMP_CONFIG_FILE_PATH 
    if (argc < 3)
    {
        printf("Usage: XboxRecomp [input TOML file path] [x86 context header file path]");
        return EXIT_SUCCESS;
    }
#endif

    const char* path = 
    #ifdef XBOX_RECOMP_CONFIG_FILE_PATH
        XBOX_RECOMP_CONFIG_FILE_PATH
    #else
        argv[1]
    #endif
        ;

    if (std::filesystem::is_regular_file(path))
    {
        Recompiler recompiler;
        if (!recompiler.LoadConfig(path))
            return -1;

        recompiler.Analyse();

        auto entry = recompiler.image.symbols.find(recompiler.image.entry_point);
        if (entry != recompiler.image.symbols.end())
        {
            entry->name = "_xstart";
        }

        const char* headerFilePath = 
#ifdef XBOX_RECOMP_HEADER_FILE_PATH
            XBOX_RECOMP_HEADER_FILE_PATH
#else
        argv[2]
#endif
            ;

        recompiler.Recompile(headerFilePath);
    }
    else
    {
        //TestRecompiler::RecompileTests(path, argv[2]);
    }

    return EXIT_SUCCESS;
}
