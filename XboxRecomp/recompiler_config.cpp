#include "recompiler_config.h"
#include <iostream>
#include <toml++/toml.hpp>
#include <algorithm>

void RecompilerConfig::Load(const std::string_view& configFilePath)
{
    directoryPath = configFilePath.substr(0, configFilePath.find_last_of('/') + 1);


    toml::table toml = toml::parse_file(configFilePath)
#if !TOML_EXCEPTIONS
        .table()
#endif
        ;

    if (auto mainPtr = toml["main"].as_table())
    {
        const auto& main = *mainPtr;
        filePath = main["file_path"].value_or<std::string>("");
        outDirectoryPath = main["out_directory_path"].value_or<std::string>("");
        switchTableFilePath = main["switch_table_file_path"].value_or<std::string>("");

        //this technically shouldn't be needed as Xbox titles were built with Microsoft's XDK, which encouraged SEH over setjmp/longjmp.
        //but maybe there is one super rare xbox game that didn't follow this, so just in case...
        longJmpAddress = main["longjmp_address"].value_or(0u);
        setJmpAddress = main["setjmp_address"].value_or(0u);
        fastTrig = main["fast_trig"].value_or(false);


        if (auto functionsArray = main["functions"].as_array())
        {
            for (auto& func : *functionsArray)
            {
                auto& funcTable = *func.as_table();
                uint32_t address = *funcTable["address"].value<uint32_t>();
                uint32_t size = *funcTable["size"].value<uint32_t>();
                functions.emplace(address, size);
            }
        }

        if (auto invalidArray = main["invalid_instructions"].as_array())
        {
            for (auto& instr : *invalidArray)
            {
                auto& instrTable = *instr.as_table();
                uint32_t data = *instrTable["data"].value<uint32_t>();
                uint32_t size = *instrTable["size"].value<uint32_t>();
                invalidInstructions.emplace(data, size);
            }
        }       
        
        if (auto invalidAddress = main["banned_addresses"].as_array())
        {
            for (auto& instr : *invalidAddress)
            {
                auto& instrTable = *instr.as_table();
                uint32_t data = *instrTable["start"].value<uint32_t>();
                uint32_t size = *instrTable["end"].value<uint32_t>();
                bannedAddresses.emplace(data, size);
            }
        }

        if (auto pushPatchArray = main["push_patch"].as_array())
        {
            for (auto& instr : *pushPatchArray)
            {
                auto& instrTable = *instr.as_table();
                uint32_t address = *instrTable["address"].value<uint32_t>();
                uint32_t value = *instrTable["value"].value<uint32_t>();
                pushPatches.emplace(address, value);
            }
        }

        if (!switchTableFilePath.empty())
        {
            toml::table switchToml = toml::parse_file(directoryPath + switchTableFilePath)
#if !TOML_EXCEPTIONS
                .table()
#endif
                ;
            if (auto switchArray = switchToml["switch"].as_array())
            {
                for (auto& entry : *switchArray)
                {
                    auto& table = *entry.as_table();
                    RecompilerSwitchTable switchTable;
                    switchTable.r = *table["r"].value<uint32_t>();
                    switchTable.base = *table["base"].value<size_t>();
                    switchTable.start = *table["default"].value<size_t>();


                    for (auto& label : *table["labels"].as_array())
                    {
                        switchTable.labels.push_back(*label.value<uint32_t>());
                    }
                    /**if (table.contains("indirect"))
                    {
                        for (auto& indirect : *table["indirect"].as_array())
                        {
                            switchTable.indirect.push_back(*indirect.value<uint8_t>());
                        }
                    }*/
                    switchTables.emplace(*table["base"].value<uint32_t>(), std::move(switchTable));
                }
            }
        }
    }

    if (auto midAsmHookArray = toml["midasm_hook"].as_array())
    {
        for (auto& entry : *midAsmHookArray)
        {
            auto& table = *entry.as_table();

            RecompilerMidAsmHook midAsmHook;
            midAsmHook.name = *table["name"].value<std::string>();
            if (auto registerArray = table["registers"].as_array())
            {
                for (auto& reg : *registerArray)
                    midAsmHook.registers.push_back(*reg.value<std::string>());
            }

            midAsmHook.ret = table["return"].value_or(false);
            midAsmHook.returnOnTrue = table["return_on_true"].value_or(false);
            midAsmHook.returnOnFalse = table["return_on_false"].value_or(false);

            midAsmHook.jumpAddress = table["jump_address"].value_or(0u);
            midAsmHook.jumpAddressOnTrue = table["jump_address_on_true"].value_or(0u);
            midAsmHook.jumpAddressOnFalse = table["jump_address_on_false"].value_or(0u);

            if ((midAsmHook.ret && midAsmHook.jumpAddress != NULL) ||
                (midAsmHook.returnOnTrue && midAsmHook.jumpAddressOnTrue != NULL) ||
                (midAsmHook.returnOnFalse && midAsmHook.jumpAddressOnFalse != NULL))
            {
                fmt::println("{}: can't return and jump at the same time", midAsmHook.name);
            }

            if ((midAsmHook.ret || midAsmHook.jumpAddress != NULL) &&
                (midAsmHook.returnOnFalse != NULL || midAsmHook.returnOnTrue != NULL ||
                    midAsmHook.jumpAddressOnFalse != NULL || midAsmHook.jumpAddressOnTrue != NULL))
            {
                fmt::println("{}: can't mix direct and conditional return/jump", midAsmHook.name);
            }

            midAsmHook.afterInstruction = table["after_instruction"].value_or(false);

            midAsmHooks.emplace(*table["address"].value<uint32_t>(), std::move(midAsmHook));
        }
    }



}
