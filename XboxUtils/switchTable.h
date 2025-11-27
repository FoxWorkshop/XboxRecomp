
#pragma once
#include <vector>

struct SwitchTable
{
    std::vector<size_t> labels{};
    std::vector<uint8_t> indirectTable{};
    size_t base{};
    size_t defaultLabel{};
    //size_t end{};
    uint32_t r{};
    uint32_t type{};
};

struct RecompilerSwitchTable
{
    uint32_t r;
    std::vector<uint32_t> labels;
   // std::vector<uint8_t> indirect; //for switch reconsitution
    size_t base{};
    size_t start{}; //for comparison with fake function call that are actually jump table because x86 is funny
    size_t end{};
};
