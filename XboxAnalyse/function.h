#pragma once

#include <cstddef>
#include <vector>
#include <unordered_map>
#include <switchTable.h>
#include <unordered_set>
#include "section.h"

#ifdef _DEBUG
#define DEBUG(X) X
#else
#define DEBUG(X)
#endif

struct Function;
struct Function
{
    struct Block
    {
        size_t base{};
        size_t size{};
        size_t projectedSize{ static_cast<size_t>(-1) }; // scratch
        DEBUG(size_t parent{});

        Block()
        {
        }

        Block(size_t base, size_t size)
            : base(base), size(size)
        {
        }

        Block(size_t base, size_t size, size_t projectedSize)
            : base(base), size(size), projectedSize(projectedSize)
        {
        }
    };

    size_t base{};
    //size_t end{};
    size_t size{};
    size_t tailJumpTarget{ static_cast<size_t>(-1) };
    // size_t indirectCalls{}; // Store addresses of indirect calls
    std::vector<Block> blocks{};
    std::unordered_map<size_t, std::vector<size_t>> cfg{};  // CFG adjacency list (edges)
    std::vector<size_t> calls{}; //todo delete once debugging is complete

    Function()
    {
    }

    Function(size_t base, size_t size)
        : base(base), size(size)
    {
    }

    size_t SearchBlock(size_t address) const;



    //static Function Function::Analyze(const void* code, size_t size, size_t base);
    static Function Function::Analyze(const void* code, size_t size, size_t base, std::unordered_map<uint32_t, RecompilerSwitchTable>& switchTable);
    static void Function::VfTableAnalyze(const void* code, size_t size, size_t base, Section section, std::unordered_set<size_t>& analysedFuncs, std::unordered_set<size_t>& subFunctionsFromVirtualFunc);
    //static Function Function::Analyze(const void* code, size_t size, size_t base, size_t jmpAddr, const size_t sectionStart, const size_t sectionEnd, std::unordered_map<uint32_t, RecompilerSwitchTable>* switchTable);

    bool operator==(const Function& other) const {
        return base == other.base && size == other.size;
    }
};
