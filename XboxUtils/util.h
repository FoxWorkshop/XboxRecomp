#ifndef MEMACCESS_H
#define MEMACCESS_H


#include <stdint.h>
#include <iterator>
#include <stdexcept>

template <typename Tret = size_t, typename T, size_t N>
static constexpr Tret LengthOfArray(const T(&)[N]) noexcept
{
    return (Tret)N;
}

template <typename Tret = size_t, typename T, size_t N>
static constexpr Tret SizeOfArray(const T(&)[N]) noexcept
{
    return (Tret)(N * sizeof(T));
}

#endif /* MEMACCESS_H */
