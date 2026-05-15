#pragma once

#include "process.h"
#include <string_view>
#include <vector>
#include <cstdint>

namespace signatures
{
    bool parse_signature(std::string_view signature, std::vector<uint8_t>& pattern, std::vector<uint8_t>& mask);

    uintptr_t scan_buffer(const uint8_t* data, size_t size,
                          const std::vector<uint8_t>& pattern, const std::vector<uint8_t>& mask);

    std::vector<uintptr_t> scan_buffer_all(const uint8_t* data, size_t size,
                                           const std::vector<uint8_t>& pattern, const std::vector<uint8_t>& mask);

    struct ScanResult
    {
        uintptr_t address = 0;
        size_t match_count = 0;
    };

    ScanResult scan_process(HANDLE proc, uintptr_t base, size_t size, std::string_view signature);
    std::vector<uintptr_t> scan_process_all(HANDLE proc, uintptr_t base, size_t size, std::string_view signature);
}
