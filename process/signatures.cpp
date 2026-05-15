#include "signatures.h"
#include <algorithm>

namespace signatures
{
    namespace
    {
        int hex_value(char c)
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
            if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
            return -1;
        }

        bool is_whitespace(char c)
        {
            return c == ' ' || c == '\t' || c == '\r' || c == '\n';
        }
    }

    bool parse_signature(std::string_view signature, std::vector<uint8_t>& pattern, std::vector<uint8_t>& mask)
    {
        pattern.clear();
        mask.clear();

        size_t pos = 0;
        while (pos < signature.size())
        {
            while (pos < signature.size() && is_whitespace(signature[pos]))
                ++pos;

            if (pos >= signature.size())
                break;

            size_t token_start = pos;
            while (pos < signature.size() && !is_whitespace(signature[pos]))
                ++pos;

            auto token = signature.substr(token_start, pos - token_start);
            if (token == "??" || token == "?")
            {
                pattern.push_back(0);
                mask.push_back(0);
            }
            else
            {
                if (token.empty() || token.size() > 2)
                    return false;

                uint8_t value = 0;
                for (char c : token)
                {
                    int nibble = hex_value(c);
                    if (nibble < 0)
                        return false;
                    value = static_cast<uint8_t>((value << 4) | static_cast<uint8_t>(nibble));
                }

                pattern.push_back(value);
                mask.push_back(1);
            }
        }

        return !pattern.empty();
    }

    uintptr_t scan_buffer(const uint8_t* data, size_t size,
                          const std::vector<uint8_t>& pattern, const std::vector<uint8_t>& mask)
    {
        if (pattern.empty() || pattern.size() != mask.size() || size < pattern.size())
            return UINTPTR_MAX;

        size_t end = size - pattern.size();
        for (size_t i = 0; i <= end; ++i)
        {
            bool found = true;
            for (size_t j = 0; j < pattern.size(); ++j)
            {
                if (mask[j] == 1 && data[i + j] != pattern[j])
                {
                    found = false;
                    break;
                }
            }
            if (found)
                return i;
        }

        return UINTPTR_MAX;
    }

    std::vector<uintptr_t> scan_buffer_all(const uint8_t* data, size_t size,
                                           const std::vector<uint8_t>& pattern, const std::vector<uint8_t>& mask)
    {
        std::vector<uintptr_t> results;
        if (pattern.empty() || pattern.size() != mask.size() || size < pattern.size())
            return results;

        size_t end = size - pattern.size();
        for (size_t i = 0; i <= end; ++i)
        {
            bool found = true;
            for (size_t j = 0; j < pattern.size(); ++j)
            {
                if (mask[j] == 1 && data[i + j] != pattern[j])
                {
                    found = false;
                    break;
                }
            }
            if (found)
                results.push_back(i);
        }

        return results;
    }

    ScanResult scan_process(HANDLE proc, uintptr_t base, size_t size, std::string_view signature)
    {
        auto all = scan_process_all(proc, base, size, signature);
        ScanResult result;
        result.match_count = all.size();
        if (!all.empty())
            result.address = all[0];
        return result;
    }

    std::vector<uintptr_t> scan_process_all(HANDLE proc, uintptr_t base, size_t size, std::string_view signature)
    {
        std::vector<uintptr_t> results;

        std::vector<uint8_t> pattern;
        std::vector<uint8_t> mask;
        if (!parse_signature(signature, pattern, mask))
            return results;

        uintptr_t scan_end = base + size;
        uintptr_t addr = base;

        MEMORY_BASIC_INFORMATION mbi{};
        while (addr < scan_end && VirtualQueryEx(proc, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)))
        {
            uintptr_t region_base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            size_t region_size = mbi.RegionSize;

            if (region_base + region_size <= base)
            {
                addr = region_base + region_size;
                continue;
            }

            if (mbi.State == MEM_COMMIT &&
                !(mbi.Protect & PAGE_NOACCESS) &&
                !(mbi.Protect & PAGE_GUARD))
            {
                uintptr_t read_start = (std::max)(region_base, base);
                uintptr_t read_end = (std::min)(region_base + region_size, scan_end);
                size_t read_size = static_cast<size_t>(read_end - read_start);

                std::vector<uint8_t> buffer(read_size);
                SIZE_T bytes_read = 0;
                if (ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(read_start),
                                      buffer.data(), read_size, &bytes_read) && bytes_read > 0)
                {
                    auto matches = scan_buffer_all(buffer.data(), static_cast<size_t>(bytes_read), pattern, mask);
                    for (auto offset : matches)
                        results.push_back(read_start + offset);
                }
            }

            addr = region_base + region_size;
            if (addr <= region_base)
                break;
        }

        return results;
    }
}
