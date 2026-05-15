#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace process
{
    struct HandleGuard
    {
        HANDLE h = nullptr;

        explicit HandleGuard(HANDLE handle = nullptr) : h(handle) {}
        ~HandleGuard() { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }

        HandleGuard(const HandleGuard&) = delete;
        HandleGuard& operator=(const HandleGuard&) = delete;
        HandleGuard(HandleGuard&& o) noexcept : h(o.h) { o.h = nullptr; }
        HandleGuard& operator=(HandleGuard&& o) noexcept { if (this != &o) { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); h = o.h; o.h = nullptr; } return *this; }

        explicit operator bool() const { return h && h != INVALID_HANDLE_VALUE; }
    };

    struct ProcessInfo
    {
        HANDLE handle = nullptr;
        DWORD pid = 0;
        uintptr_t base_address = 0;
        size_t image_size = 0;
    };

    DWORD find_process(const wchar_t* name);
    std::optional<ProcessInfo> open_process(const wchar_t* name);
    void close_process(ProcessInfo& info);

    bool read_memory(HANDLE proc, uintptr_t addr, void* buf, size_t size);
    bool write_memory(HANDLE proc, uintptr_t addr, const void* buf, size_t size);

    template<typename T>
    std::optional<T> read_value(HANDLE proc, uintptr_t addr)
    {
        T value{};
        if (read_memory(proc, addr, &value, sizeof(T)))
            return value;
        return std::nullopt;
    }

    std::optional<std::string> read_string(HANDLE proc, uintptr_t addr, size_t max_len = 256);
    std::vector<uint8_t> read_bytes(HANDLE proc, uintptr_t addr, size_t size);
}
