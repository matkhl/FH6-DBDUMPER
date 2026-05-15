#pragma once

#include "process.h"
#include <cstdint>
#include <optional>

namespace remote
{
    struct RemoteAlloc
    {
        HANDLE process = nullptr;
        void* address = nullptr;
        size_t size = 0;

        RemoteAlloc() = default;
        RemoteAlloc(HANDLE proc, void* addr, size_t sz) : process(proc), address(addr), size(sz) {}
        ~RemoteAlloc() { free(); }

        RemoteAlloc(const RemoteAlloc&) = delete;
        RemoteAlloc& operator=(const RemoteAlloc&) = delete;
        RemoteAlloc(RemoteAlloc&& o) noexcept : process(o.process), address(o.address), size(o.size)
        {
            o.address = nullptr;
        }
        RemoteAlloc& operator=(RemoteAlloc&& o) noexcept
        {
            if (this != &o) { free(); process = o.process; address = o.address; size = o.size; o.address = nullptr; }
            return *this;
        }

        explicit operator bool() const { return address != nullptr; }
        uintptr_t addr() const { return reinterpret_cast<uintptr_t>(address); }

        void free()
        {
            if (address && process)
            {
                VirtualFreeEx(process, address, 0, MEM_RELEASE);
                address = nullptr;
            }
        }
    };

    RemoteAlloc alloc_remote(HANDLE proc, size_t size, DWORD protect = PAGE_READWRITE);
    bool write_remote(HANDLE proc, void* remote_addr, const void* data, size_t size);
    std::optional<DWORD> execute_remote(HANDLE proc, void* code_addr, void* param, DWORD timeout_ms = 10000);
}
