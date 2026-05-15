#include "remote_thread.h"

namespace remote
{
    RemoteAlloc alloc_remote(HANDLE proc, size_t size, DWORD protect)
    {
        void* addr = VirtualAllocEx(proc, nullptr, size, MEM_COMMIT | MEM_RESERVE, protect);
        if (!addr)
            return {};
        return RemoteAlloc(proc, addr, size);
    }

    bool write_remote(HANDLE proc, void* remote_addr, const void* data, size_t size)
    {
        SIZE_T written = 0;
        return WriteProcessMemory(proc, remote_addr, data, size, &written) && written == size;
    }

    std::optional<DWORD> execute_remote(HANDLE proc, void* code_addr, void* param, DWORD timeout_ms)
    {
        process::HandleGuard thread(CreateRemoteThread(proc, nullptr, 0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(code_addr), param, 0, nullptr));

        if (!thread)
            return std::nullopt;

        DWORD wait_result = WaitForSingleObject(thread.h, timeout_ms);
        if (wait_result != WAIT_OBJECT_0)
            return std::nullopt;

        DWORD exit_code = 0;
        if (!GetExitCodeThread(thread.h, &exit_code))
            return std::nullopt;

        return exit_code;
    }
}
