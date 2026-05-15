#include "process.h"

namespace process
{
    DWORD find_process(const wchar_t* name)
    {
        HandleGuard snap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (!snap)
            return 0;

        PROCESSENTRY32W entry{};
        entry.dwSize = sizeof(entry);

        if (!Process32FirstW(snap.h, &entry))
            return 0;

        do
        {
            if (_wcsicmp(entry.szExeFile, name) == 0)
                return entry.th32ProcessID;
        }
        while (Process32NextW(snap.h, &entry));

        return 0;
    }

    std::optional<ProcessInfo> open_process(const wchar_t* name)
    {
        DWORD pid = find_process(name);
        if (!pid)
            return std::nullopt;

        HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!handle)
            return std::nullopt;

        ProcessInfo info{};
        info.handle = handle;
        info.pid = pid;

        HMODULE main_module = nullptr;
        DWORD needed = 0;
        if (EnumProcessModules(handle, &main_module, sizeof(main_module), &needed) && main_module)
        {
            MODULEINFO mod_info{};
            if (GetModuleInformation(handle, main_module, &mod_info, sizeof(mod_info)))
            {
                info.base_address = reinterpret_cast<uintptr_t>(mod_info.lpBaseOfDll);
                info.image_size = mod_info.SizeOfImage;
            }
        }

        return info;
    }

    void close_process(ProcessInfo& info)
    {
        if (info.handle)
        {
            CloseHandle(info.handle);
            info.handle = nullptr;
        }
        info.pid = 0;
        info.base_address = 0;
        info.image_size = 0;
    }

    bool read_memory(HANDLE proc, uintptr_t addr, void* buf, size_t size)
    {
        SIZE_T bytes_read = 0;
        return ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(addr), buf, size, &bytes_read)
            && bytes_read == size;
    }

    bool write_memory(HANDLE proc, uintptr_t addr, const void* buf, size_t size)
    {
        SIZE_T bytes_written = 0;
        return WriteProcessMemory(proc, reinterpret_cast<LPVOID>(addr), buf, size, &bytes_written)
            && bytes_written == size;
    }

    std::optional<std::string> read_string(HANDLE proc, uintptr_t addr, size_t max_len)
    {
        std::vector<char> buf(max_len + 1, 0);
        SIZE_T bytes_read = 0;
        if (!ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(addr), buf.data(), max_len, &bytes_read))
            return std::nullopt;

        buf[bytes_read] = '\0';
        return std::string(buf.data());
    }

    std::vector<uint8_t> read_bytes(HANDLE proc, uintptr_t addr, size_t size)
    {
        std::vector<uint8_t> buf(size);
        SIZE_T bytes_read = 0;
        if (!ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(addr), buf.data(), size, &bytes_read))
            buf.resize(static_cast<size_t>(bytes_read));
        return buf;
    }
}
