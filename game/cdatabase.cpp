#include "cdatabase.h"
#include <format>

namespace game
{
    std::optional<CDatabase> resolve_cdatabase(HANDLE proc, uintptr_t base, size_t image_size)
    {
        auto scan = signatures::scan_process(proc, base, image_size, CDATABASE_AOB);
        if (scan.match_count == 0)
            return std::nullopt;

        uintptr_t match = scan.address;

        auto disp = process::read_value<int32_t>(proc, match + 3);
        if (!disp)
            return std::nullopt;

        uintptr_t global_addr = match + 7 + static_cast<uintptr_t>(static_cast<int64_t>(*disp));

        auto instance = process::read_value<uintptr_t>(proc, global_addr);
        if (!instance || *instance == 0)
            return std::nullopt;

        auto vtable = process::read_value<uintptr_t>(proc, *instance);
        if (!vtable || *vtable == 0)
            return std::nullopt;

        auto exec_query = process::read_value<uintptr_t>(proc, *vtable + EXECUTE_QUERY_VTABLE_OFFSET);
        if (!exec_query || *exec_query == 0)
            return std::nullopt;

        CDatabase db;
        db.global_address = global_addr;
        db.instance = *instance;
        db.vtable = *vtable;
        db.execute_query = *exec_query;
        return db;
    }

    std::string format_cdatabase(const CDatabase& db)
    {
        return std::format(
            "global: 0x{:X}\ninstance: 0x{:X}\nvtable: 0x{:X}\nExecuteQuery: 0x{:X}",
            db.global_address, db.instance, db.vtable, db.execute_query);
    }
}
