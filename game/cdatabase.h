#pragma once

#include "../process/process.h"
#include "../process/signatures.h"
#include <cstdint>
#include <optional>
#include <string>

namespace game
{
    struct CDatabase
    {
        uintptr_t global_address = 0;
        uintptr_t instance = 0;
        uintptr_t vtable = 0;
        uintptr_t execute_query = 0;
    };

    constexpr auto CDATABASE_AOB =
        "48 8B 0D ?? ?? ?? ?? 48 8B 01 4C 8D 45 ?? 48 8D 55 ?? FF 50 48 90 48 8B 4D ?? 48 85 C9";

    constexpr size_t EXECUTE_QUERY_VTABLE_INDEX = 9;
    constexpr size_t EXECUTE_QUERY_VTABLE_OFFSET = EXECUTE_QUERY_VTABLE_INDEX * 8;

    std::optional<CDatabase> resolve_cdatabase(HANDLE proc, uintptr_t base, size_t image_size);
    std::string format_cdatabase(const CDatabase& db);
}
