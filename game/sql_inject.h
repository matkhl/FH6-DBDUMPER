#pragma once

#include "cdatabase.h"
#include "../process/remote_thread.h"
#include <string>
#include <vector>
#include <variant>
#include <cstdint>

namespace game
{
    enum class CellType : uint8_t
    {
        Null = 5,
        Integer = 2,
        Float = 3,
        Text = 4,
    };

    using CellValue = std::variant<std::monostate, int64_t, double, std::string>;

    struct ColumnInfo
    {
        std::string name;
        uint64_t type = 0;
    };

    struct ParsedResult
    {
        std::vector<ColumnInfo> columns;
        std::vector<std::vector<CellValue>> rows;
    };

    struct SqlResult
    {
        bool success = false;
        uintptr_t result_ptr = 0;
        std::string error;
        std::optional<ParsedResult> parsed;
    };

    SqlResult execute_sql(HANDLE proc, const CDatabase& db, const std::string& sql);
    std::optional<ParsedResult> parse_result(HANDLE proc, uintptr_t result_ptr);
    std::string format_result(const ParsedResult& result);
}
