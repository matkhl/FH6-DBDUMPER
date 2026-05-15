#include "sql_inject.h"
#include <cstring>
#include <format>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace game
{
    namespace
    {
        constexpr size_t RESULT_HEADER_SIZE = 72;
        constexpr size_t COLUMN_DEF_SIZE = 40;
        constexpr size_t CELL_SIZE = 16;
        constexpr size_t MSVC_STRING_SIZE = 32;
        constexpr size_t SSO_CAPACITY = 15;

        std::optional<std::string> read_msvc_string(HANDLE proc, uintptr_t addr)
        {
            uint8_t buf[MSVC_STRING_SIZE];
            if (!process::read_memory(proc, addr, buf, MSVC_STRING_SIZE))
                return std::nullopt;

            uint64_t length = 0, capacity = 0;
            std::memcpy(&length, &buf[16], 8);
            std::memcpy(&capacity, &buf[24], 8);

            if (length == 0)
                return std::string{};

            if (capacity <= SSO_CAPACITY)
            {
                return std::string(reinterpret_cast<char*>(buf), static_cast<size_t>(length));
            }
            else
            {
                uintptr_t heap_ptr = 0;
                std::memcpy(&heap_ptr, buf, 8);
                std::vector<char> heap_buf(static_cast<size_t>(length));
                if (!process::read_memory(proc, heap_ptr, heap_buf.data(), heap_buf.size()))
                    return std::nullopt;
                return std::string(heap_buf.data(), heap_buf.size());
            }
        }
    }

    SqlResult execute_sql(HANDLE proc, const CDatabase& db, const std::string& sql)
    {
        SqlResult result;

        auto code_alloc = remote::alloc_remote(proc, 64, PAGE_EXECUTE_READWRITE);
        if (!code_alloc) { result.error = "Failed to allocate shellcode"; return result; }

        auto sql_alloc = remote::alloc_remote(proc, sql.size() + 1, PAGE_READWRITE);
        if (!sql_alloc) { result.error = "Failed to allocate SQL string"; return result; }

        auto result_alloc = remote::alloc_remote(proc, 8, PAGE_READWRITE);
        if (!result_alloc) { result.error = "Failed to allocate result buffer"; return result; }

        if (!remote::write_remote(proc, sql_alloc.address, sql.c_str(), sql.size() + 1))
        {
            result.error = "Failed to write SQL string";
            return result;
        }

        uint64_t zero = 0;
        remote::write_remote(proc, result_alloc.address, &zero, 8);

        uint8_t shellcode[34] = {};
        size_t offset = 0;

        shellcode[offset++] = 0x48;
        shellcode[offset++] = 0xBA;
        uint64_t rdx_val = result_alloc.addr();
        std::memcpy(&shellcode[offset], &rdx_val, 8);
        offset += 8;

        shellcode[offset++] = 0x49;
        shellcode[offset++] = 0xB8;
        uint64_t r8_val = sql_alloc.addr();
        std::memcpy(&shellcode[offset], &r8_val, 8);
        offset += 8;

        shellcode[offset++] = 0xFF;
        shellcode[offset++] = 0x25;
        shellcode[offset++] = 0x00;
        shellcode[offset++] = 0x00;
        shellcode[offset++] = 0x00;
        shellcode[offset++] = 0x00;
        uint64_t jmp_target = db.execute_query;
        std::memcpy(&shellcode[offset], &jmp_target, 8);
        offset += 8;

        if (!remote::write_remote(proc, code_alloc.address, shellcode, offset))
        {
            result.error = "Failed to write shellcode";
            return result;
        }

        auto exit_code = remote::execute_remote(proc, code_alloc.address,
            reinterpret_cast<void*>(db.instance), 15000);

        if (!exit_code.has_value())
        {
            result.error = "Remote thread execution failed or timed out";
            return result;
        }

        auto res_ptr = process::read_value<uintptr_t>(proc, result_alloc.addr());
        if (!res_ptr)
        {
            result.error = "Failed to read result pointer";
            return result;
        }

        result.success = true;
        result.result_ptr = *res_ptr;

        if (result.result_ptr != 0)
            result.parsed = parse_result(proc, result.result_ptr);

        return result;
    }

    std::optional<ParsedResult> parse_result(HANDLE proc, uintptr_t result_ptr)
    {
        uint8_t header[RESULT_HEADER_SIZE];
        if (!process::read_memory(proc, result_ptr, header, RESULT_HEADER_SIZE))
            return std::nullopt;

        uintptr_t col_begin = 0, col_end = 0;
        uintptr_t row_begin = 0, row_end = 0;
        std::memcpy(&col_begin, &header[8], 8);
        std::memcpy(&col_end, &header[16], 8);
        std::memcpy(&row_begin, &header[32], 8);
        std::memcpy(&row_end, &header[40], 8);

        if (col_begin == 0 || col_end < col_begin)
            return std::nullopt;

        size_t col_bytes = static_cast<size_t>(col_end - col_begin);
        size_t num_cols = col_bytes / COLUMN_DEF_SIZE;
        size_t row_bytes = (row_end >= row_begin) ? static_cast<size_t>(row_end - row_begin) : 0;
        size_t num_rows = row_bytes / 8;

        ParsedResult parsed;

        if (num_cols > 0 && num_cols < 1000)
        {
            std::vector<uint8_t> col_data(col_bytes);
            if (!process::read_memory(proc, col_begin, col_data.data(), col_bytes))
                return std::nullopt;

            for (size_t i = 0; i < num_cols; ++i)
            {
                size_t off = i * COLUMN_DEF_SIZE;
                ColumnInfo col;

                auto name = read_msvc_string(proc, col_begin + off);
                col.name = name.value_or("?");

                std::memcpy(&col.type, &col_data[off + 32], 8);
                parsed.columns.push_back(std::move(col));
            }
        }

        if (num_rows > 0 && num_rows < 100000)
        {
            std::vector<uintptr_t> row_ptrs(num_rows);
            if (!process::read_memory(proc, row_begin, row_ptrs.data(), num_rows * 8))
                return std::nullopt;

            size_t row_data_size = num_cols * CELL_SIZE;

            for (size_t r = 0; r < num_rows; ++r)
            {
                std::vector<CellValue> row;

                if (row_ptrs[r] == 0)
                {
                    row.resize(num_cols, std::monostate{});
                    parsed.rows.push_back(std::move(row));
                    continue;
                }

                std::vector<uint8_t> cell_data(row_data_size);
                if (!process::read_memory(proc, row_ptrs[r], cell_data.data(), row_data_size))
                {
                    row.resize(num_cols, std::monostate{});
                    parsed.rows.push_back(std::move(row));
                    continue;
                }

                for (size_t c = 0; c < num_cols; ++c)
                {
                    size_t cell_off = c * CELL_SIZE;
                    uint8_t type = cell_data[cell_off];

                    switch (type)
                    {
                    case 2:
                    {
                        int64_t val = 0;
                        std::memcpy(&val, &cell_data[cell_off + 8], 8);
                        row.push_back(val);
                        break;
                    }
                    case 3:
                    {
                        double val = 0;
                        std::memcpy(&val, &cell_data[cell_off + 8], 8);
                        row.push_back(val);
                        break;
                    }
                    case 4:
                    {
                        uintptr_t str_ptr = 0;
                        std::memcpy(&str_ptr, &cell_data[cell_off + 8], 8);
                        auto str = read_msvc_string(proc, str_ptr);
                        row.push_back(str.value_or(""));
                        break;
                    }
                    default:
                        row.push_back(std::monostate{});
                        break;
                    }
                }

                parsed.rows.push_back(std::move(row));
            }
        }

        return parsed;
    }

    std::string format_result(const ParsedResult& result)
    {
        if (result.columns.empty())
            return "(no columns)";

        std::vector<size_t> widths(result.columns.size());
        for (size_t c = 0; c < result.columns.size(); ++c)
            widths[c] = result.columns[c].name.size();

        auto cell_to_string = [](const CellValue& val) -> std::string {
            if (std::holds_alternative<std::monostate>(val))
                return "NULL";
            if (std::holds_alternative<int64_t>(val))
                return std::to_string(std::get<int64_t>(val));
            if (std::holds_alternative<double>(val))
                return std::format("{}", std::get<double>(val));
            if (std::holds_alternative<std::string>(val))
                return std::get<std::string>(val);
            return "?";
        };

        std::vector<std::vector<std::string>> str_rows;
        for (const auto& row : result.rows)
        {
            std::vector<std::string> str_row;
            for (size_t c = 0; c < row.size(); ++c)
            {
                auto s = cell_to_string(row[c]);
                widths[c] = (std::max)(widths[c], s.size());
                str_row.push_back(std::move(s));
            }
            str_rows.push_back(std::move(str_row));
        }

        for (auto& w : widths)
            w = (std::min)(w, size_t{ 60 });

        std::ostringstream out;

        for (size_t c = 0; c < result.columns.size(); ++c)
        {
            if (c > 0) out << " | ";
            out << std::left << std::setw(static_cast<int>(widths[c])) << result.columns[c].name;
        }
        out << "\n";

        for (size_t c = 0; c < result.columns.size(); ++c)
        {
            if (c > 0) out << "-+-";
            out << std::string(widths[c], '-');
        }
        out << "\n";

        for (const auto& row : str_rows)
        {
            for (size_t c = 0; c < row.size(); ++c)
            {
                if (c > 0) out << " | ";
                auto display = row[c].size() > widths[c] ? row[c].substr(0, widths[c] - 3) + "..." : row[c];
                out << std::left << std::setw(static_cast<int>(widths[c])) << display;
            }
            out << "\n";
        }

        out << "\n(" << result.rows.size() << " row" << (result.rows.size() != 1 ? "s" : "") << ")";
        return out.str();
    }
}
