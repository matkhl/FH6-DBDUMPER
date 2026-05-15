#include "process/process.h"
#include "process/signatures.h"
#include "game/cdatabase.h"
#include "game/sql_inject.h"

extern "C" {
#include "include/sqlite3.h"
}

#include <format>
#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <algorithm>

namespace
{
    constexpr auto PROCESS_NAME = L"forzahorizon6.exe";

    std::string get_exe_dir()
    {
        char buf[MAX_PATH]{};
        GetModuleFileNameA(nullptr, buf, MAX_PATH);
        std::filesystem::path p(buf);
        return p.parent_path().string();
    }

    std::string escape_sql(const std::string& s)
    {
        std::string out;
        out.reserve(s.size() + 8);
        for (char c : s)
        {
            if (c == '\'') out += "''";
            else out += c;
        }
        return out;
    }

    std::string cell_to_sql(const game::CellValue& val)
    {
        if (std::holds_alternative<std::monostate>(val))
            return "NULL";
        if (std::holds_alternative<int64_t>(val))
            return std::to_string(std::get<int64_t>(val));
        if (std::holds_alternative<double>(val))
            return std::format("{}", std::get<double>(val));
        if (std::holds_alternative<std::string>(val))
            return "'" + escape_sql(std::get<std::string>(val)) + "'";
        return "NULL";
    }

    struct TableInfo
    {
        std::string name;
        std::string sql;
    };

    std::vector<TableInfo> get_tables(HANDLE proc, const game::CDatabase& db)
    {
        std::vector<TableInfo> tables;
        auto result = game::execute_sql(proc, db,
            "SELECT tbl_name, sql FROM sqlite_master WHERE type='table' ORDER BY tbl_name");
        if (!result.success || !result.parsed)
            return tables;

        for (const auto& row : result.parsed->rows)
        {
            if (row.size() >= 2 &&
                std::holds_alternative<std::string>(row[0]) &&
                std::holds_alternative<std::string>(row[1]))
            {
                tables.push_back({
                    std::get<std::string>(row[0]),
                    std::get<std::string>(row[1])
                });
            }
        }
        return tables;
    }

    struct IndexInfo
    {
        std::string sql;
    };

    std::vector<IndexInfo> get_indexes(HANDLE proc, const game::CDatabase& db)
    {
        std::vector<IndexInfo> indexes;
        auto result = game::execute_sql(proc, db,
            "SELECT sql FROM sqlite_master WHERE type='index' AND sql IS NOT NULL ORDER BY name");
        if (!result.success || !result.parsed)
            return indexes;

        for (const auto& row : result.parsed->rows)
        {
            if (!row.empty() && std::holds_alternative<std::string>(row[0]))
                indexes.push_back({ std::get<std::string>(row[0]) });
        }
        return indexes;
    }

    struct ViewInfo
    {
        std::string sql;
    };

    std::vector<ViewInfo> get_views(HANDLE proc, const game::CDatabase& db)
    {
        std::vector<ViewInfo> views;
        auto result = game::execute_sql(proc, db,
            "SELECT sql FROM sqlite_master WHERE type='view' AND sql IS NOT NULL ORDER BY name");
        if (!result.success || !result.parsed)
            return views;

        for (const auto& row : result.parsed->rows)
        {
            if (!row.empty() && std::holds_alternative<std::string>(row[0]))
                views.push_back({ std::get<std::string>(row[0]) });
        }
        return views;
    }

    bool dump_database(HANDLE proc, const game::CDatabase& db, const std::string& output_path)
    {
        sqlite3* local_db = nullptr;
        if (sqlite3_open(output_path.c_str(), &local_db) != SQLITE_OK)
        {
            std::cerr << "  [!] Failed to create " << output_path << ": " << sqlite3_errmsg(local_db) << "\n";
            sqlite3_close(local_db);
            return false;
        }

        auto exec_local = [&](const std::string& sql) -> bool {
            char* err = nullptr;
            int rc = sqlite3_exec(local_db, sql.c_str(), nullptr, nullptr, &err);
            if (rc != SQLITE_OK)
            {
                std::cerr << "  [!] SQL error: " << (err ? err : "unknown") << "\n";
                std::cerr << "      Statement: " << sql.substr(0, 120) << "\n";
                sqlite3_free(err);
                return false;
            }
            return true;
        };

        exec_local("PRAGMA journal_mode=WAL");
        exec_local("PRAGMA synchronous=NORMAL");

        std::cout << "  Fetching schema...\n";
        auto tables = get_tables(proc, db);
        auto indexes = get_indexes(proc, db);
        auto views = get_views(proc, db);

        std::cout << "  Found " << tables.size() << " tables, "
                  << indexes.size() << " indexes, "
                  << views.size() << " views\n\n";

        exec_local("BEGIN TRANSACTION");

        for (const auto& table : tables)
        {
            if (!exec_local(table.sql + ";"))
            {
                std::cerr << "  [!] Failed to create table: " << table.name << "\n";
                continue;
            }
        }

        size_t total_rows = 0;
        for (size_t t = 0; t < tables.size(); ++t)
        {
            const auto& table = tables[t];
            std::cout << "  [" << (t + 1) << "/" << tables.size() << "] " << table.name << "... ";

            auto count_result = game::execute_sql(proc, db,
                "SELECT count(*) FROM [" + table.name + "]");
            int64_t row_count = 0;
            if (count_result.success && count_result.parsed &&
                !count_result.parsed->rows.empty() &&
                std::holds_alternative<int64_t>(count_result.parsed->rows[0][0]))
            {
                row_count = std::get<int64_t>(count_result.parsed->rows[0][0]);
            }

            if (row_count == 0)
            {
                std::cout << "0 rows (empty)\n";
                continue;
            }

            constexpr int64_t BATCH_SIZE = 500;
            int64_t rows_dumped = 0;

            for (int64_t offset = 0; offset < row_count; offset += BATCH_SIZE)
            {
                auto data = game::execute_sql(proc, db,
                    std::format("SELECT * FROM [{}] LIMIT {} OFFSET {}", table.name, BATCH_SIZE, offset));

                if (!data.success || !data.parsed || data.parsed->rows.empty())
                    break;

                for (const auto& row : data.parsed->rows)
                {
                    std::string insert = "INSERT INTO [" + table.name + "] VALUES(";
                    for (size_t c = 0; c < row.size(); ++c)
                    {
                        if (c > 0) insert += ",";
                        insert += cell_to_sql(row[c]);
                    }
                    insert += ")";

                    if (!exec_local(insert))
                    {
                        std::cerr << "  [!] Insert failed for " << table.name << " row " << rows_dumped << "\n";
                    }
                    ++rows_dumped;
                }
            }

            total_rows += static_cast<size_t>(rows_dumped);
            std::cout << rows_dumped << " rows\n";
        }

        for (const auto& idx : indexes)
            exec_local(idx.sql + ";");

        for (const auto& view : views)
            exec_local(view.sql + ";");

        exec_local("COMMIT");
        sqlite3_close(local_db);

        std::cout << "\n  Done. " << total_rows << " total rows across " << tables.size() << " tables.\n";
        std::cout << "  Output: " << output_path << "\n";
        return true;
    }

    bool persist_database(HANDLE proc, const game::CDatabase& db, const std::string& input_path)
    {
        if (!std::filesystem::exists(input_path))
        {
            std::cerr << "  [!] File not found: " << input_path << "\n";
            return false;
        }

        sqlite3* local_db = nullptr;
        if (sqlite3_open_v2(input_path.c_str(), &local_db, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK)
        {
            std::cerr << "  [!] Failed to open " << input_path << ": " << sqlite3_errmsg(local_db) << "\n";
            sqlite3_close(local_db);
            return false;
        }

        // Get list of tables from local file
        std::vector<std::string> local_tables;
        {
            sqlite3_stmt* stmt = nullptr;
            sqlite3_prepare_v2(local_db, "SELECT tbl_name FROM sqlite_master WHERE type='table' ORDER BY tbl_name", -1, &stmt, nullptr);
            while (sqlite3_step(stmt) == SQLITE_ROW)
                local_tables.push_back(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)));
            sqlite3_finalize(stmt);
        }

        std::cout << "  Found " << local_tables.size() << " tables in " << input_path << "\n";

        // Get list of tables in game DB
        auto game_tables_result = game::execute_sql(proc, db,
            "SELECT tbl_name FROM sqlite_master WHERE type='table'");
        std::vector<std::string> game_tables;
        if (game_tables_result.success && game_tables_result.parsed)
        {
            for (const auto& row : game_tables_result.parsed->rows)
            {
                if (!row.empty() && std::holds_alternative<std::string>(row[0]))
                    game_tables.push_back(std::get<std::string>(row[0]));
            }
        }

        size_t total_rows = 0;
        for (size_t t = 0; t < local_tables.size(); ++t)
        {
            const auto& table = local_tables[t];

            bool exists_in_game = std::find(game_tables.begin(), game_tables.end(), table) != game_tables.end();
            if (!exists_in_game)
            {
                std::cout << "  [" << (t + 1) << "/" << local_tables.size() << "] " << table << "... SKIP (not in game)\n";
                continue;
            }

            std::cout << "  [" << (t + 1) << "/" << local_tables.size() << "] " << table << "... ";

            // Delete existing rows
            auto del = game::execute_sql(proc, db, "DELETE FROM [" + table + "]");
            if (!del.success)
            {
                std::cout << "FAILED (delete: " << del.error << ")\n";
                continue;
            }

            // Get column names
            sqlite3_stmt* col_stmt = nullptr;
            std::string pragma = "PRAGMA table_info([" + table + "])";
            sqlite3_prepare_v2(local_db, pragma.c_str(), -1, &col_stmt, nullptr);
            std::vector<std::string> col_names;
            while (sqlite3_step(col_stmt) == SQLITE_ROW)
                col_names.push_back(reinterpret_cast<const char*>(sqlite3_column_text(col_stmt, 1)));
            sqlite3_finalize(col_stmt);

            // Read all rows from local and insert into game
            sqlite3_stmt* data_stmt = nullptr;
            std::string select = "SELECT * FROM [" + table + "]";
            sqlite3_prepare_v2(local_db, select.c_str(), -1, &data_stmt, nullptr);

            size_t rows_inserted = 0;
            while (sqlite3_step(data_stmt) == SQLITE_ROW)
            {
                int ncols = sqlite3_column_count(data_stmt);
                std::string insert = "INSERT INTO [" + table + "] VALUES(";
                for (int c = 0; c < ncols; ++c)
                {
                    if (c > 0) insert += ",";
                    int coltype = sqlite3_column_type(data_stmt, c);
                    switch (coltype)
                    {
                    case SQLITE_NULL:
                        insert += "NULL";
                        break;
                    case SQLITE_INTEGER:
                        insert += std::to_string(sqlite3_column_int64(data_stmt, c));
                        break;
                    case SQLITE_FLOAT:
                        insert += std::format("{}", sqlite3_column_double(data_stmt, c));
                        break;
                    case SQLITE_TEXT:
                    {
                        auto text = reinterpret_cast<const char*>(sqlite3_column_text(data_stmt, c));
                        insert += "'" + escape_sql(text ? text : "") + "'";
                        break;
                    }
                    case SQLITE_BLOB:
                    {
                        auto blob = static_cast<const uint8_t*>(sqlite3_column_blob(data_stmt, c));
                        int blobsz = sqlite3_column_bytes(data_stmt, c);
                        insert += "X'";
                        for (int b = 0; b < blobsz; ++b)
                            insert += std::format("{:02X}", blob[b]);
                        insert += "'";
                        break;
                    }
                    }
                }
                insert += ")";

                auto ins = game::execute_sql(proc, db, insert);
                if (ins.success) ++rows_inserted;
            }
            sqlite3_finalize(data_stmt);

            total_rows += rows_inserted;
            std::cout << rows_inserted << " rows\n";
        }

        sqlite3_close(local_db);

        std::cout << "\n  Done. " << total_rows << " total rows injected across " << local_tables.size() << " tables.\n";
        return true;
    }
}

int main()
{
    std::cout << "=== FH6 Database Dumper ===\n\n";

    // Step 1: Find and attach to process
    std::cout << "[1] Searching for forzahorizon6.exe...\n";
    auto proc = process::open_process(PROCESS_NAME);
    if (!proc)
    {
        std::cerr << "  [!] Game not found. Make sure Forza Horizon 6 is running.\n";
        std::cout << "\nPress Enter to exit...";
        std::cin.get();
        return 1;
    }
    std::cout << "  PID: " << proc->pid << "\n";
    std::cout << "  Base: 0x" << std::format("{:X}", proc->base_address) << "\n";
    std::cout << "  Image size: 0x" << std::format("{:X}", proc->image_size)
              << " (" << std::format("{:.1f}", static_cast<double>(proc->image_size) / (1024.0 * 1024.0)) << " MB)\n";
    std::cout << "  [OK]\n\n";

    // Step 2: Resolve CDatabase
    std::cout << "[2] Scanning for CDatabase AOB pattern...\n";
    auto db = game::resolve_cdatabase(proc->handle, proc->base_address, proc->image_size);
    if (!db)
    {
        std::cerr << "  [!] CDatabase pattern not found. Game version may be incompatible.\n";
        process::close_process(*proc);
        std::cout << "\nPress Enter to exit...";
        std::cin.get();
        return 1;
    }
    std::cout << "  Global: 0x" << std::format("{:X}", db->global_address) << "\n";
    std::cout << "  Instance: 0x" << std::format("{:X}", db->instance) << "\n";
    std::cout << "  Vtable: 0x" << std::format("{:X}", db->vtable) << "\n";
    std::cout << "  ExecuteQuery: 0x" << std::format("{:X}", db->execute_query) << "\n";
    std::cout << "  [OK]\n\n";

    // Step 3: Verify SQL execution
    std::cout << "[3] Verifying SQL execution...\n";
    auto test = game::execute_sql(proc->handle, *db, "SELECT count(*) FROM sqlite_master");
    if (!test.success || !test.parsed)
    {
        std::cerr << "  [!] SQL execution failed: " << test.error << "\n";
        process::close_process(*proc);
        std::cout << "\nPress Enter to exit...";
        std::cin.get();
        return 1;
    }
    if (!test.parsed->rows.empty() && std::holds_alternative<int64_t>(test.parsed->rows[0][0]))
    {
        auto count = std::get<int64_t>(test.parsed->rows[0][0]);
        std::cout << "  sqlite_master entries: " << count << "\n";
    }
    std::cout << "  [OK]\n\n";

    // Step 4: Action menu
    std::string db_path = get_exe_dir() + "\\fh6_db.sqlite";

    std::cout << "=== Ready ===\n";
    std::cout << "  Output path: " << db_path << "\n\n";
    std::cout << "Select action:\n";
    std::cout << "  [1] Dump    - Extract game database to fh6_db.sqlite\n";
    std::cout << "  [2] Persist - Load fh6_db.sqlite back into game\n";
    std::cout << "  [0] Exit\n\n";
    std::cout << "> ";

    int choice = 0;
    std::cin >> choice;
    std::cout << "\n";

    switch (choice)
    {
    case 1:
    {
        if (std::filesystem::exists(db_path))
        {
            std::cout << "  Removing existing " << db_path << "\n";
            std::filesystem::remove(db_path);
        }
        std::cout << "  Starting dump...\n\n";
        dump_database(proc->handle, *db, db_path);
        break;
    }
    case 2:
    {
        if (!std::filesystem::exists(db_path))
        {
            std::cerr << "  [!] " << db_path << " not found. Run dump first.\n";
            break;
        }
        std::cout << "  WARNING: This will overwrite ALL table data in the running game.\n";
        std::cout << "  Continue? (y/n): ";
        char confirm = 'n';
        std::cin >> confirm;
        if (confirm == 'y' || confirm == 'Y')
        {
            std::cout << "\n  Starting persist...\n\n";
            persist_database(proc->handle, *db, db_path);
        }
        else
        {
            std::cout << "  Cancelled.\n";
        }
        break;
    }
    case 0:
        break;
    default:
        std::cout << "  Invalid choice.\n";
        break;
    }

    process::close_process(*proc);
    std::cout << "\nPress Enter to exit...";
    std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');
    std::cin.get();
    return 0;
}
