/**
 * @file db.h
 * @brief Common SQLite statement helpers shared by server and client.
 *
 * Provides thin wrappers around sqlite3_prepare_v2 / sqlite3_step /
 * sqlite3_finalize that eliminate repeated boilerplate in higher-level
 * database modules.
 *
 * @date 2026-06-07
 * @copyright GPLv3 License
 * @section LICENSE
 * PacPlay
 * Copyright (C) 2026 Winston Meursault & Kiraterin
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https: //www.gnu.org/licenses/>.
 */

#ifndef DB_H
#define DB_H

#include <sqlite3.h>

/* ────────────────────────────── return codes ────────────────────────────── */

/**
 * @def DB_EXEC_SUCC
 * @brief Statement executed successfully (SQLITE_DONE or SQLITE_ROW was
 *        received as the first step result).
 */
#define DB_EXEC_SUCC (0)

/**
 * @def DB_EXEC_FAIL
 * @brief Statement execution failed.  Check the log for the SQLite error
 *        code and message.
 */
#define DB_EXEC_FAIL (-1)

/* ─────────────────────────────── public API ─────────────────────────────── */

/**
 * @brief Prepare, step, and finalize a one-shot SQL statement.
 *
 * Prepares @p sql via sqlite3_prepare_v2, executes a single step, and
 * finalizes the statement.  Accepts both SQLITE_DONE (DDL / INSERT /
 * UPDATE / DELETE) and SQLITE_ROW (a single-row SELECT) as success;
 * any other result code is treated as failure and logged.
 *
 * @warning The result set is not iterated — only the first row of a
 *          multi-row query is consumed.  Use this helper for DDL, DML,
 *          and single-row queries only.
 *
 * @param dbHandle  Open sqlite3 database connection.
 * @param sql       SQL statement to execute (null-terminated, UTF-8).
 * @param context   Label for error messages (e.g. "create users table").
 * @return @c DB_EXEC_SUCC on success, @c DB_EXEC_FAIL on failure.
 */
int dbExec(sqlite3 *dbHandle, const char *sql, const char *context);

/**
 * @brief Finalize a cached prepared statement if it is non-NULL.
 *
 * Calls sqlite3_finalize on @c *stmt, then sets @c *stmt to NULL.
 * This is intended for long-lived prepared statements that are
 * prepared once and reused across many calls (e.g. prepared INSERT
 * or SELECT statements kept for the lifetime of a session).
 *
 * The double-pointer interface allows callers to safely reuse the
 * same variable after finalization without risk of double-free.
 *
 * @note Safe to call with a NULL @p stmt or a @p stmt pointing to
 *       NULL — the function is a no-op in either case.
 *
 * @param stmt  Address of the statement pointer to finalize.
 */
void dbFinalize(sqlite3_stmt **stmt);

#endif /* DB_H */
