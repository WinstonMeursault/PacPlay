/**
 * @file db.c
 * @brief Common SQLite statement helpers — implementation.
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

#include "db.h"
#include "log.h"

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
int dbExec(sqlite3 *dbHandle, const char *sql, const char *context) {
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(dbHandle, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("%s: prepare failed: %s (rc=%d)", context,
                  sqlite3_errmsg(dbHandle), rc);
        return DB_EXEC_FAIL;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        LOG_ERROR("%s: step failed: %s (rc=%d)", context,
                  sqlite3_errmsg(dbHandle), rc);
        sqlite3_finalize(stmt);
        return DB_EXEC_FAIL;
    }

    sqlite3_finalize(stmt);
    return DB_EXEC_SUCC;
}

void dbFinalize(sqlite3_stmt **stmt) {
    if (stmt != NULL && *stmt != NULL) {
        sqlite3_finalize(*stmt);
        *stmt = NULL;
    }
}
