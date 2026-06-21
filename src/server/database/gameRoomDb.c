/**
 * @file gameRoomDb.c
 * @brief Game room database operations for PacPlay server.
 *
 * Implements CRUD operations for the persistent game room registry.
 * Game rooms are stored in the game_rooms table and survive server restarts.
 *
 * @date 2026-06-20
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
#include "server/database.h"
#include "server/database/internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* ───────────────────────── SQL schema definitions ───────────────────────── */

#define SQL_CREATE_GAME_ROOMS_TABLE                                            \
    "CREATE TABLE IF NOT EXISTS game_rooms ("                                  \
    "gameRoomId INTEGER PRIMARY KEY, "                                         \
    "gameId INTEGER NOT NULL, "                                                \
    "hostUid INTEGER NOT NULL, "                                               \
    "createdAt INTEGER NOT NULL"                                               \
    ");"

/* ──────────────────────── GameRoomDB prepared SQL ───────────────────────── */

#define SQL_INSERT_GAME_ROOM                                                   \
    "INSERT INTO game_rooms (gameRoomId, gameId, hostUid, createdAt) "         \
    "VALUES (?, ?, ?, ?);"

#define SQL_DELETE_GAME_ROOM "DELETE FROM game_rooms WHERE gameRoomId = ?;"

#define SQL_LIST_GAME_ROOMS                                                    \
    "SELECT gameRoomId FROM game_rooms ORDER BY gameRoomId ASC;"

#define SQL_EXISTS_GAME_ROOM "SELECT 1 FROM game_rooms WHERE gameRoomId = ?;"

/* ────────────────────────── schema init helper ──────────────────────────── */

int initGameRoomDBSchema(sqlite3 *dbHandle) {
    return dbExec(dbHandle, SQL_CREATE_GAME_ROOMS_TABLE,
                  "CREATE TABLE game_rooms");
}

/* ──────────────────────── GameRoomDB stmt preparation ───────────────────── */

int prepareGameRoomDBStmts(DB *database) {
    int rc;

    rc = sqlite3_prepare_v2(database->handle, SQL_INSERT_GAME_ROOM, -1,
                            &database->stmtGameRoomInsert, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareGameRoomDBStmts: INSERT prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_prepare_v2(database->handle, SQL_DELETE_GAME_ROOM, -1,
                            &database->stmtGameRoomDelete, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareGameRoomDBStmts: DELETE prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_prepare_v2(database->handle, SQL_LIST_GAME_ROOMS, -1,
                            &database->stmtGameRoomSelect, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareGameRoomDBStmts: SELECT prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_prepare_v2(database->handle, SQL_EXISTS_GAME_ROOM, -1,
                            &database->stmtGameRoomExists, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareGameRoomDBStmts: EXISTS prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    return DB_SUCC;
}

/* ─────────────────── public API: game room operations ───────────────────── */

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
int createGameRoom(DB *database, uint32_t gameRoomId, uint32_t gameId,
                   uint32_t hostUid) {
    if (database == NULL) {
        LOG_ERROR("createGameRoom: NULL database");
        return DB_FAIL;
    }
    if (database->type != GameRoomDB) {
        LOG_ERROR(
            "createGameRoom: wrong database type %d (expected GameRoomDB)",
            (int)database->type);
        return DB_FAIL;
    }
    if (gameRoomId == 0) {
        LOG_ERROR("createGameRoom: gameRoomId zero is reserved");
        return DB_FAIL;
    }

    time_t now = time(NULL);

    sqlite3_stmt *stmt = database->stmtGameRoomInsert;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    int rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)gameRoomId);
    if (rc != SQLITE_OK) {
        LOG_ERROR("createGameRoom: bind gameRoomId failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 2, (sqlite3_int64)gameId);
    if (rc != SQLITE_OK) {
        LOG_ERROR("createGameRoom: bind gameId failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 3, (sqlite3_int64)hostUid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("createGameRoom: bind hostUid failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 4, (sqlite3_int64)now);
    if (rc != SQLITE_OK) {
        LOG_ERROR("createGameRoom: bind createdAt failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        LOG_ERROR("createGameRoom: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    return DB_SUCC;
}

int deleteGameRoom(DB *database, uint32_t gameRoomId) {
    if (database == NULL) {
        LOG_ERROR("deleteGameRoom: NULL database");
        return DB_FAIL;
    }
    if (database->type != GameRoomDB) {
        LOG_ERROR(
            "deleteGameRoom: wrong database type %d (expected GameRoomDB)",
            (int)database->type);
        return DB_FAIL;
    }

    sqlite3_stmt *stmt = database->stmtGameRoomDelete;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    int rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)gameRoomId);
    if (rc != SQLITE_OK) {
        LOG_ERROR("deleteGameRoom: bind gameRoomId failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        LOG_ERROR("deleteGameRoom: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    if (sqlite3_changes(database->handle) == 0) {
        LOG_WARN("deleteGameRoom: gameRoomId %u not found", gameRoomId);
        return DB_FAIL;
    }

    return DB_SUCC;
}

int listGameRooms(DB *database, uint32_t **outIds, size_t *count) {
    if (database == NULL || outIds == NULL || count == NULL) {
        LOG_ERROR(
            "listGameRooms: NULL argument (database=%p, out=%p, count=%p)",
            (void *)database, (void *)outIds, (void *)count);
        return DB_FAIL;
    }
    if (database->type != GameRoomDB) {
        LOG_ERROR("listGameRooms: wrong database type %d (expected GameRoomDB)",
                  (int)database->type);
        return DB_FAIL;
    }

    *outIds = NULL;
    *count = 0;

    sqlite3_stmt *stmt = database->stmtGameRoomSelect;
    sqlite3_reset(stmt);

    size_t capacity = QUERY_INITIAL_CAPACITY;
    size_t n = 0;
    uint32_t *results = malloc(capacity * sizeof(uint32_t));
    if (results == NULL) {
        LOG_ERROR("listGameRooms: malloc failed (errno=%d)", errno);
        return DB_FAIL;
    }

    int rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (n >= QUERY_MAX_RESULTS) {
            LOG_WARN("listGameRooms: result limit reached (%d)",
                     QUERY_MAX_RESULTS);
            break;
        }

        if (n >= capacity) {
            size_t newCapacity = capacity * 2;
            uint32_t *tmp = realloc(results, newCapacity * sizeof(uint32_t));
            if (tmp == NULL) {
                LOG_ERROR("listGameRooms: realloc failed (errno=%d)", errno);
                free(results);
                return DB_FAIL;
            }
            results = tmp;
            capacity = newCapacity;
        }

        results[n] = (uint32_t)sqlite3_column_int64(stmt, 0);
        n++;
    }

    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        LOG_ERROR("listGameRooms: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        free(results);
        return DB_FAIL;
    }

    if (n == 0) {
        free(results);
        *outIds = NULL;
        *count = 0;
        return DB_SUCC;
    }

    *outIds = results;
    *count = n;
    return DB_SUCC;
}

int gameRoomExists(DB *database, uint32_t gameRoomId) {
    if (database == NULL) {
        LOG_ERROR("gameRoomExists: NULL database");
        return DB_FAIL;
    }
    if (database->type != GameRoomDB) {
        LOG_ERROR(
            "gameRoomExists: wrong database type %d (expected GameRoomDB)",
            (int)database->type);
        return DB_FAIL;
    }
    if (gameRoomId == 0) {
        return DB_FAIL;
    }

    sqlite3_stmt *stmt = database->stmtGameRoomExists;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    int rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)gameRoomId);
    if (rc != SQLITE_OK) {
        LOG_ERROR("gameRoomExists: bind gameRoomId failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    return (rc == SQLITE_ROW) ? DB_SUCC : DB_FAIL;
}
