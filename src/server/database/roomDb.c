/**
 * @file roomDb.c
 * @brief Room database operations for PacPlay server.
 *
 * Implements CRUD operations for the persistent room registry.  Rooms are
 * stored in the rooms table and survive server restarts.
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
#include "server/database.h"
#include "server/database/internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* ───────────────────────── SQL schema definitions ───────────────────────── */

/** @brief CREATE the rooms table for RoomDB. */
#define SQL_CREATE_ROOMS_TABLE                                                 \
    "CREATE TABLE IF NOT EXISTS rooms ("                                       \
    "roomId INTEGER PRIMARY KEY, "                                             \
    "creatorUid INTEGER NOT NULL, "                                            \
    "createdAt INTEGER NOT NULL"                                               \
    ");"

/* ──────────────────────── RoomDB prepared SQL ───────────────────────────── */

/** @brief INSERT a room. Params: ?1=roomId, ?2=creatorUid, ?3=createdAt. */
#define SQL_INSERT_ROOM                                                        \
    "INSERT INTO rooms (roomId, creatorUid, createdAt) VALUES (?, ?, ?);"

/** @brief DELETE a room by roomId. Params: ?1=roomId. */
#define SQL_DELETE_ROOM "DELETE FROM rooms WHERE roomId = ?;"

/** @brief SELECT all room IDs ordered ascending. */
#define SQL_LIST_ROOMS "SELECT roomId FROM rooms ORDER BY roomId ASC;"

/** @brief SELECT 1 to check room existence. Params: ?1=roomId. */
#define SQL_EXISTS_ROOM "SELECT 1 FROM rooms WHERE roomId = ?;"

/* ────────────────────────── schema init helper ──────────────────────────── */

int initRoomDBSchema(sqlite3 *dbHandle) {
    return dbExec(dbHandle, SQL_CREATE_ROOMS_TABLE, "CREATE TABLE rooms");
}

/* ──────────────────────── RoomDB stmt preparation ───────────────────────── */

int prepareRoomDBStmts(DB *database) {
    int rc;

    rc = sqlite3_prepare_v2(database->handle, SQL_INSERT_ROOM, -1,
                            &database->stmtInsert, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareRoomDBStmts: INSERT prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_prepare_v2(database->handle, SQL_DELETE_ROOM, -1,
                            &database->stmtDelete, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareRoomDBStmts: DELETE prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_prepare_v2(database->handle, SQL_LIST_ROOMS, -1,
                            &database->stmtSelect, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareRoomDBStmts: SELECT prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_prepare_v2(database->handle, SQL_EXISTS_ROOM, -1,
                            &database->stmtRoomExists, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareRoomDBStmts: EXISTS prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    return DB_SUCC;
}

/* ─────────────────── public API: game (room) operations ─────────────────── */

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
int createRoom(DB *database, uint32_t roomId, uint32_t creatorUid) {
    if (database == NULL) {
        LOG_ERROR("createRoom: NULL database");
        return DB_FAIL;
    }
    if (database->type != RoomDB) {
        LOG_ERROR("createRoom: wrong database type %d (expected RoomDB)",
                  (int)database->type);
        return DB_FAIL;
    }
    if (roomId == 0) {
        LOG_ERROR("createRoom: roomId zero is reserved");
        return DB_FAIL;
    }

    time_t now = time(NULL);

    sqlite3_stmt *stmt = database->stmtInsert;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    /* Bind: ?1=roomId, ?2=creatorUid, ?3=createdAt */
    int rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)roomId);
    if (rc != SQLITE_OK) {
        LOG_ERROR("createRoom: bind roomId failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 2, (sqlite3_int64)creatorUid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("createRoom: bind creatorUid failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 3, (sqlite3_int64)now);
    if (rc != SQLITE_OK) {
        LOG_ERROR("createRoom: bind createdAt failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        LOG_ERROR("createRoom: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    return DB_SUCC;
}

int deleteRoom(DB *database, uint32_t roomId) {
    if (database == NULL) {
        LOG_ERROR("deleteRoom: NULL database");
        return DB_FAIL;
    }
    if (database->type != RoomDB) {
        LOG_ERROR("deleteRoom: wrong database type %d (expected RoomDB)",
                  (int)database->type);
        return DB_FAIL;
    }

    sqlite3_stmt *stmt = database->stmtDelete;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    int rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)roomId);
    if (rc != SQLITE_OK) {
        LOG_ERROR("deleteRoom: bind roomId failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        LOG_ERROR("deleteRoom: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    /* Strict mode: fail if no rows were affected */
    if (sqlite3_changes(database->handle) == 0) {
        LOG_WARN("deleteRoom: roomId %u not found", roomId);
        return DB_FAIL;
    }

    return DB_SUCC;
}

int listRooms(DB *database, uint32_t **outRoomIds, size_t *count) {
    if (database == NULL || outRoomIds == NULL || count == NULL) {
        LOG_ERROR("listRooms: NULL argument (database=%p, out=%p, count=%p)",
                  (void *)database, (void *)outRoomIds, (void *)count);
        return DB_FAIL;
    }
    if (database->type != RoomDB) {
        LOG_ERROR("listRooms: wrong database type %d (expected RoomDB)",
                  (int)database->type);
        return DB_FAIL;
    }

    *outRoomIds = NULL;
    *count = 0;

    sqlite3_stmt *stmt = database->stmtSelect;
    sqlite3_reset(stmt);

    size_t capacity = QUERY_INITIAL_CAPACITY;
    size_t n = 0;
    uint32_t *results = malloc(capacity * sizeof(uint32_t));
    if (results == NULL) {
        LOG_ERROR("listRooms: malloc failed (errno=%d)", errno);
        return DB_FAIL;
    }

    int rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (n >= QUERY_MAX_RESULTS) {
            LOG_WARN("listRooms: result limit reached (%d)", QUERY_MAX_RESULTS);
            break;
        }

        if (n >= capacity) {
            size_t newCapacity = capacity * 2;
            uint32_t *tmp = realloc(results, newCapacity * sizeof(uint32_t));
            if (tmp == NULL) {
                LOG_ERROR("listRooms: realloc failed (errno=%d)", errno);
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
        LOG_ERROR("listRooms: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        free(results);
        return DB_FAIL;
    }

    if (n == 0) {
        free(results);
        *outRoomIds = NULL;
        *count = 0;
        return DB_SUCC;
    }

    *outRoomIds = results;
    *count = n;
    return DB_SUCC;
}

int roomExists(DB *database, uint32_t roomId) {
    if (database == NULL) {
        LOG_ERROR("roomExists: NULL database");
        return DB_FAIL;
    }
    if (database->type != RoomDB) {
        LOG_ERROR("roomExists: wrong database type %d (expected RoomDB)",
                  (int)database->type);
        return DB_FAIL;
    }
    if (roomId == 0) {
        return DB_FAIL;
    }

    sqlite3_stmt *stmt = database->stmtRoomExists;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    int rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)roomId);
    if (rc != SQLITE_OK) {
        LOG_ERROR("roomExists: bind roomId failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    return (rc == SQLITE_ROW) ? DB_SUCC : DB_FAIL;
}
