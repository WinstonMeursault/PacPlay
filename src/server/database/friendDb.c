/**
 * @file friendDb.c
 * @brief Friend database operations for PacPlay server.
 *
 * Implements CRUD operations for friendships and friend requests,
 * stored in the FriendDB encrypted SQLCipher database.
 *
 * @date 2026-06-21
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
#include <time.h>

/* ───────────────────────── SQL schema definitions ───────────────────────── */

/** @brief CREATE the friendships table for FriendDB. */
#define SQL_CREATE_FRIENDSHIPS                                                 \
    "CREATE TABLE IF NOT EXISTS friendships ("                                 \
    "uid INTEGER NOT NULL, "                                                   \
    "friendUid INTEGER NOT NULL, "                                             \
    "createdAt INTEGER NOT NULL, "                                             \
    "PRIMARY KEY (uid, friendUid)"                                             \
    ");"

/** @brief CREATE the friend_requests table for FriendDB. */
#define SQL_CREATE_FRIEND_REQUESTS                                             \
    "CREATE TABLE IF NOT EXISTS friend_requests ("                             \
    "requestId INTEGER PRIMARY KEY AUTOINCREMENT, "                            \
    "fromUid INTEGER NOT NULL, "                                               \
    "toUid INTEGER NOT NULL, "                                                 \
    "status INTEGER NOT NULL DEFAULT 0, "                                      \
    "createdAt INTEGER NOT NULL, "                                             \
    "UNIQUE(fromUid, toUid)"                                                   \
    ");"

/* ─────────────────────────────── SQL DML ────────────────────────────────── */

/** @brief INSERT a friend request. Params: ?1=fromUid, ?2=toUid, ?3=createdAt.
 */
#define SQL_INSERT_FRIEND_REQUEST                                              \
    "INSERT INTO friend_requests (fromUid, toUid, status, "                    \
    "createdAt) VALUES (?, ?, 0, ?);"

/** @brief UPDATE friend request status to accepted. Params: ?1=fromUid,
 * ?2=toUid. */
#define SQL_ACCEPT_FRIEND_REQUEST                                              \
    "UPDATE friend_requests SET status=1 WHERE fromUid=? AND toUid=? AND "     \
    "status=0;"

/** @brief INSERT OR IGNORE a friendship row. Params: ?1=uid, ?2=friendUid,
 * ?3=createdAt. */
#define SQL_INSERT_FRIENDSHIP                                                  \
    "INSERT OR IGNORE INTO friendships (uid, friendUid, createdAt) VALUES "    \
    "(?, ?, ?);"

/** @brief UPDATE friend request status to rejected. Params: ?1=fromUid,
 * ?2=toUid. */
#define SQL_REJECT_FRIEND_REQUEST                                              \
    "UPDATE friend_requests SET status=2 WHERE fromUid=? AND toUid=? AND "     \
    "status=0;"

/** @brief DELETE a friendship (bidirectional). Params: ?1=uid1, ?2=uid2,
 * ?3=uid2, ?4=uid1. */
#define SQL_DELETE_FRIENDSHIP                                                  \
    "DELETE FROM friendships WHERE (uid=? AND friendUid=?) OR (uid=? AND "     \
    "friendUid=?);"

/** @brief SELECT friend list for a user. Params: ?1=uid. */
#define SQL_LIST_FRIENDS                                                       \
    "SELECT friendUid FROM friendships WHERE uid=? ORDER BY createdAt;"

/** @brief SELECT pending friend requests for a user. Params: ?1=toUid. */
#define SQL_PENDING_REQUESTS                                                   \
    "SELECT fromUid FROM friend_requests WHERE toUid=? AND status=0 "          \
    "ORDER BY createdAt;"

/** @brief SELECT 1 to check friendship existence. Params: ?1=uid, ?2=otherUid.
 */
#define SQL_IS_FRIEND "SELECT 1 FROM friendships WHERE uid=? AND friendUid=?;"

/* ─────────────────────── FriendDB stmt preparation ──────────────────────── */

/** @brief Initial capacity for result arrays (doubled on overflow). */
#define FRIEND_QUERY_INITIAL_CAPACITY 16

/** @brief Maximum result count to prevent unbounded memory allocation. */
#define FRIEND_QUERY_MAX_RESULTS 10000

/* ────────────────────────── schema init helper ──────────────────────────── */

int initFriendDBSchema(sqlite3 *dbHandle) {
    if (dbExec(dbHandle, SQL_CREATE_FRIENDSHIPS, "CREATE friendships") !=
        DB_EXEC_SUCC) {
        LOG_ERROR("initFriendDBSchema: CREATE friendships failed");
        return DB_FAIL;
    }
    if (dbExec(dbHandle, SQL_CREATE_FRIEND_REQUESTS,
               "CREATE friend_requests") != DB_EXEC_SUCC) {
        LOG_ERROR("initFriendDBSchema: CREATE friend_requests failed");
        return DB_FAIL;
    }
    return DB_SUCC;
}

/* ──────────────────────── public API: friend operations ─────────────────── */

int friendRequestCreate(DB *database, uint32_t fromUid, uint32_t toUid) {
    if (database == NULL) {
        LOG_ERROR("friendRequestCreate: NULL database");
        return DB_FAIL;
    }
    if (database->type != FriendDB) {
        LOG_ERROR(
            "friendRequestCreate: wrong database type %d (expected FriendDB)",
            (int)database->type);
        return DB_FAIL;
    }
    if (fromUid == toUid) {
        LOG_ERROR("friendRequestCreate: cannot friend yourself (uid=%u)",
                  fromUid);
        return DB_FAIL;
    }

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(database->handle, SQL_INSERT_FRIEND_REQUEST, -1,
                                &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("friendRequestCreate: prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)fromUid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("friendRequestCreate: bind fromUid failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 2, (sqlite3_int64)toUid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("friendRequestCreate: bind toUid failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 3, (sqlite3_int64)time(NULL));
    if (rc != SQLITE_OK) {
        LOG_ERROR("friendRequestCreate: bind createdAt failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        LOG_ERROR("friendRequestCreate: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    return DB_SUCC;
}

int friendRequestAccept(DB *database, uint32_t fromUid, uint32_t toUid) {
    if (database == NULL) {
        LOG_ERROR("friendRequestAccept: NULL database");
        return DB_FAIL;
    }
    if (database->type != FriendDB) {
        LOG_ERROR(
            "friendRequestAccept: wrong database type %d (expected FriendDB)",
            (int)database->type);
        return DB_FAIL;
    }

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(database->handle, SQL_ACCEPT_FRIEND_REQUEST, -1,
                                &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("friendRequestAccept: prepare accept failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)fromUid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("friendRequestAccept: bind fromUid failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 2, (sqlite3_int64)toUid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("friendRequestAccept: bind toUid failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        LOG_ERROR("friendRequestAccept: step accept failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    time_t now = time(NULL);

    rc = sqlite3_prepare_v2(database->handle, SQL_INSERT_FRIENDSHIP, -1, &stmt,
                            NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("friendRequestAccept: prepare friendship failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)fromUid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("friendRequestAccept: bind fromUid (friendship) failed: "
                  "%s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }
    rc = sqlite3_bind_int64(stmt, 2, (sqlite3_int64)toUid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("friendRequestAccept: bind toUid (friendship) failed: "
                  "%s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }
    rc = sqlite3_bind_int64(stmt, 3, (sqlite3_int64)now);
    if (rc != SQLITE_OK) {
        LOG_ERROR("friendRequestAccept: bind now (friendship) failed: "
                  "%s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        LOG_ERROR("friendRequestAccept: step friendship A->B failed: %s "
                  "(rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)toUid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("friendRequestAccept: bind toUid (reverse) failed: %s "
                  "(rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }
    rc = sqlite3_bind_int64(stmt, 2, (sqlite3_int64)fromUid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("friendRequestAccept: bind fromUid (reverse) failed: %s "
                  "(rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }
    rc = sqlite3_bind_int64(stmt, 3, (sqlite3_int64)now);
    if (rc != SQLITE_OK) {
        LOG_ERROR("friendRequestAccept: bind now (reverse) failed: %s "
                  "(rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        LOG_ERROR("friendRequestAccept: step friendship B->A failed: %s "
                  "(rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    return DB_SUCC;
}

int friendRequestReject(DB *database, uint32_t fromUid, uint32_t toUid) {
    if (database == NULL) {
        LOG_ERROR("friendRequestReject: NULL database");
        return DB_FAIL;
    }
    if (database->type != FriendDB) {
        LOG_ERROR(
            "friendRequestReject: wrong database type %d (expected FriendDB)",
            (int)database->type);
        return DB_FAIL;
    }

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(database->handle, SQL_REJECT_FRIEND_REQUEST, -1,
                                &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("friendRequestReject: prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)fromUid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("friendRequestReject: bind fromUid failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 2, (sqlite3_int64)toUid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("friendRequestReject: bind toUid failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        LOG_ERROR("friendRequestReject: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    return DB_SUCC;
}

int friendDelete(DB *database, uint32_t uid, uint32_t friendUid) {
    if (database == NULL) {
        LOG_ERROR("friendDelete: NULL database");
        return DB_FAIL;
    }
    if (database->type != FriendDB) {
        LOG_ERROR("friendDelete: wrong database type %d (expected FriendDB)",
                  (int)database->type);
        return DB_FAIL;
    }

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(database->handle, SQL_DELETE_FRIENDSHIP, -1,
                                &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("friendDelete: prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)uid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("friendDelete: bind uid failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 2, (sqlite3_int64)friendUid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("friendDelete: bind friendUid failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 3, (sqlite3_int64)friendUid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("friendDelete: bind friendUid (3) failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 4, (sqlite3_int64)uid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("friendDelete: bind uid (4) failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        LOG_ERROR("friendDelete: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    return DB_SUCC;
}

int friendListGet(DB *database, uint32_t uid, FriendInfo **out, size_t *count) {
    if (database == NULL || out == NULL || count == NULL) {
        LOG_ERROR(
            "friendListGet: NULL argument (database=%p, out=%p, count=%p)",
            (void *)database, (void *)out, (void *)count);
        return DB_FAIL;
    }
    if (database->type != FriendDB) {
        LOG_ERROR("friendListGet: wrong database type %d (expected FriendDB)",
                  (int)database->type);
        return DB_FAIL;
    }

    *out = NULL;
    *count = 0;

    sqlite3_stmt *stmt = NULL;
    int rc =
        sqlite3_prepare_v2(database->handle, SQL_LIST_FRIENDS, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("friendListGet: prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)uid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("friendListGet: bind uid failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    size_t capacity = FRIEND_QUERY_INITIAL_CAPACITY;
    size_t n = 0;
    FriendInfo *results = malloc(capacity * sizeof(FriendInfo));
    if (results == NULL) {
        LOG_ERROR("friendListGet: malloc failed (errno=%d)", errno);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (n >= FRIEND_QUERY_MAX_RESULTS) {
            LOG_WARN("friendListGet: result limit reached (%d)",
                     FRIEND_QUERY_MAX_RESULTS);
            break;
        }

        if (n >= capacity) {
            size_t newCapacity = capacity * 2;
            FriendInfo *tmp =
                realloc(results, newCapacity * sizeof(FriendInfo));
            if (tmp == NULL) {
                LOG_ERROR("friendListGet: realloc failed (errno=%d)", errno);
                free(results);
                sqlite3_finalize(stmt);
                return DB_FAIL;
            }
            results = tmp;
            capacity = newCapacity;
        }

        memset(&results[n], 0, sizeof(FriendInfo));
        results[n].uid = (uint32_t)sqlite3_column_int64(stmt, 0);
        results[n].online = 0;
        n++;
    }

    if (rc != SQLITE_DONE) {
        LOG_ERROR("friendListGet: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        free(results);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    sqlite3_finalize(stmt);

    if (n == 0) {
        free(results);
        return DB_SUCC;
    }

    *out = results;
    *count = n;
    return DB_SUCC;
}

int friendRequestPendingList(DB *database, uint32_t uid, FriendInfo **out,
                             size_t *count) {
    if (database == NULL || out == NULL || count == NULL) {
        LOG_ERROR(
            "friendRequestPendingList: NULL argument (database=%p, out=%p, "
            "count=%p)",
            (void *)database, (void *)out, (void *)count);
        return DB_FAIL;
    }
    if (database->type != FriendDB) {
        LOG_ERROR("friendRequestPendingList: wrong database type %d (expected "
                  "FriendDB)",
                  (int)database->type);
        return DB_FAIL;
    }

    *out = NULL;
    *count = 0;

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(database->handle, SQL_PENDING_REQUESTS, -1,
                                &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("friendRequestPendingList: prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)uid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("friendRequestPendingList: bind uid failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    size_t capacity = FRIEND_QUERY_INITIAL_CAPACITY;
    size_t n = 0;
    FriendInfo *results = malloc(capacity * sizeof(FriendInfo));
    if (results == NULL) {
        LOG_ERROR("friendRequestPendingList: malloc failed (errno=%d)", errno);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (n >= FRIEND_QUERY_MAX_RESULTS) {
            LOG_WARN("friendRequestPendingList: result limit reached (%d)",
                     FRIEND_QUERY_MAX_RESULTS);
            break;
        }

        if (n >= capacity) {
            size_t newCapacity = capacity * 2;
            FriendInfo *tmp =
                realloc(results, newCapacity * sizeof(FriendInfo));
            if (tmp == NULL) {
                LOG_ERROR("friendRequestPendingList: realloc failed (errno=%d)",
                          errno);
                free(results);
                sqlite3_finalize(stmt);
                return DB_FAIL;
            }
            results = tmp;
            capacity = newCapacity;
        }

        memset(&results[n], 0, sizeof(FriendInfo));
        results[n].uid = (uint32_t)sqlite3_column_int64(stmt, 0);
        results[n].online = 0;
        n++;
    }

    if (rc != SQLITE_DONE) {
        LOG_ERROR("friendRequestPendingList: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        free(results);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    sqlite3_finalize(stmt);

    if (n == 0) {
        free(results);
        return DB_SUCC;
    }

    *out = results;
    *count = n;
    return DB_SUCC;
}

int friendIsFriend(DB *database, uint32_t uid, uint32_t otherUid) {
    if (database == NULL) {
        LOG_ERROR("friendIsFriend: NULL database");
        return DB_FAIL;
    }
    if (database->type != FriendDB) {
        LOG_ERROR("friendIsFriend: wrong database type %d (expected FriendDB)",
                  (int)database->type);
        return DB_FAIL;
    }

    sqlite3_stmt *stmt = NULL;
    int rc =
        sqlite3_prepare_v2(database->handle, SQL_IS_FRIEND, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("friendIsFriend: prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)uid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("friendIsFriend: bind uid failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 2, (sqlite3_int64)otherUid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("friendIsFriend: bind otherUid failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_ROW) ? DB_SUCC : DB_FAIL;
}
