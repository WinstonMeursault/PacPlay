/**
 * @file privateChatDb.c
 * @brief Private chat database operations for PacPlay server.
 *
 * Implements CRUD operations for private chat messages.  A single table
 * (private_messages) stores all messages with a delivered flag for
 * pending-message tracking.  A global sequence table (msg_sequence)
 * provides unique, monotonically increasing message IDs.
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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ──────────────────────── named bind-parameter indices ─────────────────────
 */

enum {
    PrivateChatStoreParamCount = 5,
    PrivateChatHistoryParamCount = 6,
};

/* ───────────────────────── SQL schema definitions ───────────────────────── */

/** @brief SQL to create the global message sequence table. */
#define SQL_CREATE_MSG_SEQUENCE                                                \
    "CREATE TABLE IF NOT EXISTS msg_sequence ("                                \
    "id INTEGER PRIMARY KEY AUTOINCREMENT"                                     \
    ");"

/** @brief SQL to create the private messages table. */
#define SQL_CREATE_PRIVATE_MESSAGES                                            \
    "CREATE TABLE IF NOT EXISTS private_messages ("                            \
    "msgId INTEGER PRIMARY KEY, "                                              \
    "fromUid INTEGER NOT NULL, "                                               \
    "toUid INTEGER NOT NULL, "                                                 \
    "message TEXT NOT NULL, "                                                  \
    "timestamp INTEGER NOT NULL, "                                             \
    "delivered INTEGER NOT NULL DEFAULT 0"                                     \
    ");"

/** @brief SQL to create index on (fromUid, toUid, timestamp) for history. */
#define SQL_IDX_PM_FROM_TO_TS                                                  \
    "CREATE INDEX IF NOT EXISTS idx_pm_from_to_ts "                            \
    "ON private_messages(fromUid, toUid, timestamp);"

/** @brief SQL to create index on (toUid, delivered) for pending queries. */
#define SQL_IDX_PM_TO_DELIVERED                                                \
    "CREATE INDEX IF NOT EXISTS idx_pm_to_delivered "                          \
    "ON private_messages(toUid, delivered);"

/* ────────────────────────── schema init helper ──────────────────────────── */

int initPrivateChatDBSchema(sqlite3 *dbHandle) {
    if (dbExec(dbHandle, SQL_CREATE_MSG_SEQUENCE, "CREATE msg_sequence") !=
        DB_SUCC)
        return DB_FAIL;
    if (dbExec(dbHandle, SQL_CREATE_PRIVATE_MESSAGES,
               "CREATE private_messages") != DB_SUCC)
        return DB_FAIL;
    if (dbExec(dbHandle, SQL_IDX_PM_FROM_TO_TS, "CREATE idx_pm_from_to_ts") !=
        DB_SUCC)
        return DB_FAIL;
    return dbExec(dbHandle, SQL_IDX_PM_TO_DELIVERED,
                  "CREATE idx_pm_to_delivered");
}

/* ──────────────────────── message ID generation ─────────────────────────── */

/**
 * @brief Generate the next globally unique message ID.
 *
 * Inserts a row into msg_sequence and returns the resulting rowid.
 *
 * @param database  An open PrivateChatDB handle.
 * @param outMsgId  Output: the generated message ID.
 * @return @c DB_SUCC on success, @c DB_FAIL on failure.
 */
static int generateMsgId(DB *database, uint64_t *outMsgId) {
    sqlite3_stmt *stmt = database->stmtSeq;
    sqlite3_reset(stmt);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        LOG_ERROR("generateMsgId: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }
    *outMsgId = (uint64_t)sqlite3_last_insert_rowid(database->handle);
    return DB_SUCC;
}

/* ───────────────────────── public API: store ────────────────────────────── */

int privateChatStore(DB *database, uint32_t fromUid, uint32_t toUid,
                     const uint8_t *message, uint64_t timestamp,
                     uint32_t *outMsgId) {
    if (database == NULL || database->type != PrivateChatDB) {
        LOG_ERROR("privateChatStore: invalid database (db=%p, type=%d)",
                  (void *)database,
                  database != NULL ? (int)database->type : -1);
        return DB_FAIL;
    }
    if (message == NULL || message[0] == '\0') {
        LOG_ERROR("privateChatStore: message is NULL or empty");
        return DB_FAIL;
    }

    uint64_t msgId = 0;
    if (generateMsgId(database, &msgId) != DB_SUCC) {
        return DB_FAIL;
    }

    const char *sql =
        "INSERT INTO private_messages (msgId, fromUid, toUid, message, "
        "timestamp) VALUES (?, ?, ?, ?, ?);";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(database->handle, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("privateChatStore: prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)msgId);
    if (rc != SQLITE_OK) {
        LOG_ERROR("privateChatStore: bind msgId failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 2, (sqlite3_int64)fromUid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("privateChatStore: bind fromUid failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 3, (sqlite3_int64)toUid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("privateChatStore: bind toUid failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    rc = sqlite3_bind_text(stmt, 4, (const char *)message, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        LOG_ERROR("privateChatStore: bind message failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, PrivateChatStoreParamCount,
                            (sqlite3_int64)timestamp);
    if (rc != SQLITE_OK) {
        LOG_ERROR("privateChatStore: bind timestamp failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        LOG_ERROR("privateChatStore: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    if (outMsgId != NULL) {
        *outMsgId = (uint32_t)msgId;
    }
    return DB_SUCC;
}

/* ──────────────────────── public API: deliver ───────────────────────────── */

int privateChatDeliverPending(DB *database, uint32_t toUid, Chat **out,
                              size_t *count) {
    if (database == NULL || out == NULL || count == NULL) {
        LOG_ERROR("privateChatDeliverPending: NULL argument "
                  "(database=%p, out=%p, count=%p)",
                  (void *)database, (void *)out, (void *)count);
        return DB_FAIL;
    }
    if (database->type != PrivateChatDB) {
        LOG_ERROR("privateChatDeliverPending: wrong database type %d "
                  "(expected PrivateChatDB)",
                  (int)database->type);
        return DB_FAIL;
    }

    *out = NULL;
    *count = 0;

    const char *sql = "SELECT msgId, fromUid, toUid, message, timestamp "
                      "FROM private_messages "
                      "WHERE toUid=? AND delivered=0 ORDER BY msgId ASC;";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(database->handle, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("privateChatDeliverPending: prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)toUid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("privateChatDeliverPending: bind toUid failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    size_t capacity = QUERY_INITIAL_CAPACITY;
    size_t n = 0;
    Chat *results = malloc(capacity * sizeof(Chat));
    if (results == NULL) {
        LOG_ERROR("privateChatDeliverPending: malloc failed (errno=%d)", errno);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (n >= QUERY_MAX_RESULTS) {
            LOG_WARN("privateChatDeliverPending: result limit reached (%d)",
                     QUERY_MAX_RESULTS);
            break;
        }

        if (n >= capacity) {
            size_t newCapacity = capacity * 2;
            Chat *tmp = realloc(results, newCapacity * sizeof(Chat));
            if (tmp == NULL) {
                LOG_ERROR("privateChatDeliverPending: realloc failed "
                          "(errno=%d)",
                          errno);
                for (size_t i = 0; i < n; i++) {
                    free(results[i].message);
                }
                free(results);
                sqlite3_finalize(stmt);
                return DB_FAIL;
            }
            results = tmp;
            capacity = newCapacity;
        }

        /* Columns: 0=msgId, 1=fromUid, 2=toUid, 3=message, 4=timestamp */
        results[n].msgId = (uint64_t)sqlite3_column_int64(stmt, 0);
        results[n].uid = (uint32_t)sqlite3_column_int64(stmt, 1);

        const char *msgText = (const char *)sqlite3_column_text(stmt, 3);
        if (msgText == NULL) {
            LOG_ERROR("privateChatDeliverPending: message column is NULL "
                      "at row %zu",
                      n);
            for (size_t i = 0; i < n; i++) {
                free(results[i].message);
            }
            free(results);
            sqlite3_finalize(stmt);
            return DB_FAIL;
        }
        results[n].message = strdup(msgText);
        if (results[n].message == NULL) {
            LOG_ERROR("privateChatDeliverPending: strdup failed (errno=%d)",
                      errno);
            for (size_t i = 0; i < n; i++) {
                free(results[i].message);
            }
            free(results);
            sqlite3_finalize(stmt);
            return DB_FAIL;
        }

        results[n].timestamp = (time_t)sqlite3_column_int64(stmt, 4);
        n++;
    }

    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        LOG_ERROR("privateChatDeliverPending: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        for (size_t i = 0; i < n; i++) {
            free(results[i].message);
        }
        free(results);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    sqlite3_finalize(stmt);

    /* Mark fetched messages as delivered */
    const char *upd = "UPDATE private_messages SET delivered=1 "
                      "WHERE toUid=? AND delivered=0;";
    rc = sqlite3_prepare_v2(database->handle, upd, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, (sqlite3_int64)toUid);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    if (n == 0) {
        free(results);
        *out = NULL;
        *count = 0;
        return DB_SUCC;
    }

    *out = results;
    *count = n;
    return DB_SUCC;
}

/* ──────────────────────── public API: history ───────────────────────────── */

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
int privateChatHistory(DB *database, uint32_t uidA, uint32_t uidB,
                       uint32_t beforeMsgId, uint32_t limit, Chat **out,
                       size_t *count) {
    if (database == NULL || out == NULL || count == NULL) {
        LOG_ERROR("privateChatHistory: NULL argument "
                  "(database=%p, out=%p, count=%p)",
                  (void *)database, (void *)out, (void *)count);
        return DB_FAIL;
    }
    if (database->type != PrivateChatDB) {
        LOG_ERROR("privateChatHistory: wrong database type %d "
                  "(expected PrivateChatDB)",
                  (int)database->type);
        return DB_FAIL;
    }

    *out = NULL;
    *count = 0;

    enum { DefaultLimit = 50 };
    if (limit == 0) {
        limit = DefaultLimit;
    }

    const char *sql =
        "SELECT msgId, fromUid, toUid, message, timestamp "
        "FROM private_messages "
        "WHERE ((fromUid=? AND toUid=?) OR (fromUid=? AND toUid=?)) "
        "AND msgId < ? ORDER BY msgId DESC LIMIT ?;";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(database->handle, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("privateChatHistory: prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)uidA);
    if (rc != SQLITE_OK) {
        LOG_ERROR("privateChatHistory: bind uidA(1) failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 2, (sqlite3_int64)uidB);
    if (rc != SQLITE_OK) {
        LOG_ERROR("privateChatHistory: bind uidB(2) failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 3, (sqlite3_int64)uidB);
    if (rc != SQLITE_OK) {
        LOG_ERROR("privateChatHistory: bind uidB(3) failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 4, (sqlite3_int64)uidA);
    if (rc != SQLITE_OK) {
        LOG_ERROR("privateChatHistory: bind uidA(4) failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    sqlite3_int64 beforeId = (beforeMsgId == 0) ? (sqlite3_int64)INT64_MAX
                                                : (sqlite3_int64)beforeMsgId;
    rc = sqlite3_bind_int64(stmt, PrivateChatStoreParamCount, beforeId);
    if (rc != SQLITE_OK) {
        LOG_ERROR("privateChatHistory: bind beforeMsgId failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, PrivateChatHistoryParamCount,
                            (sqlite3_int64)limit);
    if (rc != SQLITE_OK) {
        LOG_ERROR("privateChatHistory: bind limit failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    size_t capacity = (size_t)limit;
    size_t n = 0;
    Chat *results = malloc(capacity * sizeof(Chat));
    if (results == NULL) {
        LOG_ERROR("privateChatHistory: malloc failed (errno=%d)", errno);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (n >= capacity) {
            break;
        }

        /* Columns: 0=msgId, 1=fromUid, 2=toUid, 3=message, 4=timestamp */
        results[n].msgId = (uint64_t)sqlite3_column_int64(stmt, 0);
        results[n].uid = (uint32_t)sqlite3_column_int64(stmt, 1);

        const char *msgText = (const char *)sqlite3_column_text(stmt, 3);
        if (msgText == NULL) {
            LOG_ERROR("privateChatHistory: message column is NULL at row %zu",
                      n);
            for (size_t i = 0; i < n; i++) {
                free(results[i].message);
            }
            free(results);
            sqlite3_finalize(stmt);
            return DB_FAIL;
        }
        results[n].message = strdup(msgText);
        if (results[n].message == NULL) {
            LOG_ERROR("privateChatHistory: strdup failed (errno=%d)", errno);
            for (size_t i = 0; i < n; i++) {
                free(results[i].message);
            }
            free(results);
            sqlite3_finalize(stmt);
            return DB_FAIL;
        }

        results[n].timestamp = (time_t)sqlite3_column_int64(stmt, 4);
        n++;
    }

    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        LOG_ERROR("privateChatHistory: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        for (size_t i = 0; i < n; i++) {
            free(results[i].message);
        }
        free(results);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    sqlite3_finalize(stmt);

    if (n == 0) {
        free(results);
        *out = NULL;
        *count = 0;
        return DB_SUCC;
    }

    *out = results;
    *count = n;
    return DB_SUCC;
}

/* ────────────────────── public API: last timestamp ──────────────────────── */

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
int privateChatLastMsgTimestamp(DB *database, uint32_t uidA, uint32_t uidB,
                                uint64_t *outTs) {
    if (database == NULL || outTs == NULL) {
        LOG_ERROR("privateChatLastMsgTimestamp: NULL argument "
                  "(database=%p, outTs=%p)",
                  (void *)database, (void *)outTs);
        return DB_FAIL;
    }
    if (database->type != PrivateChatDB) {
        LOG_ERROR("privateChatLastMsgTimestamp: wrong database type %d "
                  "(expected PrivateChatDB)",
                  (int)database->type);
        return DB_FAIL;
    }

    const char *sql =
        "SELECT MAX(timestamp) FROM private_messages "
        "WHERE (fromUid=? AND toUid=?) OR (fromUid=? AND toUid=?);";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(database->handle, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("privateChatLastMsgTimestamp: prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)uidA);
    if (rc != SQLITE_OK) {
        LOG_ERROR("privateChatLastMsgTimestamp: bind uidA(1) failed: %s "
                  "(rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 2, (sqlite3_int64)uidB);
    if (rc != SQLITE_OK) {
        LOG_ERROR("privateChatLastMsgTimestamp: bind uidB(2) failed: %s "
                  "(rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 3, (sqlite3_int64)uidB);
    if (rc != SQLITE_OK) {
        LOG_ERROR("privateChatLastMsgTimestamp: bind uidB(3) failed: %s "
                  "(rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 4, (sqlite3_int64)uidA);
    if (rc != SQLITE_OK) {
        LOG_ERROR("privateChatLastMsgTimestamp: bind uidA(4) failed: %s "
                  "(rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *outTs = (uint64_t)sqlite3_column_int64(stmt, 0);
    } else {
        *outTs = 0;
    }
    sqlite3_finalize(stmt);
    return DB_SUCC;
}
