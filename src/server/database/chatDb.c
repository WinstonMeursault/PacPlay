/**
 * @file chatDb.c
 * @brief Chat history database operations for PacPlay server.
 *
 * Implements CRUD operations for chat history.  Each room has its own
 * table (room_<roomId>) created on demand.  A global sequence table
 * (msg_sequence) provides unique, monotonically increasing message IDs
 * across all rooms.  Prepared statements are cached per-room in a hash
 * table and finalized collectively at shutdown.
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

/** @brief SQL to create the global message sequence table. */
#define SQL_CREATE_MSG_SEQUENCE                                                \
    "CREATE TABLE IF NOT EXISTS msg_sequence ("                                \
    "id INTEGER PRIMARY KEY AUTOINCREMENT"                                     \
    ");"

/* ─────────────────────── ChatHistoryDB prepared SQL ─────────────────────── */

/** @brief INSERT into global sequence to generate next msgId. */
#define SQL_INSERT_SEQUENCE "INSERT INTO msg_sequence DEFAULT VALUES;"

/** @brief SQL to discover all room tables from the schema. */
#define SQL_SELECT_ROOM_TABLES                                                 \
    "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE "         \
    "'room_%';"

/* ─────────────────────── room stmt cache management ─────────────────────── */

/**
 * @brief Generate the table name for a given roomId.
 *
 * Writes "room_<roomId>" into the provided buffer.
 *
 * @param roomId  The room identifier.
 * @param buf     Output buffer (must be at least ROOM_TABLE_NAME_SIZE bytes).
 */
static void roomTableName(uint32_t roomId, char buf[ROOM_TABLE_NAME_SIZE]) {
    snprintf(buf, ROOM_TABLE_NAME_SIZE, "room_%u", roomId);
}

/**
 * @brief Compute hash bucket index for a roomId.
 */
static unsigned int roomHashIndex(uint32_t roomId) {
    return roomId % ROOM_STMT_BUCKETS;
}

/**
 * @brief Look up a cached RoomStmtEntry by roomId.
 *
 * @param cache   The room statement cache.
 * @param roomId  Room to look up.
 * @return The entry if found, or NULL if not cached.
 */
static RoomStmtEntry *roomCacheLookup(RoomStmtCache *cache, uint32_t roomId) {
    unsigned int idx = roomHashIndex(roomId);
    RoomStmtEntry *entry = cache->buckets[idx];
    while (entry != NULL) {
        if (entry->roomId == roomId) {
            return entry;
        }
        entry = entry->next;
    }
    return NULL;
}

/**
 * @brief Create the room table and indices if they do not exist.
 *
 * @param dbHandle  Raw sqlite3 handle.
 * @param tableName Room table name (e.g., "room_1001").
 * @return @c DB_SUCC on success, @c DB_FAIL on failure.
 */
static int createRoomTable(sqlite3 *dbHandle, const char *tableName) {
    char sql[SQL_BUF_SIZE];

    /* Create the room table */
    snprintf(sql, sizeof(sql),
             "CREATE TABLE IF NOT EXISTS %s ("
             "msgId INTEGER PRIMARY KEY, "
             "uid INTEGER NOT NULL, "
             "message TEXT NOT NULL, "
             "timestamp INTEGER NOT NULL"
             ");",
             tableName);
    if (dbExec(dbHandle, sql, "CREATE room table") != DB_SUCC) {
        return DB_FAIL;
    }

    /* Create index on timestamp for range queries */
    snprintf(sql, sizeof(sql),
             "CREATE INDEX IF NOT EXISTS idx_%s_ts ON %s(timestamp);",
             tableName, tableName);
    if (dbExec(dbHandle, sql, "CREATE room ts index") != DB_SUCC) {
        return DB_FAIL;
    }

    /* Create composite index on (uid, timestamp) for filtered queries */
    snprintf(sql, sizeof(sql),
             "CREATE INDEX IF NOT EXISTS idx_%s_uid_ts ON %s(uid, timestamp);",
             tableName, tableName);
    if (dbExec(dbHandle, sql, "CREATE room uid_ts index") != DB_SUCC) {
        return DB_FAIL;
    }

    return DB_SUCC;
}

/**
 * @brief Prepare and cache all statements for a room.
 *
 * Creates the room table if it does not exist, compiles the four recurring
 * SQL statements, and inserts a new RoomStmtEntry into the cache.
 *
 * @param database  The DB handle (ChatHistoryDB).
 * @param roomId    Room to prepare statements for.
 * @return The newly created entry, or NULL on failure.
 */
static RoomStmtEntry *roomCacheCreate(DB *database, uint32_t roomId) {
    char tableName[ROOM_TABLE_NAME_SIZE];
    roomTableName(roomId, tableName);

    /* Ensure the room table and indices exist */
    if (createRoomTable(database->handle, tableName) != DB_SUCC) {
        return NULL;
    }

    /* Prepare the four statements */
    char sql[SQL_BUF_SIZE];
    RoomStmtEntry *entry = calloc(1, sizeof(RoomStmtEntry));
    if (entry == NULL) {
        LOG_ERROR("roomCacheCreate: calloc failed (errno=%d)", errno);
        return NULL;
    }
    entry->roomId = roomId;

    int rc;

    /* INSERT: ?1=msgId, ?2=uid, ?3=message, ?4=timestamp */
    snprintf(sql, sizeof(sql),
             "INSERT INTO %s (msgId, uid, message, timestamp) "
             "VALUES (?, ?, ?, ?);",
             tableName);
    rc =
        sqlite3_prepare_v2(database->handle, sql, -1, &entry->stmtInsert, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("roomCacheCreate: INSERT prepare failed for %s: %s (rc=%d)",
                  tableName, sqlite3_errmsg(database->handle), rc);
        free(entry);
        return NULL;
    }

    /* SELECT by msgId: ?1=msgId */
    snprintf(sql, sizeof(sql),
             "SELECT msgId, uid, message, timestamp FROM %s WHERE msgId = ?;",
             tableName);
    rc = sqlite3_prepare_v2(database->handle, sql, -1, &entry->stmtSelectById,
                            NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR(
            "roomCacheCreate: SELECT-by-id prepare failed for %s: %s (rc=%d)",
            tableName, sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(entry->stmtInsert);
        free(entry);
        return NULL;
    }

    /* SELECT by time range + uid: ?1=uid, ?2=startTime, ?3=endTime */
    snprintf(sql, sizeof(sql),
             "SELECT msgId, uid, message, timestamp FROM %s "
             "WHERE uid = ? AND timestamp >= ? AND timestamp <= ? "
             "ORDER BY msgId ASC;",
             tableName);
    rc = sqlite3_prepare_v2(database->handle, sql, -1,
                            &entry->stmtSelectByTimeUid, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("roomCacheCreate: SELECT-by-time-uid prepare failed for %s: "
                  "%s (rc=%d)",
                  tableName, sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(entry->stmtInsert);
        sqlite3_finalize(entry->stmtSelectById);
        free(entry);
        return NULL;
    }

    /* SELECT by time range (all uids): ?1=startTime, ?2=endTime */
    snprintf(sql, sizeof(sql),
             "SELECT msgId, uid, message, timestamp FROM %s "
             "WHERE timestamp >= ? AND timestamp <= ? "
             "ORDER BY msgId ASC;",
             tableName);
    rc = sqlite3_prepare_v2(database->handle, sql, -1,
                            &entry->stmtSelectByTimeAll, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("roomCacheCreate: SELECT-by-time-all prepare failed for %s: "
                  "%s (rc=%d)",
                  tableName, sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(entry->stmtInsert);
        sqlite3_finalize(entry->stmtSelectById);
        sqlite3_finalize(entry->stmtSelectByTimeUid);
        free(entry);
        return NULL;
    }

    /* Insert into hash table at the head of the chain */
    unsigned int idx = roomHashIndex(roomId);
    entry->next = database->roomCache->buckets[idx];
    database->roomCache->buckets[idx] = entry;

    return entry;
}

/**
 * @brief Get or create cached statements for a room.
 *
 * Looks up the room in the cache; if not found, creates the table and
 * prepares all statements.
 *
 * @param database  The DB handle (ChatHistoryDB).
 * @param roomId    Room to get statements for.
 * @return The RoomStmtEntry, or NULL on failure.
 */
static RoomStmtEntry *getOrCreateRoomStmts(DB *database, uint32_t roomId) {
    RoomStmtEntry *entry = roomCacheLookup(database->roomCache, roomId);
    if (entry != NULL) {
        return entry;
    }
    return roomCacheCreate(database, roomId);
}

/**
 * @brief Free all entries in the room statement cache.
 *
 * Finalizes all prepared statements and frees all allocated memory.
 *
 * @param cache  The room statement cache to destroy (may be NULL).
 */
void roomCacheDestroy(RoomStmtCache *cache) {
    if (cache == NULL) {
        return;
    }
    for (unsigned int i = 0; i < ROOM_STMT_BUCKETS; i++) {
        RoomStmtEntry *entry = cache->buckets[i];
        while (entry != NULL) {
            RoomStmtEntry *next = entry->next;
            dbFinalize(&entry->stmtInsert);
            dbFinalize(&entry->stmtSelectById);
            dbFinalize(&entry->stmtSelectByTimeUid);
            dbFinalize(&entry->stmtSelectByTimeAll);
            free(entry);
            entry = next;
        }
    }
    free(cache);
}

/* ────────────────────────── schema init helper ──────────────────────────── */

int initChatHistoryDBSchema(sqlite3 *dbHandle) {
    return dbExec(dbHandle, SQL_CREATE_MSG_SEQUENCE,
                  "CREATE TABLE msg_sequence");
}

/* ───────────────────── ChatHistoryDB stmt preparation ───────────────────── */

/**
 * @brief Prepare the global sequence statement for ChatHistoryDB.
 *
 * @param database  The DB handle to populate.
 * @return @c DB_SUCC on success, @c DB_FAIL on failure.
 */
int prepareChatGlobalStmts(DB *database) {
    int rc = sqlite3_prepare_v2(database->handle, SQL_INSERT_SEQUENCE, -1,
                                &database->stmtSeq, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareChatGlobalStmts: sequence prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    return DB_SUCC;
}

/* ──────────────────────── public API: chat history ──────────────────────── */

/**
 * @brief Generate the next globally unique message ID.
 *
 * Inserts a row into msg_sequence and returns the resulting rowid.
 * This guarantees a strictly monotonically increasing, globally unique ID
 * across all room tables.
 *
 * @param database  An open ChatHistoryDB handle.
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

int storeChat(DB *database, uint32_t roomId, Chat *chat) {
    if (database == NULL || chat == NULL) {
        LOG_ERROR("storeChat: NULL argument (database=%p, chat=%p)",
                  (void *)database, (void *)chat);
        return DB_FAIL;
    }
    if (database->type != ChatHistoryDB) {
        LOG_ERROR("storeChat: wrong database type %d (expected ChatHistoryDB)",
                  (int)database->type);
        return DB_FAIL;
    }
    if (chat->message == NULL || chat->message[0] == '\0') {
        LOG_ERROR("storeChat: message is NULL or empty");
        return DB_FAIL;
    }

    /* Generate globally unique msgId */
    uint64_t msgId = 0;
    if (generateMsgId(database, &msgId) != DB_SUCC) {
        return DB_FAIL;
    }

    /* Get or create cached statements for this room */
    RoomStmtEntry *entry = getOrCreateRoomStmts(database, roomId);
    if (entry == NULL) {
        return DB_FAIL;
    }

    sqlite3_stmt *stmt = entry->stmtInsert;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    /* Bind: ?1=msgId, ?2=uid, ?3=message, ?4=timestamp */
    int rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)msgId);
    if (rc != SQLITE_OK) {
        LOG_ERROR("storeChat: bind msgId failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 2, (sqlite3_int64)chat->uid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("storeChat: bind uid failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_bind_text(stmt, 3, chat->message, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        LOG_ERROR("storeChat: bind message failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 4, (sqlite3_int64)chat->timestamp);
    if (rc != SQLITE_OK) {
        LOG_ERROR("storeChat: bind timestamp failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        LOG_ERROR("storeChat: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    /* Populate the generated msgId back into the caller's struct */
    chat->msgId = msgId;
    return DB_SUCC;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
int queryChatByMsgId(DB *database, uint32_t roomId, uint64_t msgId, Chat *out) {
    if (database == NULL || out == NULL) {
        LOG_ERROR("queryChatByMsgId: NULL argument (database=%p, out=%p)",
                  (void *)database, (void *)out);
        return DB_FAIL;
    }
    if (database->type != ChatHistoryDB) {
        LOG_ERROR("queryChatByMsgId: wrong database type %d "
                  "(expected ChatHistoryDB)",
                  (int)database->type);
        return DB_FAIL;
    }

    RoomStmtEntry *entry = getOrCreateRoomStmts(database, roomId);
    if (entry == NULL) {
        return DB_FAIL;
    }

    sqlite3_stmt *stmt = entry->stmtSelectById;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    /* Bind: ?1=msgId */
    int rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)msgId);
    if (rc != SQLITE_OK) {
        LOG_ERROR("queryChatByMsgId: bind msgId failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE) {
        /* No matching record */
        return DB_FAIL;
    }
    if (rc != SQLITE_ROW) {
        LOG_ERROR("queryChatByMsgId: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    /* Columns: 0=msgId, 1=uid, 2=message, 3=timestamp */
    out->msgId = (uint64_t)sqlite3_column_int64(stmt, 0);
    out->uid = (uint32_t)sqlite3_column_int(stmt, 1);

    const char *msgText = (const char *)sqlite3_column_text(stmt, 2);
    if (msgText == NULL) {
        LOG_ERROR("queryChatByMsgId: message column is NULL");
        return DB_FAIL;
    }
    out->message = strdup(msgText);
    if (out->message == NULL) {
        LOG_ERROR("queryChatByMsgId: strdup failed (errno=%d)", errno);
        return DB_FAIL;
    }

    out->timestamp = (time_t)sqlite3_column_int64(stmt, 3);

    return DB_SUCC;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
int queryChatByTimeRange(DB *database, uint32_t roomId, uint32_t uid,
                         time_t startTime, time_t endTime, Chat **out,
                         size_t *count) {
    if (database == NULL || out == NULL || count == NULL) {
        LOG_ERROR("queryChatByTimeRange: NULL argument "
                  "(database=%p, out=%p, count=%p)",
                  (void *)database, (void *)out, (void *)count);
        return DB_FAIL;
    }
    if (database->type != ChatHistoryDB) {
        LOG_ERROR("queryChatByTimeRange: wrong database type %d "
                  "(expected ChatHistoryDB)",
                  (int)database->type);
        return DB_FAIL;
    }

    /* Initialize outputs */
    *out = NULL;
    *count = 0;

    RoomStmtEntry *entry = getOrCreateRoomStmts(database, roomId);
    if (entry == NULL) {
        return DB_FAIL;
    }

    /* Choose statement based on uid filter */
    sqlite3_stmt *stmt = NULL;
    if (uid == 0) {
        /* All users: ?1=startTime, ?2=endTime */
        stmt = entry->stmtSelectByTimeAll;
        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);

        int rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)startTime);
        if (rc != SQLITE_OK) {
            LOG_ERROR("queryChatByTimeRange: bind startTime failed: %s (rc=%d)",
                      sqlite3_errmsg(database->handle), rc);
            return DB_FAIL;
        }
        rc = sqlite3_bind_int64(stmt, 2, (sqlite3_int64)endTime);
        if (rc != SQLITE_OK) {
            LOG_ERROR("queryChatByTimeRange: bind endTime failed: %s (rc=%d)",
                      sqlite3_errmsg(database->handle), rc);
            return DB_FAIL;
        }
    } else {
        /* Specific uid: ?1=uid, ?2=startTime, ?3=endTime */
        stmt = entry->stmtSelectByTimeUid;
        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);

        int rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)uid);
        if (rc != SQLITE_OK) {
            LOG_ERROR("queryChatByTimeRange: bind uid failed: %s (rc=%d)",
                      sqlite3_errmsg(database->handle), rc);
            return DB_FAIL;
        }
        rc = sqlite3_bind_int64(stmt, 2, (sqlite3_int64)startTime);
        if (rc != SQLITE_OK) {
            LOG_ERROR("queryChatByTimeRange: bind startTime failed: %s (rc=%d)",
                      sqlite3_errmsg(database->handle), rc);
            return DB_FAIL;
        }
        rc = sqlite3_bind_int64(stmt, 3, (sqlite3_int64)endTime);
        if (rc != SQLITE_OK) {
            LOG_ERROR("queryChatByTimeRange: bind endTime failed: %s (rc=%d)",
                      sqlite3_errmsg(database->handle), rc);
            return DB_FAIL;
        }
    }

    /* Iterate result rows and build the output array */
    size_t capacity = QUERY_INITIAL_CAPACITY;
    size_t n = 0;
    Chat *results = malloc(capacity * sizeof(Chat));
    if (results == NULL) {
        LOG_ERROR("queryChatByTimeRange: malloc failed (errno=%d)", errno);
        return DB_FAIL;
    }

    int rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (n >= QUERY_MAX_RESULTS) {
            LOG_WARN("queryChatByTimeRange: result limit reached (%d)",
                     QUERY_MAX_RESULTS);
            break;
        }

        /* Grow the array if needed (doubling strategy) */
        if (n >= capacity) {
            size_t newCapacity = capacity * 2;
            Chat *tmp = realloc(results, newCapacity * sizeof(Chat));
            if (tmp == NULL) {
                LOG_ERROR("queryChatByTimeRange: realloc failed (errno=%d)",
                          errno);
                /* Free already-allocated messages */
                for (size_t i = 0; i < n; i++) {
                    free(results[i].message);
                }
                free(results);
                return DB_FAIL;
            }
            results = tmp;
            capacity = newCapacity;
        }

        /* Columns: 0=msgId, 1=uid, 2=message, 3=timestamp */
        results[n].msgId = (uint64_t)sqlite3_column_int64(stmt, 0);
        results[n].uid = (uint32_t)sqlite3_column_int(stmt, 1);

        const char *msgText = (const char *)sqlite3_column_text(stmt, 2);
        if (msgText == NULL) {
            LOG_ERROR("queryChatByTimeRange: message column is NULL at row %zu",
                      n);
            for (size_t i = 0; i < n; i++) {
                free(results[i].message);
            }
            free(results);
            return DB_FAIL;
        }
        results[n].message = strdup(msgText);
        if (results[n].message == NULL) {
            LOG_ERROR("queryChatByTimeRange: strdup failed (errno=%d)", errno);
            for (size_t i = 0; i < n; i++) {
                free(results[i].message);
            }
            free(results);
            return DB_FAIL;
        }

        results[n].timestamp = (time_t)sqlite3_column_int64(stmt, 3);
        n++;
    }

    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        LOG_ERROR("queryChatByTimeRange: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        for (size_t i = 0; i < n; i++) {
            free(results[i].message);
        }
        free(results);
        return DB_FAIL;
    }

    /* Handle empty result set */
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

/* ──────────────────────── queryChatByUserAllRooms ───────────────────────── */

/**
 * @brief Comparison function for qsort: order Chat by msgId ascending.
 */
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
static int compareChatByMsgId(const void *a, const void *b) {
    const Chat *ha = (const Chat *)a;
    const Chat *hb = (const Chat *)b;
    if (ha->msgId < hb->msgId) {
        return -1;
    }
    if (ha->msgId > hb->msgId) {
        return 1;
    }
    return 0;
}

/**
 * @brief Collect chat records from one room's stmtSelectByTimeUid into array.
 *
 * Resets and binds the statement, then iterates rows appending to the
 * dynamic array. The caller provides the current array state and this
 * function updates it in place.
 *
 * @param database   The DB handle.
 * @param entry      Room statement cache entry.
 * @param uid        User ID to filter by.
 * @param startTime  Start of range (inclusive).
 * @param endTime    End of range (inclusive).
 * @param results    Pointer to current results array (may be reallocated).
 * @param n          Pointer to current count of collected results.
 * @param capacity   Pointer to current array capacity.
 * @return @c DB_SUCC on success, @c DB_FAIL on error.
 */
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
static int collectRoomResults(DB *database, RoomStmtEntry *entry, uint32_t uid,
                              time_t startTime, time_t endTime, Chat **results,
                              size_t *n, size_t *capacity) {
    sqlite3_stmt *stmt = entry->stmtSelectByTimeUid;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    /* Bind: ?1=uid, ?2=startTime, ?3=endTime */
    int rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)uid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("collectRoomResults: bind uid failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }
    rc = sqlite3_bind_int64(stmt, 2, (sqlite3_int64)startTime);
    if (rc != SQLITE_OK) {
        LOG_ERROR("collectRoomResults: bind startTime failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }
    rc = sqlite3_bind_int64(stmt, 3, (sqlite3_int64)endTime);
    if (rc != SQLITE_OK) {
        LOG_ERROR("collectRoomResults: bind endTime failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (*n >= QUERY_MAX_RESULTS) {
            LOG_WARN("collectRoomResults: global result limit reached (%d)",
                     QUERY_MAX_RESULTS);
            break;
        }

        /* Grow the array if needed (doubling strategy) */
        if (*n >= *capacity) {
            size_t newCapacity = (*capacity) * 2;
            Chat *tmp = realloc(*results, newCapacity * sizeof(Chat));
            if (tmp == NULL) {
                LOG_ERROR("collectRoomResults: realloc failed (errno=%d)",
                          errno);
                return DB_FAIL;
            }
            *results = tmp;
            *capacity = newCapacity;
        }

        /* Columns: 0=msgId, 1=uid, 2=message, 3=timestamp */
        (*results)[*n].msgId = (uint64_t)sqlite3_column_int64(stmt, 0);
        (*results)[*n].uid = (uint32_t)sqlite3_column_int(stmt, 1);

        const char *msgText = (const char *)sqlite3_column_text(stmt, 2);
        if (msgText == NULL) {
            LOG_ERROR("collectRoomResults: message column is NULL at row %zu",
                      *n);
            return DB_FAIL;
        }
        (*results)[*n].message = strdup(msgText);
        if ((*results)[*n].message == NULL) {
            LOG_ERROR("collectRoomResults: strdup failed (errno=%d)", errno);
            return DB_FAIL;
        }

        (*results)[*n].timestamp = (time_t)sqlite3_column_int64(stmt, 3);
        (*n)++;
    }

    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        LOG_ERROR("collectRoomResults: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    return DB_SUCC;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
int queryChatByUserAllRooms(DB *database, uint32_t uid, time_t startTime,
                            time_t endTime, Chat **out, size_t *count) {
    if (database == NULL || out == NULL || count == NULL) {
        LOG_ERROR("queryChatByUserAllRooms: NULL argument "
                  "(database=%p, out=%p, count=%p)",
                  (void *)database, (void *)out, (void *)count);
        return DB_FAIL;
    }
    if (database->type != ChatHistoryDB) {
        LOG_ERROR("queryChatByUserAllRooms: wrong database type %d "
                  "(expected ChatHistoryDB)",
                  (int)database->type);
        return DB_FAIL;
    }
    if (uid == 0) {
        LOG_ERROR("queryChatByUserAllRooms: uid must be non-zero");
        return DB_FAIL;
    }

    /* Initialize outputs */
    *out = NULL;
    *count = 0;

    /* Discover all room tables via sqlite_master */
    sqlite3_stmt *stmtMaster = NULL;
    int rc = sqlite3_prepare_v2(database->handle, SQL_SELECT_ROOM_TABLES, -1,
                                &stmtMaster, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("queryChatByUserAllRooms: prepare sqlite_master query "
                  "failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    /* Collect room IDs first, then finalize the master statement before
     * executing per-room queries (avoids nested statement issues). */
    size_t roomCount = 0;
    size_t roomCapacity = QUERY_INITIAL_CAPACITY;
    uint32_t *roomIds = malloc(roomCapacity * sizeof(uint32_t));
    if (roomIds == NULL) {
        LOG_ERROR("queryChatByUserAllRooms: malloc roomIds failed (errno=%d)",
                  errno);
        sqlite3_finalize(stmtMaster);
        return DB_FAIL;
    }

    while ((rc = sqlite3_step(stmtMaster)) == SQLITE_ROW) {
        const char *tableName =
            (const char *)sqlite3_column_text(stmtMaster, 0);
        if (tableName == NULL) {
            continue;
        }

        /* Parse roomId from table name "room_<uint32>" using strtoul */
        const char *numStart = tableName + strlen("room_");
        char *endPtr = NULL;
        enum { DecimalBase = 10 };
        unsigned long parsed = strtoul(numStart, &endPtr, DecimalBase);
        if (endPtr == numStart || *endPtr != '\0' || parsed > UINT32_MAX) {
            /* Table name does not match expected format; skip */
            continue;
        }
        uint32_t roomId = (uint32_t)parsed;

        /* Grow roomIds array if needed */
        if (roomCount >= roomCapacity) {
            size_t newCapacity = roomCapacity * 2;
            uint32_t *tmp = realloc(roomIds, newCapacity * sizeof(uint32_t));
            if (tmp == NULL) {
                LOG_ERROR("queryChatByUserAllRooms: realloc roomIds failed "
                          "(errno=%d)",
                          errno);
                free(roomIds);
                sqlite3_finalize(stmtMaster);
                return DB_FAIL;
            }
            roomIds = tmp;
            roomCapacity = newCapacity;
        }

        roomIds[roomCount] = roomId;
        roomCount++;
    }

    sqlite3_finalize(stmtMaster);

    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        LOG_ERROR("queryChatByUserAllRooms: sqlite_master step failed: %s "
                  "(rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        free(roomIds);
        return DB_FAIL;
    }

    /* No rooms exist yet — empty result */
    if (roomCount == 0) {
        free(roomIds);
        return DB_SUCC;
    }

    /* Allocate result array and iterate over each room */
    size_t capacity = QUERY_INITIAL_CAPACITY;
    size_t n = 0;
    Chat *results = malloc(capacity * sizeof(Chat));
    if (results == NULL) {
        LOG_ERROR("queryChatByUserAllRooms: malloc results failed (errno=%d)",
                  errno);
        free(roomIds);
        return DB_FAIL;
    }

    for (size_t i = 0; i < roomCount; i++) {
        RoomStmtEntry *entry = getOrCreateRoomStmts(database, roomIds[i]);
        if (entry == NULL) {
            LOG_ERROR("queryChatByUserAllRooms: getOrCreateRoomStmts failed "
                      "for room %u",
                      roomIds[i]);
            /* Clean up and fail */
            for (size_t j = 0; j < n; j++) {
                free(results[j].message);
            }
            free(results);
            free(roomIds);
            return DB_FAIL;
        }

        if (collectRoomResults(database, entry, uid, startTime, endTime,
                               &results, &n, &capacity) != DB_SUCC) {
            for (size_t j = 0; j < n; j++) {
                free(results[j].message);
            }
            free(results);
            free(roomIds);
            return DB_FAIL;
        }

        if (n >= QUERY_MAX_RESULTS) {
            break;
        }
    }

    free(roomIds);

    /* Handle empty result set */
    if (n == 0) {
        free(results);
        *out = NULL;
        *count = 0;
        return DB_SUCC;
    }

    /* Sort results globally by msgId for chronological order */
    qsort(results, n, sizeof(Chat), compareChatByMsgId);

    *out = results;
    *count = n;
    return DB_SUCC;
}
