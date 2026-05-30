/**
 * @file database.c
 * @brief SQLite3 database operations for PacPlay server.
 *
 * Implements database initialization (with automatic schema creation),
 * teardown, and CRUD operations for users and chat history.
 *
 * For ChatHistoryDB, each room has its own table (room_<roomId>) created
 * on demand. A global sequence table (msg_sequence) provides unique,
 * monotonically increasing message IDs across all rooms.
 *
 * Prepared statements are cached per-room in a hash table and finalized
 * collectively in dbClose().
 *
 * @date 2026-05-24
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

#include "database.h"
#include "crypto.h"
#include "log.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <openssl/crypto.h>

#ifdef _WIN32
#include <direct.h>
/** @brief Cross-platform mkdir wrapper (Windows ignores mode). */
#define PLATFORM_MKDIR(path, mode) _mkdir(path)
#else
/** @brief Cross-platform mkdir wrapper (POSIX). */
#define PLATFORM_MKDIR(path, mode) mkdir(path, mode)
#endif

/* ──────────────────────── SQL schema definitions ──────────────────────── */

/** @brief SQL statement to create the users table.
 *
 * uid is server-assigned via random generation with uniqueness check;
 * AUTOINCREMENT is intentionally not used so that the server controls
 * the ID space. */
#define SQL_CREATE_USERS_TABLE                                                 \
    "CREATE TABLE IF NOT EXISTS users ("                                       \
    "uid INTEGER PRIMARY KEY, "                                                \
    "username TEXT UNIQUE NOT NULL, "                                          \
    "nickname TEXT NOT NULL, "                                                 \
    "password TEXT NOT NULL, "                                                 \
    "totp_secret BLOB"                                                         \
    ");"

/** @brief SQL to create the global message sequence table. */
#define SQL_CREATE_MSG_SEQUENCE                                                \
    "CREATE TABLE IF NOT EXISTS msg_sequence ("                                \
    "id INTEGER PRIMARY KEY AUTOINCREMENT"                                     \
    ");"

/* ──────────────────────── UserDB prepared SQL ───────────────────────────── */

/** @brief INSERT a user record. Params: ?1=uid, ?2=username, ?3=nickname,
    ?4=password. uid is server-generated and validated as unique before insert. */
#define SQL_INSERT_USER                                                        \
    "INSERT INTO users (uid, username, nickname, password, totp_secret) "      \
    "VALUES (?, ?, ?, ?, ?);"

/** @brief DELETE a user by uid. Params: ?1=uid. */
#define SQL_DELETE_USER "DELETE FROM users WHERE uid = ?;"

/** @brief SELECT uid, nickname, password by username (uid is no longer
    required for authentication — the server assigns it on registration and
    returns it on login). Params: ?1=username.
    Columns: 0=uid, 1=nickname, 2=password. */
#define SQL_SELECT_USER_PASSWORD                                               \
    "SELECT uid, nickname, password, totp_secret FROM users WHERE username = ?;"

/** @brief Check whether a uid already exists. Params: ?1=uid. */
#define SQL_UID_CHECK "SELECT 1 FROM users WHERE uid = ?;"

/** @brief UPDATE totp_secret for a user. Params: ?1=secret, ?2=uid. */
#define SQL_SET_TOTP_SECRET "UPDATE users SET totp_secret = ? WHERE uid = ?;"

/** @brief SELECT totp_secret by uid. Params: ?1=uid. Columns: 0=totp_secret. */
#define SQL_SELECT_TOTP_BY_UID "SELECT totp_secret FROM users WHERE uid = ?;"

/* ──────────────────────── ServerDB prepared SQL ─────────────────────────── */

/** @brief CREATE the server keys table. */
#define SQL_CREATE_SERVER_KEYS_TABLE                                            \
    "CREATE TABLE IF NOT EXISTS server_keys ("                                  \
    "key_name TEXT PRIMARY KEY, "                                               \
    "key_value BLOB NOT NULL, "                                                 \
    "created_at INTEGER NOT NULL"                                               \
    ");"

/** @brief INSERT OR REPLACE a server key. Params: ?1=key_name, ?2=key_value,
    ?3=created_at. */
#define SQL_UPSERT_SERVER_KEY                                                   \
    "INSERT OR REPLACE INTO server_keys (key_name, key_value, created_at) "    \
    "VALUES (?, ?, ?);"

/** @brief SELECT key_value by key name. Params: ?1=key_name.
    Columns: 0=key_value. */
#define SQL_SELECT_SERVER_KEY "SELECT key_value FROM server_keys WHERE key_name = ?;"

/* ──────────────────────── ChatHistoryDB prepared SQL ────────────────────── */

/** @brief INSERT into global sequence to generate next msgId. */
#define SQL_INSERT_SEQUENCE "INSERT INTO msg_sequence DEFAULT VALUES;"

/* ──────────────────────── GameDB prepared SQL ────────────────────────────── */

/** @brief CREATE the rooms table for GameDB. */
#define SQL_CREATE_ROOMS_TABLE                                                  \
    "CREATE TABLE IF NOT EXISTS rooms ("                                        \
    "roomId INTEGER PRIMARY KEY, "                                              \
    "creatorUid INTEGER NOT NULL, "                                             \
    "createdAt INTEGER NOT NULL"                                                \
    ");"

/** @brief INSERT a room. Params: ?1=roomId, ?2=creatorUid, ?3=createdAt. */
#define SQL_INSERT_ROOM                                                         \
    "INSERT INTO rooms (roomId, creatorUid, createdAt) VALUES (?, ?, ?);"

/** @brief DELETE a room by roomId. Params: ?1=roomId. */
#define SQL_DELETE_ROOM "DELETE FROM rooms WHERE roomId = ?;"

/** @brief SELECT all room IDs ordered ascending. */
#define SQL_LIST_ROOMS "SELECT roomId FROM rooms ORDER BY roomId ASC;"

/** @brief SELECT 1 to check room existence. Params: ?1=roomId. */
#define SQL_EXISTS_ROOM "SELECT 1 FROM rooms WHERE roomId = ?;"

/* ──────────────────────── misc constants ────────────────────────────────── */

/** @brief Directory permission mode: rwx for owner, rx for group/others. */
#define DB_DIR_MODE 0755

/** @brief Maximum length of a dynamically generated SQL string. */
#define SQL_BUF_SIZE 512

/** @brief Maximum length of a room table name (e.g., "room_4294967295"). */
#define ROOM_TABLE_NAME_SIZE 32

/** @brief Initial capacity for queryChatByTimeRange result array. */
#define QUERY_INITIAL_CAPACITY 16

/** @brief Maximum result count to prevent unbounded memory allocation. */
#define QUERY_MAX_RESULTS 100000

/* ──────────────────────── internal helpers ─────────────────────────────── */

/**
 * @brief Ensure the database directory exists, creating it if necessary.
 *
 * Uses stat() to check existence, then mkdir() if needed. Cross-platform
 * via the PLATFORM_MKDIR macro.
 *
 * @return @c DB_SUCC if directory exists or was created, @c DB_FAIL on error.
 */
static int ensureDBDirectoryExists(void) {
    struct stat st;
    if (stat(DB_DIRECTORY, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            return DB_SUCC;
        }
        LOG_ERROR("dbInit: path '%s' exists but is not a directory",
                  DB_DIRECTORY);
        return DB_FAIL;
    }

    if (PLATFORM_MKDIR(DB_DIRECTORY, DB_DIR_MODE) != 0) {
        LOG_ERROR("dbInit: failed to create directory '%s': %s (errno=%d)",
                  DB_DIRECTORY, strerror(errno), errno);
        return DB_FAIL;
    }

    LOG_INFO("dbInit: created database directory '%s'", DB_DIRECTORY);
    return DB_SUCC;
}

/**
 * @brief Execute a single SQL statement with no bound parameters.
 *
 * Uses the prepared-statement lifecycle: sqlite3_prepare_v2 -> sqlite3_step
 * -> sqlite3_finalize. Accepts both SQLITE_DONE and SQLITE_ROW as success.
 *
 * @param dbHandle  Raw sqlite3 handle.
 * @param sql       A single SQL statement to execute (NUL-terminated).
 * @param context   Human-readable context string for error messages.
 * @return @c DB_SUCC on success, @c DB_FAIL on failure.
 */
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
static int execStmt(sqlite3 *dbHandle, const char *sql, const char *context) {
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(dbHandle, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("%s: prepare failed: %s (rc=%d)", context,
                  sqlite3_errmsg(dbHandle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        LOG_ERROR("%s: step failed: %s (rc=%d)", context,
                  sqlite3_errmsg(dbHandle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    sqlite3_finalize(stmt);
    return DB_SUCC;
}

/**
 * @brief Finalize a cached prepared statement if it is non-NULL.
 *
 * Sets the pointer to NULL after finalization.
 *
 * @param stmt  Address of the statement pointer to finalize.
 */
static void finalizeStmt(sqlite3_stmt **stmt) {
    if (stmt != NULL && *stmt != NULL) {
        sqlite3_finalize(*stmt);
        *stmt = NULL;
    }
}

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

/* ──────────────────────── room stmt cache management ─────────────────── */

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
    if (execStmt(dbHandle, sql, "CREATE room table") != DB_SUCC) {
        return DB_FAIL;
    }

    /* Create index on timestamp for range queries */
    snprintf(sql, sizeof(sql),
             "CREATE INDEX IF NOT EXISTS idx_%s_ts ON %s(timestamp);",
             tableName, tableName);
    if (execStmt(dbHandle, sql, "CREATE room ts index") != DB_SUCC) {
        return DB_FAIL;
    }

    /* Create composite index on (uid, timestamp) for filtered queries */
    snprintf(sql, sizeof(sql),
             "CREATE INDEX IF NOT EXISTS idx_%s_uid_ts ON %s(uid, timestamp);",
             tableName, tableName);
    if (execStmt(dbHandle, sql, "CREATE room uid_ts index") != DB_SUCC) {
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
static void roomCacheDestroy(RoomStmtCache *cache) {
    if (cache == NULL) {
        return;
    }
    for (unsigned int i = 0; i < ROOM_STMT_BUCKETS; i++) {
        RoomStmtEntry *entry = cache->buckets[i];
        while (entry != NULL) {
            RoomStmtEntry *next = entry->next;
            finalizeStmt(&entry->stmtInsert);
            finalizeStmt(&entry->stmtSelectById);
            finalizeStmt(&entry->stmtSelectByTimeUid);
            finalizeStmt(&entry->stmtSelectByTimeAll);
            free(entry);
            entry = next;
        }
    }
    free(cache);
}

/* ──────────────────────── schema init helpers ─────────────────────────── */

/**
 * @brief Initialize the schema for the user database.
 *
 * @param dbHandle  Raw sqlite3 handle.
 * @return @c DB_SUCC on success, @c DB_FAIL on failure.
 */
static int initUserDBSchema(sqlite3 *dbHandle) {
    return execStmt(dbHandle, SQL_CREATE_USERS_TABLE, "CREATE TABLE users");
}

/**
 * @brief Initialize the schema for the chat history database.
 *
 * Creates only the global message sequence table. Room tables are
 * created on demand when first accessed.
 *
 * @param dbHandle  Raw sqlite3 handle.
 * @return @c DB_SUCC on success, @c DB_FAIL on failure.
 */
static int initChatHistoryDBSchema(sqlite3 *dbHandle) {
    return execStmt(dbHandle, SQL_CREATE_MSG_SEQUENCE,
                    "CREATE TABLE msg_sequence");
}

/**
 * @brief Initialize the schema for the game database.
 *
 * Creates the rooms table.
 *
 * @param dbHandle  Raw sqlite3 handle.
 * @return @c DB_SUCC on success, @c DB_FAIL on failure.
 */
static int initGameDBSchema(sqlite3 *dbHandle) {
    return execStmt(dbHandle, SQL_CREATE_ROOMS_TABLE, "CREATE TABLE rooms");
}

/**
 * @brief Initialize the schema for the server key-value database.
 *
 * Creates the server_keys table.
 *
 * @param dbHandle  Raw sqlite3 handle.
 * @return @c DB_SUCC on success, @c DB_FAIL on failure.
 */
static int initServerDBSchema(sqlite3 *dbHandle) {
    return execStmt(dbHandle, SQL_CREATE_SERVER_KEYS_TABLE,
                    "CREATE TABLE server_keys");
}

/* ──────────────────────── UserDB stmt preparation ─────────────────────── */

/**
 * @brief Prepare and cache the recurring statements for a UserDB handle.
 *
 * @param database  The DB handle to populate.
 * @return @c DB_SUCC on success, @c DB_FAIL on failure.
 */
static int prepareUserStmts(DB *database) {
    int rc;

    rc = sqlite3_prepare_v2(database->handle, SQL_INSERT_USER, -1,
                            &database->stmtInsert, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareUserStmts: INSERT prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_prepare_v2(database->handle, SQL_DELETE_USER, -1,
                            &database->stmtDelete, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareUserStmts: DELETE prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_prepare_v2(database->handle, SQL_SELECT_USER_PASSWORD, -1,
                            &database->stmtSelect, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareUserStmts: SELECT prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_prepare_v2(database->handle, SQL_UID_CHECK, -1,
                            &database->stmtUidCheck, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareUserStmts: UID check prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_prepare_v2(database->handle, SQL_SET_TOTP_SECRET, -1,
                            &database->stmtSetTotpSecret, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareUserStmts: SET totp_secret prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_prepare_v2(database->handle, SQL_SELECT_TOTP_BY_UID, -1,
                            &database->stmtGetTOTPSecret, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareUserStmts: SELECT totp_secret prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    return DB_SUCC;
}

/* ──────────────────────── ChatHistoryDB stmt preparation ─────────────── */

/**
 * @brief Prepare the global sequence statement for ChatHistoryDB.
 *
 * @param database  The DB handle to populate.
 * @return @c DB_SUCC on success, @c DB_FAIL on failure.
 */
static int prepareChatGlobalStmts(DB *database) {
    int rc = sqlite3_prepare_v2(database->handle, SQL_INSERT_SEQUENCE, -1,
                                &database->stmtSeq, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareChatGlobalStmts: sequence prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    return DB_SUCC;
}

/* ──────────────────────── GameDB stmt preparation ──────────────────────── */

/**
 * @brief Prepare the cached statements for a GameDB handle.
 *
 * @param database  The DB handle to populate.
 * @return @c DB_SUCC on success, @c DB_FAIL on failure.
 */
static int prepareGameDBStmts(DB *database) {
    int rc;

    rc = sqlite3_prepare_v2(database->handle, SQL_INSERT_ROOM, -1,
                            &database->stmtInsert, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareGameDBStmts: INSERT prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_prepare_v2(database->handle, SQL_DELETE_ROOM, -1,
                            &database->stmtDelete, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareGameDBStmts: DELETE prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_prepare_v2(database->handle, SQL_LIST_ROOMS, -1,
                            &database->stmtSelect, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareGameDBStmts: SELECT prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_prepare_v2(database->handle, SQL_EXISTS_ROOM, -1,
                            &database->stmtRoomExists, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareGameDBStmts: EXISTS prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    return DB_SUCC;
}

/* ──────────────────────── ServerDB stmt preparation ────────────────────── */

/**
 * @brief Prepare the cached statements for a ServerDB handle.
 *
 * @param database  The DB handle to populate.
 * @return @c DB_SUCC on success, @c DB_FAIL on failure.
 */
static int prepareServerDBStmts(DB *database) {
    int rc;

    rc = sqlite3_prepare_v2(database->handle, SQL_UPSERT_SERVER_KEY, -1,
                            &database->stmtSetKey, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareServerDBStmts: UPSERT prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_prepare_v2(database->handle, SQL_SELECT_SERVER_KEY, -1,
                            &database->stmtGetKey, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareServerDBStmts: SELECT prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    return DB_SUCC;
}

/* ──────────────────────── public API: lifecycle ───────────────────────── */

DB *dbInit(DBType dbType) {
    const char *dbPath = NULL;

    switch (dbType) {
    case UserDB:
        dbPath = USER_DB_PATH;
        break;
    case ChatHistoryDB:
        dbPath = CHAT_HISTORY_DB_PATH;
        break;
    case GameDB:
        dbPath = GAME_DB_PATH;
        break;
    case ServerDB:
        dbPath = SERVER_DB_PATH;
        break;
    default:
        LOG_ERROR("dbInit: unknown DBType %d", (int)dbType);
        return NULL;
    }

    /* Ensure the parent directory exists */
    if (ensureDBDirectoryExists() != DB_SUCC) {
        return NULL;
    }

    /* Allocate the wrapper struct */
    DB *database = calloc(1, sizeof(DB));
    if (database == NULL) {
        LOG_ERROR("dbInit: calloc failed (errno=%d)", errno);
        return NULL;
    }
    database->type = dbType;

    /* Open (or create) the database file */
    int rc = sqlite3_open(dbPath, &database->handle);
    if (rc != SQLITE_OK) {
        LOG_ERROR("dbInit: sqlite3_open('%s') failed: %s (rc=%d)", dbPath,
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_close(database->handle);
        free(database);
        return NULL;
    }

    /* Enable WAL mode for better concurrent read performance */
    if (execStmt(database->handle, "PRAGMA journal_mode=WAL;",
                 "PRAGMA journal_mode") != DB_SUCC) {
        LOG_WARN("dbInit: WAL mode not enabled, continuing with default");
    }

    /* Enable foreign key enforcement */
    if (execStmt(database->handle, "PRAGMA foreign_keys=ON;",
                 "PRAGMA foreign_keys") != DB_SUCC) {
        LOG_WARN("dbInit: foreign_keys not enabled, continuing");
    }

    /* Initialize the appropriate schema */
    int schemaResult = DB_FAIL;
    switch (dbType) {
    case UserDB:
        schemaResult = initUserDBSchema(database->handle);
        break;
    case ChatHistoryDB:
        schemaResult = initChatHistoryDBSchema(database->handle);
        break;
    case GameDB:
        schemaResult = initGameDBSchema(database->handle);
        break;
    case ServerDB:
        schemaResult = initServerDBSchema(database->handle);
        break;
    default:
        break;
    }

    if (schemaResult != DB_SUCC) {
        LOG_ERROR("dbInit: schema initialization failed for '%s'", dbPath);
        sqlite3_close(database->handle);
        free(database);
        return NULL;
    }

    /* Prepare cached statements for this database type */
    int stmtResult = DB_FAIL;
    switch (dbType) {
    case UserDB:
        stmtResult = prepareUserStmts(database);
        break;
    case ChatHistoryDB:
        stmtResult = prepareChatGlobalStmts(database);
        if (stmtResult == DB_SUCC) {
            /* Allocate the room statement cache */
            database->roomCache = calloc(1, sizeof(RoomStmtCache));
            if (database->roomCache == NULL) {
                LOG_ERROR("dbInit: roomCache calloc failed (errno=%d)", errno);
                stmtResult = DB_FAIL;
            }
        }
        break;
    case GameDB:
        stmtResult = prepareGameDBStmts(database);
        break;
    case ServerDB:
        stmtResult = prepareServerDBStmts(database);
        break;
    default:
        break;
    }

    if (stmtResult != DB_SUCC) {
        LOG_ERROR("dbInit: statement preparation failed for '%s'", dbPath);
        finalizeStmt(&database->stmtInsert);
        finalizeStmt(&database->stmtDelete);
        finalizeStmt(&database->stmtSelect);
        finalizeStmt(&database->stmtRoomExists);
        finalizeStmt(&database->stmtUidCheck);
        finalizeStmt(&database->stmtSetTotpSecret);
        finalizeStmt(&database->stmtGetTOTPSecret);
        finalizeStmt(&database->stmtSetKey);
        finalizeStmt(&database->stmtGetKey);
        finalizeStmt(&database->stmtSeq);
        roomCacheDestroy(database->roomCache);
        sqlite3_close(database->handle);
        free(database);
        return NULL;
    }

    LOG_INFO("dbInit: database '%s' opened successfully", dbPath);
    return database;
}

void dbClose(DB *database) {
    if (database == NULL) {
        return;
    }

    /* Finalize UserDB cached statements */
    finalizeStmt(&database->stmtInsert);
    finalizeStmt(&database->stmtDelete);
    finalizeStmt(&database->stmtSelect);
    finalizeStmt(&database->stmtRoomExists);
    finalizeStmt(&database->stmtUidCheck);
    finalizeStmt(&database->stmtSetTotpSecret);
    finalizeStmt(&database->stmtGetTOTPSecret);

    /* Finalize ServerDB cached statements */
    finalizeStmt(&database->stmtSetKey);
    finalizeStmt(&database->stmtGetKey);

    /* Finalize ChatHistoryDB cached statements */
    finalizeStmt(&database->stmtSeq);
    roomCacheDestroy(database->roomCache);

    /* Close the sqlite3 connection */
    int rc = sqlite3_close(database->handle);
    if (rc != SQLITE_OK) {
        LOG_ERROR("dbClose: sqlite3_close failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
    }

    OPENSSL_cleanse(database->dekKey, sizeof(database->dekKey));
    free(database);
}

/* ──────────────────────── public API: user operations ─────────────────── */

static uint8_t *encryptTOTP(const char *secret, const uint8_t *dekKey,
                            size_t *outLen);
static char *decryptTOTP(const uint8_t *blob, size_t blobLen,
                         const uint8_t *dekKey);

int createUser(DB *database, User *user) {
    if (database == NULL || user == NULL) {
        LOG_ERROR("createUser: NULL argument (database=%p, user=%p)",
                  (void *)database, (void *)user);
        return DB_FAIL;
    }
    if (database->type != UserDB) {
        LOG_ERROR("createUser: wrong database type %d (expected UserDB)",
                  (int)database->type);
        return DB_FAIL;
    }
    if (user->password == NULL || user->password[0] == '\0') {
        LOG_ERROR("createUser: password is NULL or empty");
        return DB_FAIL;
    }
    if (user->username[0] == '\0') {
        LOG_ERROR("createUser: username is empty");
        return DB_FAIL;
    }
    if (user->nickname[0] == '\0') {
        LOG_ERROR("createUser: nickname is empty");
        return DB_FAIL;
    }

    /* Generate a unique random uid.  Loop with a hard limit to prevent
     * theoretical infinite spinning when the ID space is nearly exhausted. */
    enum { MaxAttempts = 10 };
    int found = 0;
    for (int attempt = 0; attempt < MaxAttempts; attempt++) {
        uint32_t candidate = 0;
        /* RAND_bytes is cryptographically strong and seeded by the OS. */
        if (RAND_bytes((unsigned char *)&candidate, (int)sizeof(candidate)) !=
            1) {
            LOG_ERROR("createUser: RAND_bytes failed on attempt %d", attempt);
            continue;
        }
        /* uid 0 is reserved for the "no user" sentinel. */
        if (candidate == 0) {
            continue;
        }

        sqlite3_stmt *checkStmt = database->stmtUidCheck;
        sqlite3_reset(checkStmt);
        sqlite3_clear_bindings(checkStmt);
        int rc = sqlite3_bind_int64(checkStmt, 1, (sqlite3_int64)candidate);
        if (rc != SQLITE_OK) {
            LOG_ERROR("createUser: bind uid check failed: %s (rc=%d)",
                      sqlite3_errmsg(database->handle), rc);
            continue;
        }
        rc = sqlite3_step(checkStmt);
        if (rc == SQLITE_DONE) {
            /* No row returned — uid is unique. */
            user->uid = candidate;
            found = 1;
            break;
        }
        if (rc != SQLITE_ROW) {
            LOG_ERROR("createUser: uid check step failed: %s (rc=%d)",
                      sqlite3_errmsg(database->handle), rc);
        }
        /* UID collision — loop and try another random value. */
    }

    if (!found) {
        LOG_ERROR("createUser: failed to generate unique uid after %d attempts",
                  MaxAttempts);
        return DB_FAIL;
    }

    /* Hash the plaintext password for secure storage */
    char *hashed = hashPassword(user->password);
    if (hashed == NULL) {
        LOG_ERROR("createUser: hashPassword failed");
        return DB_FAIL;
    }

    sqlite3_stmt *stmt = database->stmtInsert;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    int rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)user->uid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("createUser: bind uid failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        OPENSSL_cleanse(hashed, strlen(hashed));
        free(hashed);
        return DB_FAIL;
    }

    rc = sqlite3_bind_text(stmt, 2, user->username, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        LOG_ERROR("createUser: bind username failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        OPENSSL_cleanse(hashed, strlen(hashed));
        free(hashed);
        return DB_FAIL;
    }

    rc = sqlite3_bind_text(stmt, 3, user->nickname, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        LOG_ERROR("createUser: bind nickname failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        OPENSSL_cleanse(hashed, strlen(hashed));
        free(hashed);
        return DB_FAIL;
    }

    rc = sqlite3_bind_text(stmt, 4, hashed, -1, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
        LOG_ERROR("createUser: bind password failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        OPENSSL_cleanse(hashed, strlen(hashed));
        free(hashed);
        return DB_FAIL;
    }

    enum { TotpBindIndex = 5 };
    if (user->totpSecret != NULL) {
        size_t encLen = 0;
        uint8_t *enc = encryptTOTP(user->totpSecret, database->dekKey, &encLen);
        if (enc == NULL) {
            OPENSSL_cleanse(hashed, strlen(hashed));
            free(hashed);
            return DB_FAIL;
        }
        rc = sqlite3_bind_blob(stmt, TotpBindIndex, enc, (int)encLen, free);
    } else {
        rc = sqlite3_bind_null(stmt, TotpBindIndex);
    }
    if (rc != SQLITE_OK) {
        LOG_ERROR("createUser: bind totp_secret failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        OPENSSL_cleanse(hashed, strlen(hashed));
        free(hashed);
        return DB_FAIL;
    }

    rc = sqlite3_step(stmt);

    /* Securely wipe the hashed password from memory */
    OPENSSL_cleanse(hashed, strlen(hashed));
    free(hashed);

    if (rc != SQLITE_DONE) {
        LOG_ERROR("createUser: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    return DB_SUCC;
}

int deleteUser(DB *database, User *user) {
    if (database == NULL || user == NULL) {
        LOG_ERROR("deleteUser: NULL argument (database=%p, user=%p)",
                  (void *)database, (void *)user);
        return DB_FAIL;
    }
    if (database->type != UserDB) {
        LOG_ERROR("deleteUser: wrong database type %d (expected UserDB)",
                  (int)database->type);
        return DB_FAIL;
    }

    sqlite3_stmt *stmt = database->stmtDelete;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    int rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)user->uid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("deleteUser: bind uid failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        LOG_ERROR("deleteUser: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    /* Strict mode: fail if no rows were affected */
    if (sqlite3_changes(database->handle) == 0) {
        LOG_WARN("deleteUser: uid %u not found in database", user->uid);
        return DB_FAIL;
    }

    return DB_SUCC;
}

int verifyUser(DB *database, User *user) {
    if (database == NULL || user == NULL) {
        LOG_ERROR("verifyUser: NULL argument (database=%p, user=%p)",
                  (void *)database, (void *)user);
        return DB_FAIL;
    }
    if (database->type != UserDB) {
        LOG_ERROR("verifyUser: wrong database type %d (expected UserDB)",
                  (int)database->type);
        return DB_FAIL;
    }
    if (user->password == NULL || user->password[0] == '\0') {
        LOG_ERROR("verifyUser: password is NULL or empty");
        return DB_FAIL;
    }
    if (user->username[0] == '\0') {
        LOG_ERROR("verifyUser: username is empty");
        return DB_FAIL;
    }

    sqlite3_stmt *stmt = database->stmtSelect;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    /* Look up by username only — UID is server-assigned and the client
     * does not know it before a successful login. */
    int rc = sqlite3_bind_text(stmt, 1, user->username, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        LOG_ERROR("verifyUser: bind username failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        if (rc != SQLITE_DONE) {
            LOG_ERROR("verifyUser: step failed: %s (rc=%d)",
                      sqlite3_errmsg(database->handle), rc);
        }
        return DB_FAIL;
    }

    /* Columns: 0=uid, 1=nickname, 2=password, 3=totp_secret */
    user->uid = (uint32_t)sqlite3_column_int64(stmt, 0);

    const char *storedNickname = (const char *)sqlite3_column_text(stmt, 1);
    if (storedNickname == NULL) {
        LOG_ERROR("verifyUser: stored nickname is NULL");
        return DB_FAIL;
    }

    const char *storedHash = (const char *)sqlite3_column_text(stmt, 2);
    if (storedHash == NULL) {
        LOG_ERROR("verifyUser: stored password hash is NULL");
        return DB_FAIL;
    }

    int result = verifyPassword(user->password, storedHash);
    if (result != CRYPTO_SUCC) {
        return DB_FAIL;
    }

    const void *storedTotpBlob = sqlite3_column_blob(stmt, 3);
    int storedTotpLen = sqlite3_column_bytes(stmt, 3);
    if (storedTotpBlob != NULL && storedTotpLen > 0) {
        user->totpSecret =
            decryptTOTP((const uint8_t *)storedTotpBlob,
                        (size_t)storedTotpLen, database->dekKey);
        if (user->totpSecret == NULL) {
            return DB_FAIL;
        }
    } else {
        user->totpSecret = NULL;
    }

    memcpy(user->nickname, storedNickname, NICKNAME_MAX_LEN);
    return DB_SUCC;
}

/* ──────────── TOTP secret AES-256-GCM envelope helpers ─────────────────── */

/**
 * @brief Encrypt a TOTP secret with the DEK via AES-256-GCM.
 *
 * Returns a heap-allocated BLOB in the format
 * @c nonce(12) @c || @c ciphertext(n) @c || @c tag(16).
 * The caller must @c free() the returned pointer.
 *
 * @param secret   Null-terminated plaintext secret.
 * @param dekKey   Pointer to 32-byte DEK.
 * @param outLen   Receives the total encrypted blob length.
 * @return Heap-allocated encrypted blob, or NULL on failure.
 */
static uint8_t *encryptTOTP(const char *secret, const uint8_t *dekKey,
                            size_t *outLen) {
    size_t ptLen = strlen(secret);
    AESGCMKey key;
    memcpy(key.key, dekKey, AES_GCM_KEY_LEN);
    if (cryptoRandomBytes(key.nonce, AES_GCM_NONCE_LEN) != CRYPTO_SUCC) {
        LOG_ERROR("encryptTOTP: nonce generation failed");
        return NULL;
    }

    AESGCMBuffer pt = {.data = (uint8_t *)(uintptr_t)secret,
                        .len = ptLen,
                        .capacity = ptLen};
    AESGCMCipher ct;
    if (aesGCMBufferInit(&ct.buffer, ptLen) != CRYPTO_SUCC) {
        return NULL;
    }

    if (encryptAESGCM(&pt, NULL, &key, &ct) != CRYPTO_SUCC) {
        LOG_ERROR("encryptTOTP: encryption failed");
        aesGCMBufferDeinit(&ct.buffer);
        return NULL;
    }

    size_t total = AES_GCM_NONCE_LEN + ptLen + AES_GCM_TAG_LEN;
    uint8_t *blob = malloc(total);
    if (blob == NULL) {
        LOG_ERROR("encryptTOTP: malloc failed (errno=%d)", errno);
        aesGCMBufferDeinit(&ct.buffer);
        return NULL;
    }

    memcpy(blob, key.nonce, AES_GCM_NONCE_LEN);
    memcpy(blob + AES_GCM_NONCE_LEN, ct.buffer.data, ptLen);
    memcpy(blob + AES_GCM_NONCE_LEN + ptLen, ct.tag, AES_GCM_TAG_LEN);
    *outLen = total;

    aesGCMBufferDeinit(&ct.buffer);
    return blob;
}

/**
 * @brief Decrypt a TOTP secret envelope with the DEK.
 *
 * Parses the @c nonce @c || @c ciphertext @c || @c tag BLOB, decrypts
 * via AES-256-GCM, and returns a null-terminated plaintext string.
 * The caller must @c free() the returned pointer.
 *
 * @param blob      Encrypted BLOB (nonce + CT + tag).
 * @param blobLen   Total length of @p blob.
 * @param dekKey    Pointer to 32-byte DEK.
 * @return Heap-allocated plaintext TOTP secret, or NULL on failure.
 */
static char *decryptTOTP(const uint8_t *blob, size_t blobLen,
                         const uint8_t *dekKey) {
    if (blobLen < AES_GCM_NONCE_LEN + AES_GCM_TAG_LEN) {
        LOG_ERROR("decryptTOTP: blob too short (%zu bytes)", blobLen);
        return NULL;
    }

    size_t ctLen = blobLen - AES_GCM_NONCE_LEN - AES_GCM_TAG_LEN;
    AESGCMKey key;
    memcpy(key.key, dekKey, AES_GCM_KEY_LEN);
    memcpy(key.nonce, blob, AES_GCM_NONCE_LEN);

    AESGCMCipher ct;
    ct.buffer.data = (uint8_t *)(uintptr_t)(blob + AES_GCM_NONCE_LEN);
    ct.buffer.len = ctLen;
    ct.buffer.capacity = ctLen;
    memcpy(ct.tag, blob + AES_GCM_NONCE_LEN + ctLen, AES_GCM_TAG_LEN);

    AESGCMBuffer pt;
    if (aesGCMBufferInit(&pt, ctLen) != CRYPTO_SUCC) {
        return NULL;
    }

    int ret = decryptAESGCM(&ct, NULL, &key, &pt);
    if (ret != CRYPTO_SUCC) {
        aesGCMBufferDeinit(&pt);
        if (ret == CRYPTO_AUTH_FAIL) {
            LOG_ERROR("decryptTOTP: authentication failed — wrong DEK?");
        }
        return NULL;
    }

    char *result = malloc(pt.len + 1);
    if (result == NULL) {
        LOG_ERROR("decryptTOTP: malloc failed (errno=%d)", errno);
        aesGCMBufferDeinit(&pt);
        return NULL;
    }
    memcpy(result, pt.data, pt.len);
    result[pt.len] = '\0';
    aesGCMBufferDeinit(&pt);
    return result;
}

/* ──────────────────────── public API: set/TOTP operations ─────────────── */

void dbSetDekKey(DB *database, const uint8_t *dekKey) {
    if (database == NULL) {
        return;
    }
    if (dekKey != NULL) {
        memcpy(database->dekKey, dekKey, AES_GCM_KEY_LEN);
    } else {
        memset(database->dekKey, 0, sizeof(database->dekKey));
    }
}

/**
 * @brief Read and decrypt the TOTP secret for a user.
 *
 * @param database  UserDB handle with DEK set.
 * @param user      User whose @c uid identifies the row.
 * @return Heap-allocated plaintext Base32 secret, or NULL.
 */
char *getTOTPSecret(DB *database, User *user) {
    sqlite3_stmt *stmt = database->stmtGetTOTPSecret;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    int rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)user->uid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("getTOTPSecret: bind uid failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return NULL;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE) {
        return NULL;
    }
    if (rc != SQLITE_ROW) {
        return NULL;
    }

    const void *blobData = sqlite3_column_blob(stmt, 0);
    int blobLen = sqlite3_column_bytes(stmt, 0);
    if (blobData == NULL || blobLen == 0) {
        return NULL;
    }

    return decryptTOTP((const uint8_t *)blobData, (size_t)blobLen,
                       database->dekKey);
}

int setTOTPSecret(DB *database, User *user, const char *secret) {
    if (database == NULL || user == NULL) {
        LOG_ERROR("setTOTPSecret: NULL argument (database=%p, user=%p)",
                  (void *)database, (void *)user);
        return DB_FAIL;
    }
    if (database->type != UserDB) {
        LOG_ERROR("setTOTPSecret: wrong database type %d (expected UserDB)",
                  (int)database->type);
        return DB_FAIL;
    }

    sqlite3_stmt *stmt = database->stmtSetTotpSecret;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    int rc;
    if (secret != NULL && secret[0] != '\0') {
        size_t encLen = 0;
        uint8_t *enc = encryptTOTP(secret, database->dekKey, &encLen);
        if (enc == NULL) {
            return DB_FAIL;
        }
        rc = sqlite3_bind_blob(stmt, 1, enc, (int)encLen, free);
    } else {
        rc = sqlite3_bind_null(stmt, 1);
    }
    if (rc != SQLITE_OK) {
        LOG_ERROR("setTOTPSecret: bind secret failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 2, (sqlite3_int64)user->uid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("setTOTPSecret: bind uid failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        LOG_ERROR("setTOTPSecret: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    if (sqlite3_changes(database->handle) == 0) {
        LOG_WARN("setTOTPSecret: uid %u not found in database", user->uid);
        return DB_FAIL;
    }

    return DB_SUCC;
}

/* ──────────────────────── public API: set TOTP secret ─────────────────── */

int setTotpSecret(DB *database, User *user, const char *secret) {
    if (database == NULL || user == NULL) {
        LOG_ERROR("setTotpSecret: NULL argument (database=%p, user=%p)",
                  (void *)database, (void *)user);
        return DB_FAIL;
    }
    if (database->type != UserDB) {
        LOG_ERROR("setTotpSecret: wrong database type %d (expected UserDB)",
                  (int)database->type);
        return DB_FAIL;
    }

    sqlite3_stmt *stmt = database->stmtSetTotpSecret;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    /* ?1 = totp_secret (text or NULL) */
    int rc;
    if (secret != NULL && secret[0] != '\0') {
        rc = sqlite3_bind_text(stmt, 1, secret, -1, SQLITE_STATIC);
    } else {
        rc = sqlite3_bind_null(stmt, 1);
    }
    if (rc != SQLITE_OK) {
        LOG_ERROR("setTotpSecret: bind secret failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    /* ?2 = uid */
    rc = sqlite3_bind_int64(stmt, 2, (sqlite3_int64)user->uid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("setTotpSecret: bind uid failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        LOG_ERROR("setTotpSecret: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    if (sqlite3_changes(database->handle) == 0) {
        LOG_WARN("setTotpSecret: uid %u not found in database", user->uid);
        return DB_FAIL;
    }

    return DB_SUCC;
}

/* ──────────────────────── public API: server keys ─────────────────────── */

int setServerKey(DB *database, const char *keyName, const uint8_t *value,
                 size_t valueLen) {
    if (database == NULL || keyName == NULL) {
        LOG_ERROR("setServerKey: NULL argument (database=%p, keyName=%p)",
                  (void *)database, (const void *)keyName);
        return DB_FAIL;
    }
    if (keyName[0] == '\0') {
        LOG_ERROR("setServerKey: keyName is empty");
        return DB_FAIL;
    }
    if (database->type != ServerDB) {
        LOG_ERROR("setServerKey: wrong database type %d (expected ServerDB)",
                  (int)database->type);
        return DB_FAIL;
    }
    if (valueLen > 0 && value == NULL) {
        LOG_ERROR("setServerKey: value is NULL with positive valueLen (%zu)",
                  valueLen);
        return DB_FAIL;
    }

    sqlite3_stmt *stmt = database->stmtSetKey;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    int rc =
        sqlite3_bind_text(stmt, 1, keyName, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        LOG_ERROR("setServerKey: bind key_name failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    if (valueLen > 0) {
        rc = sqlite3_bind_blob(stmt, 2, value, (int)valueLen, SQLITE_STATIC);
    } else {
        rc = sqlite3_bind_zeroblob(stmt, 2, 0);
    }
    if (rc != SQLITE_OK) {
        LOG_ERROR("setServerKey: bind key_value failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 3, (sqlite3_int64)time(NULL));
    if (rc != SQLITE_OK) {
        LOG_ERROR("setServerKey: bind created_at failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        LOG_ERROR("setServerKey: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    return DB_SUCC;
}

int getServerKey(DB *database, const char *keyName, uint8_t **outValue,
                 size_t *outLen) {
    *outValue = NULL;
    *outLen = 0;

    if (database == NULL || keyName == NULL || outValue == NULL ||
        outLen == NULL) {
        LOG_ERROR("getServerKey: NULL argument "
                  "(database=%p, keyName=%p, outValue=%p, outLen=%p)",
                  (void *)database, (const void *)keyName, (void *)outValue,
                  (void *)outLen);
        return DB_FAIL;
    }
    if (keyName[0] == '\0') {
        LOG_ERROR("getServerKey: keyName is empty");
        return DB_FAIL;
    }
    if (database->type != ServerDB) {
        LOG_ERROR("getServerKey: wrong database type %d (expected ServerDB)",
                  (int)database->type);
        return DB_FAIL;
    }

    sqlite3_stmt *stmt = database->stmtGetKey;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    int rc =
        sqlite3_bind_text(stmt, 1, keyName, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        LOG_ERROR("getServerKey: bind key_name failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE) {
        /* Key not found — not an error, output stays NULL/0 */
        return DB_SUCC;
    }
    if (rc != SQLITE_ROW) {
        LOG_ERROR("getServerKey: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    /* Column 0 = key_value (BLOB) */
    int blobLen = sqlite3_column_bytes(stmt, 0);
    const void *blobData = sqlite3_column_blob(stmt, 0);

    if (blobLen > 0) {
        uint8_t *copy = malloc((size_t)blobLen);
        if (copy == NULL) {
            LOG_ERROR("getServerKey: malloc failed (errno=%d)", errno);
            return DB_FAIL;
        }
        if (blobData != NULL) {
            memcpy(copy, blobData, (size_t)blobLen);
        }
        *outValue = copy;
        *outLen = (size_t)blobLen;
    }

    return DB_SUCC;
}

/* ──────────────────────── public API: chat history ────────────────────── */

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
        LOG_ERROR(
            "storeChat: wrong database type %d (expected ChatHistoryDB)",
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
int queryChatByMsgId(DB *database, uint32_t roomId, uint64_t msgId,
                     Chat *out) {
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
            Chat *tmp =
                realloc(results, newCapacity * sizeof(Chat));
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

/* ──────────────────────── queryChatByUserAllRooms ─────────────────────── */

/** @brief SQL to discover all room tables from the schema. */
#define SQL_SELECT_ROOM_TABLES                                                 \
    "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE "         \
    "'room_%';"

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
                              time_t startTime, time_t endTime,
                              Chat **results, size_t *n,
                              size_t *capacity) {
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
            Chat *tmp =
                realloc(*results, newCapacity * sizeof(Chat));
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

/* ──────────────────────── public API: game (room) operations ──────────── */

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
int createRoom(DB *database, uint32_t roomId, uint32_t creatorUid) {
    if (database == NULL) {
        LOG_ERROR("createRoom: NULL database");
        return DB_FAIL;
    }
    if (database->type != GameDB) {
        LOG_ERROR("createRoom: wrong database type %d (expected GameDB)",
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
    if (database->type != GameDB) {
        LOG_ERROR("deleteRoom: wrong database type %d (expected GameDB)",
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
    if (database->type != GameDB) {
        LOG_ERROR("listRooms: wrong database type %d (expected GameDB)",
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
            uint32_t *tmp =
                realloc(results, newCapacity * sizeof(uint32_t));
            if (tmp == NULL) {
                LOG_ERROR("listRooms: realloc failed (errno=%d)", errno);
                free(results);
                return DB_FAIL;
            }
            results = tmp;
            capacity = newCapacity;
        }

        results[n] = (uint32_t)sqlite3_column_int(stmt, 0);
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
    if (database->type != GameDB) {
        LOG_ERROR("roomExists: wrong database type %d (expected GameDB)",
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
