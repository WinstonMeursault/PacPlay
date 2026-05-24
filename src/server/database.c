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

/** @brief SQL statement to create the users table. */
#define SQL_CREATE_USERS_TABLE                                                 \
    "CREATE TABLE IF NOT EXISTS users ("                                       \
    "uid INTEGER PRIMARY KEY, "                                                \
    "username TEXT UNIQUE NOT NULL, "                                          \
    "password TEXT NOT NULL"                                                   \
    ");"

/** @brief SQL to create the global message sequence table. */
#define SQL_CREATE_MSG_SEQUENCE                                                \
    "CREATE TABLE IF NOT EXISTS msg_sequence ("                                \
    "id INTEGER PRIMARY KEY AUTOINCREMENT"                                     \
    ");"

/* ──────────────────────── UserDB prepared SQL ───────────────────────────── */

/** @brief INSERT a user record. Params: ?1=uid, ?2=username, ?3=password. */
#define SQL_INSERT_USER                                                        \
    "INSERT INTO users (uid, username, password) VALUES (?, ?, ?);"

/** @brief DELETE a user by uid. Params: ?1=uid. */
#define SQL_DELETE_USER "DELETE FROM users WHERE uid = ?;"

/** @brief SELECT password by username+uid. Params: ?1=username, ?2=uid. */
#define SQL_SELECT_USER_PASSWORD                                               \
    "SELECT password FROM users WHERE username = ? AND uid = ?;"

/* ──────────────────────── ChatHistoryDB prepared SQL ────────────────────── */

/** @brief INSERT into global sequence to generate next msgId. */
#define SQL_INSERT_SEQUENCE "INSERT INTO msg_sequence DEFAULT VALUES;"

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
    default:
        break;
    }

    if (stmtResult != DB_SUCC) {
        LOG_ERROR("dbInit: statement preparation failed for '%s'", dbPath);
        finalizeStmt(&database->stmtInsert);
        finalizeStmt(&database->stmtDelete);
        finalizeStmt(&database->stmtSelect);
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

    /* Finalize ChatHistoryDB cached statements */
    finalizeStmt(&database->stmtSeq);
    roomCacheDestroy(database->roomCache);

    /* Close the sqlite3 connection */
    int rc = sqlite3_close(database->handle);
    if (rc != SQLITE_OK) {
        LOG_ERROR("dbClose: sqlite3_close failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
    }

    free(database);
}

/* ──────────────────────── public API: user operations ─────────────────── */

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
    if (user->uid == 0) {
        LOG_ERROR("createUser: uid zero is reserved");
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

    int rc = sqlite3_bind_int(stmt, 1, (int)user->uid);
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

    rc = sqlite3_bind_text(stmt, 3, hashed, -1, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
        LOG_ERROR("createUser: bind password failed: %s (rc=%d)",
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

    int rc = sqlite3_bind_int(stmt, 1, (int)user->uid);
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

    int rc = sqlite3_bind_text(stmt, 1, user->username, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        LOG_ERROR("verifyUser: bind username failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int(stmt, 2, (int)user->uid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("verifyUser: bind uid failed: %s (rc=%d)",
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

    const char *storedHash = (const char *)sqlite3_column_text(stmt, 0);
    if (storedHash == NULL) {
        LOG_ERROR("verifyUser: stored password hash is NULL");
        return DB_FAIL;
    }

    int result = verifyPassword(user->password, storedHash);

    return (result == CRYPTO_SUCC) ? DB_SUCC : DB_FAIL;
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

int storeChatHistory(DB *database, uint32_t roomId, ChatHistory *chatHistory) {
    if (database == NULL || chatHistory == NULL) {
        LOG_ERROR("storeChatHistory: NULL argument (database=%p, chat=%p)",
                  (void *)database, (void *)chatHistory);
        return DB_FAIL;
    }
    if (database->type != ChatHistoryDB) {
        LOG_ERROR(
            "storeChatHistory: wrong database type %d (expected ChatHistoryDB)",
            (int)database->type);
        return DB_FAIL;
    }
    if (chatHistory->message == NULL || chatHistory->message[0] == '\0') {
        LOG_ERROR("storeChatHistory: message is NULL or empty");
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
        LOG_ERROR("storeChatHistory: bind msgId failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int(stmt, 2, (int)chatHistory->uid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("storeChatHistory: bind uid failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_bind_text(stmt, 3, chatHistory->message, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        LOG_ERROR("storeChatHistory: bind message failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 4, (sqlite3_int64)chatHistory->timestamp);
    if (rc != SQLITE_OK) {
        LOG_ERROR("storeChatHistory: bind timestamp failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        LOG_ERROR("storeChatHistory: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    /* Populate the generated msgId back into the caller's struct */
    chatHistory->msgId = msgId;
    return DB_SUCC;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
int queryChatByMsgId(DB *database, uint32_t roomId, uint64_t msgId,
                     ChatHistory *out) {
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
                         time_t startTime, time_t endTime, ChatHistory **out,
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

        int rc = sqlite3_bind_int(stmt, 1, (int)uid);
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
    ChatHistory *results = malloc(capacity * sizeof(ChatHistory));
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
            ChatHistory *tmp =
                realloc(results, newCapacity * sizeof(ChatHistory));
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
