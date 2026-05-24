/**
 * @file database.h
 * @brief Database abstraction layer for PacPlay server (SQLite3).
 *
 * Provides initialization, teardown, and CRUD operations for the user
 * database and chat history database. Each database is stored as a
 * separate SQLite3 file under the "db/" directory.
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

#ifndef SERVER_DATABASE_H
#define SERVER_DATABASE_H

#include <stdint.h>
#include <time.h>

#include <sqlite3.h>

/* ──────────────────────── constants ────────────────────────────────────── */

/** @brief File path for the user database. */
#define USER_DB_PATH "db/user.db"

/** @brief File path for the chat history database. */
#define CHAT_HISTORY_DB_PATH "db/chatHistory.db"

/** @brief Directory containing all database files. */
#define DB_DIRECTORY "db"

/** @brief Maximum username length (including NUL terminator). */
#define DB_USERNAME_MAX_LEN 32

/* ──────────────────────── return codes ─────────────────────────────────── */

#define DB_SUCC (0)
#define DB_FAIL (-1)

/* ──────────────────────── types ────────────────────────────────────────── */

/** @brief Identifies which database to open. */
typedef enum { UserDB = 1, ChatHistoryDB } DBType;

/** @brief Represents a user record in the user database. */
typedef struct {
    char username[DB_USERNAME_MAX_LEN];
    uint32_t uid;
    char *password; /**< Plaintext password (hashed internally on storage). */
} User;

/** @brief Represents a single chat message record. */
typedef struct {
    uint32_t uid;
    uint64_t msgId; /**< Globally unique, monotonically increasing ID. */
    char *message;
    time_t timestamp; /**< UNIX timestamp (seconds since epoch, UTC). */
} ChatHistory;

/* ──────────────────────── room statement cache ────────────────────────── */

/** @brief Number of hash buckets for the room statement cache. */
#define ROOM_STMT_BUCKETS 32

/**
 * @brief Cached prepared statements for a single room table.
 *
 * Each room (identified by roomId) has its own set of pre-compiled
 * statements for INSERT, SELECT-by-id, and SELECT-by-time-range queries.
 * Entries are chained in a hash table bucket.
 */
typedef struct RoomStmtEntry {
    uint32_t roomId;
    sqlite3_stmt *stmtInsert;          /**< INSERT into room table. */
    sqlite3_stmt *stmtSelectById;      /**< SELECT by msgId. */
    sqlite3_stmt *stmtSelectByTimeUid; /**< SELECT by time range + uid. */
    sqlite3_stmt *stmtSelectByTimeAll; /**< SELECT by time range (all uids). */
    struct RoomStmtEntry *next;        /**< Next entry in hash chain. */
} RoomStmtEntry;

/**
 * @brief Hash table mapping roomId to cached prepared statements.
 *
 * Used by ChatHistoryDB handles to avoid re-preparing SQL statements
 * for frequently accessed rooms. Finalized entirely in dbClose().
 */
typedef struct {
    RoomStmtEntry *buckets[ROOM_STMT_BUCKETS];
} RoomStmtCache;

/* ──────────────────────── database handle ─────────────────────────────── */

/**
 * @brief Database handle wrapping sqlite3 and cached prepared statements.
 *
 * For UserDB: uses the fixed stmtInsert/stmtDelete/stmtSelect fields.
 * For ChatHistoryDB: uses roomCache (per-room hash table) and stmtSeq
 * for the global message sequence generator.
 */
typedef struct {
    sqlite3 *handle; /**< Underlying sqlite3 connection. */
    DBType type;     /**< Type of database this handle serves. */
    /* UserDB cached statements */
    sqlite3_stmt *stmtInsert; /**< Cached INSERT statement (UserDB). */
    sqlite3_stmt *stmtDelete; /**< Cached DELETE statement (UserDB). */
    sqlite3_stmt *stmtSelect; /**< Cached SELECT statement (UserDB). */
    /* ChatHistoryDB cached statements */
    sqlite3_stmt *stmtSeq; /**< Global msg sequence INSERT (ChatHistoryDB). */
    RoomStmtCache *roomCache; /**< Per-room statement cache (ChatHistoryDB). */
} DB;

/* ──────────────────────── lifecycle ────────────────────────────────────── */

/**
 * @brief Open (and optionally create) a database of the specified type.
 *
 * If the database file does not exist, it is created along with the
 * required schema (tables and indices). The parent directory "db/" is
 * created automatically if it does not exist.
 *
 * Schema for UserDB:
 *   - users(uid INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
 *           password TEXT NOT NULL)
 *
 * Schema for ChatHistoryDB:
 *   - msg_sequence(id INTEGER PRIMARY KEY AUTOINCREMENT)
 *     Provides globally unique, monotonically increasing message IDs.
 *   - Per-room tables (created on demand via storeChatHistory):
 *     room_<roomId>(msgId INTEGER PRIMARY KEY, uid INTEGER NOT NULL,
 *                   message TEXT NOT NULL, timestamp INTEGER NOT NULL)
 *
 * @param dbType  The database to open (@c UserDB or @c ChatHistoryDB).
 * @return A database handle on success, or @c NULL on failure.
 */
DB *dbInit(DBType dbType);

/**
 * @brief Close a database handle and release all associated resources.
 *
 * Safe to call with @c NULL (no-op in that case).
 *
 * @param database  The database handle to close.
 */
void dbClose(DB *database);

/* ──────────────────────── user operations ──────────────────────────────── */

/**
 * @brief Insert a new user record into the user database.
 *
 * The plaintext password in @p user->password is hashed internally via
 * @c hashPassword() before storage.  The caller retains ownership of the
 * User struct and its fields.
 *
 * @param database  An open UserDB handle.
 * @param user      User data to insert. Must not be NULL.
 * @return @c DB_SUCC on success, @c DB_FAIL on failure.
 */
int createUser(DB *database, User *user);

/**
 * @brief Delete a user record from the user database.
 *
 * @param database  An open UserDB handle.
 * @param user      User to delete (matched by uid). Must not be NULL.
 * @return @c DB_SUCC on success, @c DB_FAIL on failure.
 */
int deleteUser(DB *database, User *user);

/**
 * @brief Verify a user's credentials against the database.
 *
 * Fetches the stored password hash from the database and verifies the
 * plaintext password in @p user->password against it using
 * @c verifyPassword() (constant-time comparison with stored salt).
 *
 * @param database  An open UserDB handle.
 * @param user      User credentials to verify. @c user->password must
 *                  contain the plaintext password. Must not be NULL.
 * @return @c DB_SUCC if credentials are valid, @c DB_FAIL otherwise.
 */
int verifyUser(DB *database, User *user);

/* ──────────────────────── chat history operations ─────────────────────── */

/**
 * @brief Store a chat message into a room's table.
 *
 * Inserts a new record into the table for @p roomId. If the room table
 * does not yet exist, it is created automatically (along with indices).
 *
 * The @c msgId field of @p chatHistory is ignored on input; after a
 * successful insert, it is populated with the globally unique,
 * monotonically increasing message ID assigned by the database.
 *
 * @param database     An open ChatHistoryDB handle.
 * @param roomId       The room to store the message in.
 * @param chatHistory  Chat record to store. @c uid, @c message, and
 *                     @c timestamp must be set. Must not be NULL.
 * @return @c DB_SUCC on success, @c DB_FAIL on failure.
 */
int storeChatHistory(DB *database, uint32_t roomId, ChatHistory *chatHistory);

/**
 * @brief Query a single chat message by its globally unique message ID.
 *
 * Retrieves the message identified by @p msgId from the specified room.
 * On success, all fields of @p out are populated; @c out->message is a
 * newly allocated string that the caller must free with @c free().
 *
 * @param database  An open ChatHistoryDB handle.
 * @param roomId    The room to query.
 * @param msgId     The globally unique message ID to look up.
 * @param out       Output structure. Must not be NULL.
 * @return @c DB_SUCC on success, @c DB_FAIL if not found or on error.
 */
int queryChatByMsgId(DB *database, uint32_t roomId, uint64_t msgId,
                     ChatHistory *out);

/**
 * @brief Query chat messages within a time range, optionally filtered by uid.
 *
 * Retrieves all messages in @p roomId whose timestamp falls within
 * [@p startTime, @p endTime] (inclusive). If @p uid is 0, messages from
 * all users are returned; otherwise only messages from that uid.
 *
 * On success, @p *out is set to a newly allocated array of ChatHistory
 * records and @p *count is set to the number of results. Each entry's
 * @c message field is a separate allocation; the caller must free each
 * @c message and the array itself.
 *
 * An empty result set (no matching records) is considered success:
 * returns @c DB_SUCC with @p *count = 0 and @p *out = NULL.
 *
 * @param database   An open ChatHistoryDB handle.
 * @param roomId     The room to query.
 * @param uid        User ID filter, or 0 to query all users.
 * @param startTime  Start of the time range (inclusive).
 * @param endTime    End of the time range (inclusive).
 * @param out        Output pointer to the result array. Must not be NULL.
 * @param count      Output pointer to the result count. Must not be NULL.
 * @return @c DB_SUCC on success, @c DB_FAIL on error.
 */
int queryChatByTimeRange(DB *database, uint32_t roomId, uint32_t uid,
                         time_t startTime, time_t endTime, ChatHistory **out,
                         size_t *count);

#endif /* SERVER_DATABASE_H */
