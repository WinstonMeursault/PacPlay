/**
 * @file database.h
 * @brief Database abstraction layer for PacPlay server (SQLite3/SQLCipher).
 *
 * Provides initialization, teardown, and CRUD operations for user,
 * chat history, game (room), and server key-value databases. Each
 * database is stored as a separate encrypted SQLCipher file under the
 * "db/" directory.
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

#include "server.h"

/* ─────────────────────────────── constants ──────────────────────────────── */

/** @brief File path for the user database. */
#define USER_DB_PATH "./db/user.db"

/** @brief File path for the chat history database. */
#define CHAT_HISTORY_DB_PATH "./db/chatHistory.db"

/** @brief File path for the game database. */
#define GAME_DB_PATH "./db/game.db"

/** @brief File path for the server key-value database. */
#define SERVER_DB_PATH "./db/server.db"

/** @brief Directory containing all database files. */
#define DB_DIRECTORY "./db"

/* ────────────────────────────── return codes ────────────────────────────── */

#define DB_SUCC (0)
#define DB_FAIL (-1)

/* ───────────────────────────────── types ────────────────────────────────── */

/** @brief Identifies which database to open. */
typedef enum { UserDB = 1, ChatHistoryDB, GameDB, ServerDB } DBType;

/* ────────────────────────── room statement cache ────────────────────────── */

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

/* ──────────────────────────── database handle ───────────────────────────── */

/**
 * @brief Database handle wrapping sqlite3 and cached prepared statements.
 *
 * For UserDB: uses the fixed stmtInsert/stmtDelete/stmtSelect fields.
 * For ChatHistoryDB: uses roomCache (per-room hash table) and stmtSeq
 * for the global message sequence generator.
 */
typedef struct DB {
    sqlite3 *handle; /**< Underlying sqlite3 connection. */
    DBType type;     /**< Type of database this handle serves. */
    /* UserDB cached statements */
    sqlite3_stmt *stmtInsert; /**< Cached INSERT statement (UserDB / GameDB). */
    sqlite3_stmt *stmtDelete; /**< Cached DELETE statement (UserDB / GameDB). */
    sqlite3_stmt *stmtSelect; /**< Cached SELECT statement (UserDB / GameDB). */
    sqlite3_stmt *stmtRoomExists; /**< cached SELECT 1 FROM rooms WHERE roomId=?
                                     (GameDB). */
    sqlite3_stmt
        *stmtUidCheck; /**< Cached SELECT 1 FROM users WHERE uid=? (UserDB). */
    sqlite3_stmt *stmtSetTotpSecret; /**< Cached UPDATE totp_secret (UserDB). */
    sqlite3_stmt *stmtGetTOTPSecret; /**< Cached SELECT totp_secret (UserDB). */
    sqlite3_stmt
        *stmtGetCDBKey; /**< Cached SELECT cdbkey WHERE uid=? (UserDB). */
    /* ChatHistoryDB cached statements */
    sqlite3_stmt *stmtSeq; /**< Global msg sequence INSERT (ChatHistoryDB). */
    RoomStmtCache *roomCache; /**< Per-room statement cache (ChatHistoryDB). */
    /* ServerDB cached statements */
    sqlite3_stmt *stmtSetKey; /**< Cached INSERT OR REPLACE (ServerDB). */
    sqlite3_stmt *stmtGetKey; /**< Cached SELECT key_value (ServerDB). */
    /* Key material held in memory for the lifetime of the handle */
    uint8_t dekKey[AES_GCM_KEY_LEN];  /**< DEK for TOTP secret envelope
                                         encryption. */
    uint8_t dbEncKey[DB_ENC_KEY_LEN]; /**< Per-database encryption key. */
} DB;

/* ─────────────────────────────── lifecycle ──────────────────────────────── */

/**
 * @brief Open (and optionally create) a database of the specified type.
 *
 * If the database file does not exist, it is created along with the
 * required schema (tables and indices). The parent directory "db/" is
 * created automatically if it does not exist.
 *
 * Schema for UserDB:
 *   - users(uid INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
 *           nickname TEXT NOT NULL, password TEXT NOT NULL,
 *           totp_secret BLOB, cdbkey BLOB)
 *
 * Schema for ChatHistoryDB:
 *   - msg_sequence(id INTEGER PRIMARY KEY AUTOINCREMENT)
 *     Provides globally unique, monotonically increasing message IDs.
 *   - Per-room tables (created on demand via storeChat):
 *     room_<roomId>(msgId INTEGER PRIMARY KEY, uid INTEGER NOT NULL,
 *                   message TEXT NOT NULL, timestamp INTEGER NOT NULL)
 *
 * @param dbType  The database to open (@c UserDB or @c ChatHistoryDB).
 * @return A database handle on success, or @c NULL on failure.
 */
DB *dbInit(DBType dbType, const uint8_t *encKey);

/**
 * @brief Close a database handle and release all associated resources.
 *
 * Safe to call with @c NULL (no-op in that case).
 *
 * @param database  The database handle to close.
 */
void dbClose(DB *database);

/**
 * @brief Set the DEK for envelope encryption of TOTP secrets.
 *
 * Copies the 32-byte DEK into the UserDB handle.  The DEK is used
 * internally by @c createUser(), @c verifyUser(), and
 * @c setTOTPSecret() to encrypt / decrypt the @c totp_secret column.
 * It is securely wiped when @c dbClose() is called.
 *
 * Safe to call multiple times on the same handle (overwrites).
 * Passing @c NULL zeros the DEK.
 *
 * @param database  An open UserDB handle.
 * @param dekKey    Pointer to 32-byte AES-256 DEK, or NULL to clear.
 */
void dbSetDekKey(DB *database, const uint8_t *dekKey);

/**
 * @brief Set the per-database encryption key on a DB handle.
 *
 * Copies @p key (must be @c DB_ENC_KEY_LEN bytes, or NULL to clear)
 * into the handle.  The key is securely wiped when @c dbClose() is
 * called.
 *
 * @param database  An open DB handle.
 * @param key       Pointer to @c DB_ENC_KEY_LEN key bytes, or NULL to clear.
 */
void dbSetDbEncKey(DB *database, const uint8_t *key);

/* ──────────────────────────── user operations ───────────────────────────── */

/**
 * @brief Insert a new user record into the user database.
 *
 * The plaintext password in @p user->password is hashed internally via
 * @c hashPassword() before storage.  The optional @c user->totpSecret is
 * stored as-is (Base32-encoded, or NULL if TOTP is not set).  The caller
 * retains ownership of the User struct and its fields.
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
 * On success, also populates @c user->totpSecret (via @c strdup) with
 * the stored TOTP secret, or sets it to @c NULL if none is stored.
 *
 * @param database  An open UserDB handle.
 * @param user      User credentials to verify. @c user->password must
 *                  contain the plaintext password. Must not be NULL.
 * @return @c DB_SUCC if credentials are valid, @c DB_FAIL otherwise.
 */
int verifyUser(DB *database, User *user);

/**
 * @brief Retrieve the decrypted TOTP secret for a user.
 *
 * Reads the encrypted envelope from the database, decrypts it with the
 * DEK stored in @p database, and returns the plaintext Base32 string.
 * Returns @c NULL if the user has no TOTP secret set or on error.
 *
 * The caller must @c free() the returned string.
 *
 * @param database  An open UserDB handle with DEK set via dbSetDekKey().
 * @param user      User whose @c uid identifies the row.  Must not be NULL.
 * @return Heap-allocated decrypted TOTP secret, or @c NULL.
 */
char *getTOTPSecret(DB *database, User *user);

/**
 * @brief Set or clear the TOTP secret for an existing user.
 *
 * Updates the @c totp_secret column for the user identified by
 * @p user->uid.  @p secret is a Base32-encoded TOTP shared secret
 * (null-terminated).  Passing @c NULL or an empty string clears the
 * secret (column set to @c NULL).
 *
 * @param database  An open UserDB handle.
 * @param user      User record whose uid identifies the target.  Must not
 *                  be NULL.
 * @param secret    Base32-encoded TOTP secret, or NULL / "" to clear.
 * @return @c DB_SUCC on success, @c DB_FAIL if the user does not exist
 *         or on error.
 */
int setTOTPSecret(DB *database, User *user, const char *secret);

/**
 * @brief Retrieve and decrypt the per-user CDBKey (Client Database Key).
 *
 * Reads the encrypted envelope from the database for the given @p uid,
 * decrypts it with the DEK stored in @p database, and writes the 32-byte
 * CDBKey into @p outKey.
 *
 * @param database  An open UserDB handle with DEK set via dbSetDekKey().
 * @param uid       The user whose CDBKey is requested.
 * @param outKey    Output buffer of DB_ENC_KEY_LEN bytes.  Must not be NULL.
 * @return DB_SUCC on success, DB_FAIL if the user does not exist, has no
 *         CDBKey, or on decryption error.
 */
int getCDBKey(DB *database, uint32_t uid, uint8_t outKey[DB_ENC_KEY_LEN]);

/* ───────────────────────── server key operations ────────────────────────── */

/**
 * @brief Store a key-value pair into the server database.
 *
 * Inserts or replaces a row in the @c server_keys table.  @p value is
 * copied as a BLOB; @p valueLen may be zero (an empty blob is stored).
 * The @c created_at column is set to the current UNIX timestamp.
 *
 * @param database  An open ServerDB handle.
 * @param keyName   Unique key name (null-terminated).  Must not be NULL
 *                  or empty.
 * @param value     Pointer to the value bytes.  Must not be NULL when
 *                  @p valueLen > 0.
 * @param valueLen  Length of @p value in bytes.  May be 0.
 * @return @c DB_SUCC on success, @c DB_FAIL on error.
 */
int setServerKey(DB *database, const char *keyName, const uint8_t *value,
                 size_t valueLen);

/**
 * @brief Retrieve a stored server key by name.
 *
 * Looks up @p keyName in the @c server_keys table and, on success,
 * allocates a buffer containing the stored value.  If the key does not
 * exist the call still returns @c DB_SUCC with @p *outValue = NULL and
 * @p *outLen = 0.
 *
 * The caller is responsible for freeing @p *outValue with @c free().
 *
 * @param database  An open ServerDB handle.
 * @param keyName   Key name to look up (null-terminated).  Must not be
 *                  NULL or empty.
 * @param outValue  Output parameter receiving the heap-allocated value
 *                  bytes.  Set to @c NULL on failure or if not found.
 * @param outLen    Output parameter receiving the value length in bytes.
 *                  Set to 0 on failure or if not found.
 * @return @c DB_SUCC on success, @c DB_FAIL on error (invalid argument,
 *         wrong DB type, or allocation failure).
 */
int getServerKey(DB *database, const char *keyName, uint8_t **outValue,
                 size_t *outLen);

/* ──────────────────────── chat history operations ───────────────────────── */

/**
 * @brief Store a chat message into a room's table.
 *
 * Inserts a new record into the table for @p roomId. If the room table
 * does not yet exist, it is created automatically (along with indices).
 *
 * The @c msgId field of @p chat is ignored on input; after a
 * successful insert, it is populated with the globally unique,
 * monotonically increasing message ID assigned by the database.
 *
 * @param database     An open ChatHistoryDB handle.
 * @param roomId       The room to store the message in.
 * @param chat         Chat record to store. @c uid, @c message, and
 *                     @c timestamp must be set. Must not be NULL.
 * @return @c DB_SUCC on success, @c DB_FAIL on failure.
 */
int storeChat(DB *database, uint32_t roomId, Chat *chat);

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
int queryChatByMsgId(DB *database, uint32_t roomId, uint64_t msgId, Chat *out);

/**
 * @brief Query chat messages within a time range, optionally filtered by uid.
 *
 * Retrieves all messages in @p roomId whose timestamp falls within
 * [@p startTime, @p endTime] (inclusive). If @p uid is 0, messages from
 * all users are returned; otherwise only messages from that uid.
 *
 * On success, @p *out is set to a newly allocated array of Chat
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
                         time_t startTime, time_t endTime, Chat **out,
                         size_t *count);

/**
 * @brief Query all chat messages from a user across all rooms in a time range.
 *
 * Iterates over every existing room table (discovered via sqlite_master)
 * and retrieves messages where uid matches and timestamp falls within
 * [@p startTime, @p endTime] (inclusive). Results are sorted globally by
 * msgId (ascending), providing a unified chronological view.
 *
 * On success, @p *out is set to a newly allocated array of Chat
 * records and @p *count is set to the number of results. Each entry's
 * @c message field is a separate allocation; the caller must free each
 * @c message and the array itself.
 *
 * An empty result set (no matching records) is considered success:
 * returns @c DB_SUCC with @p *count = 0 and @p *out = NULL.
 *
 * @param database   An open ChatHistoryDB handle.
 * @param uid        User ID to query (must be non-zero).
 * @param startTime  Start of the time range (inclusive).
 * @param endTime    End of the time range (inclusive).
 * @param out        Output pointer to the result array. Must not be NULL.
 * @param count      Output pointer to the result count. Must not be NULL.
 * @return @c DB_SUCC on success, @c DB_FAIL on error.
 */
int queryChatByUserAllRooms(DB *database, uint32_t uid, time_t startTime,
                            time_t endTime, Chat **out, size_t *count);

/* ───────────────────────── game (room) operations ───────────────────────── */

/**
 * @brief Create a new game room record.
 *
 * Inserts a row into the rooms table with the current UNIX timestamp.
 * @p roomId must be non-zero and must not already exist.
 *
 * @param database    An open GameDB handle.
 * @param roomId      The room identifier (must be > 0).
 * @param creatorUid  The uid of the user creating the room.
 * @return @c DB_SUCC on success, @c DB_FAIL if @p roomId already exists
 *         or on error.
 */
int createRoom(DB *database, uint32_t roomId, uint32_t creatorUid);

/**
 * @brief Delete a room record from the game database.
 *
 * Fails in strict mode: if @p roomId does not exist the call returns
 * @c DB_FAIL.
 *
 * @param database  An open GameDB handle.
 * @param roomId    The room to delete.
 * @return @c DB_SUCC on success, @c DB_FAIL if not found or on error.
 */
int deleteRoom(DB *database, uint32_t roomId);

/**
 * @brief List all room IDs in the game database.
 *
 * On success @p *outRoomIds is set to a newly allocated array of
 * @c uint32_t and @p *count is set to the number of rooms.  The caller
 * must @c free(*outRoomIds).
 *
 * An empty database is considered success: returns @c DB_SUCC with
 * @p *count = 0 and @p *outRoomIds = NULL.
 *
 * @param database    An open GameDB handle.
 * @param outRoomIds  Output array of room IDs. Must not be NULL.
 * @param count       Output count of rooms. Must not be NULL.
 * @return @c DB_SUCC on success, @c DB_FAIL on error.
 */
int listRooms(DB *database, uint32_t **outRoomIds, size_t *count);

/**
 * @brief Check whether a room exists in the game database.
 *
 * @param database  An open GameDB handle.
 * @param roomId    The room to check.
 * @return @c DB_SUCC if the room exists, @c DB_FAIL if not found or on error.
 */
int roomExists(DB *database, uint32_t roomId);

#endif /* SERVER_DATABASE_H */
