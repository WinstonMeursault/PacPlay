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

/** @brief File path for the game metadata database. */
#define GAME_DB_PATH "./db/game.db"

/** @brief File path for the server key-value database. */
#define SERVER_DB_PATH "./db/server.db"

/** @brief File path for the game room database. */
#define GAME_ROOM_DB_PATH "./db/gameRoom.db"

/** @brief File path for the friend database. */
#define FRIEND_DB_PATH "./db/friend.db"

/** @brief File path for the private chat database. */
#define PRIVATE_CHAT_DB_PATH "./db/privateChat.db"

/** @brief File path for the group database. */
#define GROUP_DB_PATH "./db/group.db"

/** @brief Directory containing all database files. */
#define DB_DIRECTORY "./db"

/* ────────────────────────────── return codes ────────────────────────────── */

#define DB_SUCC (0)
#define DB_FAIL (-1)

/* ───────────────────────────────── types ────────────────────────────────── */

/** @brief Identifies which database to open. */
typedef enum {
    UserDB = 1,
    ServerDB,
    GameDB,
    GameRoomDB,
    FriendDB,
    PrivateChatDB,
    GroupDB
} DBType;

/* ──────────────────────── group statement cache ───────────────────────── */

/** @brief Number of hash buckets for the group statement cache. */
#define GROUP_STMT_BUCKETS 32

/**
 * @brief Cached prepared statements for a single group chat table.
 *
 * Each group (identified by groupId) has its own set of pre-compiled
 * statements for INSERT and SELECT queries on the group_<groupId> table.
 */
typedef struct GroupStmtEntry {
    uint32_t groupId;
    sqlite3_stmt *stmtInsert;      /**< INSERT into group chat table. */
    sqlite3_stmt *stmtChatHistory; /**< SELECT chat history by beforeMsgId. */
    sqlite3_stmt *stmtLastTs;      /**< SELECT MAX(timestamp) from group. */
    struct GroupStmtEntry *next;   /**< Next entry in hash chain. */
} GroupStmtEntry;

/**
 * @brief Hash table mapping groupId to cached prepared statements.
 *
 * Used by GroupDB handles to avoid re-preparing SQL statements
 * for frequently accessed groups. Finalized entirely in dbClose().
 */
typedef struct {
    GroupStmtEntry *buckets[GROUP_STMT_BUCKETS];
} GroupStmtCache;

/* ──────────────────────────── database handle ───────────────────────────── */

/**
 * @brief Database handle wrapping sqlite3 and cached prepared statements.
 *
 * For UserDB: uses the fixed stmtInsert/stmtDelete/stmtSelect fields.
 */
typedef struct DB {
    sqlite3 *handle; /**< Underlying sqlite3 connection. */
    DBType type;     /**< Type of database this handle serves. */
    /* UserDB cached statements */
    sqlite3_stmt *stmtInsert; /**< Cached INSERT statement (UserDB). */
    sqlite3_stmt *stmtDelete; /**< Cached DELETE statement (UserDB). */
    sqlite3_stmt *stmtSelect; /**< Cached SELECT statement (UserDB). */
    sqlite3_stmt
        *stmtUidCheck; /**< Cached SELECT 1 FROM users WHERE uid=? (UserDB). */
    sqlite3_stmt *stmtSetTotpSecret; /**< Cached UPDATE totp_secret (UserDB). */
    sqlite3_stmt *stmtGetTOTPSecret; /**< Cached SELECT totp_secret (UserDB). */
    sqlite3_stmt
        *stmtGetCDBKey; /**< Cached SELECT cdbkey WHERE uid=? (UserDB). */
    /* GroupDB cached statements */
    sqlite3_stmt *stmtGroupSeq; /**< Global msg sequence INSERT (GroupDB). */
    sqlite3_stmt *stmtSeq;      /**< Global msg sequence INSERT (PrivateChatDB). */
    GroupStmtCache *groupCache; /**< Per-group statement cache (GroupDB). */
    /* ServerDB cached statements */
    sqlite3_stmt *stmtSetKey; /**< Cached INSERT OR REPLACE (ServerDB). */
    sqlite3_stmt *stmtGetKey; /**< Cached SELECT key_value (ServerDB). */
    /* GameDB cached statements */
    sqlite3_stmt *stmtGameInsert;
    sqlite3_stmt *stmtGameDelete;
    sqlite3_stmt *stmtGameUpdate;
    sqlite3_stmt *stmtGameSelectById;
    sqlite3_stmt *stmtGameSelectByName;
    sqlite3_stmt *stmtGameList;
    sqlite3_stmt *stmtGameGetKey;
    sqlite3_stmt *stmtGameListAll;
    sqlite3_stmt *stmtGameListRange;
    sqlite3_stmt *stmtGameListPlatformAll;
    sqlite3_stmt *stmtGameListPlatformRange;
    sqlite3_stmt *stmtPlatformInsert;
    sqlite3_stmt *stmtPlatformSelect;
    sqlite3_stmt *stmtPlatformList;
    /* GameRoomDB cached statements */
    sqlite3_stmt *stmtGameRoomInsert;
    sqlite3_stmt *stmtGameRoomDelete;
    sqlite3_stmt *stmtGameRoomSelect;
    sqlite3_stmt *stmtGameRoomExists;
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
 * @param dbType  The database to open (@c UserDB or @c ServerDB, etc.).
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

/* ────────────────────── private chat operations ──────────────────────── */

/**
 * @brief Store a private chat message.
 *
 * Inserts a new record into the private_messages table with delivered=0.
 * The message content is copied from @p message into the database.
 *
 * @param database   An open PrivateChatDB handle.
 * @param fromUid    Sender user ID.
 * @param toUid      Recipient user ID.
 * @param message    Message content (null-terminated UTF-8).
 * @param timestamp  UNIX timestamp in seconds.
 * @param outMsgId   Output: the generated message ID (may be NULL).
 * @return @c DB_SUCC on success, @c DB_FAIL on failure.
 */
int privateChatStore(DB *database, uint32_t fromUid, uint32_t toUid,
                     const uint8_t *message, uint64_t timestamp,
                     uint32_t *outMsgId);

/**
 * @brief Retrieve and mark as delivered all pending messages for a user.
 *
 * Fetches all messages where toUid matches and delivered=0, marks them
 * as delivered in the database, and returns them as an array of Chat
 * records. On success, @p *out is set to a newly allocated array and
 * @p *count is set to the number of results. Each entry's @c message
 * field is a separate allocation; the caller must free each @c message
 * and the array itself.
 *
 * An empty result set (no pending messages) is considered success:
 * returns @c DB_SUCC with @p *count = 0 and @p *out = NULL.
 *
 * @param database  An open PrivateChatDB handle.
 * @param toUid     Recipient user ID.
 * @param out       Output pointer to the result array. Must not be NULL.
 * @param count     Output pointer to the result count. Must not be NULL.
 * @return @c DB_SUCC on success, @c DB_FAIL on error.
 */
int privateChatDeliverPending(DB *database, uint32_t toUid, Chat **out,
                              size_t *count);

/**
 * @brief Retrieve paginated chat history between two users.
 *
 * Fetches messages exchanged between @p uidA and @p uidB (in both
 * directions), with msgId less than @p beforeMsgId (or all if 0),
 * ordered by msgId descending, limited to @p limit entries (default 50
 * if 0). Results are returned as an array of Chat records.
 *
 * On success, @p *out is set to a newly allocated array and
 * @p *count is set to the number of results. Each entry's @c message
 * field is a separate allocation; the caller must free each @c message
 * and the array itself.
 *
 * An empty result set is considered success: returns @c DB_SUCC with
 * @p *count = 0 and @p *out = NULL.
 *
 * @param database     An open PrivateChatDB handle.
 * @param uidA         First user ID.
 * @param uidB         Second user ID.
 * @param beforeMsgId  Return messages with msgId < this (0 = no upper bound).
 * @param limit        Maximum number of results (0 = default 50).
 * @param out          Output pointer to the result array. Must not be NULL.
 * @param count        Output pointer to the result count. Must not be NULL.
 * @return @c DB_SUCC on success, @c DB_FAIL on error.
 */
int privateChatHistory(DB *database, uint32_t uidA, uint32_t uidB,
                       uint32_t beforeMsgId, uint32_t limit, Chat **out,
                       size_t *count);

/**
 * @brief Get the timestamp of the most recent message between two users.
 *
 * @param database  An open PrivateChatDB handle.
 * @param uidA      First user ID.
 * @param uidB      Second user ID.
 * @param outTs     Output: timestamp of the most recent message, or 0 if
 *                  no messages exist. Must not be NULL.
 * @return @c DB_SUCC on success, @c DB_FAIL on error.
 */
int privateChatLastMsgTimestamp(DB *database, uint32_t uidA, uint32_t uidB,
                                uint64_t *outTs);

/* ──────────────────── game metadata (registry) operations ──────────────── */

int registerGame(DB *database, GameInfo *game, const uint8_t *encKeyEnvelope,
                 size_t envelopeLen);
int unregisterGame(DB *database, uint32_t gameId);
int updateGameVersion(DB *database, uint32_t gameId, const char *version);
int getGameById(DB *database, uint32_t gameId, GameInfo *out);
int getGameByName(DB *database, const char *name, GameInfo *out);
int listRegisteredGames(DB *database, GameInfo **out, size_t *count);
int listGameBrief(DB *database, uint32_t rangeStart, uint32_t rangeEnd,
                  const char *platform, GameInfoEntry **out, size_t *count);
int getGameEncKey(DB *database, uint32_t gameId, uint8_t **outEnvelope,
                  size_t *outLen);
int registerGamePlatform(DB *database, uint32_t gameId,
                         const GamePlatformInfo *platform);
int getGamePlatform(DB *database, uint32_t gameId, const char *platform,
                    const char *role, GamePlatformInfo *out);
int listGamePlatforms(DB *database, uint32_t gameId, GamePlatformInfo **out,
                      size_t *count);
void gameInfoFree(GameInfo *info);
void gameInfoArrayFree(GameInfo *arr, size_t count);
void gamePlatformInfoFree(GamePlatformInfo *info);
void gamePlatformInfoArrayFree(GamePlatformInfo *arr, size_t count);

/* ────────────────────── game room persistence operations ────────────────── */

int createGameRoom(DB *database, uint32_t gameRoomId, uint32_t gameId,
                   uint32_t hostUid);
int deleteGameRoom(DB *database, uint32_t gameRoomId);
int listGameRooms(DB *database, uint32_t **outIds, size_t *count);
int gameRoomExists(DB *database, uint32_t gameRoomId);

/* ────────────────────────── friend operations ───────────────────────────── */

int initFriendDBSchema(sqlite3 *dbHandle);
int friendRequestCreate(DB *database, uint32_t fromUid, uint32_t toUid);
int friendRequestAccept(DB *database, uint32_t fromUid, uint32_t toUid);
int friendRequestReject(DB *database, uint32_t fromUid, uint32_t toUid);
int friendDelete(DB *database, uint32_t uid, uint32_t friendUid);
int friendListGet(DB *database, uint32_t uid, FriendInfo **out, size_t *count);
int friendRequestPendingList(DB *database, uint32_t uid, FriendInfo **out,
                             size_t *count);
int friendIsFriend(DB *database, uint32_t uid, uint32_t otherUid);

/* ──────────────────────── group database operations ────────────────────────
 */

int groupCreate(DB *database, uint32_t groupId, const char *groupName,
                uint32_t ownerUid);
int groupDelete(DB *database, uint32_t groupId);
int groupAddMember(DB *database, uint32_t groupId, uint32_t uid);
int groupRemoveMember(DB *database, uint32_t groupId, uint32_t uid);
int groupIsMember(DB *database, uint32_t groupId, uint32_t uid);
int groupMemberList(DB *database, uint32_t groupId, uint32_t **outUids,
                    size_t *count);
int groupListAll(DB *database, GroupInfo **out, size_t *count);
int groupGetInfo(DB *database, uint32_t groupId, GroupInfo *out);
int groupStoreChat(DB *database, uint32_t groupId, uint32_t uid,
                   const char *message, int64_t timestamp, uint64_t *outMsgId);
int groupChatHistory(DB *database, uint32_t groupId, uint32_t beforeMsgId,
                     uint32_t limit, Chat **out, size_t *count);
int groupLastMsgTimestamp(DB *database, uint32_t groupId, uint64_t *outTs);

#endif /* SERVER_DATABASE_H */
