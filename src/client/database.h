/**
 * @file database.h
 * @brief Encrypted client-side database for storing local game library.
 *
 * Uses SQLCipher with the per-user CDBKey received from the server during
 * login.  The database file is encrypted at the page level — all data
 * stored on disk is opaque without the correct key.
 *
 * @date 2026-06-01
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

#ifndef CLIENT_DATABASE_H
#define CLIENT_DATABASE_H

#include "protocol.h"

#include <sqlite3.h>
#include <stdint.h>
#include <time.h>

/* Forward — full definition in client.h. */
struct Client;

/* ─────────────────────────────── constants ──────────────────────────────── */

/** @brief File path for the client-side encrypted database. */
#define CLIENT_DB_PATH "./db/client.db"

/** @brief Directory containing the client database file. */
#define CLIENT_DB_DIR "./db"

/* ────────────────────────────── return codes ────────────────────────────── */

#define CLIENT_DB_SUCC (0)
#define CLIENT_DB_FAIL (-1)

/* ───────────────────────────────── types ────────────────────────────────── */

/**
 * @brief A single row from the gameList table.
 *
 * @c gameName and @c gamePath are heap-allocated copies that the caller
 * must free with @c free().
 */
typedef struct {
    uint32_t gameId;
    char *gameName;    /**< Human-readable game name, caller-freed. */
    char *gamePath;    /**< Filesystem path to the game, caller-freed. */
    char *gameVersion; /**< Version string, caller-freed. */
    char *platform;    /**< Platform identifier, caller-freed. */
    char *fileHash;    /**< File hash for integrity verification, caller-freed. */
    uint64_t playTime; /**< Accumulated play time in seconds. */
} GameRecord;

/**
 * @brief Opaque client-side database handle.
 *
 * Wraps a SQLCipher connection and cached prepared statements for the
 * gameList table.  The key material is securely wiped when the handle
 * is closed.
 */
typedef struct ClientDB {
    sqlite3 *handle;
    sqlite3_stmt *stmtInsert;
    sqlite3_stmt *stmtSelectAll;
    sqlite3_stmt *stmtSelectById;
    sqlite3_stmt *stmtDelete;
    sqlite3_stmt *stmtUpdatePlayTime;
    uint8_t dbEncKey[CLIENT_DB_KEY_LEN]; /**< SQLCipher page-level key. */
} ClientDB;

/* ─────────────────────────────── lifecycle ──────────────────────────────── */

/**
 * @brief Open (and optionally create) the client encrypted database.
 *
 * If the database file does not exist it is created with the required
 * schema.  The parent directory is created automatically if needed.
 *
 * @param client  Fully-connected client with @c cdbkey populated.
 * @return @c CLIENT_DB_SUCC on success, @c CLIENT_DB_FAIL on error.
 */
int clientInitDB(struct Client *client);

/**
 * @brief Close the client database and securely wipe key material.
 *
 * Safe to call with a NULL @c client->db (no-op in that case).
 *
 * @param client  Client whose database handle is to be closed.
 */
void clientCloseDB(struct Client *client);

/* ──────────────────────────── game operations ───────────────────────────── */

/**
 * @brief Insert a game record into the local game library.
 *
 * @c playTime is initialised to 0 for new entries.
 *
 * @param client    Client with an open database handle.
 * @param gameId    Unique game identifier.
 * @param gameName  Display name (null-terminated).
 * @param gamePath  Filesystem path to the game executable.
 * @return @c CLIENT_DB_SUCC on success, @c CLIENT_DB_FAIL on error or
 *         duplicate @c gameId.
 */
int addGame(struct Client *client, uint32_t gameId, const char *gameName,
            const char *gamePath, const char *gameVersion,
            const char *platform, const char *fileHash);

/**
 * @brief List all games in the local library, ordered by gameName.
 *
 * On success @c *outRecords is set to a heap-allocated array of
 * @c GameRecord pointers and @c *count is the number of records.
 * The caller must free each record's @c gameName and @c gamePath,
 * then free the array itself.
 *
 * An empty database returns @c CLIENT_DB_SUCC with @c *count = 0
 * and @c *outRecords = NULL.
 *
 * @param client       Client with an open database handle.
 * @param outRecords   Output pointer array (must not be NULL).
 * @param count        Output count (must not be NULL).
 * @return @c CLIENT_DB_SUCC on success, @c CLIENT_DB_FAIL on error.
 */
int listGames(struct Client *client, GameRecord ***outRecords, size_t *count);

/**
 * @brief Delete a game record from the local library.
 *
 * @param client  Client with an open database handle.
 * @param gameId  Game to delete.
 * @return @c CLIENT_DB_SUCC on success, @c CLIENT_DB_FAIL if not found
 *         or on error.
 */
int deleteGame(struct Client *client, uint32_t gameId);

/**
 * @brief Update the accumulated play time for a game.
 *
 * @param client    Client with an open database handle.
 * @param gameId    Game to update.
 * @param playTime  New total play time in seconds.
 * @return @c CLIENT_DB_SUCC on success, @c CLIENT_DB_FAIL if not found
 *         or on error.
 */
int updatePlayTime(struct Client *client, uint32_t gameId, uint64_t playTime);

#endif /* CLIENT_DATABASE_H */
