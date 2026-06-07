/**
 * @file internal.h
 * @brief Shared internal helpers and constants for the server database
 * subsystem.
 *
 * Included only by source files under src/server/database/.
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

#ifndef SERVER_DATABASE_INTERNAL_H
#define SERVER_DATABASE_INTERNAL_H

#include "server/database.h"

/** @brief Buffer size for the "room_<roomId>" table name string. */
#define ROOM_TABLE_NAME_SIZE 32

/** @brief Maximum length of a dynamically generated SQL string. */
#define SQL_BUF_SIZE 512

/** @brief Initial capacity for result arrays (doubled on overflow). */
#define QUERY_INITIAL_CAPACITY 16

/** @brief Maximum result count to prevent unbounded memory allocation. */
#define QUERY_MAX_RESULTS 100000

/* ─────────────────────── internal lifecycle helpers ────────────────────────
 */

/**
 * @brief Initialize the schema for the user database.
 * @param dbHandle  Raw sqlite3 handle.
 * @return @c DB_SUCC on success, @c DB_FAIL on failure.
 */
int initUserDBSchema(sqlite3 *dbHandle);

/**
 * @brief Initialize the schema for the chat history database.
 * @param dbHandle  Raw sqlite3 handle.
 * @return @c DB_SUCC on success, @c DB_FAIL on failure.
 */
int initChatHistoryDBSchema(sqlite3 *dbHandle);

/**
 * @brief Initialize the schema for the game database.
 * @param dbHandle  Raw sqlite3 handle.
 * @return @c DB_SUCC on success, @c DB_FAIL on failure.
 */
int initGameDBSchema(sqlite3 *dbHandle);

/**
 * @brief Initialize the schema for the server key-value database.
 * @param dbHandle  Raw sqlite3 handle.
 * @return @c DB_SUCC on success, @c DB_FAIL on failure.
 */
int initServerDBSchema(sqlite3 *dbHandle);

/* ───────────────── internal statement preparation helpers ──────────────────
 */

/**
 * @brief Prepare cached statements for a UserDB handle.
 * @param database  The DB handle to populate.
 * @return @c DB_SUCC on success, @c DB_FAIL on failure.
 */
int prepareUserStmts(DB *database);

/**
 * @brief Prepare the global sequence statement for ChatHistoryDB.
 * @param database  The DB handle to populate.
 * @return @c DB_SUCC on success, @c DB_FAIL on failure.
 */
int prepareChatGlobalStmts(DB *database);

/**
 * @brief Prepare cached statements for a GameDB handle.
 * @param database  The DB handle to populate.
 * @return @c DB_SUCC on success, @c DB_FAIL on failure.
 */
int prepareGameDBStmts(DB *database);

/**
 * @brief Prepare cached statements for a ServerDB handle.
 * @param database  The DB handle to populate.
 * @return @c DB_SUCC on success, @c DB_FAIL on failure.
 */
int prepareServerDBStmts(DB *database);

/* ─────────────────────── room cache lifecycle ──────────────────────────────
 */

/**
 * @brief Free all entries in the room statement cache.
 *
 * Finalizes all prepared statements and frees all allocated memory.
 * Safe to call with @c NULL (no-op).
 *
 * @param cache  The room statement cache to destroy (may be NULL).
 */
void roomCacheDestroy(RoomStmtCache *cache);

#endif /* SERVER_DATABASE_INTERNAL_H */
