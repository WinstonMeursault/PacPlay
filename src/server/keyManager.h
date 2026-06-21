/**
 * @file keyManager.h
 * @brief Server cryptographic key generation and envelope management.
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

#ifndef SERVER_KEY_MANAGER_H
#define SERVER_KEY_MANAGER_H

#include "server.h"
#include <stdbool.h>

/**
 * @brief Check whether this is the first server run.
 *
 * Returns true when the @c server_keys table in ServerDB is empty
 * (no key envelopes have been stored yet).
 *
 * @param s  An initialised Server with @c serverDB open.
 * @return @c true if first run, @c false otherwise.
 */
bool serverIsFirstRun(Server *s);

/**
 * @brief Verify that all expected key envelopes exist in ServerDB.
 *
 * Checks for the presence of @c "DEK", @c "UserDBKey",
 * @c "ChatHistoryDBKey", @c "RoomDBKey", @c "GameDBKey", and
 * @c "GameRoomDBKey".  If any is missing the
 * database is considered corrupted and the server must refuse to start.
 *
 * @param s  An initialised Server with @c serverDB open.
 * @return @c true if all envelopes are present, @c false otherwise.
 */
bool serverKeysAreComplete(Server *s);

/**
 * @brief Generate fresh cryptographic keys and store envelopes in
 *        ServerDB.
 *
 * Generates MK, DEK, UserDBKey, ChatHistoryDBKey, RoomDBKey,
 * GameDBKey, and GameRoomDBKey via
 * @c cryptoRandomBytes() (each 256-bit).  Wraps DEK and the three
 * per-DB keys with MK using AES-256-GCM into 60-byte envelopes and
 * stores them in ServerDB.
 *
 * **The derived keys are NOT populated into the Server struct.**  Call
 * @c serverUnlockWithMK() afterwards (with the same MK) to populate
 * them.
 *
 * Sets @c freshKeysGenerated = true.
 *
 * @param s  An initialised Server with @c serverDB open.
 * @return A malloc'd 64-character hex string of the Master Key, or
 *         @c NULL on failure.  The caller must @c free() the string
 *         and @c OPENSSL_cleanse() it before freeing.
 */
char *serverGenerateFreshKeys(Server *s);

/**
 * @brief Unlock the server by decrypting all key envelopes with the
 *        given Master Key.
 *
 * Reads the envelopes ("DEK", "UserDBKey", "ChatHistoryDBKey",
 * "RoomDBKey", "GameDBKey", "GameRoomDBKey") from ServerDB, decrypts
 * each with @p masterKeyHex via AES-256-GCM, and populates the
 * corresponding fields in the Server struct (@c dekKey,
 * @c userDbEncKey, @c chatDbEncKey, @c roomDbEncKey, @c gameDbEncKey,
 * @c gameRoomDbEncKey).
 *
 * Sets @c freshKeysGenerated = false on success.
 *
 * @param s             An initialised Server with @c serverDB open.
 * @param masterKeyHex  64-character hex-encoded Master Key.
 * @return @c SERVER_SUCC on success, @c SERVER_FAIL if the MK is
 *         incorrect or envelopes are corrupted.
 */
int serverUnlockWithMK(Server *s, const char *masterKeyHex);

#endif /* SERVER_KEY_MANAGER_H */
