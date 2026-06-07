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

/**
 * @brief Initialise server cryptographic keys (envelope encryption).
 *
 * **First run** (no "DEK" key in ServerDB):
 * - Generates MK, DEK, UserDBKey, ChatHistoryDBKey, and GameDBKey via
 *   @c cryptoRandomBytes() (each 256-bit).
 * - Uses AES-256-GCM to wrap DEK and the three per-DB keys with MK,
 *   producing 60-byte envelopes stored in ServerDB.
 * - Copies plaintext keys into the Server struct.
 * - Displays MK once in hex to the administrator, then securely wipes
 *   it from memory via @c OPENSSL_cleanse().
 * - Sets @c freshKeysGenerated = true.
 *
 * **Subsequent runs** ("DEK" key exists in ServerDB):
 * - Reads all four envelopes from ServerDB and validates completeness.
 * - Prompts for the 64-character hex Master Key (masked input).
 * - Decrypts each envelope with MK and loads plaintext keys into the
 *   Server struct.
 * - Sets @c freshKeysGenerated = false.
 *
 * Internal helpers @c encryptAndStoreKey() and @c decryptAndLoadKey()
 * are static functions within @c keyManager.c and are not exposed.
 *
 * @param s  An initialised Server with @c serverDB open.
 * @return @c SERVER_SUCC on success, @c SERVER_FAIL on error (incorrect
 *         Master Key, corrupted envelope, I/O failure).
 */
int serverInitKeys(Server *s);

#endif /* SERVER_KEY_MANAGER_H */
