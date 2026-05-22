/**
 * @file communication.h
 * @brief Client-side communication helpers (key exchange, session management).
 *
 * @date 2026-05-20
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

#ifndef CLIENT_COMMUNICATION_H
#define CLIENT_COMMUNICATION_H

#include "crypto.h"
#include "protocol.h"

#define COMM_SUCC (0)
#define COMM_FAIL (-1)

/**
 * @brief Perform ECDH+HKDF key exchange with the server to derive an AES-256
 *        symmetric key.
 *
 * Generates an ephemeral X25519 key pair, sends the 32-byte raw public key
 * to the server, receives the server's 32-byte raw public key, performs ECDH
 * key agreement to compute a shared secret, then derives an AES-256-GCM
 * symmetric key from that shared secret via HKDF-SHA256.
 *
 * On success @c outKey->nonce is zeroed; the caller must set a fresh random
 * nonce (e.g. via @c cryptoRandomBytes) before each subsequent encryption.
 *
 * @param socketFD An already-connected socket to the server.  Must be a valid,
 *                 open TCP socket; the function does not create or close it.
 * @param outKey   Output parameter receiving the derived AES-256 key material.
 *                 Must not be NULL.
 * @return @c COMM_SUCC on success, @c COMM_FAIL on failure (socket error,
 *         key generation failure, import failure, or derivation failure).
 */
int clientExchangeAESKey(SocketFD socketFD, AESGCMKey *outKey);

#endif /* CLIENT_COMMUNICATION_H */
