/**
 * @file communication.h
 * @brief Client-side communication helpers (key exchange, encrypted packet
 * I/O).
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

struct Client; /* forward — full definition in client.h */

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
 * @return @c PROTOCOL_SUCC on success, @c PROTOCOL_FAIL on failure (socket
 * error, key generation failure, import failure, or derivation failure).
 */
int clientExchangeAESKey(SocketFD socketFD, AESGCMKey *outKey);

/**
 * @brief Build, encrypt, and send a packet to the server.
 *
 * Convenience wrapper around @c packetSendEncrypted that reads the
 * socket, AES key, and sequence counter from @p client.
 *
 * @param client   Connected client (must have completed key exchange).
 * @param mt       Application-layer message type.
 * @param data     Payload bytes (may be NULL if dataLen is 0).
 * @param dataLen  Length of @p data in bytes.
 * @return @c PROTOCOL_SUCC on success, @c PROTOCOL_FAIL on failure.
 */
int clientSendEncryptedPacket(struct Client *client, MessageType mt,
                              const void *data, size_t dataLen);

/**
 * @brief Receive and decrypt one AES-256-GCM packet from the server.
 *
 * Convenience wrapper around @c packetRecvEncrypted.
 *
 * @param client  Connected client.
 * @param out     Destination packet (payload must be NULL on entry).
 * @return @c PROTOCOL_SUCC on success, @c PROTOCOL_FAIL or
 *         @c PROTOCOL_AUTH_FAIL on failure.
 */
int clientRecvEncryptedPacket(struct Client *client, Packet *out);

/**
 * @brief Receive a status response from the server and return the value.
 *
 * Receives and decrypts a packet whose message type must match
 * @p expectedMt, then reads a single-byte status from its payload.
 *
 * @param client      Connected client.
 * @param expectedMt  Expected @c MessageType of the response.
 * @return Status byte 0-255 on success, -1 on failure.
 */
int clientRecvStatusResponse(struct Client *client, MessageType expectedMt);

#endif /* CLIENT_COMMUNICATION_H */
