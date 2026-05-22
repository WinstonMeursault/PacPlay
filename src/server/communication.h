/**
 * @file communication.h
 * @brief Server-side communication helpers (key exchange, session management).
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

#ifndef SERVER_COMMUNICATION_H
#define SERVER_COMMUNICATION_H

#include "crypto.h"
#include "protocol.h"

#define COMM_SUCC (0)
#define COMM_FAIL (-1)

/**
 * @brief Complete the server side of an ECDH+HKDF key exchange.
 *
 * Generates an ephemeral X25519 key pair, immediately sends the server's
 * 32-byte public key back to the client in a @c MsgKeyExchangeResp packet,
 * then validates the client's previously-received @c MsgKeyExchangeReq packet
 * and derives the shared AES-256-GCM symmetric key.
 *
 * The caller is responsible for receiving the @c MsgKeyExchangeReq packet
 * via @c packetRecv before calling this function, and for calling
 * @c packetClear on @p reqPacket afterwards.
 *
 * As a defence-in-depth measure the function zeroes @c reqPacket->payload
 * in-place after extracting the client's public key.
 *
 * On success @c outKey->nonce is zeroed; the caller must set a fresh random
 * nonce (e.g. via @c cryptoRandomBytes) before each subsequent encryption.
 *
 * @param clientFD  The connected client socket.  Must be a valid, open TCP
 *                  socket; the function does not create or close it.
 * @param reqPacket The client's key-exchange request packet previously received
 *                  via @c packetRecv.  Must not be NULL and must have a
 *                  non-NULL payload.  Its payload is zeroed on return.
 * @param outKey    Output parameter receiving the derived AES-256 key
 *                  material.  Must not be NULL.
 * @return @c COMM_SUCC on success, @c COMM_FAIL on failure.
 */
int serverExchangeAESKey(SocketFD clientFD, Packet *reqPacket,
                         AESGCMKey *outKey);

#endif /* SERVER_COMMUNICATION_H */
