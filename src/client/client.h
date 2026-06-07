/**
 * @file client.h
 * @brief PacPlay CLI client — state machine types and public API.
 *
 * @date 2026-05-27
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

#ifndef CLIENT_H
#define CLIENT_H

#include "crypto.h"
#include "protocol.h"

struct ClientDB; /* forward — full definition in client/database.h */

#include <stdint.h>

/* ────────────────────────────── return codes ────────────────────────────── */

#define CLIENT_SUCC (0)
#define CLIENT_FAIL (-1)

/* ───────────────────────────────── types ────────────────────────────────── */

typedef struct Client {
    SocketFD fd;
    AESGCMKey aesKey;
    uint32_t uid;
    uint32_t currentRoomId;
    uint32_t seqID;
    uint8_t
        cdbkey[CLIENT_DB_KEY_LEN]; /**< Per-user CDBKey received from server. */
    struct ClientDB *db;           /**< Opaque encrypted client database. */
} Client;

/* ─────────────────────────────── public API ─────────────────────────────── */

/**
 * @brief Connect to the server and perform ECDH+HKDF key exchange.
 *
 * @param client  Must be zero-initialised.
 * @param addr    Server IPv4 address (e.g. "127.0.0.1").
 * @param port    Server port.
 * @return @c CLIENT_SUCC on success, @c CLIENT_FAIL on failure.
 */
int clientConnect(Client *client, const char *addr, uint16_t port);

/**
 * @brief Authenticate the user to the server.
 *
 * The login flow proceeds in up to five stages:
 *  1. Prompt for username and password via stdin.
 *  2. Validate field lengths; build a @c LoginRequestPayload and send it as
 *     @c MsgLoginReq.
 *  3. If the server responds with @c MsgTOTPVerifyReq (TOTP is enabled on
 *     this account), prompt for the 6-digit code and send it as
 *     @c MsgTOTPVerifyResp.
 *  4. Validate the (final) @c MsgLoginResp — on success @c client->uid is
 *     set and the nickname is printed.
 *  5. Request the per-user encryption key via @c MsgDBKeyReq /
 *     @c MsgDBKeyResp and use it to initialise the encrypted local database
 *     (@c clientInitDB).  The key is wiped from memory immediately afterwards.
 *
 * @param client  Connected client (key exchange must have completed).
 * @return @c CLIENT_SUCC on successful login and database initialisation,
 *         @c CLIENT_FAIL on any error (I/O, auth failure, crypto, etc.).
 */
int clientLogin(Client *client);

/**
 * @brief Register a new account with the server.
 *
 * Collects a username, nickname, and password from the user via stdin,
 * validates field lengths against the protocol limits, builds a
 * @c RegisterRequestPayload with {username, nickname, password} as FAM, and
 * sends it as @c MsgRegisterReq.  The server responds with a single-byte
 * status code: 0 = success, 1 = username already taken.
 *
 * @param client  Connected client (key exchange must have completed).
 * @return @c CLIENT_SUCC if registration was accepted by the server,
 *         @c CLIENT_FAIL on error or if the server rejected the request.
 */
int clientRegister(Client *client);

/**
 * @brief Enter the room lobby — list rooms, offer create / join options.
 *
 * @param client  Authenticated client.
 * @return @c CLIENT_SUCC on success, @c CLIENT_FAIL on error or logout.
 */
int clientRoomMenu(Client *client);

/**
 * @brief Enter the chat loop inside a room — send messages and display
 *        incoming broadcasts.
 *
 * @param client  Client inside a room.
 * @return @c CLIENT_SUCC on clean exit (/exit), @c CLIENT_FAIL on error.
 */
int clientChatLoop(Client *client);

/**
 * @brief Set up TOTP two-factor authentication for the current user.
 *
 * Sends @c MsgTOTPSetupReq to the server.  On success, receives a
 * @c TOTPSetupRespPayload containing a Base32-encoded (RFC 4648, no padding)
 * 160-bit TOTP shared secret.  The secret is displayed to the user along
 * with an @c otpauth:// URI QR code (if URI generation succeeds) for
 * importing into an authenticator app.  If the secret is empty the server
 * reports that TOTP is already enabled — this is not treated as an error.
 *
 * @param client  Connected client (must be already logged in, as
 *                @c client->uid is used to construct the URI username).
 * @return @c CLIENT_SUCC (even if TOTP was already enabled; only I/O or
 *         protocol errors produce @c CLIENT_FAIL).
 */
int clientTOTPSetup(Client *client);

/**
 * @brief Disconnect and clean up client resources.
 *
 * @param client  Client to tear down.
 */
void clientDisconnect(Client *client);

#endif /* CLIENT_H */
