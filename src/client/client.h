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

/* ──────────────────────── return codes ─────────────────────────────────── */

#define CLIENT_SUCC (0)
#define CLIENT_FAIL (-1)

/* ──────────────────────── types ────────────────────────────────────────── */

typedef struct Client {
    SocketFD fd;
    AESGCMKey aesKey;
    uint32_t uid;
    uint32_t currentRoomId;
    uint32_t seqID;
    uint8_t cdbkey[CLIENT_DB_KEY_LEN]; /**< Per-user CDBKey received from server. */
    struct ClientDB *db;               /**< Opaque encrypted client database. */
} Client;

/* ──────────────────────── public API ───────────────────────────────────── */

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
 * @brief Prompt the user for credentials and perform login.
 *
 * Reads username, password, and uid from stdin, sends MsgLoginReq,
 * and waits for MsgLoginResp.
 *
 * @param client  Fully-connected client with completed key exchange.
 * @return @c CLIENT_SUCC on success, @c CLIENT_FAIL on failure.
 */
int clientLogin(Client *client);

/**
 * @brief Prompt the user for credentials and perform registration.
 *
 * Reads username, nickname, password, and uid from stdin, sends
 * MsgRegisterReq, and waits for MsgRegisterResp.
 *
 * @param client  Fully-connected client with completed key exchange.
 * @return @c CLIENT_SUCC on success, @c CLIENT_FAIL on failure.
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
 * @brief Perform TOTP setup — request a new secret from the server.
 *
 * Sends @c MsgTOTPSetupReq, receives @c MsgTOTPSetupResp containing
 * a Base32-encoded TOTP secret, displays it along with the otpauth
 * URI for import into an authenticator app.
 *
 * @param client  Authenticated client (must have completed login).
 * @return @c CLIENT_SUCC on success, @c CLIENT_FAIL on failure.
 */
int clientTOTPSetup(Client *client);

/**
 * @brief Disconnect and clean up client resources.
 *
 * @param client  Client to tear down.
 */
void clientDisconnect(Client *client);

#endif /* CLIENT_H */
