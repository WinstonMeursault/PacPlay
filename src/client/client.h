/**
 * @file client.h
 * @brief PacPlay client — state machine types and public API.
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

#include <pthread.h>

struct ClientDB;   /* forward — full definition in client/database.h */
struct PacPlaySDK; /* forward — full definition in pacplay_sdk.h */

#include <stdint.h>

/* ────────────────────────────── return codes ────────────────────────────── */

#define CLIENT_SUCC (0)
#define CLIENT_FAIL (-1)

#define SERVER_ADDR_LEN 64

/** @brief select() timeout for client IO thread in microseconds (~60 Hz). */
#define CLIENT_SELECT_TIMEOUT_US 16000

/* ───────────────────────────────── types ────────────────────────────────── */

typedef struct Client {
    SocketFD fd;
    AESGCMKey aesKey;
    uint32_t uid;
    char nickname[LOGIN_NICKNAME_LEN];
    uint32_t currentRoomId;
    uint32_t currentGameRoomId; /**< 0 if not in any game room. */
    uint32_t seqID;
    char serverAddr[SERVER_ADDR_LEN]; /**< Server address for data channel
                                         connections. */
    uint16_t serverPort;              /**< Server control port number. */
    uint8_t
        cdbkey[CLIENT_DB_KEY_LEN]; /**< Per-user CDBKey received from server. */
    struct ClientDB *db;           /**< Opaque encrypted client database. */
    /** IO thread fields — available after clientLaunch(). */
    pthread_t ioThread;              /**< Background IO thread handle. */
    volatile bool running;           /**< IO thread continues while true. */
    struct PacPlaySDK *sdk;          /**< Client SDK handle (NULL if unused). */
    GameRoomMemberInfo *roomMembers; /**< Current room member list. */
    int roomMemberCount;             /**< Count of roomMembers entries. */
    volatile bool gameStarted; /**< Set by poll when start resp received. */
} Client;

/* ─────────────────────── IO thread lifecycle ────────────────────────────── */

/**
 * @brief Launch the client IO thread for asynchronous send/recv.
 *
 * After a successful connect and login, this spawns a background thread
 * that drives a select()-based event loop on the control-channel socket.
 * Game payloads are routed through the SDK ring buffers.
 *
 * @param client  Connected and authenticated client.
 * @param sdk     Client SDK handle (may be NULL if no game bridge needed).
 * @return @c CLIENT_SUCC or @c CLIENT_FAIL.
 */
int clientLaunch(Client *client, struct PacPlaySDK *sdk);

/**
 * @brief Stop the client IO thread and wait for it to exit.
 * @param client  Client whose IO thread should be stopped.
 */
void clientShutdown(Client *client);

#endif // CLIENT_H