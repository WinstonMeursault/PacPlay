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

struct ClientDB; /* forward — full definition in client/database.h */

#include <stdint.h>

/* ────────────────────────────── return codes ────────────────────────────── */

#define CLIENT_SUCC (0)
#define CLIENT_FAIL (-1)

#define SERVER_ADDR_LEN 64

/* ───────────────────────────────── types ────────────────────────────────── */

typedef struct Client {
    SocketFD fd;
    AESGCMKey aesKey;
    uint32_t uid;
    char nickname[LOGIN_NICKNAME_LEN];
    uint32_t currentRoomId;
    uint32_t seqID;
    char serverAddr[SERVER_ADDR_LEN]; /**< Server address for data channel
                                         connections. */
    uint16_t serverPort;              /**< Server control port number. */
    uint8_t
        cdbkey[CLIENT_DB_KEY_LEN]; /**< Per-user CDBKey received from server. */
    struct ClientDB *db;           /**< Opaque encrypted client database. */
} Client;

#endif // CLIENT_H