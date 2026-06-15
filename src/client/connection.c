/**
 * @file connection.c
 * @brief PacPlay client connect and disconnect.
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

#include "connection.h"
#include "communication.h"
#include "database.h"
#include "log.h"
#include <string.h>
#include <sys/select.h>
#include <unistd.h>

#include <openssl/crypto.h>

/* ─────────────────────────────── public API ─────────────────────────────── */

int clientConnect(Client *client, const char *addr, uint16_t port) {
    SocketFD fd = clientSetup(addr, port);
    if (fd == NULL_SOCKETFD) {
        LOG_ERROR("clientConnect: failed to connect to %s:%u", addr,
                  (unsigned int)port);
        return CLIENT_FAIL;
    }

    AESGCMKey key;
    if (clientExchangeAESKey(fd, &key) != PROTOCOL_SUCC) {
        LOG_ERROR("clientConnect: key exchange failed");
        socketClose(&fd);
        return CLIENT_FAIL;
    }

    client->fd = fd;
    memcpy(&client->aesKey, &key, sizeof(key));
    OPENSSL_cleanse(&key, sizeof(key));
    LOG_INFO("Connected and key exchanged with %s:%u", addr,
             (unsigned int)port);
    return CLIENT_SUCC;
}

void clientDisconnect(Client *client) {
    if (client->fd != NULL_SOCKETFD) {
        clientCloseDB(client);
        OPENSSL_cleanse(&client->aesKey, sizeof(client->aesKey));
        OPENSSL_cleanse(client->cdbkey, sizeof(client->cdbkey));
        socketClose(&client->fd);
    }
    LOG_INFO("Client disconnected");
}
