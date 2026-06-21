/**
 * @file connection.c
 * @brief PacPlay client connect, disconnect, and IO thread management.
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
#include "pacplay_sdk.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>

#include <openssl/crypto.h>

enum {
    SdkCtlMagic = 0xFF,
    SdkCtlGameIdOffset = 1,
    SdkCtlPlatformOffset = 5,
    SdkCtlStartServerLen = 1 + 4 + PLATFORM_NAME_LEN
};

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
    strncpy(client->serverAddr, addr, SERVER_ADDR_LEN - 1);
    client->serverAddr[SERVER_ADDR_LEN - 1] = '\0';
    client->serverPort = port;
    memcpy(&client->aesKey, &key, sizeof(key));
    OPENSSL_cleanse(&key, sizeof(key));
    LOG_INFO("Connected and key exchanged with %s:%u", addr,
             (unsigned int)port);
    return CLIENT_SUCC;
}

void clientDisconnect(Client *client) {
    clientShutdown(client);
    if (client->fd != NULL_SOCKETFD) {
        clientCloseDB(client);
        OPENSSL_cleanse(&client->aesKey, sizeof(client->aesKey));
        OPENSSL_cleanse(client->cdbkey, sizeof(client->cdbkey));
        socketClose(&client->fd);
    }
    free(client->roomMembers);
    client->roomMembers = NULL;
    client->roomMemberCount = 0;
    LOG_INFO("Client disconnected");
}

/* ════════════════════════ IO thread management ════════════════════════════ */

static void *clientEventLoop(void *arg);

int clientLaunch(Client *client, PacPlaySDK *sdk) {
    if (client == NULL || client->fd == NULL_SOCKETFD) {
        return CLIENT_FAIL;
    }

    client->sdk = sdk;
    client->running = true;

    if (pthread_create(&client->ioThread, NULL, clientEventLoop, client) != 0) {
        LOG_ERROR("clientLaunch: pthread_create failed (errno=%d)", errno);
        client->running = false;
        client->sdk = NULL;
        return CLIENT_FAIL;
    }

    LOG_INFO("Client IO thread started (fd=%d)", client->fd);
    return CLIENT_SUCC;
}

void clientShutdown(Client *client) {
    if (client == NULL || !client->running) {
        return;
    }
    client->running = false;
    pthread_join(client->ioThread, NULL);
    if (client->sdk != NULL) {
        pacplay_cli_destroy(client->sdk);
    }
    client->sdk = NULL;
    LOG_INFO("Client IO thread stopped");
}

/* ════════════════════════ background event loop ═══════════════════════════ */

static void *clientEventLoop(void *arg) {
    Client *c = (Client *)arg;

    while (c->running) {
        fd_set readFds;
        FD_ZERO(&readFds);
        FD_SET(c->fd, &readFds);

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = CLIENT_SELECT_TIMEOUT_US;

        int ready = select(c->fd + 1, &readFds, NULL, NULL, &tv);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            LOG_ERROR("clientEventLoop: select() failed (errno=%d, fd=%d)",
                      errno, c->fd);
            break;
        }

        /* 1. Drain SDK send queue — encrypt and send game payloads. */
        if (c->sdk != NULL) {
            uint8_t *gamePayload = NULL;
            size_t gameLen = 0;
            while (pacplay_cli_poll_send(c->sdk, &gamePayload, &gameLen)) {
                if (gameLen == SdkCtlStartServerLen &&
                    gamePayload[0] == SdkCtlMagic) {
                    GameStartReqPayload req;
                    memcpy(&req.gameId, gamePayload + SdkCtlGameIdOffset,
                           sizeof(req.gameId));
                    memcpy(req.platform, gamePayload + SdkCtlPlatformOffset,
                           PLATFORM_NAME_LEN);
                    clientSendEncryptedPacket(c, MsgGameStartReq, &req,
                                              sizeof(req));
                } else if (c->currentGameRoomId != 0) {
                    clientSendEncryptedPacket(c, MsgGameRoomPlayData,
                                              gamePayload, gameLen);
                } else {
                    clientSendEncryptedPacket(c, MsgGamePayload, gamePayload,
                                              gameLen);
                }
                pacplay_cli_free_payload(c->sdk, gamePayload);
            }
        }

        /* 2. Receive and dispatch incoming packets. */
        if (ready > 0 && FD_ISSET(c->fd, &readFds)) {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));

            if (clientRecvEncryptedPacket(c, &pkt) == PROTOCOL_SUCC) {
                MessageType mt = (MessageType)pkt.header.messageType;
                if ((mt == MsgGamePayload || mt == MsgGameRoomPlayData) &&
                    c->sdk != NULL && pkt.header.payloadLength > 0) {
                    pacplay_cli_push_received(c->sdk, pkt.payload,
                                              pkt.header.payloadLength);
                }
            }
            packetClear(&pkt);
        }
    }

    return NULL;
}
