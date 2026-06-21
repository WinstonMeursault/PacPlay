/**
 * @file gameRoom.c
 * @brief Client-side game room module — implementation.
 *
 * @date 2026-06-20
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
#include "client/gameRoom.h"
#include "client/communication.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>

enum { StatusSuccess = 0 };

int clientGameRoomList(Client *client, uint32_t gameId,
                       GameRoomListEntry **outEntries, size_t *outCount) {
    if (clientSendEncryptedPacket(client, MsgGameRoomListReq, NULL, 0) !=
        PROTOCOL_SUCC) {
        return CLIENT_FAIL;
    }

    Packet resp;
    memset(&resp, 0, sizeof(resp));
    if (clientRecvEncryptedPacket(client, &resp) != PROTOCOL_SUCC) {
        return CLIENT_FAIL;
    }

    if (resp.header.messageType != MsgGameRoomListResp) {
        LOG_ERROR("clientGameRoomList: unexpected message type %d",
                  (int)resp.header.messageType);
        packetClear(&resp);
        return CLIENT_FAIL;
    }

    if (resp.payload == NULL || resp.header.payloadLength == 0) {
        *outEntries = NULL;
        *outCount = 0;
        packetClear(&resp);
        return CLIENT_SUCC;
    }

    size_t totalEntries = resp.header.payloadLength / sizeof(GameRoomListEntry);
    size_t filteredCount = 0;

    GameRoomListEntry *allEntries = (GameRoomListEntry *)resp.payload;
    GameRoomListEntry *filtered =
        malloc(totalEntries * sizeof(GameRoomListEntry));
    if (filtered == NULL) {
        packetClear(&resp);
        return CLIENT_FAIL;
    }

    for (size_t i = 0; i < totalEntries; i++) {
        if (allEntries[i].gameId == gameId) {
            memcpy(&filtered[filteredCount], &allEntries[i],
                   sizeof(GameRoomListEntry));
            filteredCount++;
        }
    }

    *outEntries = filtered;
    *outCount = filteredCount;
    packetClear(&resp);
    return CLIENT_SUCC;
}

int clientGameRoomCreate(Client *client, uint32_t gameId, uint32_t *outRoomId) {
    GameRoomCreatePayload req;
    memset(&req, 0, sizeof(req));
    req.gameId = gameId;

    if (clientSendEncryptedPacket(client, MsgGameRoomCreate, &req,
                                  sizeof(req)) != PROTOCOL_SUCC) {
        return CLIENT_FAIL;
    }

    Packet resp;
    memset(&resp, 0, sizeof(resp));
    if (clientRecvEncryptedPacket(client, &resp) != PROTOCOL_SUCC) {
        return CLIENT_FAIL;
    }

    if (resp.header.messageType != MsgGameRoomCreateResp ||
        resp.header.payloadLength != sizeof(GameRoomCreateRespPayload)) {
        LOG_ERROR("clientGameRoomCreate: unexpected response");
        packetClear(&resp);
        return CLIENT_FAIL;
    }

    const GameRoomCreateRespPayload *createResp =
        (const GameRoomCreateRespPayload *)resp.payload;
    if (createResp->status != StatusSuccess) {
        LOG_ERROR("clientGameRoomCreate: server returned failure status");
        packetClear(&resp);
        return CLIENT_FAIL;
    }

    *outRoomId = createResp->gameRoomId;
    client->currentGameRoomId = createResp->gameRoomId;
    packetClear(&resp);
    LOG_INFO("clientGameRoomCreate: created room %u", *outRoomId);
    return CLIENT_SUCC;
}

int clientGameRoomJoin(Client *client, uint32_t gameRoomId) {
    GameRoomJoinPayload req;
    memset(&req, 0, sizeof(req));
    req.gameRoomId = gameRoomId;

    if (clientSendEncryptedPacket(client, MsgGameRoomJoin, &req, sizeof(req)) !=
        PROTOCOL_SUCC) {
        return CLIENT_FAIL;
    }

    int joinStatus = clientRecvStatusResponse(client, MsgGameRoomJoinResp);
    if (joinStatus != 0) {
        LOG_ERROR("clientGameRoomJoin: failed to join room %u", gameRoomId);
        return CLIENT_FAIL;
    }

    client->currentGameRoomId = gameRoomId;
    LOG_INFO("clientGameRoomJoin: joined room %u", gameRoomId);
    return CLIENT_SUCC;
}

void clientGameRoomQuit(Client *client) {
    clientSendEncryptedPacket(client, MsgGameRoomQuit, NULL, 0);
    client->currentGameRoomId = 0;
}

int clientGameRoomStart(Client *client, uint32_t gameRoomId) {
    GameRoomStartPayload req;
    memset(&req, 0, sizeof(req));
    req.gameRoomId = gameRoomId;

    if (clientSendEncryptedPacket(client, MsgGameRoomStart, &req,
                                  sizeof(req)) != PROTOCOL_SUCC) {
        return CLIENT_FAIL;
    }

    int startStatus = clientRecvStatusResponse(client, MsgGameRoomStartResp);
    if (startStatus != 0) {
        LOG_ERROR("clientGameRoomStart: failed to start game in room %u",
                  gameRoomId);
        return CLIENT_FAIL;
    }

    LOG_INFO("clientGameRoomStart: game started in room %u", gameRoomId);
    return CLIENT_SUCC;
}

void clientPollNotifications(Client *client) {
    if (client == NULL || client->fd == NULL_SOCKETFD) {
        return;
    }

    fd_set readFds;
    FD_ZERO(&readFds);
    FD_SET(client->fd, &readFds);
    struct timeval tv = {0, 0};

    if (select(client->fd + 1, &readFds, NULL, NULL, &tv) <= 0) {
        return;
    }
    if (!FD_ISSET(client->fd, &readFds)) {
        return;
    }

    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    if (clientRecvEncryptedPacket(client, &pkt) != PROTOCOL_SUCC) {
        return;
    }

    switch ((MessageType)pkt.header.messageType) {
    case MsgGameRoomMemberList: {
        if (client->roomMembers != NULL) {
            free(client->roomMembers);
        }
        client->roomMemberCount =
            (int)(pkt.header.payloadLength / sizeof(GameRoomMemberInfo));
        if (client->roomMemberCount > 0) {
            client->roomMembers = (GameRoomMemberInfo *)malloc(
                (size_t)client->roomMemberCount * sizeof(GameRoomMemberInfo));
            if (client->roomMembers != NULL) {
                memcpy(client->roomMembers, pkt.payload,
                       pkt.header.payloadLength);
            } else {
                client->roomMemberCount = 0;
            }
        } else {
            client->roomMembers = NULL;
        }
        break;
    }
    case MsgGameRoomMemberJoin: {
        const GameRoomMemberInfo *info =
            (const GameRoomMemberInfo *)pkt.payload;
        if (pkt.header.payloadLength >= sizeof(GameRoomMemberInfo)) {
            int nc = client->roomMemberCount + 1;
            GameRoomMemberInfo *tmp = (GameRoomMemberInfo *)realloc(
                client->roomMembers, (size_t)nc * sizeof(GameRoomMemberInfo));
            if (tmp != NULL) {
                client->roomMembers = tmp;
                memcpy(&client->roomMembers[client->roomMemberCount], info,
                       sizeof(GameRoomMemberInfo));
                client->roomMemberCount = nc;
            }
        }
        break;
    }
    case MsgGameRoomMemberQuit: {
        const GameRoomMemberQuitPayload *qp =
            (const GameRoomMemberQuitPayload *)pkt.payload;
        if (pkt.header.payloadLength >= sizeof(GameRoomMemberQuitPayload)) {
            if (qp->dissolved) {
                if (client->roomMembers != NULL) {
                    free(client->roomMembers);
                    client->roomMembers = NULL;
                }
                client->roomMemberCount = 0;
                client->currentGameRoomId = 0;
            } else if (client->roomMembers != NULL) {
                for (int i = 0; i < client->roomMemberCount; i++) {
                    if (client->roomMembers[i].uid == qp->uid) {
                        int r = client->roomMemberCount - i - 1;
                        if (r > 0) {
                            memmove(&client->roomMembers[i],
                                    &client->roomMembers[i + 1],
                                    (size_t)r * sizeof(GameRoomMemberInfo));
                        }
                        client->roomMemberCount--;
                        break;
                    }
                }
            }
        }
        break;
    }
    case MsgGameRoomStartResp: {
        if (pkt.header.payloadLength >= sizeof(uint8_t)) {
            const uint8_t *status = (const uint8_t *)pkt.payload;
            if (*status == StatusSuccess) {
                client->gameStarted = true;
            }
        }
        break;
    }
    default:
        break;
    }

    packetClear(&pkt);
}
