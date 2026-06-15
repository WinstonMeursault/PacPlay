/**
 * @file room.c
 * @brief Client-side room menu module — implementation.
 *
 * @date 2026-06-07
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
#include "client/room.h"
#include "client/auth.h"
#include "client/chat.h"
#include "client/communication.h"
#include "log.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { MaxInputLen = 512, MaxRoomDisplay = 100, IdInputLen = 32, DecBase = 10 };

// free roomIds after reaching the end of its lifetime
int clientRoomList(Client *client, uint32_t **roomIds, size_t *roomCount) {
    if (clientSendEncryptedPacket(client, MsgRoomListReq, NULL, 0) !=
        PROTOCOL_SUCC) {
        return CLIENT_FAIL;
    }

    Packet resp;
    memset(&resp, 0, sizeof(resp));
    if (clientRecvEncryptedPacket(client, &resp) != PROTOCOL_SUCC) {
        return CLIENT_FAIL;
    }

    if (resp.header.messageType != MsgRoomListResp) {
        LOG_ERROR("clientRoomMenu: unexpected message type %d",
                  (int)resp.header.messageType);
        packetClear(&resp);
        return CLIENT_FAIL;
    }

    *roomCount = resp.header.payloadLength / sizeof(uint32_t);
    *roomIds = (uint32_t *)resp.payload;

    return CLIENT_SUCC;
}

int clientCreateRoom(Client *client, uint32_t id) {
    if (id == 0 || id > UINT32_MAX) {
        LOG_ERROR("clientRoom: Invalid room ID");
    }

    if (clientSendEncryptedPacket(client, MsgCreateRoom, &id, sizeof(id)) !=
        PROTOCOL_SUCC) {
        return CLIENT_FAIL;
    }

    int createStatus = clientRecvStatusResponse(client, MsgCreateRoomResp);
    if (createStatus != 0) {
        LOG_ERROR("clientRoom: Room %u already exists", id);
    }

    return CLIENT_SUCC;
}

int clientJoinRoom(Client *client, uint32_t id) {
    if (clientSendEncryptedPacket(client, MsgJoinRoom, &id, sizeof(id)) !=
        PROTOCOL_SUCC) {
        return CLIENT_FAIL;
    }

    int joinAfterCreate = clientRecvStatusResponse(client, MsgJoinRoomResp);
    if (joinAfterCreate != 0) {
        LOG_ERROR("clientRoom: Failed to join room %u", id);
        return CLIENT_FAIL;
    }

    client->currentRoomId = id;
    LOG_INFO("clientRoom: Joined room %u", id);
    return CLIENT_SUCC;
}

void clientQuitRoom(Client *client) {
    clientSendEncryptedPacket(client, MsgQuitRoom, NULL, 0);
}
