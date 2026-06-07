/**
 * @file room.c
 * @brief Server-side active room lifecycle management — implementation.
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
#include "room.h"
#include "log.h"
#include "server/communication.h"
#include "server/database.h"
#include <stdlib.h>
#include <string.h>

/* ──────────────────────────── local constants ───────────────────────────── */
enum { StatusSuccess = 0, StatusFailure = 1 };

/* ────────────────────────────── room helpers ────────────────────────────── */

ActiveRoom *serverFindActiveRoom(const Server *s, uint32_t roomId) {
    for (int i = 0; i < s->activeRoomCount; i++)
        if (s->activeRooms[i]->roomId == roomId)
            return s->activeRooms[i];
    return NULL;
}

ActiveRoom *serverGetOrCreateActiveRoom(Server *s, uint32_t roomId) {
    ActiveRoom *room = serverFindActiveRoom(s, roomId);
    if (room != NULL)
        return room;
    if (s->activeRoomCount >= s->activeRoomCapacity) {
        int nc = s->activeRoomCapacity * 2;
        ActiveRoom **tmp = (ActiveRoom **)realloc(
            (void *)s->activeRooms, (size_t)nc * sizeof(ActiveRoom *));
        if (tmp == NULL) {
            LOG_ERROR("%s: realloc failed", __func__);
            return NULL;
        }
        s->activeRooms = tmp;
        s->activeRoomCapacity = nc;
    }
    room = calloc(1, sizeof(ActiveRoom));
    if (room == NULL) {
        LOG_ERROR("%s: calloc failed", __func__);
        return NULL;
    }
    room->roomId = roomId;
    s->activeRooms[s->activeRoomCount++] = room;
    return room;
}

void serverRemoveActiveRoom(Server *s, uint32_t roomId) {
    for (int i = 0; i < s->activeRoomCount; i++) {
        if (s->activeRooms[i]->roomId == roomId) {
            free(s->activeRooms[i]);
            int r = s->activeRoomCount - i - 1;
            if (r > 0)
                memmove((void *)&s->activeRooms[i],
                        (const void *)&s->activeRooms[i + 1],
                        (size_t)r * sizeof(ActiveRoom *));
            s->activeRoomCount--;
            return;
        }
    }
}

void serverRemoveClientFromRoom(Server *s, ClientSession *cs) {
    if (cs->currentRoomId == 0)
        return;
    ActiveRoom *room = serverFindActiveRoom(s, cs->currentRoomId);
    if (room == NULL) {
        cs->currentRoomId = 0;
        return;
    }
    for (int i = 0; i < room->memberCount; i++) {
        if (room->members[i] == cs) {
            int r = room->memberCount - i - 1;
            if (r > 0)
                memmove((void *)&room->members[i],
                        (const void *)&room->members[i + 1],
                        (size_t)r * sizeof(ClientSession *));
            room->memberCount--;
            break;
        }
    }
    cs->currentRoomId = 0;
    if (room->memberCount == 0)
        serverRemoveActiveRoom(s, room->roomId);
}

/* ───────────────────────────── room handlers ────────────────────────────── */

int serverHandleRoomList(Server *s, ClientSession *cs) {
    uint32_t *roomIds = NULL;
    size_t count = 0;
    if (listRooms(s->gameDB, &roomIds, &count) != DB_SUCC) {
        serverSendEncryptedPacket(cs, MsgRoomListResp, NULL, 0);
        return SERVER_SUCC;
    }
    int ret = serverSendEncryptedPacket(cs, MsgRoomListResp, roomIds,
                                        count * sizeof(uint32_t));
    free(roomIds);
    return (ret == SERVER_SUCC) ? SERVER_SUCC : SERVER_FAIL;
}

int serverHandleRoomCreate(Server *s, ClientSession *cs, const Packet *pkt) {
    if (pkt->header.payloadLength != sizeof(uint32_t)) {
        serverSendStatusResponse(cs, MsgCreateRoomResp, StatusFailure);
        return SERVER_SUCC;
    }
    uint32_t roomId = *(uint32_t *)pkt->payload;
    if (createRoom(s->gameDB, roomId, cs->currentUser.uid) != DB_SUCC) {
        serverSendStatusResponse(cs, MsgCreateRoomResp, StatusFailure);
        return SERVER_SUCC;
    }
    serverSendStatusResponse(cs, MsgCreateRoomResp, StatusSuccess);
    return SERVER_SUCC;
}

int serverHandleRoomJoin(Server *s, ClientSession *cs, const Packet *pkt) {
    if (pkt->header.payloadLength != sizeof(uint32_t)) {
        serverSendStatusResponse(cs, MsgJoinRoomResp, StatusFailure);
        return SERVER_SUCC;
    }
    uint32_t roomId = *(uint32_t *)pkt->payload;
    if (roomExists(s->gameDB, roomId) != DB_SUCC) {
        serverSendStatusResponse(cs, MsgJoinRoomResp, StatusFailure);
        return SERVER_SUCC;
    }
    if (cs->currentRoomId != 0)
        serverRemoveClientFromRoom(s, cs);
    ActiveRoom *room = serverGetOrCreateActiveRoom(s, roomId);
    if (room == NULL || room->memberCount >= MAX_CLIENTS_PER_ROOM) {
        serverSendStatusResponse(cs, MsgJoinRoomResp, StatusFailure);
        return SERVER_SUCC;
    }
    room->members[room->memberCount++] = cs;
    cs->currentRoomId = roomId;
    cs->state = SessionChat;
    serverSendStatusResponse(cs, MsgJoinRoomResp, StatusSuccess);
    return SERVER_SUCC;
}
