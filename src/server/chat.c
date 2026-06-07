/**
 * @file chat.c
 * @brief Server-side chat message handling — implementation.
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

#include "chat.h"
#include "log.h"
#include "server.h"
#include "server/communication.h"
#include "server/database.h"

#include <stdlib.h>
#include <string.h>

/* ───────────────────────────── local helpers ────────────────────────────── */

/**
 * @brief Find an active room by its room ID, or NULL.
 *
 * Linear search through the server's dynamic active room array.
 */
static ActiveRoom *findActiveRoom(const Server *s, uint32_t roomId) {
    for (int i = 0; i < s->activeRoomCount; i++) {
        if (s->activeRooms[i]->roomId == roomId) {
            return s->activeRooms[i];
        }
    }
    return NULL;
}

/**
 * @brief Broadcast a chat message to all room members except the sender.
 *
 * Constructs a @c ChatBroadcastPayload on the heap (struct layout always
 * matches the wire format) and sends it to every member whose pointer
 * differs from @p sender.
 */
static void
broadcastToRoom(Server *s, uint32_t roomId, ClientSession *sender,
                // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
                uint32_t uid, uint64_t msgId, int64_t timestamp,
                // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
                const uint8_t *message, size_t msgLen) {
    ActiveRoom *room = findActiveRoom(s, roomId);
    if (room == NULL) {
        return;
    }

    _Static_assert(offsetof(ChatBroadcastPayload, message) ==
                       sizeof(uint32_t) + sizeof(uint64_t) + sizeof(int64_t),
                   "ChatBroadcastPayload layout mismatch");
    size_t bcLen = offsetof(ChatBroadcastPayload, message) + msgLen;
    ChatBroadcastPayload *bc = malloc(bcLen);
    if (bc == NULL) {
        LOG_ERROR("broadcastToRoom: malloc failed (errno=%d)", errno);
        return;
    }

    bc->uid = uid;
    bc->msgId = msgId;
    bc->timestamp = timestamp;
    memcpy(bc->message, message, msgLen);

    for (int i = 0; i < room->memberCount; i++) {
        ClientSession *member = room->members[i];
        if (member == sender) {
            continue;
        }
        serverSendEncryptedPacket(member, MsgChat, bc, bcLen);
    }

    free(bc);
}

/* ─────────────────────────────── public API ─────────────────────────────── */

int serverHandleChatMessage(Server *s, ClientSession *cs, const Packet *pkt) {
    /* Minimum: timestamp (int64_t = 8 bytes). */
    if (pkt->header.payloadLength < sizeof(int64_t)) {
        LOG_WARN("serverHandleChatMessage: payload too small (%u bytes)",
                 pkt->header.payloadLength);
        return SERVER_FAIL;
    }

    ChatPacketPayload *chat = (ChatPacketPayload *)pkt->payload;
    size_t msgLen = pkt->header.payloadLength - sizeof(int64_t);

    /* Ensure NUL-terminated within bounds. */
    if (msgLen == 0 || memchr(chat->message, '\0', msgLen) == NULL) {
        LOG_WARN("serverHandleChatMessage: message not NUL-terminated or "
                 "empty");
        return SERVER_FAIL;
    }

    /* Store in ChatHistoryDB. */
    Chat ch;
    memset(&ch, 0, sizeof(ch));
    ch.uid = cs->currentUser.uid;
    ch.message = strdup((const char *)chat->message);
    if (ch.message == NULL) {
        return SERVER_FAIL;
    }
    ch.timestamp = (time_t)chat->timestamp;

    if (storeChat(s->chatDB, cs->currentRoomId, &ch) != DB_SUCC) {
        LOG_WARN("serverHandleChatMessage: storeChat failed");
        free(ch.message);
        return SERVER_FAIL;
    }

    /* Broadcast to all other members. */
    broadcastToRoom(s, cs->currentRoomId, cs, ch.uid, ch.msgId, ch.timestamp,
                    chat->message, msgLen);

    free(ch.message);
    return SERVER_SUCC;
}
