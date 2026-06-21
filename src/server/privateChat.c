/**
 * @file privateChat.c
 * @brief Server-side private chat message handling — implementation.
 *
 * @date 2026-06-21
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

#include "privateChat.h"
#include "log.h"
#include "server.h"
#include "server/communication.h"
#include "server/database.h"
#include "server/onlineTracker.h"

#include <stdlib.h>
#include <string.h>

/* ─────────────────────────────── public API ────────────────────────────────
 */

/* ════════════════════════════ private chat send ════════════════════════════
 */

int serverHandlePrivateChatSend(Server *s, ClientSession *cs,
                                const Packet *pkt) {
    /* Minimum: fromUid + toUid + msgId + timestamp + NUL. */
    _Static_assert(offsetof(PrivateChatPayload, message) ==
                       sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t) +
                           sizeof(int64_t),
                   "PrivateChatPayload layout mismatch");
    enum {
        PrivateChatFixedLen = sizeof(uint32_t) + sizeof(uint32_t) +
                              sizeof(uint32_t) + sizeof(int64_t)
    };
    if (pkt->header.payloadLength < PrivateChatFixedLen + 1) {
        LOG_WARN("serverHandlePrivateChatSend: payload too small (%u bytes)",
                 pkt->header.payloadLength);
        return SERVER_FAIL;
    }

    const PrivateChatPayload *req = (const PrivateChatPayload *)pkt->payload;
    size_t msgLen = pkt->header.payloadLength - PrivateChatFixedLen;
    if (msgLen == 0 || memchr(req->message, '\0', msgLen) == NULL) {
        LOG_WARN("serverHandlePrivateChatSend: message not NUL-terminated or "
                 "empty");
        return SERVER_FAIL;
    }

    uint32_t fromUid = cs->currentUser.uid;
    uint32_t toUid = req->toUid;
    int64_t timestamp = req->timestamp;

    /* serverOverwrites client-supplied fromUid and msgId. */

    uint32_t msgId = 0;
    if (privateChatStore(s->privateChatDB, fromUid, toUid, req->message,
                         (uint64_t)timestamp, &msgId) != DB_SUCC) {
        LOG_WARN("serverHandlePrivateChatSend: privateChatStore failed");
        return SERVER_FAIL;
    }

    /* Deliver immediately if receiver is online. */
    ClientSession *receiver = onlineTrackerFind(s->onlineTrk, toUid);
    if (receiver != NULL) {
        size_t bcLen = offsetof(PrivateChatPayload, message) + msgLen;
        PrivateChatPayload *bc = malloc(bcLen);
        if (bc == NULL) {
            LOG_ERROR("serverHandlePrivateChatSend: malloc failed (errno=%d)",
                      errno);
            return SERVER_FAIL;
        }

        bc->fromUid = fromUid;
        bc->toUid = toUid;
        bc->msgId = msgId;
        bc->timestamp = timestamp;
        memcpy(bc->message, req->message, msgLen);

        int ret = serverSendEncryptedPacket(receiver, MsgPrivateChatBroadcast,
                                            bc, bcLen);
        free(bc);
        if (ret != SERVER_SUCC) {
            LOG_WARN("serverHandlePrivateChatSend: delivery to uid=%u failed",
                     toUid);
            return SERVER_FAIL;
        }
    }

    return SERVER_SUCC;
}

/* ══════════════════════════ private chat history ═══════════════════════════
 */

int serverHandlePrivateChatHistory(Server *s, ClientSession *cs,
                                   const Packet *pkt) {
    if (pkt->header.payloadLength < sizeof(PrivateChatHistoryReqPayload)) {
        LOG_WARN("serverHandlePrivateChatHistory: payload too small (%u "
                 "bytes, need %zu)",
                 pkt->header.payloadLength,
                 sizeof(PrivateChatHistoryReqPayload));
        return SERVER_FAIL;
    }

    const PrivateChatHistoryReqPayload *req =
        (const PrivateChatHistoryReqPayload *)pkt->payload;

    Chat *chats = NULL;
    size_t count = 0;
    if (privateChatHistory(s->privateChatDB, cs->currentUser.uid, req->peerUid,
                           req->beforeMsgId, req->limit, &chats,
                           &count) != DB_SUCC) {
        LOG_WARN("serverHandlePrivateChatHistory: privateChatHistory failed");
        return SERVER_FAIL;
    }

    /* Build response: uint32_t count followed by PrivateChatPayload array. */
    size_t bufSize = sizeof(uint32_t);
    size_t *entrySizes = NULL;
    if (count > 0) {
        entrySizes = malloc(count * sizeof(size_t));
        if (entrySizes == NULL) {
            LOG_ERROR("serverHandlePrivateChatHistory: malloc failed "
                      "(errno=%d)",
                      errno);
            for (size_t i = 0; i < count; i++) {
                free(chats[i].message);
            }
            free(chats);
            return SERVER_FAIL;
        }
    }

    for (size_t i = 0; i < count; i++) {
        size_t msgLen = strlen(chats[i].message) + 1;
        entrySizes[i] = offsetof(PrivateChatPayload, message) + msgLen;
        bufSize += entrySizes[i];
    }

    uint8_t *buf = malloc(bufSize);
    if (buf == NULL) {
        LOG_ERROR("serverHandlePrivateChatHistory: malloc failed (errno=%d)",
                  errno);
        free(entrySizes);
        for (size_t i = 0; i < count; i++) {
            free(chats[i].message);
        }
        free(chats);
        return SERVER_FAIL;
    }

    /* Write count. */
    uint32_t netCount = htonl((uint32_t)count);
    memcpy(buf, &netCount, sizeof(uint32_t));
    size_t offset = sizeof(uint32_t);

    for (size_t i = 0; i < count; i++) {
        PrivateChatPayload *pc = (PrivateChatPayload *)(buf + offset);
        uint32_t peerUid = req->peerUid;
        uint32_t myUid = cs->currentUser.uid;

        if (chats[i].uid == myUid) {
            pc->fromUid = myUid;
            pc->toUid = peerUid;
        } else {
            pc->fromUid = chats[i].uid;
            pc->toUid = myUid;
        }
        pc->msgId = (uint32_t)chats[i].msgId;
        pc->timestamp = (int64_t)chats[i].timestamp;
        size_t msgLen = strlen(chats[i].message) + 1;
        memcpy(pc->message, chats[i].message, msgLen);

        offset += entrySizes[i];
    }

    int ret =
        serverSendEncryptedPacket(cs, MsgPrivateChatHistoryResp, buf, bufSize);

    free(buf);
    free(entrySizes);
    for (size_t i = 0; i < count; i++) {
        free(chats[i].message);
    }
    free(chats);

    if (ret != SERVER_SUCC) {
        LOG_WARN("serverHandlePrivateChatHistory: send failed");
        return SERVER_FAIL;
    }

    return SERVER_SUCC;
}

/* ═══════════════════════ offline message delivery ══════════════════════════
 */

void serverDeliverOfflineMessages(Server *s, ClientSession *cs) {
    Chat *chats = NULL;
    size_t count = 0;
    if (privateChatDeliverPending(s->privateChatDB, cs->currentUser.uid, &chats,
                                  &count) != DB_SUCC) {
        LOG_WARN("serverDeliverOfflineMessages: privateChatDeliverPending "
                 "failed for uid=%u",
                 cs->currentUser.uid);
        return;
    }

    for (size_t i = 0; i < count; i++) {
        size_t msgLen = strlen(chats[i].message) + 1;
        size_t pcLen = offsetof(PrivateChatPayload, message) + msgLen;
        PrivateChatPayload *pc = malloc(pcLen);
        if (pc == NULL) {
            LOG_ERROR("serverDeliverOfflineMessages: malloc failed (errno=%d)",
                      errno);
            continue;
        }

        pc->fromUid = chats[i].uid;
        pc->toUid = cs->currentUser.uid;
        pc->msgId = (uint32_t)chats[i].msgId;
        pc->timestamp = (int64_t)chats[i].timestamp;
        memcpy(pc->message, chats[i].message, msgLen);

        int ret =
            serverSendEncryptedPacket(cs, MsgPrivateChatBroadcast, pc, pcLen);
        free(pc);
        if (ret != SERVER_SUCC) {
            LOG_WARN(
                "serverDeliverOfflineMessages: send failed for msgId=%" PRIu64,
                chats[i].msgId);
        }
    }

    for (size_t i = 0; i < count; i++) {
        free(chats[i].message);
    }
    free(chats);
}
