/**
 * @file social.c
 * @brief Client-side social module — friend, private chat, and group requests.
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

#include "social.h"

#include "client.h"
#include "client/communication.h"
#include "protocol.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <time.h>

/* ─────────────────── socket polling (shared by TUI pages) ────────────────── */

int clientPollAndDispatch(Client *c, Packet *outPkt) {
    if (c == NULL || c->fd == NULL_SOCKETFD) {
        return -1;
    }

    fd_set readFds;
    FD_ZERO(&readFds);
    FD_SET(c->fd, &readFds);
    struct timeval tv = {0, 0};

    if (select(c->fd + 1, &readFds, NULL, NULL, &tv) <= 0) {
        return 0;
    }
    if (!FD_ISSET(c->fd, &readFds)) {
        return 0;
    }

    memset(outPkt, 0, sizeof(*outPkt));
    if (clientRecvEncryptedPacket(c, outPkt) != PROTOCOL_SUCC) {
        return -1;
    }
    return 1;
}

/* ─────────────────────────── friend system ──────────────────────────────── */

int clientFriendRequest(Client *c, uint32_t targetUid) {
    FriendOpPayload p = {.targetUid = targetUid};
    return packetSendEncrypted(c->fd, MsgFriendRequest, &c->seqID,
                               c->aesKey.key, &p, sizeof(p));
}

int clientFriendAccept(Client *c, uint32_t targetUid) {
    FriendOpPayload p = {.targetUid = targetUid};
    return packetSendEncrypted(c->fd, MsgFriendAccept, &c->seqID, c->aesKey.key,
                               &p, sizeof(p));
}

int clientFriendReject(Client *c, uint32_t targetUid) {
    FriendOpPayload p = {.targetUid = targetUid};
    return packetSendEncrypted(c->fd, MsgFriendReject, &c->seqID, c->aesKey.key,
                               &p, sizeof(p));
}

int clientFriendDelete(Client *c, uint32_t targetUid) {
    FriendOpPayload p = {.targetUid = targetUid};
    return packetSendEncrypted(c->fd, MsgFriendDelete, &c->seqID, c->aesKey.key,
                               &p, sizeof(p));
}

int clientFriendListRequest(Client *c) {
    return packetSendEncrypted(c->fd, MsgFriendListReq, &c->seqID,
                               c->aesKey.key, NULL, 0);
}

/* ─────────────────────────── private chat ───────────────────────────────── */

int clientPrivateChatSend(Client *c, uint32_t toUid, const char *message) {
    size_t msgLen = strlen(message) + 1;
    size_t payloadLen = sizeof(PrivateChatPayload) + msgLen;
    uint8_t *buf = malloc(payloadLen);
    if (buf == NULL) {
        return CLIENT_FAIL;
    }
    PrivateChatPayload *p = (PrivateChatPayload *)buf;
    p->fromUid = c->uid;
    p->toUid = toUid;
    p->msgId = 0;
    p->timestamp = (int64_t)time(NULL);
    memcpy(p->message, message, msgLen);
    int ret = packetSendEncrypted(c->fd, MsgPrivateChat, &c->seqID,
                                  c->aesKey.key, buf, payloadLen);
    free(buf);
    return ret;
}

int clientPrivateChatHistoryRequest(Client *c, uint32_t peerUid,
                                    uint32_t beforeMsgId, uint32_t limit) {
    PrivateChatHistoryReqPayload p = {
        .peerUid = peerUid, .beforeMsgId = beforeMsgId, .limit = limit};
    return packetSendEncrypted(c->fd, MsgPrivateChatHistoryReq, &c->seqID,
                               c->aesKey.key, &p, sizeof(p));
}

/* ────────────────────────────── group chat ──────────────────────────────── */

int clientGroupCreate(Client *c, const char *groupName) {
    GroupCreatePayload p;
    memset(&p, 0, sizeof(p));
    strncpy(p.groupName, groupName, GROUP_NAME_LEN - 1);
    return packetSendEncrypted(c->fd, MsgGroupCreate, &c->seqID, c->aesKey.key,
                               &p, sizeof(p));
}

int clientGroupJoin(Client *c, uint32_t groupId) {
    GroupOpPayload p = {.groupId = groupId};
    return packetSendEncrypted(c->fd, MsgGroupJoin, &c->seqID, c->aesKey.key,
                               &p, sizeof(p));
}

int clientGroupQuit(Client *c, uint32_t groupId) {
    GroupOpPayload p = {.groupId = groupId};
    return packetSendEncrypted(c->fd, MsgGroupQuit, &c->seqID, c->aesKey.key,
                               &p, sizeof(p));
}

int clientGroupListRequest(Client *c) {
    return packetSendEncrypted(c->fd, MsgGroupListReq, &c->seqID, c->aesKey.key,
                               NULL, 0);
}

int clientGroupChatSend(Client *c, uint32_t groupId, const char *message) {
    size_t msgLen = strlen(message) + 1;
    size_t payloadLen = sizeof(GroupChatPayload) + msgLen;
    uint8_t *buf = malloc(payloadLen);
    if (buf == NULL) {
        return CLIENT_FAIL;
    }
    GroupChatPayload *p = (GroupChatPayload *)buf;
    p->groupId = groupId;
    p->timestamp = (int64_t)time(NULL);
    memcpy(p->message, message, msgLen);
    int ret = packetSendEncrypted(c->fd, MsgGroupChat, &c->seqID, c->aesKey.key,
                                  buf, payloadLen);
    free(buf);
    return ret;
}

int clientGroupKick(Client *c, uint32_t groupId, uint32_t targetUid) {
    GroupKickPayload p = {.groupId = groupId, .targetUid = targetUid};
    return packetSendEncrypted(c->fd, MsgGroupKick, &c->seqID, c->aesKey.key,
                               &p, sizeof(p));
}

int clientGroupDisband(Client *c, uint32_t groupId) {
    GroupOpPayload p = {.groupId = groupId};
    return packetSendEncrypted(c->fd, MsgGroupDisband, &c->seqID, c->aesKey.key,
                               &p, sizeof(p));
}

int clientGroupChatHistoryRequest(Client *c, uint32_t groupId,
                                  uint32_t beforeMsgId, uint32_t limit) {
    GroupChatHistoryReqPayload p = {
        .groupId = groupId, .beforeMsgId = beforeMsgId, .limit = limit};
    return packetSendEncrypted(c->fd, MsgGroupChatHistoryReq, &c->seqID,
                               c->aesKey.key, &p, sizeof(p));
}
