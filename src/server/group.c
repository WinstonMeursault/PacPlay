/**
 * @file group.c
 * @brief Server-side group chat lifecycle management — implementation.
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

#include "group.h"

#include "crypto.h"
#include "log.h"
#include "server.h"
#include "server/communication.h"
#include "server/database.h"
#include "server/onlineTracker.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* ──────────────────────────── local constants ───────────────────────────── */
enum {
    StatusSuccess = 0,
    StatusFailure = 1,
    MaxGroupMembers = 50,
    MaxRandomRetries = 10
};

/* ────────────────────────────── local helpers ───────────────────────────── */

/**
 * @brief Generate a random non-zero groupId and verify it does not collide.
 *
 * Uses cryptoRandomBytes for the raw entropy.  Retries up to
 * MaxRandomRetries if the generated id already exists or is zero.
 *
 * @param s  Server instance (groupDB must be open).
 * @return Generated groupId, or 0 on failure.
 */
static uint32_t generateGroupId(Server *s) {
    for (int attempt = 0; attempt < MaxRandomRetries; attempt++) {
        uint32_t candidate = 0;
        if (cryptoRandomBytes((uint8_t *)&candidate, sizeof(candidate)) !=
            PROTOCOL_SUCC) {
            LOG_ERROR("%s: cryptoRandomBytes failed", __func__);
            return 0;
        }
        if (candidate == 0) {
            continue;
        }
        GroupInfo info;
        memset(&info, 0, sizeof(info));
        if (groupGetInfo(s->groupDB, candidate, &info) == DB_FAIL) {
            return candidate;
        }
    }
    LOG_ERROR("%s: failed to generate unique groupId after %d attempts",
              __func__, MaxRandomRetries);
    return 0;
}

/**
 * @brief Send a GroupMemberNotify to every online member of a group.
 *
 * Looks up member UIDs via groupMemberList(), then sends @p mt (either
 * MsgGroupMemberJoin or MsgGroupMemberQuit) with the supplied @p notify
 * payload to each online member except @p exclude.
 *
 * @param s        Server instance.
 * @param groupId  Target group.
 * @param mt       Notification message type.
 * @param notify   GroupMemberNotify payload (pointer to a single struct).
 * @param exclude  ClientSession to skip, or NULL.
 */
static void notifyGroupMembers(Server *s, uint32_t groupId, MessageType mt,
                               const GroupMemberNotify *notify,
                               const ClientSession *exclude) {
    uint32_t *uids = NULL;
    size_t count = 0;
    if (groupMemberList(s->groupDB, groupId, &uids, &count) != DB_SUCC) {
        return;
    }
    for (size_t i = 0; i < count; i++) {
        ClientSession *member = onlineTrackerFind(s->onlineTrk, uids[i]);
        if (member == NULL || member == exclude) {
            continue;
        }
        serverSendEncryptedPacket(member, mt, notify,
                                  sizeof(GroupMemberNotify));
    }
    free(uids);
}

/**
 * @brief Leave the group identified by @p groupId for client @p cs.
 *
 * Calls groupRemoveMember() and notifies remaining online members.
 * If the group becomes empty the group is deleted from the database.
 *
 * @param s        Server instance.
 * @param cs       Leaving client session.
 * @param groupId  Group to leave.
 */
static void leaveGroup(Server *s, ClientSession *cs, uint32_t groupId) {
    if (groupRemoveMember(s->groupDB, groupId, cs->currentUser.uid) !=
        DB_SUCC) {
        return;
    }

    GroupMemberNotify notify;
    memset(&notify, 0, sizeof(notify));
    notify.groupId = groupId;
    notify.uid = cs->currentUser.uid;
    memcpy(notify.nickname, cs->currentUser.nickname, LOGIN_NICKNAME_LEN);

    notifyGroupMembers(s, groupId, MsgGroupMemberQuit, &notify, cs);

    GroupInfo info;
    memset(&info, 0, sizeof(info));
    if (groupGetInfo(s->groupDB, groupId, &info) == DB_SUCC &&
        info.memberCount == 0) {
        groupDelete(s->groupDB, groupId);
    }
}

/* ───────────────────────────── group handlers ──────────────────────────────
 */

int serverHandleGroupCreate(Server *s, ClientSession *cs, const Packet *pkt) {
    if (pkt->header.payloadLength < GROUP_NAME_LEN) {
        LOG_WARN("%s: payload too small (%u bytes)", __func__,
                 pkt->header.payloadLength);
        serverSendStatusResponse(cs, MsgGroupCreateResp, StatusFailure);
        return SERVER_SUCC;
    }
    if (pkt->header.payloadLength > sizeof(GroupCreatePayload)) {
        LOG_WARN("%s: payload too large (%u bytes)", __func__,
                 pkt->header.payloadLength);
        serverSendStatusResponse(cs, MsgGroupCreateResp, StatusFailure);
        return SERVER_SUCC;
    }

    const GroupCreatePayload *payload =
        (const GroupCreatePayload *)pkt->payload;

    if (memchr(payload->groupName, '\0', GROUP_NAME_LEN) == NULL) {
        LOG_WARN("%s: groupName not NUL-terminated", __func__);
        serverSendStatusResponse(cs, MsgGroupCreateResp, StatusFailure);
        return SERVER_SUCC;
    }

    uint32_t groupId = generateGroupId(s);
    if (groupId == 0) {
        serverSendStatusResponse(cs, MsgGroupCreateResp, StatusFailure);
        return SERVER_SUCC;
    }

    if (groupCreate(s->groupDB, groupId, payload->groupName,
                    cs->currentUser.uid) != DB_SUCC) {
        LOG_ERROR("%s: groupCreate failed (groupId=%u)", __func__, groupId);
        serverSendStatusResponse(cs, MsgGroupCreateResp, StatusFailure);
        return SERVER_SUCC;
    }

    if (groupAddMember(s->groupDB, groupId, cs->currentUser.uid) != DB_SUCC) {
        LOG_ERROR("%s: groupAddMember failed (groupId=%u uid=%u)", __func__,
                  groupId, cs->currentUser.uid);
        groupDelete(s->groupDB, groupId);
        serverSendStatusResponse(cs, MsgGroupCreateResp, StatusFailure);
        return SERVER_SUCC;
    }

    cs->currentGroupId = groupId;

    GroupCreateRespPayload resp;
    memset(&resp, 0, sizeof(resp));
    resp.status = StatusSuccess;
    resp.groupId = groupId;

    int ret =
        serverSendEncryptedPacket(cs, MsgGroupCreateResp, &resp, sizeof(resp));
    return (ret == SERVER_SUCC) ? SERVER_SUCC : SERVER_FAIL;
}

int serverHandleGroupJoin(Server *s, ClientSession *cs, const Packet *pkt) {
    if (pkt->header.payloadLength != sizeof(GroupOpPayload)) {
        LOG_WARN("%s: invalid payload length (%u, expected %zu)", __func__,
                 pkt->header.payloadLength, sizeof(GroupOpPayload));
        serverSendStatusResponse(cs, MsgGroupJoinResp, StatusFailure);
        return SERVER_SUCC;
    }

    const GroupOpPayload *payload = (const GroupOpPayload *)pkt->payload;
    uint32_t groupId = payload->groupId;

    GroupInfo info;
    memset(&info, 0, sizeof(info));
    if (groupGetInfo(s->groupDB, groupId, &info) != DB_SUCC) {
        LOG_WARN("%s: group %u does not exist", __func__, groupId);
        serverSendStatusResponse(cs, MsgGroupJoinResp, StatusFailure);
        return SERVER_SUCC;
    }

    if (groupIsMember(s->groupDB, groupId, cs->currentUser.uid) == DB_SUCC) {
        LOG_WARN("%s: uid %u already member of group %u", __func__,
                 cs->currentUser.uid, groupId);
        serverSendStatusResponse(cs, MsgGroupJoinResp, StatusFailure);
        return SERVER_SUCC;
    }

    if (info.memberCount >= MaxGroupMembers) {
        LOG_WARN("%s: group %u is full (%u/%u)", __func__, groupId,
                 info.memberCount, MaxGroupMembers);
        serverSendStatusResponse(cs, MsgGroupJoinResp, StatusFailure);
        return SERVER_SUCC;
    }

    if (cs->currentGroupId != 0) {
        leaveGroup(s, cs, cs->currentGroupId);
    }

    if (groupAddMember(s->groupDB, groupId, cs->currentUser.uid) != DB_SUCC) {
        LOG_ERROR("%s: groupAddMember failed (groupId=%u uid=%u)", __func__,
                  groupId, cs->currentUser.uid);
        serverSendStatusResponse(cs, MsgGroupJoinResp, StatusFailure);
        return SERVER_SUCC;
    }

    GroupMemberNotify notify;
    memset(&notify, 0, sizeof(notify));
    notify.groupId = groupId;
    notify.uid = cs->currentUser.uid;
    memcpy(notify.nickname, cs->currentUser.nickname, LOGIN_NICKNAME_LEN);

    notifyGroupMembers(s, groupId, MsgGroupMemberJoin, &notify, cs);

    /* Owner's currentGroupId is set in serverHandleGroupCreate. */

    cs->currentGroupId = groupId;

    serverSendStatusResponse(cs, MsgGroupJoinResp, StatusSuccess);
    return SERVER_SUCC;
}

int serverHandleGroupQuit(Server *s, ClientSession *cs, const Packet *pkt) {
    if (pkt->header.payloadLength != sizeof(GroupOpPayload)) {
        LOG_WARN("%s: invalid payload length (%u, expected %zu)", __func__,
                 pkt->header.payloadLength, sizeof(GroupOpPayload));
        serverSendStatusResponse(cs, MsgGroupQuitResp, StatusFailure);
        return SERVER_SUCC;
    }

    const GroupOpPayload *payload = (const GroupOpPayload *)pkt->payload;
    uint32_t groupId = payload->groupId;

    if (cs->currentGroupId != groupId) {
        LOG_WARN("%s: uid %u not in group %u (currentGroupId=%u)", __func__,
                 cs->currentUser.uid, groupId, cs->currentGroupId);
        serverSendStatusResponse(cs, MsgGroupQuitResp, StatusFailure);
        return SERVER_SUCC;
    }

    leaveGroup(s, cs, groupId);
    cs->currentGroupId = 0;

    serverSendStatusResponse(cs, MsgGroupQuitResp, StatusSuccess);
    return SERVER_SUCC;
}

int serverHandleGroupList(Server *s, ClientSession *cs) {
    GroupInfo *groups = NULL;
    size_t count = 0;
    if (groupListAll(s->groupDB, &groups, &count) != DB_SUCC) {
        serverSendEncryptedPacket(cs, MsgGroupListResp, NULL, 0);
        return SERVER_SUCC;
    }
    if (count == 0) {
        serverSendEncryptedPacket(cs, MsgGroupListResp, NULL, 0);
        return SERVER_SUCC;
    }

    size_t bufLen = sizeof(uint32_t) + count * sizeof(GroupInfo);
    uint8_t *buf = malloc(bufLen);
    if (buf == NULL) {
        LOG_ERROR("%s: malloc failed", __func__);
        free(groups);
        return SERVER_FAIL;
    }

    uint32_t cnt = (uint32_t)count;
    memcpy(buf, &cnt, sizeof(cnt));

    size_t offset = sizeof(uint32_t);
    for (size_t i = 0; i < count; i++) {
        memcpy(buf + offset, &groups[i], sizeof(GroupInfo));
        offset += sizeof(GroupInfo);
    }

    int ret = serverSendEncryptedPacket(cs, MsgGroupListResp, buf, bufLen);
    free(buf);
    free(groups);
    return (ret == SERVER_SUCC) ? SERVER_SUCC : SERVER_FAIL;
}

int serverHandleGroupChat(Server *s, ClientSession *cs, const Packet *pkt) {
    /* Minimum: groupId (uint32_t) + timestamp (int64_t) = 12 bytes. */
    if (pkt->header.payloadLength < sizeof(uint32_t) + sizeof(int64_t)) {
        LOG_WARN("%s: payload too small (%u bytes)", __func__,
                 pkt->header.payloadLength);
        return SERVER_FAIL;
    }

    const GroupChatPayload *chat = (const GroupChatPayload *)pkt->payload;
    size_t msgLen =
        pkt->header.payloadLength - sizeof(uint32_t) - sizeof(int64_t);

    if (msgLen == 0 || memchr(chat->message, '\0', msgLen) == NULL) {
        LOG_WARN("%s: message not NUL-terminated or empty", __func__);
        return SERVER_FAIL;
    }

    if (cs->currentGroupId != chat->groupId) {
        LOG_WARN("%s: uid %u not in group %u (currentGroupId=%u)", __func__,
                 cs->currentUser.uid, chat->groupId, cs->currentGroupId);
        return SERVER_FAIL;
    }

    uint64_t msgId = 0;
    if (groupStoreChat(s->groupDB, chat->groupId, cs->currentUser.uid,
                       (const char *)chat->message, chat->timestamp,
                       &msgId) != DB_SUCC) {
        LOG_WARN("%s: groupStoreChat failed", __func__);
        return SERVER_FAIL;
    }

    _Static_assert(offsetof(GroupChatBroadcastPayload, message) ==
                       sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t) +
                           sizeof(int64_t),
                   "GroupChatBroadcastPayload layout mismatch");
    size_t bcLen = offsetof(GroupChatBroadcastPayload, message) + msgLen;
    GroupChatBroadcastPayload *bc = malloc(bcLen);
    if (bc == NULL) {
        LOG_ERROR("%s: malloc failed (errno=%d)", __func__, errno);
        return SERVER_FAIL;
    }

    bc->groupId = chat->groupId;
    bc->uid = cs->currentUser.uid;
    bc->msgId = (uint32_t)msgId;
    bc->timestamp = chat->timestamp;
    memcpy(bc->message, chat->message, msgLen);

    uint32_t *uids = NULL;
    size_t memberCount = 0;
    if (groupMemberList(s->groupDB, chat->groupId, &uids, &memberCount) ==
        DB_SUCC) {
        for (size_t i = 0; i < memberCount; i++) {
            ClientSession *memberCs = onlineTrackerFind(s->onlineTrk, uids[i]);
            if (memberCs == NULL || memberCs == cs) {
                continue;
            }
            serverSendEncryptedPacket(memberCs, MsgGroupChatBroadcast, bc,
                                      bcLen);
        }
        free(uids);
    }

    free(bc);
    return SERVER_SUCC;
}

int serverHandleGroupKick(Server *s, ClientSession *cs, const Packet *pkt) {
    if (pkt->header.payloadLength != sizeof(GroupKickPayload)) {
        LOG_WARN("%s: invalid payload length (%u, expected %zu)", __func__,
                 pkt->header.payloadLength, sizeof(GroupKickPayload));
        serverSendStatusResponse(cs, MsgGroupKickResp, StatusFailure);
        return SERVER_SUCC;
    }

    const GroupKickPayload *payload = (const GroupKickPayload *)pkt->payload;

    GroupInfo info;
    memset(&info, 0, sizeof(info));
    if (groupGetInfo(s->groupDB, payload->groupId, &info) != DB_SUCC) {
        LOG_WARN("%s: group %u does not exist", __func__, payload->groupId);
        serverSendStatusResponse(cs, MsgGroupKickResp, StatusFailure);
        return SERVER_SUCC;
    }

    if (info.ownerUid != cs->currentUser.uid) {
        LOG_WARN("%s: uid %u not owner of group %u (owner=%u)", __func__,
                 cs->currentUser.uid, payload->groupId, info.ownerUid);
        serverSendStatusResponse(cs, MsgGroupKickResp, StatusFailure);
        return SERVER_SUCC;
    }

    if (payload->targetUid == info.ownerUid) {
        LOG_WARN("%s: cannot kick owner (uid=%u groupId=%u)", __func__,
                 payload->targetUid, payload->groupId);
        serverSendStatusResponse(cs, MsgGroupKickResp, StatusFailure);
        return SERVER_SUCC;
    }

    if (groupIsMember(s->groupDB, payload->groupId, payload->targetUid) !=
        DB_SUCC) {
        LOG_WARN("%s: uid %u not member of group %u", __func__,
                 payload->targetUid, payload->groupId);
        serverSendStatusResponse(cs, MsgGroupKickResp, StatusFailure);
        return SERVER_SUCC;
    }

    if (groupRemoveMember(s->groupDB, payload->groupId, payload->targetUid) !=
        DB_SUCC) {
        LOG_ERROR("%s: groupRemoveMember failed (groupId=%u uid=%u)", __func__,
                  payload->groupId, payload->targetUid);
        serverSendStatusResponse(cs, MsgGroupKickResp, StatusFailure);
        return SERVER_SUCC;
    }

    GroupMemberNotify notify;
    memset(&notify, 0, sizeof(notify));
    notify.groupId = payload->groupId;
    notify.uid = payload->targetUid;
    memcpy(notify.nickname, "", 1);

    ClientSession *targetCs = onlineTrackerFind(s->onlineTrk, payload->targetUid);
    if (targetCs != NULL) {
        memcpy(notify.nickname, targetCs->currentUser.nickname,
               LOGIN_NICKNAME_LEN);
        serverSendEncryptedPacket(targetCs, MsgGroupMemberQuit,
                                  &notify, sizeof(notify));
        targetCs->currentGroupId = 0;
    }

    notifyGroupMembers(s, payload->groupId, MsgGroupMemberQuit, &notify, cs);

    serverSendStatusResponse(cs, MsgGroupKickResp, StatusSuccess);
    return SERVER_SUCC;
}

int serverHandleGroupDisband(Server *s, ClientSession *cs, const Packet *pkt) {
    if (pkt->header.payloadLength != sizeof(GroupOpPayload)) {
        LOG_WARN("%s: invalid payload length (%u, expected %zu)", __func__,
                 pkt->header.payloadLength, sizeof(GroupOpPayload));
        serverSendStatusResponse(cs, MsgGroupDisbandResp, StatusFailure);
        return SERVER_SUCC;
    }

    const GroupOpPayload *payload = (const GroupOpPayload *)pkt->payload;

    GroupInfo info;
    memset(&info, 0, sizeof(info));
    if (groupGetInfo(s->groupDB, payload->groupId, &info) != DB_SUCC) {
        LOG_WARN("%s: group %u does not exist", __func__, payload->groupId);
        serverSendStatusResponse(cs, MsgGroupDisbandResp, StatusFailure);
        return SERVER_SUCC;
    }

    if (info.ownerUid != cs->currentUser.uid) {
        LOG_WARN("%s: uid %u not owner of group %u (owner=%u)", __func__,
                 cs->currentUser.uid, payload->groupId, info.ownerUid);
        serverSendStatusResponse(cs, MsgGroupDisbandResp, StatusFailure);
        return SERVER_SUCC;
    }

    GroupDisbandNotifyPayload notify;
    memset(&notify, 0, sizeof(notify));
    notify.groupId = payload->groupId;

    uint32_t *uids = NULL;
    size_t memberCount = 0;
    if (groupMemberList(s->groupDB, payload->groupId, &uids, &memberCount) ==
        DB_SUCC) {
        for (size_t i = 0; i < memberCount; i++) {
            ClientSession *memberCs =
                onlineTrackerFind(s->onlineTrk, uids[i]);
            if (memberCs != NULL) {
                serverSendEncryptedPacket(memberCs,
                                          MsgGroupDisbandNotify, &notify,
                                          sizeof(notify));
                memberCs->currentGroupId = 0;
            }
        }
    }

    if (uids != NULL) {
        for (size_t i = 0; i < memberCount; i++) {
            groupRemoveMember(s->groupDB, payload->groupId, uids[i]);
        }
        free(uids);
    }

    groupDelete(s->groupDB, payload->groupId);

    serverSendStatusResponse(cs, MsgGroupDisbandResp, StatusSuccess);
    return SERVER_SUCC;
}

int serverHandleGroupChatHistory(Server *s, ClientSession *cs,
                                 const Packet *pkt) {
    if (pkt->header.payloadLength < sizeof(GroupChatHistoryReqPayload)) {
        LOG_WARN("%s: payload too small (%u bytes, need %zu)", __func__,
                 pkt->header.payloadLength,
                 sizeof(GroupChatHistoryReqPayload));
        return SERVER_FAIL;
    }

    const GroupChatHistoryReqPayload *req =
        (const GroupChatHistoryReqPayload *)pkt->payload;

    Chat *chats = NULL;
    size_t count = 0;
    if (groupChatHistory(s->groupDB, req->groupId, req->beforeMsgId, req->limit,
                         &chats, &count) != DB_SUCC) {
        LOG_WARN("%s: groupChatHistory failed", __func__);
        return SERVER_FAIL;
    }

    size_t bufSize = sizeof(uint32_t);
    size_t *entrySizes = NULL;
    if (count > 0) {
        entrySizes = malloc(count * sizeof(size_t));
        if (entrySizes == NULL) {
            LOG_ERROR("%s: malloc failed (errno=%d)", __func__, errno);
            for (size_t i = 0; i < count; i++) {
                free(chats[i].message);
            }
            free(chats);
            return SERVER_FAIL;
        }
    }

    for (size_t i = 0; i < count; i++) {
        size_t msgLen = strlen(chats[i].message) + 1;
        entrySizes[i] = offsetof(GroupChatBroadcastPayload, message) + msgLen;
        bufSize += entrySizes[i];
    }

    uint8_t *buf = malloc(bufSize);
    if (buf == NULL) {
        LOG_ERROR("%s: malloc failed (errno=%d)", __func__, errno);
        free(entrySizes);
        for (size_t i = 0; i < count; i++) {
            free(chats[i].message);
        }
        free(chats);
        return SERVER_FAIL;
    }

    uint32_t netCount = htonl((uint32_t)count);
    memcpy(buf, &netCount, sizeof(uint32_t));
    size_t offset = sizeof(uint32_t);

    for (size_t i = 0; i < count; i++) {
        GroupChatBroadcastPayload *gc =
            (GroupChatBroadcastPayload *)(buf + offset);
        gc->groupId = req->groupId;
        gc->uid = chats[i].uid;
        gc->msgId = (uint32_t)chats[i].msgId;
        gc->timestamp = (int64_t)chats[i].timestamp;
        size_t msgLen = strlen(chats[i].message) + 1;
        memcpy(gc->message, chats[i].message, msgLen);

        offset += entrySizes[i];
    }

    int ret = serverSendEncryptedPacket(cs, MsgGroupChatHistoryResp, buf,
                                        bufSize);

    free(buf);
    free(entrySizes);
    for (size_t i = 0; i < count; i++) {
        free(chats[i].message);
    }
    free(chats);

    if (ret != SERVER_SUCC) {
        LOG_WARN("%s: send failed", __func__);
        return SERVER_FAIL;
    }

    return SERVER_SUCC;
}
