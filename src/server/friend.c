/**
 * @file friend.c
 * @brief Server-side friend system handlers — implementation.
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

#include "friend.h"
#include "log.h"
#include "server/communication.h"
#include "server/database.h"
#include "server/onlineTracker.h"

#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

/* ──────────────────────────── local constants ───────────────────────────── */

enum { StatusSuccess = 0, StatusFailure = 1 };

/* ──────────────────────────── static helpers ────────────────────────────── */

/**
 * @brief Look up username and nickname from UserDB by uid.
 *
 * @param userDB  Open UserDB handle.
 * @param uid     User ID to look up.
 * @param info    Output FriendInfo whose username/nickname fields are
 *                populated on success.
 * @return SERVER_SUCC on success, SERVER_FAIL if not found or on error.
 */
static int lookupUserInfo(DB *userDB, uint32_t uid, FriendInfo *info) {
    if (userDB == NULL || userDB->handle == NULL) {
        return SERVER_FAIL;
    }

    const char sql[] = "SELECT username, nickname FROM users WHERE uid = ?;";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(userDB->handle, sql, (int)sizeof(sql) - 1,
                                &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("lookupUserInfo: prepare failed: %s",
                  sqlite3_errmsg(userDB->handle));
        return SERVER_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)uid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("lookupUserInfo: bind failed: %s",
                  sqlite3_errmsg(userDB->handle));
        sqlite3_finalize(stmt);
        return SERVER_FAIL;
    }

    int found = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *username = (const char *)sqlite3_column_text(stmt, 0);
        const char *nickname = (const char *)sqlite3_column_text(stmt, 1);
        if (username != NULL) {
            strncpy(info->username, username, sizeof(info->username) - 1);
        }
        if (nickname != NULL) {
            strncpy(info->nickname, nickname, sizeof(info->nickname) - 1);
        }
        found = 1;
    }

    sqlite3_finalize(stmt);
    return found ? SERVER_SUCC : SERVER_FAIL;
}

/**
 * @brief Send a FriendNotifyPayload to a user about their new friend.
 *
 * @param s          Server instance.
 * @param targetUid  The user to notify (recipient of the notification).
 * @param friendUid  The friend being announced (uid in the payload).
 * @param friendNick The friend's nickname.
 */
static void sendFriendNotify(Server *s, uint32_t targetUid, uint32_t friendUid,
                             const char *friendNick) {
    ClientSession *cs = onlineTrackerFind(s->onlineTrk, targetUid);
    if (cs == NULL) {
        return;
    }

    FriendNotifyPayload notify;
    memset(&notify, 0, sizeof(notify));
    notify.uid = friendUid;
    notify.online = onlineTrackerIsOnline(s->onlineTrk, friendUid) ? 1U : 0U;
    if (friendNick != NULL) {
        strncpy(notify.nickname, friendNick, sizeof(notify.nickname) - 1);
    }

    serverSendEncryptedPacket(cs, MsgFriendNotify, &notify, sizeof(notify));
}

/* ───────────────────────────── friend handlers ──────────────────────────── */

int serverHandleFriendRequest(Server *s, ClientSession *cs, const Packet *pkt) {
    if (pkt->header.payloadLength != sizeof(FriendOpPayload)) {
        serverSendStatusResponse(cs, MsgFriendRequestResp, StatusFailure);
        return SERVER_SUCC;
    }

    const FriendOpPayload *req = (const FriendOpPayload *)pkt->payload;
    uint32_t uid = cs->currentUser.uid;
    uint32_t targetUid = req->targetUid;

    if (uid == 0 || targetUid == 0 || uid == targetUid) {
        serverSendStatusResponse(cs, MsgFriendRequestResp, StatusFailure);
        return SERVER_SUCC;
    }

    if (friendIsFriend(s->friendDB, uid, targetUid) == DB_SUCC) {
        serverSendStatusResponse(cs, MsgFriendRequestResp, StatusFailure);
        return SERVER_SUCC;
    }

    if (friendRequestCreate(s->friendDB, uid, targetUid) != DB_SUCC) {
        serverSendStatusResponse(cs, MsgFriendRequestResp, StatusFailure);
        return SERVER_SUCC;
    }

    serverSendStatusResponse(cs, MsgFriendRequestResp, StatusSuccess);
    return SERVER_SUCC;
}

int serverHandleFriendAccept(Server *s, ClientSession *cs, const Packet *pkt) {
    if (pkt->header.payloadLength != sizeof(FriendOpPayload)) {
        serverSendStatusResponse(cs, MsgFriendAcceptResp, StatusFailure);
        return SERVER_SUCC;
    }

    const FriendOpPayload *req = (const FriendOpPayload *)pkt->payload;
    uint32_t ownUid = cs->currentUser.uid;
    uint32_t fromUid = req->targetUid;

    if (ownUid == 0 || fromUid == 0 || ownUid == fromUid) {
        serverSendStatusResponse(cs, MsgFriendAcceptResp, StatusFailure);
        return SERVER_SUCC;
    }

    if (friendRequestAccept(s->friendDB, fromUid, ownUid) != DB_SUCC) {
        serverSendStatusResponse(cs, MsgFriendAcceptResp, StatusFailure);
        return SERVER_SUCC;
    }

    serverSendStatusResponse(cs, MsgFriendAcceptResp, StatusSuccess);

    /* Look up nicknames and notify both users. */
    FriendInfo acceptorInfo;
    FriendInfo requesterInfo;
    memset(&acceptorInfo, 0, sizeof(acceptorInfo));
    memset(&requesterInfo, 0, sizeof(requesterInfo));
    lookupUserInfo(s->userDB, ownUid, &acceptorInfo);
    lookupUserInfo(s->userDB, fromUid, &requesterInfo);

    sendFriendNotify(s, ownUid, fromUid, requesterInfo.nickname);
    sendFriendNotify(s, fromUid, ownUid, acceptorInfo.nickname);

    return SERVER_SUCC;
}

int serverHandleFriendReject(Server *s, ClientSession *cs, const Packet *pkt) {
    if (pkt->header.payloadLength != sizeof(FriendOpPayload)) {
        serverSendStatusResponse(cs, MsgFriendReject, StatusFailure);
        return SERVER_SUCC;
    }

    const FriendOpPayload *req = (const FriendOpPayload *)pkt->payload;
    uint32_t ownUid = cs->currentUser.uid;
    uint32_t fromUid = req->targetUid;

    if (ownUid == 0 || fromUid == 0 || ownUid == fromUid) {
        serverSendStatusResponse(cs, MsgFriendReject, StatusFailure);
        return SERVER_SUCC;
    }

    if (friendRequestReject(s->friendDB, fromUid, ownUid) != DB_SUCC) {
        serverSendStatusResponse(cs, MsgFriendReject, StatusFailure);
        return SERVER_SUCC;
    }

    serverSendStatusResponse(cs, MsgFriendReject, StatusSuccess);
    return SERVER_SUCC;
}

int serverHandleFriendDelete(Server *s, ClientSession *cs, const Packet *pkt) {
    if (pkt->header.payloadLength != sizeof(FriendOpPayload)) {
        serverSendStatusResponse(cs, MsgFriendDeleteResp, StatusFailure);
        return SERVER_SUCC;
    }

    const FriendOpPayload *req = (const FriendOpPayload *)pkt->payload;
    uint32_t uid = cs->currentUser.uid;
    uint32_t targetUid = req->targetUid;

    if (uid == 0 || targetUid == 0 || uid == targetUid) {
        serverSendStatusResponse(cs, MsgFriendDeleteResp, StatusFailure);
        return SERVER_SUCC;
    }

    if (friendDelete(s->friendDB, uid, targetUid) != DB_SUCC) {
        serverSendStatusResponse(cs, MsgFriendDeleteResp, StatusFailure);
        return SERVER_SUCC;
    }

    serverSendStatusResponse(cs, MsgFriendDeleteResp, StatusSuccess);
    return SERVER_SUCC;
}

int serverHandleFriendList(Server *s, ClientSession *cs) {
    uint32_t uid = cs->currentUser.uid;

    FriendInfo *friends = NULL;
    size_t count = 0;

    if (uid == 0 ||
        friendListGet(s->friendDB, uid, &friends, &count) != DB_SUCC) {
        uint32_t zeroCount = 0;
        serverSendEncryptedPacket(cs, MsgFriendListResp, &zeroCount,
                                  sizeof(zeroCount));
        return SERVER_SUCC;
    }

    /* Enrich each friend entry with username, nickname, and online status. */
    for (size_t i = 0; i < count; i++) {
        uint32_t friendUid = friends[i].uid;
        lookupUserInfo(s->userDB, friendUid, &friends[i]);
        friends[i].online = onlineTrackerIsOnline(s->onlineTrk, friendUid) ? 1U : 0U;
    }

    /* Build response: uint32_t count + FriendInfo[count]. */
    size_t respSize = sizeof(uint32_t) + count * sizeof(FriendInfo);
    uint8_t *respBuf = malloc(respSize);
    if (respBuf == NULL) {
        LOG_ERROR("serverHandleFriendList: malloc failed (errno=%d)", errno);
        free(friends);
        return SERVER_FAIL;
    }

    uint32_t netCount = (uint32_t)count;
    memcpy(respBuf, &netCount, sizeof(netCount));
    memcpy(respBuf + sizeof(netCount), friends, count * sizeof(FriendInfo));

    int ret =
        serverSendEncryptedPacket(cs, MsgFriendListResp, respBuf, respSize);
    free(respBuf);
    free(friends);
    return (ret == SERVER_SUCC) ? SERVER_SUCC : SERVER_FAIL;
}
