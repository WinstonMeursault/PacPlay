#include "server/gameRoom.h"
#include "crypto.h"
#include "log.h"
#include "pacplay_sdk.h"
#include "server/communication.h"
#include "server/database.h"
#include "server/gameControl.h"
#include "server/gameRunner.h"

#include <stdlib.h>
#include <string.h>

enum { StatusSuccess = 0, StatusFailure = 1 };

static void broadcastToRoom(ActiveGameRoom *gr, MessageType mt,
                            const void *data, size_t dataLen,
                            ClientSession *exclude) {
    for (int i = 0; i < gr->memberCount; i++) {
        if (gr->members[i] != exclude) {
            serverSendEncryptedPacket(gr->members[i], mt, data, dataLen);
        }
    }
}

ActiveGameRoom *serverFindActiveGameRoom(const Server *s, uint32_t gameRoomId) {
    for (int i = 0; i < s->activeGameRoomCount; i++) {
        if (s->activeGameRooms[i]->gameRoomId == gameRoomId) {
            return s->activeGameRooms[i];
        }
    }
    return NULL;
}

ActiveGameRoom *serverGetOrCreateActiveGameRoom(Server *s, uint32_t gameRoomId,
                                                uint32_t gameId,
                                                uint32_t hostUid) {
    ActiveGameRoom *gr = serverFindActiveGameRoom(s, gameRoomId);
    if (gr != NULL) {
        return gr;
    }
    if (s->activeGameRoomCount >= s->activeGameRoomCapacity) {
        int nc = s->activeGameRoomCapacity * 2;
        ActiveGameRoom **tmp = (ActiveGameRoom **)realloc(
            (void *)s->activeGameRooms, (size_t)nc * sizeof(ActiveGameRoom *));
        if (tmp == NULL) {
            LOG_ERROR("%s: realloc failed", __func__);
            return NULL;
        }
        s->activeGameRooms = tmp;
        s->activeGameRoomCapacity = nc;
    }
    gr = calloc(1, sizeof(ActiveGameRoom));
    if (gr == NULL) {
        LOG_ERROR("%s: calloc failed", __func__);
        return NULL;
    }
    gr->gameRoomId = gameRoomId;
    gr->gameId = gameId;
    gr->hostUid = hostUid;
    gr->state = GameRoomLobby;
    s->activeGameRooms[s->activeGameRoomCount++] = gr;
    return gr;
}

void serverRemoveActiveGameRoom(Server *s, uint32_t gameRoomId) {
    for (int i = 0; i < s->activeGameRoomCount; i++) {
        if (s->activeGameRooms[i]->gameRoomId == gameRoomId) {
            ActiveGameRoom *gr = s->activeGameRooms[i];
            if (gr->gameRunning) {
                gameRoomStopGame(gr);
            }
            free(gr);
            int r = s->activeGameRoomCount - i - 1;
            if (r > 0) {
                memmove((void *)&s->activeGameRooms[i],
                        (const void *)&s->activeGameRooms[i + 1],
                        (size_t)r * sizeof(ActiveGameRoom *));
            }
            s->activeGameRoomCount--;
            return;
        }
    }
}

void serverRemoveClientFromGameRoom(Server *s, ClientSession *cs) {
    if (cs->currentGameRoomId == 0) {
        return;
    }
    uint32_t grId = cs->currentGameRoomId;
    ActiveGameRoom *gr = serverFindActiveGameRoom(s, grId);
    if (gr == NULL) {
        cs->currentGameRoomId = 0;
        cs->state = SessionLobby;
        return;
    }

    if (cs->currentUser.uid == gr->hostUid) {
        serverDissolveGameRoom(s, grId, cs);
        return;
    }

    for (int i = 0; i < gr->memberCount; i++) {
        if (gr->members[i] == cs) {
            int r = gr->memberCount - i - 1;
            if (r > 0) {
                memmove((void *)&gr->members[i],
                        (const void *)&gr->members[i + 1],
                        (size_t)r * sizeof(ClientSession *));
            }
            gr->memberCount--;
            break;
        }
    }
    cs->currentGameRoomId = 0;
    cs->state = SessionLobby;

    {
        GameRoomMemberQuitPayload quitPayload;
        memset(&quitPayload, 0, sizeof(quitPayload));
        quitPayload.roomId = grId;
        quitPayload.uid = cs->currentUser.uid;
        quitPayload.dissolved = 0;
        broadcastToRoom(gr, MsgGameRoomMemberQuit, &quitPayload,
                        sizeof(quitPayload), NULL);
    }

    if (gr->memberCount == 0) {
        deleteGameRoom(s->gameRoomDB, grId);
        serverRemoveActiveGameRoom(s, grId);
    }
}

void serverDissolveGameRoom(Server *s, uint32_t gameRoomId,
                            ClientSession *exclude) {
    ActiveGameRoom *gr = serverFindActiveGameRoom(s, gameRoomId);
    if (gr == NULL) {
        return;
    }

    GameRoomMemberQuitPayload quitPayload;
    memset(&quitPayload, 0, sizeof(quitPayload));
    quitPayload.roomId = gameRoomId;
    quitPayload.uid = 0;
    quitPayload.dissolved = 1;
    broadcastToRoom(gr, MsgGameRoomMemberQuit, &quitPayload,
                    sizeof(quitPayload), exclude);

    if (gr->gameRunning) {
        gameRoomStopGame(gr);
    }

    for (int i = 0; i < gr->memberCount; i++) {
        gr->members[i]->currentGameRoomId = 0;
        gr->members[i]->state = SessionLobby;
    }
    gr->memberCount = 0;

    deleteGameRoom(s->gameRoomDB, gameRoomId);
    serverRemoveActiveGameRoom(s, gameRoomId);
}

int serverHandleGameRoomList(Server *s, ClientSession *cs) {
    size_t entryCount = (size_t)s->activeGameRoomCount;
    if (entryCount == 0) {
        return serverSendEncryptedPacket(cs, MsgGameRoomListResp, NULL, 0);
    }

    size_t payloadLen = entryCount * sizeof(GameRoomListEntry);
    GameRoomListEntry *entries = malloc(payloadLen);
    if (entries == NULL) {
        return serverSendEncryptedPacket(cs, MsgGameRoomListResp, NULL, 0);
    }

    for (size_t i = 0; i < entryCount; i++) {
        ActiveGameRoom *room = s->activeGameRooms[i];
        entries[i].gameRoomId = room->gameRoomId;
        entries[i].gameId = room->gameId;
        entries[i].hostUid = room->hostUid;
        entries[i].memberCount = (uint32_t)room->memberCount;
        entries[i].state = (uint8_t)room->state;

        memset(entries[i].hostNickname, 0, sizeof(entries[i].hostNickname));
        memset(entries[i].hostUsername, 0, sizeof(entries[i].hostUsername));
        for (int j = 0; j < room->memberCount; j++) {
            if (room->members[j]->currentUser.uid == room->hostUid) {
                memcpy(entries[i].hostNickname,
                       room->members[j]->currentUser.nickname,
                       sizeof(entries[i].hostNickname) - 1);
                memcpy(entries[i].hostUsername,
                       room->members[j]->currentUser.username,
                       sizeof(entries[i].hostUsername) - 1);
                break;
            }
        }
    }

    int ret =
        serverSendEncryptedPacket(cs, MsgGameRoomListResp, entries, payloadLen);
    free(entries);
    return ret;
}

int serverHandleGameRoomCreate(Server *s, ClientSession *cs,
                               const Packet *pkt) {
    if (pkt->header.payloadLength != sizeof(GameRoomCreatePayload)) {
        GameRoomCreateRespPayload resp = {.status = StatusFailure,
                                          .gameRoomId = 0};
        return serverSendEncryptedPacket(cs, MsgGameRoomCreateResp, &resp,
                                         sizeof(resp));
    }

    const GameRoomCreatePayload *req =
        (const GameRoomCreatePayload *)pkt->payload;

    if (cs->currentGameRoomId != 0) {
        serverRemoveClientFromGameRoom(s, cs);
    }
    if (cs->currentGroupId != 0) {
        (void)groupRemoveMember(s->groupDB, cs->currentGroupId,
                                cs->currentUser.uid);
        cs->currentGroupId = 0;
    }

    enum { MaxGenRetries = 100 };
    uint32_t genRoomId = 0;
    for (int retry = 0; retry < MaxGenRetries; retry++) {
        uint8_t raw[sizeof(uint32_t)];
        if (cryptoRandomBytes(raw, sizeof(raw)) != 0) {
            GameRoomCreateRespPayload resp = {.status = StatusFailure,
                                              .gameRoomId = 0};
            return serverSendEncryptedPacket(cs, MsgGameRoomCreateResp, &resp,
                                             sizeof(resp));
        }
        memcpy(&genRoomId, raw, sizeof(genRoomId));
        if (genRoomId == 0) {
            continue;
        }
        if (gameRoomExists(s->gameRoomDB, genRoomId) == DB_FAIL) {
            break;
        }
    }
    if (genRoomId == 0) {
        GameRoomCreateRespPayload resp = {.status = StatusFailure,
                                          .gameRoomId = 0};
        return serverSendEncryptedPacket(cs, MsgGameRoomCreateResp, &resp,
                                         sizeof(resp));
    }

    if (createGameRoom(s->gameRoomDB, genRoomId, req->gameId,
                       cs->currentUser.uid) != DB_SUCC) {
        GameRoomCreateRespPayload resp = {.status = StatusFailure,
                                          .gameRoomId = 0};
        return serverSendEncryptedPacket(cs, MsgGameRoomCreateResp, &resp,
                                         sizeof(resp));
    }

    ActiveGameRoom *gr = serverGetOrCreateActiveGameRoom(
        s, genRoomId, req->gameId, cs->currentUser.uid);
    if (gr == NULL) {
        deleteGameRoom(s->gameRoomDB, genRoomId);
        GameRoomCreateRespPayload resp = {.status = StatusFailure,
                                          .gameRoomId = 0};
        return serverSendEncryptedPacket(cs, MsgGameRoomCreateResp, &resp,
                                         sizeof(resp));
    }

    gr->members[gr->memberCount++] = cs;
    cs->currentGameRoomId = genRoomId;
    cs->state = SessionGameRoomLobby;

    GameRoomCreateRespPayload resp = {.status = StatusSuccess,
                                      .gameRoomId = genRoomId};
    return serverSendEncryptedPacket(cs, MsgGameRoomCreateResp, &resp,
                                     sizeof(resp));
}

int serverHandleGameRoomJoin(Server *s, ClientSession *cs, const Packet *pkt) {
    if (pkt->header.payloadLength != sizeof(GameRoomJoinPayload)) {
        uint8_t status = StatusFailure;
        return serverSendEncryptedPacket(cs, MsgGameRoomJoinResp, &status,
                                         sizeof(status));
    }

    const GameRoomJoinPayload *req = (const GameRoomJoinPayload *)pkt->payload;
    ActiveGameRoom *gr = serverFindActiveGameRoom(s, req->gameRoomId);

    if (gr == NULL || gr->memberCount >= MAX_CLIENTS_PER_ROOM ||
        gr->state != GameRoomLobby) {
        uint8_t status = StatusFailure;
        return serverSendEncryptedPacket(cs, MsgGameRoomJoinResp, &status,
                                         sizeof(status));
    }

    if (cs->currentGameRoomId != 0) {
        serverRemoveClientFromGameRoom(s, cs);
    }
    if (cs->currentGroupId != 0) {
        (void)groupRemoveMember(s->groupDB, cs->currentGroupId,
                                cs->currentUser.uid);
        cs->currentGroupId = 0;
    }

    gr = serverFindActiveGameRoom(s, req->gameRoomId);
    if (gr == NULL || gr->memberCount >= MAX_CLIENTS_PER_ROOM ||
        gr->state != GameRoomLobby) {
        uint8_t status = StatusFailure;
        return serverSendEncryptedPacket(cs, MsgGameRoomJoinResp, &status,
                                         sizeof(status));
    }

    gr->members[gr->memberCount++] = cs;
    cs->currentGameRoomId = req->gameRoomId;
    cs->state = SessionGameRoomLobby;

    {
        uint8_t status = StatusSuccess;
        serverSendEncryptedPacket(cs, MsgGameRoomJoinResp, &status,
                                  sizeof(status));
    }

    {
        size_t listLen = (size_t)gr->memberCount * sizeof(GameRoomMemberInfo);
        GameRoomMemberInfo *memberList = malloc(listLen);
        if (memberList != NULL) {
            for (int i = 0; i < gr->memberCount; i++) {
                memberList[i].roomId = gr->gameRoomId;
                memberList[i].uid = gr->members[i]->currentUser.uid;
                memcpy(memberList[i].nickname,
                       gr->members[i]->currentUser.nickname,
                       sizeof(memberList[i].nickname) - 1);
                memberList[i].nickname[sizeof(memberList[i].nickname) - 1] =
                    '\0';
                memcpy(memberList[i].username,
                       gr->members[i]->currentUser.username,
                       sizeof(memberList[i].username) - 1);
                memberList[i].username[sizeof(memberList[i].username) - 1] =
                    '\0';
            }
            serverSendEncryptedPacket(cs, MsgGameRoomMemberList, memberList,
                                      listLen);
            free(memberList);
        }

        GameRoomMemberInfo joinInfo;
        memset(&joinInfo, 0, sizeof(joinInfo));
        joinInfo.roomId = gr->gameRoomId;
        joinInfo.uid = cs->currentUser.uid;
        memcpy(joinInfo.nickname, cs->currentUser.nickname,
               sizeof(joinInfo.nickname) - 1);
        memcpy(joinInfo.username, cs->currentUser.username,
               sizeof(joinInfo.username) - 1);
        broadcastToRoom(gr, MsgGameRoomMemberJoin, &joinInfo, sizeof(joinInfo),
                        cs);
    }

    return SERVER_SUCC;
}

int serverHandleGameRoomQuit(Server *s, ClientSession *cs) {
    serverRemoveClientFromGameRoom(s, cs);
    uint8_t status = StatusSuccess;
    return serverSendEncryptedPacket(cs, MsgGameRoomQuitResp, &status,
                                     sizeof(status));
}

int serverHandleGameRoomStart(Server *s, ClientSession *cs, const Packet *pkt) {
    if (pkt->header.payloadLength != sizeof(GameRoomStartPayload)) {
        uint8_t status = StatusFailure;
        return serverSendEncryptedPacket(cs, MsgGameRoomStartResp, &status,
                                         sizeof(status));
    }

    const GameRoomStartPayload *req =
        (const GameRoomStartPayload *)pkt->payload;
    ActiveGameRoom *gr = serverFindActiveGameRoom(s, req->gameRoomId);

    if (gr == NULL || cs->currentUser.uid != gr->hostUid ||
        gr->state != GameRoomLobby) {
        uint8_t status = StatusFailure;
        return serverSendEncryptedPacket(cs, MsgGameRoomStartResp, &status,
                                         sizeof(status));
    }

    GameInfo gameInfo;
    if (getGameById(s->gameDB, gr->gameId, &gameInfo) != DB_SUCC) {
        uint8_t status = StatusFailure;
        return serverSendEncryptedPacket(cs, MsgGameRoomStartResp, &status,
                                         sizeof(status));
    }

    GamePlatformInfo platInfo;
    if (getGamePlatform(s->gameDB, gr->gameId, "linux", "server", &platInfo) !=
        DB_SUCC) {
        gameInfoFree(&gameInfo);
        uint8_t status = StatusFailure;
        return serverSendEncryptedPacket(cs, MsgGameRoomStartResp, &status,
                                         sizeof(status));
    }

    enum { PathBufSize = 512 };
    char soPath[PathBufSize];
    snprintf(soPath, sizeof(soPath), GAME_LIB_DIR "/%u/%s/server/%s/%s",
             gr->gameId, gameInfo.version, "linux", platInfo.fileName);
    gameInfoFree(&gameInfo);
    gamePlatformInfoFree(&platInfo);

    if (gameRoomStartGame(gr, soPath) != SERVER_SUCC) {
        uint8_t status = StatusFailure;
        return serverSendEncryptedPacket(cs, MsgGameRoomStartResp, &status,
                                         sizeof(status));
    }

    gr->state = GameRoomPlaying;
    for (int i = 0; i < gr->memberCount; i++) {
        gr->members[i]->state = SessionGameRoomPlay;
    }

    uint8_t status = StatusSuccess;
    for (int i = 0; i < gr->memberCount; i++) {
        serverSendEncryptedPacket(gr->members[i], MsgGameRoomStartResp, &status,
                                  sizeof(status));
    }
    return SERVER_SUCC;
}

int serverHandleGameRoomPlayData(Server *s, ClientSession *cs,
                                 const Packet *pkt) {
    if (cs->currentGameRoomId == 0 || pkt->payload == NULL ||
        pkt->header.payloadLength == 0 ||
        pkt->header.payloadLength > MAX_PAYLOAD_LEN) {
        return SERVER_SUCC;
    }

    ActiveGameRoom *gr = serverFindActiveGameRoom(s, cs->currentGameRoomId);
    if (gr == NULL || !gr->gameRunning || gr->sdk == NULL) {
        return SERVER_SUCC;
    }

    pacplay_srv_push_received(gr->sdk, pkt->payload, pkt->header.payloadLength);

    for (int i = 0; i < gr->memberCount; i++) {
        if (gr->members[i] != cs) {
            serverSendEncryptedPacket(gr->members[i], MsgGameRoomPlayData,
                                      pkt->payload, pkt->header.payloadLength);
        }
    }

    return SERVER_SUCC;
}
