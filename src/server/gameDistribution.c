#include "server/gameDistribution.h"

#include "crypto.h"
#include "log.h"
#include "server/communication.h"
#include "server/database.h"
#include "server/downloadPool.h"
#include "server/gameControl.h"
#include "server/gameRunner.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum {
    StatusOk = 0,
    StatusError = 1
};

int serverHandleGameList(Server *s, ClientSession *cs, const Packet *pkt) {
    if (pkt->header.payloadLength < sizeof(GameListReqPayload)) {
        LOG_WARN("serverHandleGameList: payload too short (fd=%d)", cs->fd);
        return SERVER_FAIL;
    }

    const GameListReqPayload *req = (const GameListReqPayload *)pkt->payload;
    uint32_t rangeStart = req->rangeStart;
    uint32_t rangeEnd = req->rangeEnd;

    GameInfoEntry *entries = NULL;
    size_t count = 0;
    if (listGameBrief(s->gameDB, rangeStart, rangeEnd, req->platform, &entries,
                      &count) != DB_SUCC) {
        LOG_ERROR("serverHandleGameList: listGameBrief failed");
        return SERVER_FAIL;
    }

    if (count == 0) {
        if (packetSendEncrypted(cs->fd, MsgGameListResp, &cs->seqID,
                                    cs->aesKey.key, NULL, 0) != PROTOCOL_SUCC) {
            return SERVER_FAIL;
        }
        return SERVER_SUCC;
    }

    size_t payloadSize = count * sizeof(GameInfoEntry);
    if (packetSendEncrypted(cs->fd, MsgGameListResp, &cs->seqID,
                                cs->aesKey.key, entries,
                                payloadSize) != PROTOCOL_SUCC) {
        free(entries);
        return SERVER_FAIL;
    }

    free(entries);
    return SERVER_SUCC;
}

static void sendDownloadFailure(ClientSession *cs) {
    GameDownloadRespPayload resp;
    memset(&resp, 0, sizeof(resp));
    resp.status = StatusError;
    (void)serverSendEncryptedPacket(cs, MsgGameDownloadResp, &resp,
                                    sizeof(resp));
}

int serverHandleGameDownload(Server *s, ClientSession *cs, const Packet *pkt) {
    if (pkt->header.payloadLength < sizeof(GameDownloadReqPayload)) {
        LOG_WARN("serverHandleGameDownload: payload too short (fd=%d)", cs->fd);
        return SERVER_FAIL;
    }

    const GameDownloadReqPayload *req =
        (const GameDownloadReqPayload *)pkt->payload;
    uint32_t gameId = req->gameId;
    uint32_t resumeChunkIndex = req->resumeChunkIndex;
    char platform[PLATFORM_NAME_LEN];
    memcpy(platform, req->platform, PLATFORM_NAME_LEN);
    platform[PLATFORM_NAME_LEN - 1] = '\0';

    GameInfo gameInfo;
    memset(&gameInfo, 0, sizeof(gameInfo));
    GamePlatformInfo platInfo;
    memset(&platInfo, 0, sizeof(platInfo));

    if (getGameById(s->gameDB, gameId, &gameInfo) != DB_SUCC) {
        LOG_WARN("serverHandleGameDownload: game %u not found", gameId);
        sendDownloadFailure(cs);
        return SERVER_SUCC;
    }

    if (getGamePlatform(s->gameDB, gameId, platform, "client", &platInfo) != DB_SUCC) {
        LOG_WARN("serverHandleGameDownload: platform %s not found for game %u",
                 platform, gameId);
        sendDownloadFailure(cs);
        gameInfoFree(&gameInfo);
        return SERVER_SUCC;
    }

    char filePath[FILE_PATH_MAX_LEN];
    (void)snprintf(filePath, sizeof(filePath), GAME_LIB_DIR "/%u/%s/download.tar.gz",
                   gameId, gameInfo.version);

    if (access(filePath, R_OK) != 0) {
        LOG_WARN("serverHandleGameDownload: file not readable: %s", filePath);
        sendDownloadFailure(cs);
        gameInfoFree(&gameInfo);
        gamePlatformInfoFree(&platInfo);
        return SERVER_SUCC;
    }

    uint32_t totalChunks =
        (uint32_t)((platInfo.fileSize + GAME_CHUNK_SIZE - 1) / GAME_CHUNK_SIZE);

    uint8_t token[DATA_AUTH_TOKEN_LEN];
    cryptoRandomBytes(token, DATA_AUTH_TOKEN_LEN);

    PendingToken pt;
    memset(&pt, 0, sizeof(pt));
    memcpy(pt.token, token, DATA_AUTH_TOKEN_LEN);
    memcpy(pt.mainAESKey, cs->aesKey.key, AES_GCM_KEY_LEN);
    pt.gameId = gameId;
    pt.resumeChunkIndex = resumeChunkIndex;
    strncpy(pt.filePath, filePath, FILE_PATH_MAX_LEN);
    pt.fileSize = platInfo.fileSize;
    pt.totalChunks = totalChunks;
    pt.metadata.gameId = gameId;
    pt.metadata.fileSize = platInfo.fileSize;
    strncpy(pt.metadata.name, gameInfo.name, GAME_NAME_LEN);
    strncpy(pt.metadata.version, gameInfo.version, GAME_VERSION_LEN);
    strncpy(pt.metadata.hash, platInfo.hash, GAME_HASH_LEN);
    strncpy(pt.metadata.platform, platform, PLATFORM_NAME_LEN);

    if (downloadPoolRegisterToken(s->downloadPool, &pt) != 0) {
        LOG_ERROR("serverHandleGameDownload: token registration failed");
        sendDownloadFailure(cs);
        gameInfoFree(&gameInfo);
        gamePlatformInfoFree(&platInfo);
        return SERVER_SUCC;
    }

    GameDownloadRespPayload resp;
    memset(&resp, 0, sizeof(resp));
    resp.status = StatusOk;
    resp.gameId = gameId;
    resp.fileSize = platInfo.fileSize;
    resp.totalChunks = totalChunks;
    resp.dataPort = (uint16_t)(s->port + DATA_PORT_OFFSET);
    memcpy(resp.token, token, DATA_AUTH_TOKEN_LEN);
    strncpy(resp.hash, platInfo.hash, GAME_HASH_LEN);

    int ret =
        serverSendEncryptedPacket(cs, MsgGameDownloadResp, &resp, sizeof(resp));

    gameInfoFree(&gameInfo);
    gamePlatformInfoFree(&platInfo);

    return ret;
}

int serverHandleGameDownloadCancel(Server *s, ClientSession *cs,
                                   const Packet *pkt) {
    (void)cs;
    if (pkt->header.payloadLength < sizeof(DataAuthPayload)) {
        LOG_WARN("serverHandleGameDownloadCancel: payload too short (fd=%d)",
                 cs->fd);
        return SERVER_FAIL;
    }

    const DataAuthPayload *payload = (const DataAuthPayload *)pkt->payload;
    (void)downloadPoolCancelByToken(s->downloadPool, payload->token);

    return SERVER_SUCC;
}

int serverHandleGameStart(Server *s, ClientSession *cs, const Packet *pkt) {
    if (pkt->header.payloadLength < sizeof(GameStartReqPayload)) {
        LOG_WARN("serverHandleGameStart: payload too short (fd=%d)", cs->fd);
        return SERVER_FAIL;
    }

    const GameStartReqPayload *req =
        (const GameStartReqPayload *)pkt->payload;
    uint32_t gameId = ntohl(req->gameId);
    char platform[PLATFORM_NAME_LEN];
    memcpy(platform, req->platform, PLATFORM_NAME_LEN);
    platform[PLATFORM_NAME_LEN - 1] = '\0';

    GameInfo gameInfo;
    memset(&gameInfo, 0, sizeof(gameInfo));
    GamePlatformInfo platInfo;
    memset(&platInfo, 0, sizeof(platInfo));

    if (getGameById(s->gameDB, gameId, &gameInfo) != DB_SUCC) {
        LOG_WARN("serverHandleGameStart: game %u not found", gameId);
        gameInfoFree(&gameInfo);
        (void)serverSendStatusResponse(cs, MsgGameStartResp, StatusError);
        return SERVER_SUCC;
    }

    if (getGamePlatform(s->gameDB, gameId, platform, "server", &platInfo) != DB_SUCC) {
        LOG_WARN("serverHandleGameStart: platform %s not found for game %u",
                 platform, gameId);
        gameInfoFree(&gameInfo);
        (void)serverSendStatusResponse(cs, MsgGameStartResp, StatusError);
        return SERVER_SUCC;
    }

    char soPath[FILE_PATH_MAX_LEN];
    (void)snprintf(soPath, sizeof(soPath), GAME_LIB_DIR "/%u/%s/server/%s/%s",
                   gameId, gameInfo.version, platform, platInfo.fileName);

    if (access(soPath, R_OK) != 0) {
        LOG_WARN("serverHandleGameStart: .so not readable: %s", soPath);
        gameInfoFree(&gameInfo);
        gamePlatformInfoFree(&platInfo);
        (void)serverSendStatusResponse(cs, MsgGameStartResp, StatusError);
        return SERVER_SUCC;
    }

    if (serverStartGame(s, soPath) != SERVER_SUCC) {
        LOG_ERROR("serverHandleGameStart: serverStartGame failed for %s",
                  soPath);
        gameInfoFree(&gameInfo);
        gamePlatformInfoFree(&platInfo);
        (void)serverSendStatusResponse(cs, MsgGameStartResp, StatusError);
        return SERVER_SUCC;
    }

    gameInfoFree(&gameInfo);
    gamePlatformInfoFree(&platInfo);

    (void)serverSendStatusResponse(cs, MsgGameStartResp, StatusOk);
    LOG_INFO("serverHandleGameStart: game %u started (platform=%s)", gameId,
             platform);
    return SERVER_SUCC;
}
