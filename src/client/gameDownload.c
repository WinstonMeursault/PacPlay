/**
 * @file gameDownload.c
 * @brief Client-side game download manager with resume and verification.
 *
 * @date 2026-06-17
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

#include "gameDownload.h"

#include "cJSON.h"
#include "client/database.h"
#include "log.h"
#include "platform.h"

#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

#define HKDF_INFO_DATA_CHANNEL "PacPlay-DataChannel"

enum {
    PathBufLen = 256,
    HashReadBufLen = 8192,
    Sha256DigestLen = 32,
    MetaJsonBufLen = 4096,
    DataAuthStatusOk = 0,
    DownloadRespStatusOk = 0,
    DeriveOk = 0,
    DeriveFail = -1,
    FilePermRw = 0644
};

typedef struct DownloadContext {
    uint32_t gameId;
    DownloadProgress progress;
    pthread_t thread;
    SocketFD dataFd;
    uint8_t dataKey[AES_GCM_KEY_LEN];
    uint8_t token[DATA_AUTH_TOKEN_LEN];
    char hash[GAME_HASH_LEN];
    uint64_t fileSize;
    uint32_t totalChunks;
    uint16_t dataPort;
    volatile bool cancelled;
    bool active;
    Client *client;
} DownloadContext;

struct DownloadManager {
    Client *client;
    DownloadContext downloads[MAX_CLIENT_DOWNLOADS];
    pthread_mutex_t mutex;
};

static int deriveDataChannelKey(const uint8_t mainKey[AES_GCM_KEY_LEN],
                                const uint8_t salt[DATA_AUTH_TOKEN_LEN],
                                uint8_t outKey[AES_GCM_KEY_LEN]) {
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (kdf == NULL) {
        return DeriveFail;
    }

    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (ctx == NULL) {
        return DeriveFail;
    }

    const char *info = HKDF_INFO_DATA_CHANNEL;
    const char *digest = "SHA256";

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", (char *)digest, 0),
        OSSL_PARAM_construct_octet_string("key", (void *)mainKey,
                                          AES_GCM_KEY_LEN),
        OSSL_PARAM_construct_octet_string("salt", (void *)salt,
                                          DATA_AUTH_TOKEN_LEN),
        OSSL_PARAM_construct_octet_string("info", (void *)info, strlen(info)),
        OSSL_PARAM_construct_end()};

    int result = DeriveOk;
    if (EVP_KDF_derive(ctx, outKey, AES_GCM_KEY_LEN, params) <= 0) {
        OPENSSL_cleanse(outKey, AES_GCM_KEY_LEN);
        result = DeriveFail;
    }

    EVP_KDF_CTX_free(ctx);
    return result;
}

static int computeFileHash(const char *filePath, char outHex[GAME_HASH_LEN]) {
    int fd = open(filePath, O_RDONLY);
    if (fd < 0) {
        return CLIENT_FAIL;
    }

    EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
    if (mdCtx == NULL) {
        close(fd);
        return CLIENT_FAIL;
    }

    if (EVP_DigestInit_ex(mdCtx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(mdCtx);
        close(fd);
        return CLIENT_FAIL;
    }

    uint8_t buf[HashReadBufLen];
    ssize_t bytesRead;
    while ((bytesRead = read(fd, buf, sizeof(buf))) > 0) {
        if (EVP_DigestUpdate(mdCtx, buf, (size_t)bytesRead) != 1) {
            EVP_MD_CTX_free(mdCtx);
            close(fd);
            return CLIENT_FAIL;
        }
    }
    close(fd);

    if (bytesRead < 0) {
        EVP_MD_CTX_free(mdCtx);
        return CLIENT_FAIL;
    }

    uint8_t digest[Sha256DigestLen];
    unsigned int digestLen = 0;
    if (EVP_DigestFinal_ex(mdCtx, digest, &digestLen) != 1) {
        EVP_MD_CTX_free(mdCtx);
        return CLIENT_FAIL;
    }
    EVP_MD_CTX_free(mdCtx);

    for (unsigned int i = 0; i < digestLen; i++) {
        snprintf(outHex + i * 2, 3, "%02x", digest[i]); // NOLINT
    }

    return CLIENT_SUCC;
}

static void writeResumeMeta(const char *metaPath,
                            const DownloadResumeInfo *info) {
    FILE *fp = fopen(metaPath, "wb");
    if (fp == NULL) {
        LOG_WARN("Failed to write resume meta: %s", metaPath);
        return;
    }
    fwrite(info, sizeof(*info), 1, fp);
    fclose(fp);
}

static int readResumeMeta(const char *metaPath, DownloadResumeInfo *info) {
    FILE *fp = fopen(metaPath, "rb");
    if (fp == NULL) {
        return CLIENT_FAIL;
    }
    size_t n = fread(info, sizeof(*info), 1, fp);
    fclose(fp);
    return (n == 1) ? CLIENT_SUCC : CLIENT_FAIL;
}

static void *downloadThread(void *arg);

int clientRequestGameList(Client *client, uint32_t rangeStart,
                          uint32_t rangeEnd, const char *platform,
                          GameInfoEntry **outList, size_t *outCount) {
    if (client == NULL || outList == NULL || outCount == NULL ||
        platform == NULL) {
        return CLIENT_FAIL;
    }

    GameListReqPayload req;
    memset(&req, 0, sizeof(req));
    req.rangeStart = rangeStart;
    req.rangeEnd = rangeEnd;
    strncpy(req.platform, platform, PLATFORM_NAME_LEN - 1);

    if (packetSendEncrypted(client->fd, MsgGameListReq, &client->seqID,
                            client->aesKey.key, &req,
                            sizeof(req)) != PROTOCOL_SUCC) {
        LOG_ERROR("Failed to send game list request");
        return CLIENT_FAIL;
    }

    Packet resp;
    memset(&resp, 0, sizeof(resp));
    if (packetRecvEncrypted(client->fd, &resp, client->aesKey.key) !=
        PROTOCOL_SUCC) {
        LOG_ERROR("Failed to receive game list response");
        return CLIENT_FAIL;
    }

    if (resp.header.messageType != (uint32_t)MsgGameListResp) {
        LOG_ERROR("Unexpected response type: %u", resp.header.messageType);
        packetClear(&resp);
        return CLIENT_FAIL;
    }

    size_t count = resp.header.payloadLength / sizeof(GameInfoEntry);
    if (count == 0) {
        *outList = NULL;
        *outCount = 0;
        packetClear(&resp);
        return CLIENT_SUCC;
    }

    *outList = malloc(count * sizeof(GameInfoEntry));
    if (*outList == NULL) {
        packetClear(&resp);
        return CLIENT_FAIL;
    }

    memcpy(*outList, resp.payload, count * sizeof(GameInfoEntry));
    *outCount = count;
    packetClear(&resp);
    return CLIENT_SUCC;
}

void clientFreeGameList(GameInfoEntry *list) { free(list); }

int downloadManagerInit(DownloadManager **mgr, Client *client) {
    if (mgr == NULL || client == NULL) {
        return CLIENT_FAIL;
    }

    DownloadManager *m = calloc(1, sizeof(DownloadManager));
    if (m == NULL) {
        return CLIENT_FAIL;
    }

    m->client = client;

    if (pthread_mutex_init(&m->mutex, NULL) != 0) {
        free(m);
        return CLIENT_FAIL;
    }

    memset(m->downloads, 0, sizeof(m->downloads));

    if (platformMkdirp(CLIENT_GAME_LIB_DIR) != PLATFORM_SUCC) {
        LOG_WARN("Failed to create game library directory");
    }

    *mgr = m;
    return CLIENT_SUCC;
}

void downloadManagerDestroy(DownloadManager *mgr) {
    if (mgr == NULL) {
        return;
    }

    pthread_mutex_lock(&mgr->mutex);
    for (int i = 0; i < MAX_CLIENT_DOWNLOADS; i++) {
        if (mgr->downloads[i].active) {
            mgr->downloads[i].cancelled = true;
        }
    }
    pthread_mutex_unlock(&mgr->mutex);

    for (int i = 0; i < MAX_CLIENT_DOWNLOADS; i++) {
        if (mgr->downloads[i].active) {
            pthread_join(mgr->downloads[i].thread, NULL);
        }
    }

    pthread_mutex_destroy(&mgr->mutex);
    free(mgr);
}

int downloadManagerStartDownload(DownloadManager *mgr, uint32_t gameId,
                                 const char *platform) {
    if (mgr == NULL || platform == NULL) {
        return CLIENT_FAIL;
    }

    pthread_mutex_lock(&mgr->mutex);

    int slot = -1;
    for (int i = 0; i < MAX_CLIENT_DOWNLOADS; i++) {
        if (!mgr->downloads[i].active) {
            slot = i;
            break;
        }
    }

    if (slot < 0) {
        pthread_mutex_unlock(&mgr->mutex);
        LOG_WARN("No free download slots");
        return CLIENT_FAIL;
    }

    DownloadContext *ctx = &mgr->downloads[slot];
    memset(ctx, 0, sizeof(*ctx));
    ctx->client = mgr->client;
    ctx->gameId = gameId;

    char metaPath[PathBufLen];
    snprintf(metaPath, sizeof(metaPath), "%s/%u.downloading.meta",
             CLIENT_GAME_LIB_DIR, gameId);

    char dlPath[PathBufLen];
    snprintf(dlPath, sizeof(dlPath), "%s/%u.downloading", CLIENT_GAME_LIB_DIR,
             gameId);

    uint32_t resumeChunkIndex = 0;
    DownloadResumeInfo resumeInfo;
    if (access(metaPath, F_OK) == 0 && access(dlPath, F_OK) == 0 &&
        readResumeMeta(metaPath, &resumeInfo) == CLIENT_SUCC) {
        resumeChunkIndex = resumeInfo.receivedChunks;
        LOG_INFO("Resuming download for game %u from chunk %u", gameId,
                 resumeChunkIndex);
    }

    GameDownloadReqPayload req;
    memset(&req, 0, sizeof(req));
    req.gameId = gameId;
    req.resumeChunkIndex = resumeChunkIndex;
    strncpy(req.platform, platform, PLATFORM_NAME_LEN - 1);

    if (packetSendEncrypted(mgr->client->fd, MsgGameDownloadReq,
                            &mgr->client->seqID, mgr->client->aesKey.key, &req,
                            sizeof(req)) != PROTOCOL_SUCC) {
        LOG_ERROR("Failed to send download request for game %u", gameId);
        pthread_mutex_unlock(&mgr->mutex);
        return CLIENT_FAIL;
    }

    Packet resp;
    memset(&resp, 0, sizeof(resp));
    if (packetRecvEncrypted(mgr->client->fd, &resp, mgr->client->aesKey.key) !=
        PROTOCOL_SUCC) {
        LOG_ERROR("Failed to receive download response for game %u", gameId);
        pthread_mutex_unlock(&mgr->mutex);
        return CLIENT_FAIL;
    }

    if (resp.header.messageType != (uint32_t)MsgGameDownloadResp ||
        resp.header.payloadLength < sizeof(GameDownloadRespPayload)) {
        LOG_ERROR("Invalid download response for game %u", gameId);
        packetClear(&resp);
        pthread_mutex_unlock(&mgr->mutex);
        return CLIENT_FAIL;
    }

    const GameDownloadRespPayload *dlResp =
        (const GameDownloadRespPayload *)resp.payload;

    if (dlResp->status != DownloadRespStatusOk) {
        LOG_ERROR("Download denied for game %u (status=%u)", gameId,
                  dlResp->status);
        packetClear(&resp);
        pthread_mutex_unlock(&mgr->mutex);
        return CLIENT_FAIL;
    }

    memcpy(ctx->token, dlResp->token, DATA_AUTH_TOKEN_LEN);
    ctx->dataPort = dlResp->dataPort;
    ctx->fileSize = dlResp->fileSize;
    ctx->totalChunks = dlResp->totalChunks;
    memcpy(ctx->hash, dlResp->hash, GAME_HASH_LEN);

    packetClear(&resp);

    ctx->progress.gameId = gameId;
    ctx->progress.fileSize = ctx->fileSize;
    ctx->progress.totalChunks = ctx->totalChunks;
    ctx->progress.receivedChunks = resumeChunkIndex;
    ctx->progress.status = DlPending;

    ctx->dataFd = NULL_SOCKETFD;
    ctx->active = true;
    ctx->cancelled = false;

    if (pthread_create(&ctx->thread, NULL, downloadThread, ctx) != 0) {
        LOG_ERROR("Failed to create download thread for game %u", gameId);
        ctx->active = false;
        pthread_mutex_unlock(&mgr->mutex);
        return CLIENT_FAIL;
    }

    pthread_mutex_unlock(&mgr->mutex);
    return CLIENT_SUCC;
}

static void *downloadThread(void *arg) {
    DownloadContext *ctx = (DownloadContext *)arg;
    char dlPath[PathBufLen];
    char metaPath[PathBufLen];
    char gameDirPath[PathBufLen];
    char metaJsonPath[PathBufLen];
    int fileFd = -1;
    uint32_t dataSeqID = 0;

    snprintf(dlPath, sizeof(dlPath), "%s/%u.downloading", CLIENT_GAME_LIB_DIR,
             ctx->gameId);
    snprintf(metaPath, sizeof(metaPath), "%s/%u.downloading.meta",
             CLIENT_GAME_LIB_DIR, ctx->gameId);
    snprintf(gameDirPath, sizeof(gameDirPath), "%s/%u", CLIENT_GAME_LIB_DIR,
             ctx->gameId);
    snprintf(metaJsonPath, sizeof(metaJsonPath), "%s/%u/metadata.json",
             CLIENT_GAME_LIB_DIR, ctx->gameId);

    ctx->dataFd = clientSetup(ctx->client->serverAddr, ctx->dataPort);
    if (ctx->dataFd == NULL_SOCKETFD) {
        LOG_ERROR("Download thread: failed to connect data channel for game %u",
                  ctx->gameId);
        ctx->progress.status = DlFailed;
        ctx->active = false;
        return NULL;
    }

    Packet authPkt;
    memset(&authPkt, 0, sizeof(authPkt));
    DataAuthPayload authPayload;
    memcpy(authPayload.token, ctx->token, DATA_AUTH_TOKEN_LEN);
    if (packetInit(&authPkt, MsgDataAuth, 0, PlaintextPacket, &authPayload,
                   sizeof(authPayload)) != PROTOCOL_SUCC) {
        LOG_ERROR("Download thread: failed to init DataAuth packet");
        goto fail;
    }
    if (packetSend(&authPkt, ctx->dataFd) != PROTOCOL_SUCC) {
        LOG_ERROR("Download thread: failed to send DataAuth");
        packetClear(&authPkt);
        goto fail;
    }
    packetClear(&authPkt);

    if (deriveDataChannelKey(ctx->client->aesKey.key, ctx->token,
                             ctx->dataKey) != DeriveOk) {
        LOG_ERROR("Download thread: HKDF key derivation failed");
        goto fail;
    }

    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    if (packetRecvEncrypted(ctx->dataFd, &pkt, ctx->dataKey) != PROTOCOL_SUCC) {
        LOG_ERROR("Download thread: failed to receive DataAuthResp");
        goto fail_cleanse;
    }

    if (pkt.header.messageType != (uint32_t)MsgDataAuthResp ||
        pkt.header.payloadLength < 1 || pkt.payload[0] != DataAuthStatusOk) {
        LOG_ERROR("Download thread: data auth rejected");
        packetClear(&pkt);
        goto fail_cleanse;
    }
    packetClear(&pkt);

    ctx->progress.status = DlDownloading;

    memset(&pkt, 0, sizeof(pkt));
    if (packetRecvEncrypted(ctx->dataFd, &pkt, ctx->dataKey) != PROTOCOL_SUCC) {
        LOG_ERROR("Download thread: failed to receive GameMetadata");
        goto fail_cleanse;
    }

    if (pkt.header.messageType != (uint32_t)MsgGameMetadata ||
        pkt.header.payloadLength < sizeof(GameMetadataPayload)) {
        LOG_ERROR("Download thread: invalid GameMetadata");
        packetClear(&pkt);
        goto fail_cleanse;
    }

    {
        const GameMetadataPayload *meta =
            (const GameMetadataPayload *)pkt.payload;
        strncpy(ctx->progress.gameName, meta->name, GAME_NAME_LEN - 1);
        strncpy(ctx->progress.gameVersion, meta->version, GAME_VERSION_LEN - 1);
        strncpy(ctx->progress.platform, meta->platform, PLATFORM_NAME_LEN - 1);
    }
    packetClear(&pkt);

    if (ctx->progress.receivedChunks > 0) {
        fileFd = open(dlPath, O_WRONLY);
    } else {
        fileFd = open(dlPath, O_WRONLY | O_CREAT | O_TRUNC, FilePermRw);
    }
    if (fileFd < 0) {
        LOG_ERROR("Download thread: failed to open download file: %s", dlPath);
        goto fail_cleanse;
    }

    {
        DownloadResumeInfo resumeInfo;
        memset(&resumeInfo, 0, sizeof(resumeInfo));
        resumeInfo.gameId = ctx->gameId;
        memcpy(resumeInfo.hash, ctx->hash, GAME_HASH_LEN);
        resumeInfo.totalChunks = ctx->totalChunks;
        resumeInfo.receivedChunks = ctx->progress.receivedChunks;
        resumeInfo.fileSize = ctx->fileSize;
        resumeInfo.dataPort = ctx->dataPort;
        writeResumeMeta(metaPath, &resumeInfo);
    }

    while (ctx->progress.receivedChunks < ctx->totalChunks && !ctx->cancelled) {
        memset(&pkt, 0, sizeof(pkt));
        if (packetRecvEncrypted(ctx->dataFd, &pkt, ctx->dataKey) !=
            PROTOCOL_SUCC) {
            LOG_ERROR("Download thread: failed to receive chunk");
            close(fileFd);
            fileFd = -1;
            goto fail_cleanse;
        }

        if (pkt.header.messageType != (uint32_t)MsgGameChunk) {
            LOG_ERROR("Download thread: unexpected message type %u",
                      pkt.header.messageType);
            packetClear(&pkt);
            close(fileFd);
            fileFd = -1;
            goto fail_cleanse;
        }

        const GameChunkPayload *chunk = (const GameChunkPayload *)pkt.payload;
        uint64_t offset = (uint64_t)chunk->chunkIndex * GAME_CHUNK_SIZE;
        pwrite(fileFd, pkt.payload + sizeof(GameChunkPayload), chunk->chunkSize,
               (off_t)offset);

        ctx->progress.receivedChunks++;

        {
            DownloadResumeInfo updInfo;
            memset(&updInfo, 0, sizeof(updInfo));
            updInfo.gameId = ctx->gameId;
            memcpy(updInfo.hash, ctx->hash, GAME_HASH_LEN);
            updInfo.totalChunks = ctx->totalChunks;
            updInfo.receivedChunks = ctx->progress.receivedChunks;
            updInfo.fileSize = ctx->fileSize;
            updInfo.dataPort = ctx->dataPort;
            writeResumeMeta(metaPath, &updInfo);
        }

        GameChunkAckPayload ack;
        ack.chunkIndex = chunk->chunkIndex;

        packetClear(&pkt);

        if (packetSendEncrypted(ctx->dataFd, MsgGameChunkAck, &dataSeqID,
                                    ctx->dataKey, &ack,
                                    sizeof(ack)) != PROTOCOL_SUCC) {
            LOG_ERROR("Download thread: failed to send chunk ACK");
            close(fileFd);
            fileFd = -1;
            goto fail_cleanse;
        }
    }

    close(fileFd);
    fileFd = -1;

    if (ctx->cancelled) {
        ctx->progress.status = DlCancelled;
        goto cleanup;
    }

    memset(&pkt, 0, sizeof(pkt));
    if (packetRecvEncrypted(ctx->dataFd, &pkt, ctx->dataKey) != PROTOCOL_SUCC) {
        LOG_WARN("Download thread: failed to receive DownloadDone");
    } else {
        packetClear(&pkt);
    }

    ctx->progress.status = DlVerifying;

    char computedHash[GAME_HASH_LEN];
    memset(computedHash, 0, sizeof(computedHash));
    if (computeFileHash(dlPath, computedHash) != CLIENT_SUCC ||
        memcmp(computedHash, ctx->hash, GAME_HASH_LEN) != 0) {
        LOG_ERROR("Download thread: hash verification failed for game %u",
                  ctx->gameId);
        remove(dlPath);
        remove(metaPath);
        ctx->progress.status = DlFailed;
        goto cleanup;
    }

    if (platformMkdirp(gameDirPath) != PLATFORM_SUCC) {
        LOG_ERROR("Download thread: failed to create game directory: %s",
                  gameDirPath);
        remove(dlPath);
        remove(metaPath);
        ctx->progress.status = DlFailed;
        goto cleanup;
    }

    if (extractTarGz(dlPath, gameDirPath) != ARCHIVE_SUCC) {
        LOG_ERROR("Download thread: extraction failed for game %u",
                  ctx->gameId);
        remove(dlPath);
        remove(metaPath);
        ctx->progress.status = DlFailed;
        goto cleanup;
    }

    if (ctx->client->db != NULL && access(metaJsonPath, F_OK) == 0) {
        FILE *jsonFp = fopen(metaJsonPath, "r");
        if (jsonFp != NULL) {
            char jsonBuf[MetaJsonBufLen];
            size_t jsonLen = fread(jsonBuf, 1, sizeof(jsonBuf) - 1, jsonFp);
            fclose(jsonFp);
            jsonBuf[jsonLen] = '\0';

            cJSON *root = cJSON_Parse(jsonBuf);
            if (root != NULL) {
                const char *gameName = ctx->progress.gameName;
                const char *gameVersion = ctx->progress.gameVersion;
                const char *soRelPath = NULL;

                cJSON *nameItem = cJSON_GetObjectItem(root, "gameName");
                cJSON *versionItem = cJSON_GetObjectItem(root, "version");

                if (cJSON_IsString(nameItem) &&
                    cJSON_GetStringValue(nameItem) != NULL) {
                    gameName = cJSON_GetStringValue(nameItem);
                }
                if (cJSON_IsString(versionItem) &&
                    cJSON_GetStringValue(versionItem) != NULL) {
                    gameVersion = cJSON_GetStringValue(versionItem);
                }

                cJSON *clientSection =
                    cJSON_GetObjectItem(root, "client");
                if (clientSection != NULL) {
                    cJSON *platItem =
                        cJSON_GetObjectItem(clientSection,
                                            ctx->progress.platform);
                    if (platItem != NULL) {
                        cJSON *lpItem =
                            cJSON_GetObjectItem(platItem, "libraryPath");
                        if (cJSON_IsString(lpItem)) {
                            soRelPath = cJSON_GetStringValue(lpItem);
                        }
                    }
                }

                if (soRelPath == NULL) {
                    LOG_ERROR("Download thread: libraryPath not found "
                              "in metadata for platform %s",
                              ctx->progress.platform);
                    cJSON_Delete(root);
                    remove(dlPath);
                    remove(metaPath);
                    ctx->progress.status = DlFailed;
                    goto cleanup;
                }

                const char *relPath = soRelPath;
                if (relPath[0] == '.' && relPath[1] == '/') {
                    relPath += 2;
                }

                char gameSoPath[PathBufLen];
                snprintf(gameSoPath, sizeof(gameSoPath), "%s/%s",
                         gameDirPath, relPath);

                addGame(ctx->client, ctx->gameId, gameName, gameSoPath,
                        gameVersion, ctx->progress.platform, ctx->hash);
                cJSON_Delete(root);
            }
        }
    }

    remove(metaJsonPath);
    remove(dlPath);
    remove(metaPath);
    ctx->progress.status = DlDone;
    LOG_INFO("Game %u download complete", ctx->gameId);
    goto cleanup;

fail:
    ctx->progress.status = DlFailed;
    goto cleanup_socket;

fail_cleanse:
    ctx->progress.status = DlFailed;

cleanup:
    OPENSSL_cleanse(ctx->dataKey, AES_GCM_KEY_LEN);

cleanup_socket:
    if (fileFd >= 0) {
        close(fileFd);
    }
    socketClose(&ctx->dataFd);
    ctx->active = false;
    return NULL;
}

int downloadManagerCancel(DownloadManager *mgr, uint32_t gameId) {
    if (mgr == NULL) {
        return CLIENT_FAIL;
    }

    pthread_mutex_lock(&mgr->mutex);

    DownloadContext *found = NULL;
    for (int i = 0; i < MAX_CLIENT_DOWNLOADS; i++) {
        if (mgr->downloads[i].active && mgr->downloads[i].gameId == gameId) {
            found = &mgr->downloads[i];
            break;
        }
    }

    if (found == NULL) {
        pthread_mutex_unlock(&mgr->mutex);
        return CLIENT_FAIL;
    }

    found->cancelled = true;

    DataAuthPayload cancelPayload;
    memcpy(cancelPayload.token, found->token, DATA_AUTH_TOKEN_LEN);
    packetSendEncrypted(mgr->client->fd, MsgGameDownloadCancel,
                        &mgr->client->seqID, mgr->client->aesKey.key,
                        &cancelPayload, sizeof(cancelPayload));

    pthread_mutex_unlock(&mgr->mutex);
    return CLIENT_SUCC;
}

int downloadManagerGetProgress(DownloadManager *mgr, DownloadProgress *out,
                               size_t *count) {
    if (mgr == NULL || out == NULL || count == NULL) {
        return CLIENT_FAIL;
    }

    pthread_mutex_lock(&mgr->mutex);

    size_t idx = 0;
    for (int i = 0; i < MAX_CLIENT_DOWNLOADS; i++) {
        if (mgr->downloads[i].active) {
            out[idx] = mgr->downloads[i].progress;
            idx++;
        }
    }

    *count = idx;
    pthread_mutex_unlock(&mgr->mutex);
    return CLIENT_SUCC;
}
