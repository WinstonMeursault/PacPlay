#include "server/downloadPool.h"

#include "crypto.h"
#include "log.h"
#include "protocol.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

enum {
    DeriveSuccess = 0,
    DeriveFail = -1,
    PoolSuccess = 0,
    PoolFail = -1,
    DataAuthRespStatusOk = 0,
    MaxChunkRetries = 3
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

    int result = DeriveSuccess;
    if (EVP_KDF_derive(ctx, outKey, AES_GCM_KEY_LEN, params) <= 0) {
        OPENSSL_cleanse(outKey, AES_GCM_KEY_LEN);
        result = DeriveFail;
    }

    EVP_KDF_CTX_free(ctx);
    return result;
}

static void enqueueTask(DownloadPool *pool, const DownloadTask *task) {
    pthread_mutex_lock(&pool->queueMutex);
    if (pool->queueCount < MAX_QUEUED_TASKS) {
        pool->taskQueue[pool->queueTail] = *task;
        pool->queueTail = (pool->queueTail + 1) % MAX_QUEUED_TASKS;
        pool->queueCount++;
        pthread_cond_signal(&pool->queueNotEmpty);
    } else {
        LOG_WARN("Download task queue full, dropping task for game %u",
                 task->gameId);
        close(task->dataFd);
    }
    pthread_mutex_unlock(&pool->queueMutex);
}

static void *acceptThreadFunc(void *arg) {
    DownloadPool *pool = (DownloadPool *)arg;

    while (!pool->shutdown) {
        int clientFd = accept(pool->listenFd, NULL, NULL);
        if (clientFd < 0) {
            if (pool->shutdown) {
                break;
            }
            if (errno == EINTR) {
                continue;
            }
            LOG_WARN("Download pool accept() failed: %s", strerror(errno));
            continue;
        }

        struct timeval tv;
        tv.tv_sec = ACCEPT_RECV_TIMEOUT_SECS;
        tv.tv_usec = 0;
        setsockopt(clientFd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        Packet authPkt;
        memset(&authPkt, 0, sizeof(authPkt));
        if (packetRecv(&authPkt, clientFd) != PROTOCOL_SUCC) {
            LOG_WARN("Download pool: failed to recv DataAuth packet");
            close(clientFd);
            continue;
        }

        if (authPkt.header.messageType != (uint32_t)MsgDataAuth ||
            authPkt.header.payloadLength < DATA_AUTH_TOKEN_LEN) {
            LOG_WARN("Download pool: invalid DataAuth packet");
            packetClear(&authPkt);
            close(clientFd);
            continue;
        }

        const uint8_t *recvToken = authPkt.payload;

        pthread_mutex_lock(&pool->tokenMutex);
        PendingToken *matched = NULL;
        int64_t now = (int64_t)time(NULL);
        for (size_t i = 0; i < MAX_PENDING_TOKENS; i++) {
            PendingToken *pt = &pool->tokens[i];
            if (!pt->used && pt->expiresAt > now &&
                memcmp(pt->token, recvToken, DATA_AUTH_TOKEN_LEN) == 0) {
                matched = pt;
                break;
            }
        }

        if (matched == NULL) {
            pthread_mutex_unlock(&pool->tokenMutex);
            LOG_WARN("Download pool: no matching token found");
            packetClear(&authPkt);
            close(clientFd);
            continue;
        }

        matched->used = true;

        DownloadTask task;
        memset(&task, 0, sizeof(task));
        task.gameId = matched->gameId;
        task.dataFd = clientFd;
        task.resumeChunkIndex = matched->resumeChunkIndex;
        memcpy(task.filePath, matched->filePath, FILE_PATH_MAX_LEN);
        task.fileSize = matched->fileSize;
        task.totalChunks = matched->totalChunks;
        memcpy(task.gameEncKey, matched->gameEncKey, AES_GCM_KEY_LEN);
        task.metadata = matched->metadata;

        if (deriveDataChannelKey(matched->mainAESKey, matched->token,
                                 task.dataKey) != DeriveSuccess) {
            pthread_mutex_unlock(&pool->tokenMutex);
            LOG_ERROR("Download pool: HKDF derivation failed");
            packetClear(&authPkt);
            close(clientFd);
            continue;
        }

        pthread_mutex_unlock(&pool->tokenMutex);
        packetClear(&authPkt);

        enqueueTask(pool, &task);
    }

    return NULL;
}

static int decryptFileAtRest(const char *filePath,
                             const uint8_t gameEncKey[AES_GCM_KEY_LEN],
                             uint8_t **outPlaintext, uint64_t *outLen) {
    int fd = open(filePath, O_RDONLY);
    if (fd < 0) {
        LOG_ERROR("Cannot open game file: %s", filePath);
        return PoolFail;
    }

    off_t rawSize = lseek(fd, 0, SEEK_END);
    if (rawSize < (off_t)(AES_GCM_NONCE_LEN + AES_GCM_TAG_LEN)) {
        close(fd);
        LOG_ERROR("Game file too small: %s", filePath);
        return PoolFail;
    }
    lseek(fd, 0, SEEK_SET);

    size_t totalSize = (size_t)rawSize;
    uint8_t *raw = malloc(totalSize);
    if (raw == NULL) {
        close(fd);
        return PoolFail;
    }

    size_t bytesRead = 0;
    while (bytesRead < totalSize) {
        ssize_t n = read(fd, raw + bytesRead, totalSize - bytesRead);
        if (n <= 0) {
            free(raw);
            close(fd);
            return PoolFail;
        }
        bytesRead += (size_t)n;
    }
    close(fd);

    size_t cipherLen = totalSize - AES_GCM_NONCE_LEN - AES_GCM_TAG_LEN;

    AESGCMKey decKey;
    memcpy(decKey.key, gameEncKey, AES_GCM_KEY_LEN);
    memcpy(decKey.nonce, raw, AES_GCM_NONCE_LEN);

    AESGCMCipher cipher;
    cipher.buffer.data = raw + AES_GCM_NONCE_LEN;
    cipher.buffer.len = cipherLen;
    cipher.buffer.capacity = cipherLen;
    memcpy(cipher.tag, raw + AES_GCM_NONCE_LEN + cipherLen, AES_GCM_TAG_LEN);

    uint8_t *plaintext = malloc(cipherLen);
    if (plaintext == NULL) {
        free(raw);
        return PoolFail;
    }

    AESGCMBuffer ptBuf;
    ptBuf.data = plaintext;
    ptBuf.capacity = cipherLen;
    ptBuf.len = 0;

    int ret = decryptAESGCM(&cipher, NULL, &decKey, &ptBuf);
    OPENSSL_cleanse(&decKey, sizeof(decKey));
    free(raw);

    if (ret != CRYPTO_SUCC) {
        free(plaintext);
        LOG_ERROR("Game file decryption failed: %s", filePath);
        return PoolFail;
    }

    *outPlaintext = plaintext;
    *outLen = ptBuf.len;
    return PoolSuccess;
}

static void *workerThreadFunc(void *arg) {
    DownloadPool *pool = (DownloadPool *)arg;

    while (true) {
        pthread_mutex_lock(&pool->queueMutex);
        while (pool->queueCount == 0 && !pool->shutdown) {
            pthread_cond_wait(&pool->queueNotEmpty, &pool->queueMutex);
        }
        if (pool->shutdown && pool->queueCount == 0) {
            pthread_mutex_unlock(&pool->queueMutex);
            break;
        }

        DownloadTask task = pool->taskQueue[pool->queueHead];
        pool->queueHead = (pool->queueHead + 1) % MAX_QUEUED_TASKS;
        pool->queueCount--;
        pthread_mutex_unlock(&pool->queueMutex);

        uint32_t seqID = 0;

        uint8_t statusOk = DataAuthRespStatusOk;
        if (packetSendEncryptedData(task.dataFd, MsgDataAuthResp, &seqID,
                                    task.dataKey, &statusOk,
                                    sizeof(statusOk)) != PROTOCOL_SUCC) {
            LOG_WARN("Worker: failed to send DataAuthResp for game %u",
                     task.gameId);
            close(task.dataFd);
            OPENSSL_cleanse(task.dataKey, AES_GCM_KEY_LEN);
            OPENSSL_cleanse(task.gameEncKey, AES_GCM_KEY_LEN);
            continue;
        }

        if (packetSendEncryptedData(task.dataFd, MsgGameMetadata, &seqID,
                                    task.dataKey, &task.metadata,
                                    sizeof(task.metadata)) != PROTOCOL_SUCC) {
            LOG_WARN("Worker: failed to send GameMetadata for game %u",
                     task.gameId);
            close(task.dataFd);
            OPENSSL_cleanse(task.dataKey, AES_GCM_KEY_LEN);
            OPENSSL_cleanse(task.gameEncKey, AES_GCM_KEY_LEN);
            continue;
        }

        uint8_t *plainData = NULL;
        uint64_t plainLen = 0;
        if (decryptFileAtRest(task.filePath, task.gameEncKey, &plainData,
                              &plainLen) != PoolSuccess) {
            LOG_ERROR("Worker: file decryption failed for game %u",
                      task.gameId);
            close(task.dataFd);
            OPENSSL_cleanse(task.dataKey, AES_GCM_KEY_LEN);
            OPENSSL_cleanse(task.gameEncKey, AES_GCM_KEY_LEN);
            continue;
        }

        OPENSSL_cleanse(task.gameEncKey, AES_GCM_KEY_LEN);

        bool transferOk = true;
        for (uint32_t i = task.resumeChunkIndex; i < task.totalChunks; i++) {
            bool chunkOk = false;
            for (uint32_t retry = 0; retry <= MaxChunkRetries; retry++) {
                uint64_t offset = (uint64_t)i * GAME_CHUNK_SIZE;
                uint32_t chunkSize = GAME_CHUNK_SIZE;
                if (offset + chunkSize > plainLen) {
                    chunkSize = (uint32_t)(plainLen - offset);
                }

                size_t pktLen = sizeof(GameChunkPayload) + chunkSize;
                uint8_t *pktBuf = malloc(pktLen);
                if (pktBuf == NULL) {
                    transferOk = false;
                    goto cleanup;
                }

                GameChunkPayload *chunkHdr = (GameChunkPayload *)pktBuf;
                chunkHdr->chunkIndex = i;
                chunkHdr->chunkSize = chunkSize;
                memcpy(pktBuf + sizeof(GameChunkPayload), plainData + offset,
                       chunkSize);

                if (packetSendEncryptedData(task.dataFd, MsgGameChunk, &seqID,
                                            task.dataKey, pktBuf,
                                            pktLen) != PROTOCOL_SUCC) {
                    free(pktBuf);
                    transferOk = false;
                    goto cleanup;
                }
                free(pktBuf);

                Packet ackPkt;
                memset(&ackPkt, 0, sizeof(ackPkt));
                if (packetRecvEncrypted(task.dataFd, &ackPkt, task.dataKey) !=
                    PROTOCOL_SUCC) {
                    transferOk = false;
                    goto cleanup;
                }

                if (ackPkt.header.messageType != (uint32_t)MsgGameChunkAck ||
                    ackPkt.header.payloadLength < sizeof(GameChunkAckPayload)) {
                    LOG_WARN("Worker: invalid ACK for game %u chunk %u "
                             "(retry %u)",
                             task.gameId, i, retry);
                    packetClear(&ackPkt);
                    continue;
                }

                const GameChunkAckPayload *ack =
                    (const GameChunkAckPayload *)ackPkt.payload;
                if (ack->chunkIndex != i) {
                    LOG_WARN("Worker: ACK mismatch for game %u "
                             "(expected %u, got %u, retry %u)",
                             task.gameId, i, ack->chunkIndex, retry);
                    packetClear(&ackPkt);
                    continue;
                }

                packetClear(&ackPkt);
                chunkOk = true;
                break;
            }
            if (!chunkOk) {
                LOG_ERROR("Worker: chunk %u exhausted retries for game %u", i,
                          task.gameId);
                transferOk = false;
                break;
            }
        }

        if (transferOk) {
            packetSendEncryptedData(task.dataFd, MsgGameDownloadDone, &seqID,
                                    task.dataKey, NULL, 0);
        }

    cleanup:
        free(plainData);
        close(task.dataFd);
        OPENSSL_cleanse(task.dataKey, AES_GCM_KEY_LEN);
    }

    return NULL;
}

int downloadPoolInit(DownloadPool *pool, uint16_t dataPort,
                     size_t workerCount) {
    if (pool == NULL || workerCount == 0 ||
        workerCount > MAX_DOWNLOAD_WORKERS) {
        return PoolFail;
    }

    memset(pool, 0, sizeof(*pool));
    pool->dataPort = dataPort;
    pool->shutdown = false;
    pool->workerCount = workerCount;

    pool->listenFd = serverSetup(dataPort);
    if (pool->listenFd == NULL_SOCKETFD) {
        LOG_ERROR("Download pool: failed to bind on port %u", dataPort);
        return PoolFail;
    }

    if (pthread_mutex_init(&pool->queueMutex, NULL) != 0) {
        socketClose(&pool->listenFd);
        return PoolFail;
    }
    if (pthread_cond_init(&pool->queueNotEmpty, NULL) != 0) {
        pthread_mutex_destroy(&pool->queueMutex);
        socketClose(&pool->listenFd);
        return PoolFail;
    }
    if (pthread_mutex_init(&pool->tokenMutex, NULL) != 0) {
        pthread_cond_destroy(&pool->queueNotEmpty);
        pthread_mutex_destroy(&pool->queueMutex);
        socketClose(&pool->listenFd);
        return PoolFail;
    }

    if (pthread_create(&pool->acceptThread, NULL, acceptThreadFunc, pool) !=
        0) {
        pthread_mutex_destroy(&pool->tokenMutex);
        pthread_cond_destroy(&pool->queueNotEmpty);
        pthread_mutex_destroy(&pool->queueMutex);
        socketClose(&pool->listenFd);
        return PoolFail;
    }

    for (size_t i = 0; i < workerCount; i++) {
        if (pthread_create(&pool->workers[i], NULL, workerThreadFunc, pool) !=
            0) {
            pool->shutdown = true;
            pthread_cond_broadcast(&pool->queueNotEmpty);
            for (size_t j = 0; j < i; j++) {
                pthread_join(pool->workers[j], NULL);
            }
            socketClose(&pool->listenFd);
            pthread_join(pool->acceptThread, NULL);
            pthread_mutex_destroy(&pool->tokenMutex);
            pthread_cond_destroy(&pool->queueNotEmpty);
            pthread_mutex_destroy(&pool->queueMutex);
            return PoolFail;
        }
    }

    LOG_INFO("Download pool started: port=%u workers=%zu", dataPort,
             workerCount);
    return PoolSuccess;
}

int downloadPoolRegisterToken(DownloadPool *pool, const PendingToken *token) {
    if (pool == NULL || token == NULL) {
        return PoolFail;
    }

    pthread_mutex_lock(&pool->tokenMutex);

    int64_t now = (int64_t)time(NULL);
    int slotIdx = -1;

    for (int i = 0; i < MAX_PENDING_TOKENS; i++) {
        PendingToken *pt = &pool->tokens[i];
        if (pt->used || pt->expiresAt <= now) {
            slotIdx = i;
            break;
        }
    }

    if (slotIdx < 0) {
        pthread_mutex_unlock(&pool->tokenMutex);
        LOG_WARN("Download pool: pending token slots full");
        return PoolFail;
    }

    pool->tokens[slotIdx] = *token;
    pool->tokens[slotIdx].used = false;
    pool->tokens[slotIdx].expiresAt = now + TOKEN_EXPIRE_SECS;

    pthread_mutex_unlock(&pool->tokenMutex);
    return PoolSuccess;
}

int downloadPoolCancelByToken(DownloadPool *pool, const uint8_t *token) {
    if (pool == NULL || token == NULL) {
        return PoolFail;
    }

    pthread_mutex_lock(&pool->tokenMutex);
    for (int i = 0; i < MAX_PENDING_TOKENS; i++) {
        PendingToken *pt = &pool->tokens[i];
        if (!pt->used && memcmp(pt->token, token, DATA_AUTH_TOKEN_LEN) == 0) {
            pt->used = true;
            pthread_mutex_unlock(&pool->tokenMutex);
            return PoolSuccess;
        }
    }
    pthread_mutex_unlock(&pool->tokenMutex);
    return PoolFail;
}

void downloadPoolDestroy(DownloadPool *pool) {
    if (pool == NULL) {
        return;
    }

    pool->shutdown = true;

    pthread_cond_broadcast(&pool->queueNotEmpty);

    if (pool->listenFd != NULL_SOCKETFD) {
        shutdown(pool->listenFd, SHUT_RDWR);
    }
    socketClose(&pool->listenFd);

    pthread_join(pool->acceptThread, NULL);

    for (size_t i = 0; i < pool->workerCount; i++) {
        pthread_join(pool->workers[i], NULL);
    }

    pthread_mutex_lock(&pool->queueMutex);
    while (pool->queueCount > 0) {
        DownloadTask *t = &pool->taskQueue[pool->queueHead];
        close(t->dataFd);
        OPENSSL_cleanse(t->dataKey, AES_GCM_KEY_LEN);
        OPENSSL_cleanse(t->gameEncKey, AES_GCM_KEY_LEN);
        pool->queueHead = (pool->queueHead + 1) % MAX_QUEUED_TASKS;
        pool->queueCount--;
    }
    pthread_mutex_unlock(&pool->queueMutex);

    pthread_mutex_destroy(&pool->queueMutex);
    pthread_cond_destroy(&pool->queueNotEmpty);
    pthread_mutex_destroy(&pool->tokenMutex);

    LOG_INFO("Download pool destroyed");
}
