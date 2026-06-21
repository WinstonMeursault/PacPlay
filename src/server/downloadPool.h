#ifndef DOWNLOAD_POOL_H
#define DOWNLOAD_POOL_H

#include "server.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#define MAX_DOWNLOAD_WORKERS 4
#define MAX_PENDING_TOKENS 32
#define MAX_QUEUED_TASKS 64
#define HKDF_INFO_DATA_CHANNEL "PacPlay-DataChannel"
#define ACCEPT_RECV_TIMEOUT_SECS 5
#define FILE_PATH_MAX_LEN 256

typedef struct {
    uint32_t gameId;
    int dataFd;
    uint8_t dataKey[AES_GCM_KEY_LEN];
    uint32_t resumeChunkIndex;
    char filePath[FILE_PATH_MAX_LEN];
    uint64_t fileSize;
    uint32_t totalChunks;
    GameMetadataPayload metadata;
} DownloadTask;

typedef struct {
    uint8_t token[DATA_AUTH_TOKEN_LEN];
    uint8_t mainAESKey[AES_GCM_KEY_LEN];
    uint32_t gameId;
    uint32_t resumeChunkIndex;
    char filePath[FILE_PATH_MAX_LEN];
    uint64_t fileSize;
    uint32_t totalChunks;
    GameMetadataPayload metadata;
    int64_t expiresAt;
    bool used;
} PendingToken;

typedef struct DownloadPool {
    pthread_t workers[MAX_DOWNLOAD_WORKERS];
    size_t workerCount;
    DownloadTask taskQueue[MAX_QUEUED_TASKS];
    size_t queueHead;
    size_t queueTail;
    size_t queueCount;
    pthread_mutex_t queueMutex;
    pthread_cond_t queueNotEmpty;
    PendingToken tokens[MAX_PENDING_TOKENS];
    pthread_mutex_t tokenMutex;
    int listenFd;
    uint16_t dataPort;
    pthread_t acceptThread;
    _Atomic bool shutdown;
} DownloadPool;

int downloadPoolInit(DownloadPool *pool, uint16_t dataPort, size_t workerCount);
int downloadPoolRegisterToken(DownloadPool *pool, const PendingToken *token);
int downloadPoolCancelByToken(DownloadPool *pool, const uint8_t *token);
void downloadPoolDestroy(DownloadPool *pool);

#endif
