/**
 * @file pacplay_sdk.c
 * @brief PacPlay SDK shared implementation — thread-safe ring buffer bridge
 *        between game threads and PacPlay IO threads.
 *
 * This file contains the internal (non-static, module-local) implementation
 * that both the client and server SDK wrappers delegate to.
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

#include "pacplay_sdk.h"

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "container.h"

/* ── constants ───────────────────────────────────────────────────────────── */

#define SDK_QUEUE_CAPACITY 64
#define SDK_MAX_PAYLOAD 65536

/* ── message type ────────────────────────────────────────────────────────── */

typedef struct {
    uint8_t *data;
    size_t len;
    size_t capacity;
} SDKMessage;

/* ── queue generation ────────────────────────────────────────────────────── */

QUEUE_DEFINE(SDKMessage)

/* ── SDK struct definition ───────────────────────────────────────────────── */

struct PacPlaySDK {
    QueueSDKMessage sendQueue;
    QueueSDKMessage recvQueue;
    pthread_mutex_t sendMutex;
    pthread_mutex_t recvMutex;
    PacPlayOnReceive callback;
    void *userData;
    volatile bool running;
};

/* ══════════════════════════ internal helpers ═══════════════════════════════ */

PacPlaySDK *sdk_create(void)
{
    PacPlaySDK *sdkObj = malloc(sizeof(PacPlaySDK));
    if (sdkObj == NULL) {
        return NULL;
    }

    if (queueSDKMessageInit(&sdkObj->sendQueue, SDK_QUEUE_CAPACITY) !=
        ContainerSucc) {
        free(sdkObj);
        return NULL;
    }

    if (queueSDKMessageInit(&sdkObj->recvQueue, SDK_QUEUE_CAPACITY) !=
        ContainerSucc) {
        queueSDKMessageDeinit(&sdkObj->sendQueue);
        free(sdkObj);
        return NULL;
    }

    if (pthread_mutex_init(&sdkObj->sendMutex, NULL) != 0) {
        queueSDKMessageDeinit(&sdkObj->recvQueue);
        queueSDKMessageDeinit(&sdkObj->sendQueue);
        free(sdkObj);
        return NULL;
    }

    if (pthread_mutex_init(&sdkObj->recvMutex, NULL) != 0) {
        pthread_mutex_destroy(&sdkObj->sendMutex);
        queueSDKMessageDeinit(&sdkObj->recvQueue);
        queueSDKMessageDeinit(&sdkObj->sendQueue);
        free(sdkObj);
        return NULL;
    }

    sdkObj->callback = NULL;
    sdkObj->userData = NULL;
    sdkObj->running = true;

    return sdkObj;
}

void sdk_destroy(PacPlaySDK *sdk)
{
    if (sdk == NULL) {
        return;
    }

    sdk->running = false;

    pthread_mutex_lock(&sdk->sendMutex);
    while (!queueSDKMessageIsEmpty(&sdk->sendQueue)) {
        SDKMessage msg;
        if (queueSDKMessageFront(&sdk->sendQueue, &msg) == ContainerSucc) {
            free(msg.data);
            queueSDKMessagePop(&sdk->sendQueue);
        }
    }
    queueSDKMessageDeinit(&sdk->sendQueue);
    pthread_mutex_unlock(&sdk->sendMutex);

    pthread_mutex_lock(&sdk->recvMutex);
    while (!queueSDKMessageIsEmpty(&sdk->recvQueue)) {
        SDKMessage msg;
        if (queueSDKMessageFront(&sdk->recvQueue, &msg) == ContainerSucc) {
            free(msg.data);
            queueSDKMessagePop(&sdk->recvQueue);
        }
    }
    queueSDKMessageDeinit(&sdk->recvQueue);
    pthread_mutex_unlock(&sdk->recvMutex);

    pthread_mutex_destroy(&sdk->sendMutex);
    pthread_mutex_destroy(&sdk->recvMutex);

    free(sdk);
}

int sdk_send(PacPlaySDK *sdk, const void *data, size_t len)
{
    if (sdk == NULL || data == NULL || len == 0 || len > SDK_MAX_PAYLOAD) {
        return -1;
    }

    uint8_t *copyBuf = malloc(len);
    if (copyBuf == NULL) {
        return -1;
    }
    memcpy(copyBuf, data, len);

    SDKMessage msg = {.data = copyBuf, .len = len, .capacity = len};

    pthread_mutex_lock(&sdk->sendMutex);
    if (!sdk->running) {
        pthread_mutex_unlock(&sdk->sendMutex);
        free(copyBuf);
        return -1;
    }
    if (queueSDKMessageSize(&sdk->sendQueue) >= SDK_QUEUE_CAPACITY) {
        pthread_mutex_unlock(&sdk->sendMutex);
        free(copyBuf);
        return -1;
    }
    ContainerRes pushRes = queueSDKMessagePush(&sdk->sendQueue, msg);
    pthread_mutex_unlock(&sdk->sendMutex);

    if (pushRes != ContainerSucc) {
        free(copyBuf);
        return -1;
    }

    return 0;
}

bool sdk_poll_send(PacPlaySDK *sdk, uint8_t **outPayload, size_t *outLen)
{
    if (sdk == NULL || outPayload == NULL || outLen == NULL) {
        return false;
    }

    pthread_mutex_lock(&sdk->sendMutex);

    if (queueSDKMessageIsEmpty(&sdk->sendQueue)) {
        pthread_mutex_unlock(&sdk->sendMutex);
        return false;
    }

    SDKMessage msg;
    queueSDKMessageFront(&sdk->sendQueue, &msg);
    queueSDKMessagePop(&sdk->sendQueue);

    pthread_mutex_unlock(&sdk->sendMutex);

    *outPayload = msg.data;
    *outLen = msg.len;
    return true;
}

void sdk_push_received(PacPlaySDK *sdk, const uint8_t *payload, size_t len)
{
    if (sdk == NULL || payload == NULL || len == 0 || len > SDK_MAX_PAYLOAD) {
        return;
    }

    uint8_t *copyBuf = malloc(len);
    if (copyBuf == NULL) {
        return;
    }
    memcpy(copyBuf, payload, len);

    SDKMessage msg = {.data = copyBuf, .len = len, .capacity = len};

    pthread_mutex_lock(&sdk->recvMutex);
    if (!sdk->running) {
        pthread_mutex_unlock(&sdk->recvMutex);
        free(copyBuf);
        return;
    }
    if (queueSDKMessagePush(&sdk->recvQueue, msg) != ContainerSucc) {
        pthread_mutex_unlock(&sdk->recvMutex);
        free(copyBuf);
        return;
    }
    pthread_mutex_unlock(&sdk->recvMutex);
}

void sdk_poll(PacPlaySDK *sdk)
{
    if (sdk == NULL) {
        return;
    }

    for (;;) {
        pthread_mutex_lock(&sdk->recvMutex);

        if (queueSDKMessageIsEmpty(&sdk->recvQueue)) {
            pthread_mutex_unlock(&sdk->recvMutex);
            break;
        }

        SDKMessage msg;
        queueSDKMessageFront(&sdk->recvQueue, &msg);
        queueSDKMessagePop(&sdk->recvQueue);

        pthread_mutex_unlock(&sdk->recvMutex);

        if (sdk->callback != NULL) {
            sdk->callback(msg.data, msg.len, sdk->userData);
        }
        free(msg.data);
    }
}

void sdk_on_receive(PacPlaySDK *sdk, PacPlayOnReceive callback,
                    void *userData)
{
    if (sdk == NULL) {
        return;
    }
    sdk->callback = callback;
    sdk->userData = userData;
}

void sdk_free_payload(PacPlaySDK *sdk, uint8_t *payload)
{
    (void)sdk;
    free(payload);
}
