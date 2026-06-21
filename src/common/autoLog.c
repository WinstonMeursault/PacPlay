/**
 * @file autoLog.c
 * @brief Shared auto-rotating compressed log engine implementation.
 *
 * Architecture
 * ============
 * Producer-consumer with a fixed-size lock-free-friendly ring buffer:
 *
 *   Caller thread(s)                Log thread             Compress thread
 *   ────────────────                ──────────             ───────────────
 *   LOG_INFO(...)                   loop:                   loop:
 *     → logLog()                      → mutex_lock            → cond_wait
 *       → logCallback()               → pop one message       → scanLogDir()
 *         ├ vsnprintf(msg)            → mutex_unlock          → for each old
 *         ├ try-push (drop if full)   → check UTC date        │   .log file:
 *         └ cond_signal               → rotate if needed      │   compressOne
 *                                     → wake compress         │   → zng_gzwrite
 *                                     → fputs + fflush        │   → remove .log
 *                                     → on error: close       → track failures
 *                                   → drain queue on stop     (never blocks
 *                                   → fclose, running=false   log thread)
 *
 * @date 2026-06-20
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

#include "autoLog.h"

#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define WITH_GZFILEOP
#include <zlib-ng.h>

enum {
    TimeStampLen = 20,
    MinRoomForBody = 2,
    HeadRoomForNewline = 1,
    LogDateLen = 16,
    LogFilenameBufSize = 64,
    CompressBufSize = 64 * 1024,
    SecondsPerDay = 86400,
    LogDateStrLen = 10,
    LogExtLen = 4,
};

enum {
    DefaultQueueCapacity = 512,
    DefaultMaxMsgLen = 1024,
    DefaultRetentionDays = 7,
    DefaultMaxRestarts = 3,
    DefaultTuiCapacity = 256,
    DefaultLogDirPerm = 0755,
    LogDirMaxLen = 256,
    PrefixMaxLen = 64,
};

#define AUTOLOG_MSG_MAX_LEN DefaultMaxMsgLen

typedef struct {
    char msg[AUTOLOG_MSG_MAX_LEN];
} LogMsg;

typedef struct {
    LogMsg *buffer;
    int head;
    int tail;
    int count;
    int capacity;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool stop;
} LogMsgQueue;

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool stop;
    bool scanPending;
    int consecutiveFailures;
} CompressState;

typedef struct {
    char msg[AUTOLOG_MSG_MAX_LEN];
    LogLevel level;
} TuiLogMsg;

typedef struct {
    TuiLogMsg *messages;
    int head;
    int tail;
    int count;
    int capacity;
    bool enabled;
    pthread_mutex_t mutex;
} TuiLogQueue;

typedef struct {
    LogMsgQueue queue;
    pthread_t thread;
    volatile bool running;
    int restartCount;
    int maxRestarts;
    FILE *fp;
    char currentDate[LogDateLen];
    CompressState compressState;
    pthread_t compressThread;
    bool compressThreadCreated;
    int compressRetentionDays;
    TuiLogQueue tuiLogQueue;
    char logDir[LogDirMaxLen];
    char prefix[PrefixMaxLen];
} LogThreadState;

static LogThreadState *gLogState = NULL;

static void getUtcDateString(char *buf, size_t bufSize) {
    time_t now = time(NULL);
    struct tm utc = {0};
    gmtime_r(&now, &utc);
    strftime(buf, bufSize, "%Y-%m-%d", &utc);
}

static FILE *openLogFile(const LogThreadState *state, const char *dateStr) {
    char filename[LogFilenameBufSize];
    int written = snprintf(filename, sizeof(filename), "%s/%s-%s.log",
                           state->logDir, state->prefix, dateStr);
    if (written < 0 || (size_t)written >= sizeof(filename)) {
        return NULL;
    }
    FILE *fp = fopen(filename, "a");
    if (fp == NULL) {
        LOG_ERROR("autoLog: failed to open '%s': %s", filename,
                  strerror(errno));
    }
    return fp;
}

static int compressOneFile(const LogThreadState *state, const char *date) {
    char plainPath[LogFilenameBufSize];
    char gzPath[LogFilenameBufSize];

    int written = snprintf(plainPath, sizeof(plainPath), "%s/%s-%s.log",
                           state->logDir, state->prefix, date);
    if (written < 0 || (size_t)written >= sizeof(plainPath)) {
        return -1;
    }
    written = snprintf(gzPath, sizeof(gzPath), "%s/%s-%s.log.gz",
                       state->logDir, state->prefix, date);
    if (written < 0 || (size_t)written >= sizeof(gzPath)) {
        return -1;
    }

    if (access(gzPath, F_OK) == 0) {
        return -1;
    }

    FILE *in = fopen(plainPath, "rb");
    if (in == NULL) {
        return -1;
    }

    gzFile out = zng_gzopen(gzPath, "wb");
    if (out == NULL) {
        fclose(in);
        return -1;
    }

    (void)zng_gzsetparams(out, Z_BEST_COMPRESSION, Z_DEFAULT_STRATEGY);

    uint8_t buf[CompressBufSize];
    size_t n;
    int writeErr = 0;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (zng_gzwrite(out, buf, (uint32_t)n) <= 0) {
            writeErr = 1;
            break;
        }
    }

    int closeRc = (int)zng_gzclose(out);
    fclose(in);

    if (writeErr != 0 || closeRc != Z_OK) {
        return -1;
    }

    if (remove(plainPath) != 0) {
        LOG_WARN("autoLog: failed to remove '%s': %s", plainPath,
                 strerror(errno));
    }

    return 0;
}

static void scanAndCompressOldLogs(LogThreadState *state, CompressState *cs) {
    time_t now = time(NULL);
    time_t threshold =
        now - (time_t)(state->compressRetentionDays * SecondsPerDay);
    struct tm utc = {0};
    gmtime_r(&threshold, &utc);
    char cutoff[LogDateLen];
    strftime(cutoff, sizeof(cutoff), "%Y-%m-%d", &utc);

    DIR *dir = opendir(state->logDir);
    if (dir == NULL) {
        return;
    }

    bool hadFailure = false;
    size_t prefixLen = strlen(state->prefix);
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        const char *name = entry->d_name;
        if (strncmp(name, state->prefix, prefixLen) != 0) {
            continue;
        }
        if (name[prefixLen] != '-') {
            continue;
        }
        size_t nameLen = strlen(name);
        static const char *suffix = ".log";
        if (nameLen < prefixLen + 1 + (size_t)LogDateStrLen +
                          (size_t)LogExtLen) {
            continue;
        }
        const char *dot = name + nameLen - LogExtLen;
        if (strcmp(dot, suffix) != 0) {
            continue;
        }

        char fileDate[LogDateLen];
        memcpy(fileDate, name + prefixLen + 1, LogDateStrLen);
        fileDate[LogDateStrLen] = '\0';

        if (strcmp(fileDate, cutoff) < 0) {
            if (compressOneFile(state, fileDate) != 0) {
                hadFailure = true;
            }
        }
    }
    closedir(dir);

    if (hadFailure) {
        cs->consecutiveFailures++;
        if (cs->consecutiveFailures >= 3) {
            LOG_WARN("Log compression failed for %d consecutive days",
                     cs->consecutiveFailures);
        }
    } else {
        cs->consecutiveFailures = 0;
    }
}

static void *compressThreadFunc(void *arg) {
    LogThreadState *state = (LogThreadState *)arg;
    CompressState *cs = &state->compressState;

    while (true) {
        pthread_mutex_lock(&cs->mutex);
        while (!cs->scanPending && !cs->stop) {
            pthread_cond_wait(&cs->cond, &cs->mutex);
        }
        if (!cs->scanPending && cs->stop) {
            pthread_mutex_unlock(&cs->mutex);
            break;
        }
        cs->scanPending = false;
        pthread_mutex_unlock(&cs->mutex);

        scanAndCompressOldLogs(state, cs);
    }
    return NULL;
}

int autoLogFetch(LogLevel minLevel, char ***outLines, int *outCount) {
    if (gLogState == NULL || outLines == NULL ||
        !gLogState->tuiLogQueue.enabled) {
        return -1;
    }

    TuiLogQueue *q = &gLogState->tuiLogQueue;
    pthread_mutex_lock(&q->mutex);

    int matchCount = 0;
    int idx = q->tail;
    for (int i = 0; i < q->count; i++) {
        if (q->messages[idx].level >= minLevel) {
            matchCount++;
        }
        idx = (idx + 1) % q->capacity;
    }

    char **lines = (char **)calloc((size_t)matchCount + 1, sizeof(char *));
    if (lines == NULL) {
        q->head = 0;
        q->tail = 0;
        q->count = 0;
        pthread_mutex_unlock(&q->mutex);
        return -1;
    }

    int outIdx = 0;
    idx = q->tail;
    for (int i = 0; i < q->count; i++) {
        if (q->messages[idx].level >= minLevel) {
            lines[outIdx] = strdup(q->messages[idx].msg);
            if (lines[outIdx] == NULL) {
                for (int j = 0; j < outIdx; j++) {
                    free(lines[j]);
                }
                free(lines);
                q->head = 0;
                q->tail = 0;
                q->count = 0;
                pthread_mutex_unlock(&q->mutex);
                return -1;
            }
            outIdx++;
        }
        idx = (idx + 1) % q->capacity;
    }
    lines[outIdx] = NULL;

    q->head = 0;
    q->tail = 0;
    q->count = 0;
    pthread_mutex_unlock(&q->mutex);

    *outLines = lines;
    if (outCount != NULL) {
        *outCount = matchCount;
    }
    return 0;
}

void autoLogFetchFree(char **lines, int count) {
    if (lines == NULL) {
        return;
    }
    for (int i = 0; i < count; i++) {
        free((void *)lines[i]);
    }
    free((void *)lines);
}

static void logCallback(LogEvent *ev) {
    if (gLogState == NULL || !gLogState->running) {
        return;
    }

    time_t now = time(NULL);
    struct tm utc = {0};
    gmtime_r(&now, &utc);
    char tbuf[TimeStampLen];
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", &utc);

    char msgBuf[AUTOLOG_MSG_MAX_LEN];
    int written = snprintf(msgBuf, sizeof(msgBuf), "%s %-5s %s:%d: ", tbuf,
                           logLevelString(ev->level), ev->file, ev->line);
    if (written < 0 || (size_t)written >= sizeof(msgBuf)) {
        return;
    }

    size_t remaining = sizeof(msgBuf) - (size_t)written;
    if (remaining < MinRoomForBody) {
        return;
    }
    remaining -= (size_t)HeadRoomForNewline;

    int bodyLen = vsnprintf(msgBuf + written, remaining, ev->fmt, ev->ap);
    if (bodyLen < 0) {
        return;
    }

    size_t actualBody = (size_t)bodyLen;
    if (actualBody >= remaining) {
        actualBody = remaining - 1;
    }

    msgBuf[written + actualBody] = '\n';
    msgBuf[written + actualBody + 1] = '\0';
    size_t msgLen = (size_t)written + actualBody + 2;

    LogMsgQueue *q = &gLogState->queue;
    pthread_mutex_lock(&q->mutex);
    if (q->count < q->capacity) {
        if (msgLen > sizeof(q->buffer[q->head].msg)) {
            msgLen = sizeof(q->buffer[q->head].msg);
        }
        memcpy(q->buffer[q->head].msg, msgBuf, msgLen);
        q->buffer[q->head].msg[sizeof(q->buffer[q->head].msg) - 1] = '\0';
        q->head = (q->head + 1) % q->capacity;
        q->count++;
        pthread_cond_signal(&q->cond);
    }
    pthread_mutex_unlock(&q->mutex);

    if (gLogState->tuiLogQueue.enabled) {
        TuiLogQueue *tq = &gLogState->tuiLogQueue;
        pthread_mutex_lock(&tq->mutex);
        if (tq->count < tq->capacity) {
            if (msgLen > sizeof(tq->messages[tq->head].msg)) {
                msgLen = sizeof(tq->messages[tq->head].msg);
            }
            memcpy(tq->messages[tq->head].msg, msgBuf, msgLen);
            tq->messages[tq->head]
                .msg[sizeof(tq->messages[tq->head].msg) - 1] = '\0';
            tq->messages[tq->head].level = ev->level;
            tq->head = (tq->head + 1) % tq->capacity;
            tq->count++;
        }
        pthread_mutex_unlock(&tq->mutex);
    }
}

static void *logThreadFunc(void *arg) {
    LogThreadState *state = (LogThreadState *)arg;

    while (true) {
        pthread_mutex_lock(&state->queue.mutex);
        while (state->queue.count == 0 && !state->queue.stop) {
            pthread_cond_wait(&state->queue.cond, &state->queue.mutex);
        }
        if (state->queue.count == 0) {
            pthread_mutex_unlock(&state->queue.mutex);
            break;
        }

        LogMsg msg = state->queue.buffer[state->queue.tail];
        state->queue.tail = (state->queue.tail + 1) % state->queue.capacity;
        state->queue.count--;
        pthread_mutex_unlock(&state->queue.mutex);

        char today[LogDateLen];
        getUtcDateString(today, sizeof(today));
        if (strcmp(today, state->currentDate) != 0) {
            if (state->fp != NULL) {
                fclose(state->fp);
                state->fp = NULL;
            }
            strncpy(state->currentDate, today, sizeof(state->currentDate) - 1);
            state->currentDate[sizeof(state->currentDate) - 1] = '\0';
            state->fp = openLogFile(state, today);

            pthread_mutex_lock(&state->compressState.mutex);
            state->compressState.scanPending = true;
            pthread_cond_signal(&state->compressState.cond);
            pthread_mutex_unlock(&state->compressState.mutex);
        }

        if (state->fp != NULL) {
            if (fputs(msg.msg, state->fp) == EOF) {
                fclose(state->fp);
                state->fp = NULL;
                LOG_ERROR("autoLog: write error, file closed");
            } else {
                fflush(state->fp);
            }
        }
    }

    if (state->fp != NULL) {
        fclose(state->fp);
        state->fp = NULL;
    }
    state->running = false;
    return NULL;
}

int autoLogInit(const AutoLogConfig *cfg) {
    if (gLogState != NULL) {
        return 0;
    }
    if (cfg == NULL || cfg->fileNamePrefix == NULL) {
        return -1;
    }

    const char *dir = cfg->logDir != NULL ? cfg->logDir : "./logs";
    if (mkdir(dir, DefaultLogDirPerm) != 0 && errno != EEXIST) {
        LOG_ERROR("autoLog: failed to create '%s': %s", dir, strerror(errno));
        return -1;
    }

    gLogState = (LogThreadState *)calloc(1, sizeof(LogThreadState));
    if (gLogState == NULL) {
        LOG_ERROR("autoLog: calloc failed");
        return -1;
    }

    strncpy(gLogState->logDir, dir, sizeof(gLogState->logDir) - 1);
    gLogState->logDir[sizeof(gLogState->logDir) - 1] = '\0';
    strncpy(gLogState->prefix, cfg->fileNamePrefix,
            sizeof(gLogState->prefix) - 1);
    gLogState->prefix[sizeof(gLogState->prefix) - 1] = '\0';

    int qCap =
        cfg->queueCapacity > 0 ? cfg->queueCapacity : DefaultQueueCapacity;
    gLogState->compressRetentionDays = cfg->compressRetentionDays > 0
                                           ? cfg->compressRetentionDays
                                           : DefaultRetentionDays;
    gLogState->maxRestarts =
        cfg->maxRestarts > 0 ? cfg->maxRestarts : DefaultMaxRestarts;

    gLogState->queue.capacity = qCap;
    gLogState->queue.buffer =
        (LogMsg *)calloc((size_t)qCap, sizeof(LogMsg));
    if (gLogState->queue.buffer == NULL) {
        LOG_ERROR("autoLog: queue buffer alloc failed");
        free(gLogState);
        gLogState = NULL;
        return -1;
    }

    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
    if (pthread_mutex_init(&gLogState->queue.mutex, &attr) != 0) {
        pthread_mutexattr_destroy(&attr);
        free(gLogState->queue.buffer);
        free(gLogState);
        gLogState = NULL;
        return -1;
    }
    pthread_mutexattr_destroy(&attr);

    if (pthread_cond_init(&gLogState->queue.cond, NULL) != 0) {
        pthread_mutex_destroy(&gLogState->queue.mutex);
        free(gLogState->queue.buffer);
        free(gLogState);
        gLogState = NULL;
        return -1;
    }

    gLogState->running = true;
    if (pthread_create(&gLogState->thread, NULL, logThreadFunc,
                       gLogState) != 0) {
        pthread_cond_destroy(&gLogState->queue.cond);
        pthread_mutex_destroy(&gLogState->queue.mutex);
        free(gLogState->queue.buffer);
        free(gLogState);
        gLogState = NULL;
        return -1;
    }

    {
        pthread_mutexattr_t cattr;
        pthread_mutexattr_init(&cattr);
        pthread_mutexattr_settype(&cattr, PTHREAD_MUTEX_ERRORCHECK);
        if (pthread_mutex_init(&gLogState->compressState.mutex, &cattr) == 0) {
            pthread_mutexattr_destroy(&cattr);
            if (pthread_cond_init(&gLogState->compressState.cond, NULL) == 0) {
                if (pthread_create(&gLogState->compressThread, NULL,
                                   compressThreadFunc, gLogState) == 0) {
                    gLogState->compressThreadCreated = true;
                } else {
                    LOG_ERROR("autoLog: compress thread creation failed");
                    pthread_cond_destroy(&gLogState->compressState.cond);
                    pthread_mutex_destroy(&gLogState->compressState.mutex);
                }
            } else {
                pthread_mutex_destroy(&gLogState->compressState.mutex);
            }
        } else {
            pthread_mutexattr_destroy(&cattr);
        }
    }

    gLogState->tuiLogQueue.enabled = cfg->enableTuiBuffer;
    if (gLogState->tuiLogQueue.enabled) {
        int tuiCap = cfg->tuiBufferCapacity > 0 ? cfg->tuiBufferCapacity
                                                : DefaultTuiCapacity;
        gLogState->tuiLogQueue.capacity = tuiCap;
        gLogState->tuiLogQueue.messages =
            (TuiLogMsg *)calloc((size_t)tuiCap, sizeof(TuiLogMsg));
        if (gLogState->tuiLogQueue.messages != NULL) {
            pthread_mutexattr_t tattr;
            pthread_mutexattr_init(&tattr);
            pthread_mutexattr_settype(&tattr, PTHREAD_MUTEX_ERRORCHECK);
            if (pthread_mutex_init(&gLogState->tuiLogQueue.mutex,
                                   &tattr) != 0) {
                pthread_mutexattr_destroy(&tattr);
                free(gLogState->tuiLogQueue.messages);
                gLogState->tuiLogQueue.messages = NULL;
                gLogState->tuiLogQueue.enabled = false;
                LOG_ERROR("autoLog: TUI log mutex init failed");
            }
            pthread_mutexattr_destroy(&tattr);
        } else {
            gLogState->tuiLogQueue.enabled = false;
            LOG_ERROR("autoLog: TUI log buffer alloc failed");
        }
    }

    if (logAddCallback(logCallback, NULL, LogLevelTrace) != 0) {
        gLogState->queue.stop = true;
        pthread_cond_signal(&gLogState->queue.cond);
        pthread_join(gLogState->thread, NULL);
        pthread_cond_destroy(&gLogState->queue.cond);
        pthread_mutex_destroy(&gLogState->queue.mutex);
        free(gLogState->queue.buffer);
        LOG_ERROR("autoLog: callback registration failed");
        free(gLogState);
        gLogState = NULL;
        return -1;
    }

    return 0;
}

void autoLogCheckAndRestart(void) {
    if (gLogState == NULL || gLogState->running) {
        return;
    }

    if (gLogState->restartCount >= gLogState->maxRestarts) {
        return;
    }

    gLogState->restartCount++;

    LOG_WARN("Log thread died, attempting restart (%d/%d)...",
             gLogState->restartCount, gLogState->maxRestarts);

    if (gLogState->fp != NULL) {
        fclose(gLogState->fp);
        gLogState->fp = NULL;
    }
    gLogState->currentDate[0] = '\0';

    pthread_mutex_lock(&gLogState->queue.mutex);
    gLogState->queue.head = 0;
    gLogState->queue.tail = 0;
    gLogState->queue.count = 0;
    gLogState->queue.stop = false;
    pthread_mutex_unlock(&gLogState->queue.mutex);

    pthread_mutex_lock(&gLogState->compressState.mutex);
    gLogState->compressState.scanPending = false;
    gLogState->compressState.consecutiveFailures = 0;
    pthread_mutex_unlock(&gLogState->compressState.mutex);

    if (gLogState->tuiLogQueue.enabled) {
        pthread_mutex_lock(&gLogState->tuiLogQueue.mutex);
        gLogState->tuiLogQueue.head = 0;
        gLogState->tuiLogQueue.tail = 0;
        gLogState->tuiLogQueue.count = 0;
        pthread_mutex_unlock(&gLogState->tuiLogQueue.mutex);
    }

    gLogState->running = true;
    if (pthread_create(&gLogState->thread, NULL, logThreadFunc,
                       gLogState) != 0) {
        LOG_ERROR("Failed to restart log thread (attempt %d)",
                  gLogState->restartCount);
        gLogState->running = false;
    }
}

void autoLogClose(void) {
    if (gLogState == NULL) {
        return;
    }

    pthread_mutex_lock(&gLogState->queue.mutex);
    gLogState->queue.stop = true;
    pthread_cond_signal(&gLogState->queue.cond);
    pthread_mutex_unlock(&gLogState->queue.mutex);

    pthread_join(gLogState->thread, NULL);

    if (gLogState->compressThreadCreated) {
        pthread_mutex_lock(&gLogState->compressState.mutex);
        gLogState->compressState.stop = true;
        pthread_cond_signal(&gLogState->compressState.cond);
        pthread_mutex_unlock(&gLogState->compressState.mutex);
        pthread_join(gLogState->compressThread, NULL);
        pthread_cond_destroy(&gLogState->compressState.cond);
        pthread_mutex_destroy(&gLogState->compressState.mutex);
    }

    if (gLogState->tuiLogQueue.enabled) {
        pthread_mutex_destroy(&gLogState->tuiLogQueue.mutex);
        free(gLogState->tuiLogQueue.messages);
    }

    pthread_cond_destroy(&gLogState->queue.cond);
    pthread_mutex_destroy(&gLogState->queue.mutex);

    free(gLogState->queue.buffer);
    free(gLogState);
    gLogState = NULL;
}
