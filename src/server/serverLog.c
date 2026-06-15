/**
 * @file serverLog.c
 * @brief Server file-logging subsystem implementation.
 *
 * Architecture
 * ============
 * Producer-consumer with a fixed-size lock-free-friendly ring buffer:
 *
 *   Caller thread(s)                Log thread             Compress thread
 *   ────────────────                ──────────             ───────────────
 *   LOG_INFO(...)                   loop:                   loop:
 *     → logLog()                      → mutex_lock            → cond_wait
 *       → serverLogCallback()         → pop one message       → scanLogDir()
 *         ├ vsnprintf(msg)            → mutex_unlock          → for each old
 *         ├ try-push (drop if full)   → check UTC date        │   .log file:
 *         └ cond_signal               → rotate if needed      │   compressOne
 *                                     → wake compress         │   → zng_gzwrite
 *                                     → fputs + fflush        │   → remove .log
 *                                     → on error: close       → track failures
 *                                   → drain queue on stop     (never blocks
 *                                   → fclose, running=false   log thread)
 *
 * The log thread is monitored by serverLogCheckAndRestart() called from the
 * server main loop.  Up to three automatic restarts are attempted before
 * giving up.
 *
 * @date 2026-06-10
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

#include "serverLog.h"

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

/* ─────────────────────────────── constants ──────────────────────────────── */

/** @brief Path to the log directory (created on init if missing). */
#define LOG_DIR_PATH "./logs"

/** @brief Permissions for the log directory. */
#define LOG_DIR_PERM 0755

/** @brief Fixed capacity of the ring buffer (message slots). */
#define LOG_QUEUE_CAPACITY 512

/** @brief Maximum length of a single formatted log message. */
#define LOG_MSG_MAX_LEN 1024

/** @brief "YYYY-MM-DD\0" — used for file-name rotation comparisons. */
#define LOG_DATE_LEN 16

/** @brief Maximum filename length (path + "server-YYYY-MM-DD.log"). */
#define LOG_FILENAME_BUF_SIZE 64

/** @brief Maximum number of automatic restarts before giving up. */
#define LOG_MAX_RESTART 3

/** @brief Read/write buffer size for log compression (64 KiB). */
#define COMPRESS_BUF_SIZE (64 * 1024)

/** @brief Number of days after which uncompressed logs are eligible. */
#define COMPRESS_RETENTION_DAYS 7

/** @brief Seconds in a UTC day. */
#define SECONDS_PER_DAY 86400

/** @brief Length of the "server-" filename prefix. */
#define LOG_PREFIX_LEN 7

/** @brief Length of a "YYYY-MM-DD" date string (excluding NUL). */
#define LOG_DATE_STR_LEN 10

/** @brief Length of the ".log" extension. */
#define LOG_EXT_LEN 4

/** @brief Fixed capacity of the TUI-facing log ring buffer. */
#define TUI_LOG_CAPACITY 256

/* ──────────────── anonymous enums (avoid bare magic numbers) ─────────────── */

enum {
    /** "YYYY-MM-DD HH:MM:SS\0" */
    TimeStampLen = 20,
    /** Minimum free bytes for message body + newline. */
    MinRoomForBody = 2,
    /** One byte reserved for the trailing newline. */
    HeadRoomForNewline = 1,
};

/* ───────────────────────────── data structures ───────────────────────────── */

/** @brief One pre-formatted log message in the ring buffer. */
typedef struct {
    char msg[LOG_MSG_MAX_LEN];
} LogMsg;

/** @brief Fixed-size ring buffer with synchronisation primitives. */
typedef struct {
    LogMsg buffer[LOG_QUEUE_CAPACITY];
    int head; /**< Insertion index. */
    int tail; /**< Removal index. */
    int count;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool stop; /**< Set by serverLogClose() to request graceful exit. */
} LogMsgQueue;

/** @brief Synchronisation state for the background log-compression thread. */
typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool stop;
    bool scanPending;
    int consecutiveFailures;
} CompressState;

/** @brief One log entry in the TUI-facing ring buffer. */
typedef struct {
    char msg[LOG_MSG_MAX_LEN]; /**< Pre-formatted log line. */
    LogLevel level;            /**< Severity for caller-side filtering. */
} TuiLogMsg;

/** @brief Fixed-size ring buffer for TUI log retrieval. */
typedef struct {
    TuiLogMsg messages[TUI_LOG_CAPACITY];
    int head;
    int tail;
    int count;
    pthread_mutex_t mutex;
} TuiLogQueue;

/** @brief Top-level state of the logging subsystem. */
typedef struct {
    LogMsgQueue queue;
    pthread_t thread;
    volatile bool running;
    int restartCount;
    FILE *fp;
    char currentDate[LOG_DATE_LEN];
    CompressState compressState;
    pthread_t compressThread;
    TuiLogQueue tuiLogQueue;
} LogThreadState;

/* ────────────────────────────── module state ─────────────────────────────── */

/** @brief Singleton — allocated in serverLogInit(), freed in serverLogClose(). */
static LogThreadState *gLogState = NULL;

/* ─────────────────────────── internal helpers ────────────────────────────── */

/**
 * @brief Write a UTC "YYYY-MM-DD" string into @p buf.
 *
 * @param buf     Output buffer (at least @c LOG_DATE_LEN bytes).
 * @param bufSize Size of @p buf.
 */
static void getUtcDateString(char *buf, size_t bufSize) {
    time_t now = time(NULL);
    struct tm utc = {0};
    gmtime_r(&now, &utc);
    strftime(buf, bufSize, "%Y-%m-%d", &utc);
}

/**
 * @brief Open (or create) the log file for the given date.
 *
 * @param dateStr A "YYYY-MM-DD" string.
 * @return FILE*  Open file handle, or @c NULL on failure.
 */
static FILE *openLogFile(const char *dateStr) {
    char filename[LOG_FILENAME_BUF_SIZE];
    int written = snprintf(filename, sizeof(filename), "%s/server-%s.log",
                           LOG_DIR_PATH, dateStr);
    if (written < 0 || (size_t)written >= sizeof(filename)) {
        return NULL;
    }
    FILE *fp = fopen(filename, "a");
    if (fp == NULL) {
        LOG_ERROR("serverLog: failed to open '%s': %s", filename,
                  strerror(errno));
    }
    return fp;
}

/**
 * @brief Compress a single log file to @c .log.gz using zlib-ng.
 *
 * @param date A "YYYY-MM-DD" date string identifying the log file.
 * @return 0 on success, -1 if the file cannot be opened, read, or written.
 *
 * Best-effort: never crashes, all failures return -1.
 */
static int compressOneFile(const char *date) {
    char plainPath[LOG_FILENAME_BUF_SIZE];
    char gzPath[LOG_FILENAME_BUF_SIZE];

    int written = snprintf(plainPath, sizeof(plainPath), "%s/server-%s.log",
                           LOG_DIR_PATH, date);
    if (written < 0 || (size_t)written >= sizeof(plainPath)) {
        return -1;
    }
    written = snprintf(gzPath, sizeof(gzPath), "%s/server-%s.log.gz",
                       LOG_DIR_PATH, date);
    if (written < 0 || (size_t)written >= sizeof(gzPath)) {
        return -1;
    }

    /* Do not overwrite an existing .gz file */
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

    uint8_t buf[COMPRESS_BUF_SIZE];
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
        /* Compression failed — leave both files on disk for next retry */
        return -1;
    }

    if (remove(plainPath) != 0) {
        LOG_WARN("serverLog: failed to remove '%s': %s", plainPath,
                 strerror(errno));
        /* Compression succeeded even if unlink failed — return success */
    }

    return 0;
}

/**
 * @brief Scan the log directory and compress all files older than
 *        @c COMPRESS_RETENTION_DAYS days.
 *
 * @param cs Pointer to the @c CompressState for failure tracking.
 */
static void scanAndCompressOldLogs(CompressState *cs) {
    time_t now = time(NULL);
    time_t threshold = now - (time_t)(COMPRESS_RETENTION_DAYS * SECONDS_PER_DAY);
    struct tm utc = {0};
    gmtime_r(&threshold, &utc);
    char cutoff[LOG_DATE_LEN];
    strftime(cutoff, sizeof(cutoff), "%Y-%m-%d", &utc);

    DIR *dir = opendir(LOG_DIR_PATH);
    if (dir == NULL) {
        return;
    }

    bool hadFailure = false;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        /* Match "server-YYYY-MM-DD.log" */
        const char *name = entry->d_name;
        if (strncmp(name, "server-", LOG_PREFIX_LEN) != 0) {
            continue;
        }
        size_t nameLen = strlen(name);
        static const char *suffix = ".log";
        if (nameLen < (size_t)LOG_PREFIX_LEN + (size_t)LOG_DATE_STR_LEN +
                          (size_t)LOG_EXT_LEN + 1) {
            continue;
        }
        const char *dot = name + nameLen - LOG_EXT_LEN;
        if (strcmp(dot, suffix) != 0) {
            continue;
        }

        /* Extract date: characters at offset LOG_PREFIX_LEN, length
         * LOG_DATE_STR_LEN */
        char fileDate[LOG_DATE_LEN];
        memcpy(fileDate, name + LOG_PREFIX_LEN, LOG_DATE_STR_LEN);
        fileDate[LOG_DATE_STR_LEN] = '\0';

        /* Compress if file date is before the cutoff */
        if (strcmp(fileDate, cutoff) < 0) {
            if (compressOneFile(fileDate) != 0) {
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

/**
 * @brief Main function of the background log-compression thread.
 *
 * Sleeps until woken by the log thread on a UTC day rollover, then scans
 * the log directory for uncompressed files older than
 * @c COMPRESS_RETENTION_DAYS days and compresses them with zlib-ng.
 *
 * @param arg Opaque pointer to the @c LogThreadState.
 * @return NULL
 */
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

        scanAndCompressOldLogs(cs);
    }
    return NULL;
}

/* ─────────────────────────────── TUI fetch API ────────────────────────────── */

int serverLogFetch(LogLevel minLevel, char ***outLines, int *outCount) {
    if (gLogState == NULL || outLines == NULL) {
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
        idx = (idx + 1) % TUI_LOG_CAPACITY;
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
        idx = (idx + 1) % TUI_LOG_CAPACITY;
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

void serverLogFetchFree(char **lines, int count) {
    if (lines == NULL) {
        return;
    }
    for (int i = 0; i < count; i++) {
        free((void *)lines[i]);
    }
    free((void *)lines);
}

/**
 * @brief Logging callback registered with log.c.
 *
 * Formats the log event into a complete message line, then attempts to
 * push it onto the ring buffer.  If the buffer is full the message is
 * silently dropped — the callback never blocks.
 *
 * @param ev Pointer to the log event (valid for the duration of this call).
 */
static void serverLogCallback(LogEvent *ev) {
    if (gLogState == NULL || !gLogState->running) {
        return;
    }

    /* Build UTC timestamp */
    time_t now = time(NULL);
    struct tm utc = {0};
    gmtime_r(&now, &utc);
    char tbuf[TimeStampLen];
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", &utc);

    /* Format: "timestamp LEVEL file:line: " */
    char msgBuf[LOG_MSG_MAX_LEN];
    int written = snprintf(msgBuf, sizeof(msgBuf), "%s %-5s %s:%d: ", tbuf,
                           logLevelString(ev->level), ev->file, ev->line);
    if (written < 0 || (size_t)written >= sizeof(msgBuf)) {
        return;
    }

    /* Format message body, leaving room for newline */
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

    /* Push to ring buffer (non-blocking — drop if full) */
    LogMsgQueue *q = &gLogState->queue;
    pthread_mutex_lock(&q->mutex);
    if (q->count < LOG_QUEUE_CAPACITY) {
        size_t msgLen = (size_t)written + actualBody + 2;
        if (msgLen > sizeof(q->buffer[q->head].msg)) {
            msgLen = sizeof(q->buffer[q->head].msg);
        }
        memcpy(q->buffer[q->head].msg, msgBuf, msgLen);
        q->buffer[q->head].msg[sizeof(q->buffer[q->head].msg) - 1] = '\0';
        q->head = (q->head + 1) % LOG_QUEUE_CAPACITY;
        q->count++;
        pthread_cond_signal(&q->cond);
    }
    pthread_mutex_unlock(&q->mutex);

    /* Push to TUI ring buffer (independent lock — never blocks file I/O) */
    TuiLogQueue *tq = &gLogState->tuiLogQueue;
    pthread_mutex_lock(&tq->mutex);
    if (tq->count < TUI_LOG_CAPACITY) {
        size_t msgLen = (size_t)written + actualBody + 2;
        if (msgLen > sizeof(tq->messages[tq->head].msg)) {
            msgLen = sizeof(tq->messages[tq->head].msg);
        }
        memcpy(tq->messages[tq->head].msg, msgBuf, msgLen);
        tq->messages[tq->head]
            .msg[sizeof(tq->messages[tq->head].msg) - 1] = '\0';
        tq->messages[tq->head].level = ev->level;
        tq->head = (tq->head + 1) % TUI_LOG_CAPACITY;
        tq->count++;
    }
    pthread_mutex_unlock(&tq->mutex);
}

/**
 * @brief Main function of the dedicated log-writer thread.
 *
 * Waits for messages on the ring buffer, performs UTC-date-based file
 * rotation, and writes each message to the current log file with an
 * immediate flush.  File I/O errors cause the file to be closed (future
 * messages are silently dropped) but never crash the thread.
 *
 * @param arg Opaque pointer to the @c LogThreadState.
 * @return NULL
 */
static void *logThreadFunc(void *arg) {
    LogThreadState *state = (LogThreadState *)arg;

    while (true) {
        /* Wait for a message or stop signal */
        pthread_mutex_lock(&state->queue.mutex);
        while (state->queue.count == 0 && !state->queue.stop) {
            pthread_cond_wait(&state->queue.cond, &state->queue.mutex);
        }
        if (state->queue.count == 0) {
            /* Stop requested and queue drained */
            pthread_mutex_unlock(&state->queue.mutex);
            break;
        }

        /* Pop one message */
        LogMsg msg = state->queue.buffer[state->queue.tail];
        state->queue.tail = (state->queue.tail + 1) % LOG_QUEUE_CAPACITY;
        state->queue.count--;
        pthread_mutex_unlock(&state->queue.mutex);

        /* Check for UTC day rollover */
        char today[LOG_DATE_LEN];
        getUtcDateString(today, sizeof(today));
        if (strcmp(today, state->currentDate) != 0) {
            if (state->fp != NULL) {
                fclose(state->fp);
                state->fp = NULL;
            }
            strncpy(state->currentDate, today, sizeof(state->currentDate) - 1);
            state->currentDate[sizeof(state->currentDate) - 1] = '\0';
            state->fp = openLogFile(today);

            /* Wake the background compression thread */
            pthread_mutex_lock(&state->compressState.mutex);
            state->compressState.scanPending = true;
            pthread_cond_signal(&state->compressState.cond);
            pthread_mutex_unlock(&state->compressState.mutex);
        }

        /* Write to file */
        if (state->fp != NULL) {
            if (fputs(msg.msg, state->fp) == EOF) {
                fclose(state->fp);
                state->fp = NULL;
                LOG_ERROR("serverLog: write error, file closed");
            } else {
                fflush(state->fp);
            }
        }
    }

    /* Clean up on exit */
    if (state->fp != NULL) {
        fclose(state->fp);
        state->fp = NULL;
    }
    state->running = false;
    return NULL;
}

/* ─────────────────────────────── public API ──────────────────────────────── */

int serverLogInit(void) {
    if (gLogState != NULL) {
        return 0;
    }

    /* Ensure log directory exists */
    if (mkdir(LOG_DIR_PATH, LOG_DIR_PERM) != 0 && errno != EEXIST) {
        LOG_ERROR("serverLog: failed to create '%s': %s", LOG_DIR_PATH,
                  strerror(errno));
        return -1;
    }

    gLogState = (LogThreadState *)calloc(1, sizeof(LogThreadState));
    if (gLogState == NULL) {
        LOG_ERROR("serverLog: calloc failed");
        return -1;
    }

    /* Initialise mutex with error-check type for robustness */
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
    if (pthread_mutex_init(&gLogState->queue.mutex, &attr) != 0) {
        pthread_mutexattr_destroy(&attr);
        LOG_ERROR("serverLog: mutex init failed");
        free(gLogState);
        gLogState = NULL;
        return -1;
    }
    pthread_mutexattr_destroy(&attr);

    if (pthread_cond_init(&gLogState->queue.cond, NULL) != 0) {
        pthread_mutex_destroy(&gLogState->queue.mutex);
        LOG_ERROR("serverLog: cond init failed");
        free(gLogState);
        gLogState = NULL;
        return -1;
    }

    /* Spawn the log-writer thread */
    gLogState->running = true;
    if (pthread_create(&gLogState->thread, NULL, logThreadFunc,
                       gLogState) != 0) {
        pthread_cond_destroy(&gLogState->queue.cond);
        pthread_mutex_destroy(&gLogState->queue.mutex);
        LOG_ERROR("serverLog: thread creation failed");
        free(gLogState);
        gLogState = NULL;
        return -1;
    }

    /* Initialise the compression subsystem (best-effort — non-fatal). */
    {
        pthread_mutexattr_t cattr;
        pthread_mutexattr_init(&cattr);
        pthread_mutexattr_settype(&cattr, PTHREAD_MUTEX_ERRORCHECK);
        if (pthread_mutex_init(&gLogState->compressState.mutex, &cattr) == 0) {
            pthread_mutexattr_destroy(&cattr);
            if (pthread_cond_init(&gLogState->compressState.cond, NULL) == 0) {
                if (pthread_create(&gLogState->compressThread, NULL,
                                   compressThreadFunc, gLogState) != 0) {
                    LOG_ERROR("serverLog: compress thread creation failed");
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

    /* Initialise the TUI log queue mutex */
    {
        pthread_mutexattr_t tattr;
        pthread_mutexattr_init(&tattr);
        pthread_mutexattr_settype(&tattr, PTHREAD_MUTEX_ERRORCHECK);
        if (pthread_mutex_init(&gLogState->tuiLogQueue.mutex, &tattr) != 0) {
            pthread_mutexattr_destroy(&tattr);
            LOG_ERROR("serverLog: TUI log mutex init failed");
        }
        pthread_mutexattr_destroy(&tattr);
    }

    /* Register the producer-side callback with log.c */
    if (logAddCallback(serverLogCallback, NULL, LogLevelTrace) != 0) {
        gLogState->queue.stop = true;
        pthread_cond_signal(&gLogState->queue.cond);
        pthread_join(gLogState->thread, NULL);
        pthread_cond_destroy(&gLogState->queue.cond);
        pthread_mutex_destroy(&gLogState->queue.mutex);
        LOG_ERROR("serverLog: callback registration failed");
        free(gLogState);
        gLogState = NULL;
        return -1;
    }

    return 0;
}

void serverLogCheckAndRestart(void) {
    if (gLogState == NULL || gLogState->running) {
        return;
    }

    if (gLogState->restartCount >= LOG_MAX_RESTART) {
        return;
    }

    gLogState->restartCount++;

    LOG_WARN("Log thread died, attempting restart (%d/%d)...",
             gLogState->restartCount, LOG_MAX_RESTART);

    /* Close any stale file handle left by the dead thread */
    if (gLogState->fp != NULL) {
        fclose(gLogState->fp);
        gLogState->fp = NULL;
    }
    gLogState->currentDate[0] = '\0';

    /* Clear the ring buffer to avoid feeding stale messages to a new thread */
    pthread_mutex_lock(&gLogState->queue.mutex);
    gLogState->queue.head = 0;
    gLogState->queue.tail = 0;
    gLogState->queue.count = 0;
    gLogState->queue.stop = false;
    pthread_mutex_unlock(&gLogState->queue.mutex);

    /* Reset compression state (do not restart the compress thread) */
    pthread_mutex_lock(&gLogState->compressState.mutex);
    gLogState->compressState.scanPending = false;
    gLogState->compressState.consecutiveFailures = 0;
    pthread_mutex_unlock(&gLogState->compressState.mutex);

    /* Clear the TUI log buffer to avoid feeding stale messages */
    pthread_mutex_lock(&gLogState->tuiLogQueue.mutex);
    gLogState->tuiLogQueue.head = 0;
    gLogState->tuiLogQueue.tail = 0;
    gLogState->tuiLogQueue.count = 0;
    pthread_mutex_unlock(&gLogState->tuiLogQueue.mutex);

    gLogState->running = true;
    if (pthread_create(&gLogState->thread, NULL, logThreadFunc,
                       gLogState) != 0) {
        LOG_ERROR("Failed to restart log thread (attempt %d)",
                  gLogState->restartCount);
        gLogState->running = false;
    }
}

void serverLogClose(void) {
    if (gLogState == NULL) {
        return;
    }

    /* Signal the log thread to stop and wait for it to drain */
    pthread_mutex_lock(&gLogState->queue.mutex);
    gLogState->queue.stop = true;
    pthread_cond_signal(&gLogState->queue.cond);
    pthread_mutex_unlock(&gLogState->queue.mutex);

    pthread_join(gLogState->thread, NULL);

    /* Stop the background compression thread */
    pthread_mutex_lock(&gLogState->compressState.mutex);
    gLogState->compressState.stop = true;
    pthread_cond_signal(&gLogState->compressState.cond);
    pthread_mutex_unlock(&gLogState->compressState.mutex);
    pthread_join(gLogState->compressThread, NULL);
    pthread_cond_destroy(&gLogState->compressState.cond);
    pthread_mutex_destroy(&gLogState->compressState.mutex);

    pthread_mutex_destroy(&gLogState->tuiLogQueue.mutex);

    pthread_cond_destroy(&gLogState->queue.cond);
    pthread_mutex_destroy(&gLogState->queue.mutex);

    free(gLogState);
    gLogState = NULL;
}
