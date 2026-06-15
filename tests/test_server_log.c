/**
 * @file test_server_log.c
 * @brief Unit tests for the server logging subsystem (serverLog.c).
 *
 * Covers serverLogInit/Close lifecycle, serverLogFetch/FetchFree API,
 * NULL safety, level filtering, and re-entrant init calls.
 *
 * @date 2026-06-15
 * @copyright GPLv3 License
 */

#include "log.h"
#include "server/serverLog.h"
#include "test_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ────────────────────────── test-local constants ────────────────────────── */

enum { LogSleepUs = 100000, LogRetryCount = 30, LogRetrySleepUs = 50000 };

/* ───────────────────────── cleanup helper ───────────────────────────────── */

static void removeLogDir(void) {
    remove("./logs/server-*.log");
    rmdir("./logs");
}

/* ──────────── serverLogFetchFree NULL safety ───────────────────────────────
 */

static void testLogFetchFreeNull(void) { serverLogFetchFree(NULL, 0); }

/* ──────────── serverLogClose without init ─────────────────────────────── */

static void testLogCloseWithoutInit(void) { serverLogClose(); }

/* ──────────── serverLogInit + serverLogClose lifecycle ─────────────────────
 */

static void testLogInitAndClose(void) {
    ASSERT_INT_EQ(serverLogInit(), 0);
    serverLogClose();
    removeLogDir();
}

/* ──────────── serverLogInit double call (re-entrant) ───────────────────────
 */

static void testLogInitDoubleCall(void) {
    ASSERT_INT_EQ(serverLogInit(), 0);
    ASSERT_INT_EQ(serverLogInit(), 0);
    serverLogClose();
    removeLogDir();
}

/* ──────────── serverLogFetch before init → returns -1 ─────────────────── */

static void testLogFetchBeforeInit(void) {
    char **lines = NULL;
    int count = 0;
    ASSERT_INT_EQ(serverLogFetch(LogLevelTrace, &lines, &count), -1);
}

/* ──────────── serverLogFetch with NULL outLines → returns -1 ──────────── */

static void testLogFetchNullOutLines(void) {
    ASSERT_INT_EQ(serverLogInit(), 0);
    int count = 0;
    ASSERT_INT_EQ(serverLogFetch(LogLevelTrace, NULL, &count), -1);
    serverLogClose();
    removeLogDir();
}

/* ──────────── serverLogFetch empty (no messages) ──────────────────────── */

static void testLogFetchEmptyAfterInit(void) {
    ASSERT_INT_EQ(serverLogInit(), 0);

    usleep(LogSleepUs);

    char **lines = NULL;
    int count = -1;
    ASSERT_INT_EQ(serverLogFetch(LogLevelFatal, &lines, &count), 0);
    ASSERT_INT_EQ(count, 0);
    ASSERT_NOT_NULL(lines);
    ASSERT_NULL(lines[0]);
    serverLogFetchFree(lines, count);

    serverLogClose();
    removeLogDir();
}

/* ──────────── serverLogFetch with messages ────────────────────────────── */

static void testLogFetchWithMessages(void) {
    ASSERT_INT_EQ(serverLogInit(), 0);

    LOG_INFO("test message alpha");
    LOG_WARN("test message beta");

    int found = 0;
    for (int attempt = 0; attempt < LogRetryCount; attempt++) {
        usleep(LogRetrySleepUs);
        char **lines = NULL;
        int count = 0;
        if (serverLogFetch(LogLevelTrace, &lines, &count) == 0 && count > 0) {
            found = count;
            serverLogFetchFree(lines, count);
            break;
        }
        serverLogFetchFree(lines, count);
    }
    ASSERT_TRUE(found >= 1);

    serverLogClose();
    removeLogDir();
}

/* ──────────── serverLogFetch level filtering ──────────────────────────── */

static void testLogFetchLevelFilter(void) {
    ASSERT_INT_EQ(serverLogInit(), 0);

    LOG_TRACE("should be filtered");
    LOG_DEBUG("should be filtered");
    LOG_ERROR("visible error");

    int errorCount = 0;
    for (int attempt = 0; attempt < LogRetryCount; attempt++) {
        usleep(LogRetrySleepUs);
        char **lines = NULL;
        int count = 0;
        if (serverLogFetch(LogLevelError, &lines, &count) == 0) {
            errorCount = count;
            serverLogFetchFree(lines, count);
            if (errorCount > 0) {
                break;
            }
        } else {
            serverLogFetchFree(lines, count);
        }
    }
    ASSERT_TRUE(errorCount >= 1);

    serverLogClose();
    removeLogDir();
}

/* ════════════════════════════════════════════════════════════════════════
   main
   ════════════════════════════════════════════════════════════════════════ */

int main(void) {
    printf("test_server_log:\n");

    RUN_TEST(testLogFetchFreeNull);
    RUN_TEST(testLogCloseWithoutInit);
    RUN_TEST(testLogInitAndClose);
    RUN_TEST(testLogInitDoubleCall);
    RUN_TEST(testLogFetchBeforeInit);
    RUN_TEST(testLogFetchNullOutLines);
    RUN_TEST(testLogFetchEmptyAfterInit);
    RUN_TEST(testLogFetchWithMessages);
    RUN_TEST(testLogFetchLevelFilter);

    return TEST_REPORT();
}
