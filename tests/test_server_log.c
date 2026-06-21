/**
 * @file test_server_log.c
 * @brief Contract tests for the serverLog wrapper API.
 *
 * Verifies the thin wrapper correctly delegates to autoLog with
 * server-specific config (prefix="server", enableTuiBuffer=true)
 * and that the full fetch pipeline works end-to-end.
 *
 * Full engine test coverage lives in test_auto_log.c.
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

enum {
    LogSleepUs = 100000,
    LogRetryCount = 30,
    LogRetrySleepUs = 50000,
};

static void removeLogDir(void) { rmdir("./logs"); }

/* ──────────── init + close lifecycle ────────────────────────────────────── */

static void testServerLogInitAndClose(void) {
    ASSERT_INT_EQ(serverLogInit(), 0);
    serverLogClose();
    removeLogDir();
}

/* ──────────── double init (re-entrant) ──────────────────────────────────── */

static void testServerLogInitDoubleCall(void) {
    ASSERT_INT_EQ(serverLogInit(), 0);
    ASSERT_INT_EQ(serverLogInit(), 0);
    serverLogClose();
    removeLogDir();
}

/* ──────────── fetch before init → returns -1 ────────────────────────────── */

static void testServerLogFetchBeforeInit(void) {
    char **lines = NULL;
    int count = 0;
    ASSERT_INT_EQ(serverLogFetch(LogLevelTrace, &lines, &count), -1);
}

/* ──────────── fetch with messages ───────────────────────────────────────── */

static void testServerLogFetchWithMessages(void) {
    ASSERT_INT_EQ(serverLogInit(), 0);

    LOG_INFO("server test message alpha");
    LOG_WARN("server test message beta");

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

/* ──────────── fetch level filtering ─────────────────────────────────────── */

static void testServerLogFetchLevelFilter(void) {
    ASSERT_INT_EQ(serverLogInit(), 0);

    LOG_TRACE("should be filtered out");
    LOG_DEBUG("should also be filtered out");
    LOG_ERROR("visible error message");

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

/* ════════════════════════════════════════════════════════════════════════ */

int main(void) {
    printf("test_server_log:\n");

    RUN_TEST(testServerLogInitAndClose);
    RUN_TEST(testServerLogInitDoubleCall);
    RUN_TEST(testServerLogFetchBeforeInit);
    RUN_TEST(testServerLogFetchWithMessages);
    RUN_TEST(testServerLogFetchLevelFilter);

    return TEST_REPORT();
}
