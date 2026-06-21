/**
 * @file test_auto_log.c
 * @brief Unit tests for the shared autoLog engine (autoLog.c).
 *
 * Covers autoLogInit/Close lifecycle, autoLogFetch/FetchFree API,
 * NULL safety, TUI buffer disabled mode, level filtering,
 * re-entrant init, config validation, and boundary conditions.
 *
 * @date 2026-06-20
 * @copyright GPLv3 License
 */

#include "common/autoLog.h"
#include "test_utils.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ────────────────────────── test-local constants ────────────────────────── */

enum {
    LogSleepUs = 100000,
    LogRetryCount = 30,
    LogRetrySleepUs = 50000,
    CustomQueueCap = 64,
    CustomRetention = 14,
    CustomTuiCap = 32,
    CustomMsgLen = 512,
    CustomMaxRestarts = 5,
};

/* ───────────────────────── cleanup helper ───────────────────────────────── */

static void removeLogDir(void) { rmdir("./logs"); }

static void closeAndClean(void) {
    autoLogClose();
    removeLogDir();
}

/* ──────────── autoLogFetchFree NULL safety ──────────────────────────────── */

static void testFetchFreeNull(void) { autoLogFetchFree(NULL, 0); }

static void testFetchFreeNullCount(void) { autoLogFetchFree(NULL, -1); }

/* ──────────── autoLogClose without init ─────────────────────────────────── */

static void testCloseWithoutInit(void) { autoLogClose(); }

/* ──────────── init with NULL config ────────────────────────────────────────
 */

static void testInitNullConfig(void) { ASSERT_INT_EQ(autoLogInit(NULL), -1); }

/* ──────────── init with NULL prefix ────────────────────────────────────────
 */

static void testInitNullPrefix(void) {
    AutoLogConfig cfg = {0};
    cfg.fileNamePrefix = NULL;
    ASSERT_INT_EQ(autoLogInit(&cfg), -1);
}

/* ──────────── init + close lifecycle ───────────────────────────────────────
 */

static void testInitAndClose(void) {
    AutoLogConfig cfg = {.fileNamePrefix = "test", .enableTuiBuffer = false};
    ASSERT_INT_EQ(autoLogInit(&cfg), 0);
    closeAndClean();
}

/* ──────────── double init (re-entrant) ─────────────────────────────────────
 */

static void testInitDoubleCall(void) {
    AutoLogConfig cfg = {.fileNamePrefix = "test", .enableTuiBuffer = false};
    ASSERT_INT_EQ(autoLogInit(&cfg), 0);
    ASSERT_INT_EQ(autoLogInit(&cfg), 0);
    closeAndClean();
}

/* ──────────── init with custom capacity ────────────────────────────────────
 */

static void testInitCustomCapacity(void) {
    AutoLogConfig cfg = {.fileNamePrefix = "test",
                         .queueCapacity = CustomQueueCap,
                         .enableTuiBuffer = false};
    ASSERT_INT_EQ(autoLogInit(&cfg), 0);
    closeAndClean();
}

/* ──────────── init with custom retention ───────────────────────────────────
 */

static void testInitCustomRetention(void) {
    AutoLogConfig cfg = {.fileNamePrefix = "test",
                         .compressRetentionDays = CustomRetention,
                         .enableTuiBuffer = false};
    ASSERT_INT_EQ(autoLogInit(&cfg), 0);
    closeAndClean();
}

/* ──────────── init with custom max message len ─────────────────────────────
 */

static void testInitCustomMaxMsgLen(void) {
    AutoLogConfig cfg = {.fileNamePrefix = "test",
                         .maxMsgLen = CustomMsgLen,
                         .enableTuiBuffer = false};
    ASSERT_INT_EQ(autoLogInit(&cfg), 0);
    closeAndClean();
}

/* ──────────── init with custom max restarts ────────────────────────────────
 */

static void testInitCustomMaxRestarts(void) {
    AutoLogConfig cfg = {.fileNamePrefix = "test",
                         .maxRestarts = CustomMaxRestarts,
                         .enableTuiBuffer = false};
    ASSERT_INT_EQ(autoLogInit(&cfg), 0);
    closeAndClean();
}

/* ──────────── fetch before init ────────────────────────────────────────────
 */

static void testFetchBeforeInit(void) {
    char **lines = NULL;
    int count = 0;
    ASSERT_INT_EQ(autoLogFetch(LogLevelTrace, &lines, &count), -1);
}

/* ──────────── fetch with NULL outLines ─────────────────────────────────────
 */

static void testFetchNullOutLines(void) {
    AutoLogConfig cfg = {.fileNamePrefix = "test", .enableTuiBuffer = true};
    ASSERT_INT_EQ(autoLogInit(&cfg), 0);
    int count = 0;
    ASSERT_INT_EQ(autoLogFetch(LogLevelTrace, NULL, &count), -1);
    closeAndClean();
}

/* ──────────── fetch with TUI buffer disabled ───────────────────────────────
 */

static void testFetchWithTuiDisabled(void) {
    AutoLogConfig cfg = {.fileNamePrefix = "test", .enableTuiBuffer = false};
    ASSERT_INT_EQ(autoLogInit(&cfg), 0);

    char **lines = NULL;
    int count = 0;
    ASSERT_INT_EQ(autoLogFetch(LogLevelTrace, &lines, &count), -1);
    closeAndClean();
}

/* ──────────── fetch empty (no messages, TUI enabled) ────────────────────────
 */

static void testFetchEmptyAfterInit(void) {
    AutoLogConfig cfg = {.fileNamePrefix = "test", .enableTuiBuffer = true};
    ASSERT_INT_EQ(autoLogInit(&cfg), 0);

    usleep(LogSleepUs);

    char **lines = NULL;
    int count = -1;
    ASSERT_INT_EQ(autoLogFetch(LogLevelFatal, &lines, &count), 0);
    ASSERT_INT_EQ(count, 0);
    ASSERT_NOT_NULL(lines);
    ASSERT_NULL(lines[0]);
    autoLogFetchFree(lines, count);

    closeAndClean();
}

/* ──────────── fetch with messages (TUI enabled) ─────────────────────────────
 */

static void testFetchWithMessages(void) {
    AutoLogConfig cfg = {.fileNamePrefix = "test", .enableTuiBuffer = true};
    ASSERT_INT_EQ(autoLogInit(&cfg), 0);

    LOG_INFO("autoLog test message alpha");
    LOG_WARN("autoLog test message beta");

    int found = 0;
    for (int attempt = 0; attempt < LogRetryCount; attempt++) {
        usleep(LogRetrySleepUs);
        char **lines = NULL;
        int count = 0;
        if (autoLogFetch(LogLevelTrace, &lines, &count) == 0 && count > 0) {
            found = count;
            autoLogFetchFree(lines, count);
            break;
        }
        autoLogFetchFree(lines, count);
    }
    ASSERT_TRUE(found >= 1);

    closeAndClean();
}

/* ──────────── fetch level filtering (TUI enabled) ───────────────────────────
 */

static void testFetchLevelFilter(void) {
    AutoLogConfig cfg = {.fileNamePrefix = "test", .enableTuiBuffer = true};
    ASSERT_INT_EQ(autoLogInit(&cfg), 0);

    LOG_TRACE("should be filtered out");
    LOG_DEBUG("should also be filtered out");
    LOG_ERROR("visible error message");

    int errorCount = 0;
    for (int attempt = 0; attempt < LogRetryCount; attempt++) {
        usleep(LogRetrySleepUs);
        char **lines = NULL;
        int count = 0;
        if (autoLogFetch(LogLevelError, &lines, &count) == 0) {
            errorCount = count;
            autoLogFetchFree(lines, count);
            if (errorCount > 0) {
                break;
            }
        } else {
            autoLogFetchFree(lines, count);
        }
    }
    ASSERT_TRUE(errorCount >= 1);

    closeAndClean();
}

/* ──────────── init after close (reuse) ──────────────────────────────────────
 */

static void testInitAfterClose(void) {
    AutoLogConfig cfg = {.fileNamePrefix = "test", .enableTuiBuffer = false};
    ASSERT_INT_EQ(autoLogInit(&cfg), 0);
    closeAndClean();

    AutoLogConfig cfg2 = {.fileNamePrefix = "test2", .enableTuiBuffer = true};
    ASSERT_INT_EQ(autoLogInit(&cfg2), 0);
    closeAndClean();
}

/* ──────────── fetch with custom TUI capacity ────────────────────────────────
 */

static void testFetchCustomTuiCapacity(void) {
    AutoLogConfig cfg = {.fileNamePrefix = "test",
                         .tuiBufferCapacity = CustomTuiCap,
                         .enableTuiBuffer = true};
    ASSERT_INT_EQ(autoLogInit(&cfg), 0);

    LOG_INFO("test message for custom capacity");

    int found = 0;
    for (int attempt = 0; attempt < LogRetryCount; attempt++) {
        usleep(LogRetrySleepUs);
        char **lines = NULL;
        int count = 0;
        if (autoLogFetch(LogLevelTrace, &lines, &count) == 0 && count > 0) {
            found = count;
            autoLogFetchFree(lines, count);
            break;
        }
        autoLogFetchFree(lines, count);
    }
    ASSERT_TRUE(found >= 1);

    closeAndClean();
}

/* ──────────── autoLogCheckAndRestart when not inited ────────────────────────
 */

static void testCheckAndRestartNotInited(void) { autoLogCheckAndRestart(); }

/* ──────────── autoLogCheckAndRestart when running ────────────────────────────
 */

static void testCheckAndRestartWhenRunning(void) {
    AutoLogConfig cfg = {.fileNamePrefix = "test", .enableTuiBuffer = false};
    ASSERT_INT_EQ(autoLogInit(&cfg), 0);
    autoLogCheckAndRestart();
    closeAndClean();
}

/* ──────────── zero config values → defaults ─────────────────────────────────
 */

static void testZeroConfigUsesDefaults(void) {
    AutoLogConfig cfg = {.fileNamePrefix = "test",
                         .queueCapacity = 0,
                         .maxMsgLen = 0,
                         .compressRetentionDays = 0,
                         .maxRestarts = 0,
                         .tuiBufferCapacity = 0,
                         .enableTuiBuffer = false};
    ASSERT_INT_EQ(autoLogInit(&cfg), 0);
    closeAndClean();
}

/* ──────────── NULL logDir → defaults to "./logs" ────────────────────────────
 */

static void testNullLogDirUsesDefault(void) {
    AutoLogConfig cfg = {
        .fileNamePrefix = "test", .logDir = NULL, .enableTuiBuffer = false};
    ASSERT_INT_EQ(autoLogInit(&cfg), 0);
    closeAndClean();
}

/* ═══════════════ Supplementary adversarial tests ════════════════════════ */

enum {
    SmallQueueCap = 4,
    SmallTuiCap = 4,
    FloodCount = 200,
    ThreadCount = 4,
    MsgsPerThread = 50,
    LongMsgFillByte = 'X',
    LongMsgMaxLen = 1024,
};

/* ──────────── queue overflow (drop-on-full, no crash) ──────────────────────
 */

static void testQueueOverflowNoCrash(void) {
    AutoLogConfig cfg = {.fileNamePrefix = "test",
                         .queueCapacity = SmallQueueCap,
                         .enableTuiBuffer = true,
                         .tuiBufferCapacity = SmallTuiCap};
    ASSERT_INT_EQ(autoLogInit(&cfg), 0);

    for (int i = 0; i < FloodCount; i++) {
        LOG_INFO("flood message %d", i);
    }

    usleep(LogSleepUs);

    char **lines = NULL;
    int count = 0;
    int rc = autoLogFetch(LogLevelTrace, &lines, &count);
    ASSERT_INT_EQ(rc, 0);
    ASSERT_TRUE(count <= SmallTuiCap);
    autoLogFetchFree(lines, count);

    closeAndClean();
}

/* ──────────── concurrent logging from multiple threads ─────────────────────
 */

static void *concurrentLogWorker(void *arg) {
    int id = *(int *)arg;
    for (int i = 0; i < MsgsPerThread; i++) {
        LOG_INFO("thread %d msg %d", id, i);
    }
    return NULL;
}

static void testConcurrentLogging(void) {
    AutoLogConfig cfg = {.fileNamePrefix = "test", .enableTuiBuffer = true};
    ASSERT_INT_EQ(autoLogInit(&cfg), 0);

    pthread_t threads[ThreadCount];
    int ids[ThreadCount];
    for (int i = 0; i < ThreadCount; i++) {
        ids[i] = i;
        pthread_create(&threads[i], NULL, concurrentLogWorker, &ids[i]);
    }
    for (int i = 0; i < ThreadCount; i++) {
        pthread_join(threads[i], NULL);
    }

    int totalFound = 0;
    for (int attempt = 0; attempt < LogRetryCount; attempt++) {
        usleep(LogRetrySleepUs);
        char **lines = NULL;
        int count = 0;
        if (autoLogFetch(LogLevelTrace, &lines, &count) == 0 && count > 0) {
            totalFound += count;
            autoLogFetchFree(lines, count);
            break;
        }
        autoLogFetchFree(lines, count);
    }
    ASSERT_TRUE(totalFound >= 1);

    closeAndClean();
}

/* ──────────── long message boundary (near max length) ──────────────────────
 */

static void testLongMessageBoundary(void) {
    AutoLogConfig cfg = {.fileNamePrefix = "test", .enableTuiBuffer = true};
    ASSERT_INT_EQ(autoLogInit(&cfg), 0);

    enum { FillLen = 900 };
    char longMsg[LongMsgMaxLen];
    memset(longMsg, LongMsgFillByte, FillLen);
    longMsg[FillLen] = '\0';

    LOG_INFO("%s", longMsg);

    int found = 0;
    for (int attempt = 0; attempt < LogRetryCount; attempt++) {
        usleep(LogRetrySleepUs);
        char **lines = NULL;
        int count = 0;
        if (autoLogFetch(LogLevelTrace, &lines, &count) == 0 && count > 0) {
            found = count;
            autoLogFetchFree(lines, count);
            break;
        }
        autoLogFetchFree(lines, count);
    }
    ASSERT_TRUE(found >= 1);

    closeAndClean();
}

/* ──────────── TUI buffer full → drop (no overwrite) ────────────────────────
 */

static void testTuiBufferFullDrop(void) {
    AutoLogConfig cfg = {.fileNamePrefix = "test",
                         .enableTuiBuffer = true,
                         .tuiBufferCapacity = SmallTuiCap};
    ASSERT_INT_EQ(autoLogInit(&cfg), 0);

    for (int i = 0; i < SmallTuiCap + FloodCount; i++) {
        LOG_WARN("tui overflow %d", i);
    }

    usleep(LogSleepUs);

    char **lines = NULL;
    int count = 0;
    ASSERT_INT_EQ(autoLogFetch(LogLevelTrace, &lines, &count), 0);
    ASSERT_TRUE(count <= SmallTuiCap);
    autoLogFetchFree(lines, count);

    closeAndClean();
}

/* ──────────── fetch drains buffer — second fetch returns 0 ─────────────────
 */

static void testFetchDrainsBuffer(void) {
    AutoLogConfig cfg = {.fileNamePrefix = "test", .enableTuiBuffer = true};
    ASSERT_INT_EQ(autoLogInit(&cfg), 0);

    LOG_ERROR("drain test message");

    int found = 0;
    for (int attempt = 0; attempt < LogRetryCount; attempt++) {
        usleep(LogRetrySleepUs);
        char **lines = NULL;
        int count = 0;
        if (autoLogFetch(LogLevelTrace, &lines, &count) == 0 && count > 0) {
            found = count;
            autoLogFetchFree(lines, count);
            break;
        }
        autoLogFetchFree(lines, count);
    }
    ASSERT_TRUE(found >= 1);

    char **lines2 = NULL;
    int count2 = 0;
    ASSERT_INT_EQ(autoLogFetch(LogLevelTrace, &lines2, &count2), 0);
    ASSERT_INT_EQ(count2, 0);
    ASSERT_NOT_NULL(lines2);
    ASSERT_NULL(lines2[0]);
    autoLogFetchFree(lines2, count2);

    closeAndClean();
}

/* ──────────── fetch with NULL outCount ──────────────────────────────────────
 */

static void testFetchNullOutCount(void) {
    AutoLogConfig cfg = {.fileNamePrefix = "test", .enableTuiBuffer = true};
    ASSERT_INT_EQ(autoLogInit(&cfg), 0);

    LOG_INFO("null count test");

    usleep(LogSleepUs);

    char **lines = NULL;
    ASSERT_INT_EQ(autoLogFetch(LogLevelTrace, &lines, NULL), 0);
    ASSERT_NOT_NULL(lines);

    int manualCount = 0;
    while (lines[manualCount] != NULL) {
        manualCount++;
    }
    autoLogFetchFree(lines, manualCount);

    closeAndClean();
}

/* ──────────── TUI buffer refill after drain ────────────────────────────────
 */

static void testTuiRefillAfterDrain(void) {
    AutoLogConfig cfg = {.fileNamePrefix = "test",
                         .enableTuiBuffer = true,
                         .tuiBufferCapacity = SmallTuiCap};
    ASSERT_INT_EQ(autoLogInit(&cfg), 0);

    LOG_INFO("round one");
    usleep(LogSleepUs);

    char **lines = NULL;
    int count = 0;
    ASSERT_INT_EQ(autoLogFetch(LogLevelTrace, &lines, &count), 0);
    ASSERT_TRUE(count >= 1);
    autoLogFetchFree(lines, count);

    LOG_INFO("round two");
    usleep(LogSleepUs);

    char **lines2 = NULL;
    int count2 = 0;
    for (int attempt = 0; attempt < LogRetryCount; attempt++) {
        usleep(LogRetrySleepUs);
        if (autoLogFetch(LogLevelTrace, &lines2, &count2) == 0 && count2 > 0) {
            break;
        }
        autoLogFetchFree(lines2, count2);
        lines2 = NULL;
        count2 = 0;
    }
    ASSERT_TRUE(count2 >= 1);
    autoLogFetchFree(lines2, count2);

    closeAndClean();
}

/* ════════════════════════════════════════════════════════════════════════
   main
   ════════════════════════════════════════════════════════════════════════ */

int main(void) {
    printf("test_auto_log:\n");

    RUN_TEST(testFetchFreeNull);
    RUN_TEST(testFetchFreeNullCount);
    RUN_TEST(testCloseWithoutInit);
    RUN_TEST(testInitNullConfig);
    RUN_TEST(testInitNullPrefix);
    RUN_TEST(testInitAndClose);
    RUN_TEST(testInitDoubleCall);
    RUN_TEST(testInitCustomCapacity);
    RUN_TEST(testInitCustomRetention);
    RUN_TEST(testInitCustomMaxMsgLen);
    RUN_TEST(testInitCustomMaxRestarts);
    RUN_TEST(testFetchBeforeInit);
    RUN_TEST(testFetchNullOutLines);
    RUN_TEST(testFetchWithTuiDisabled);
    RUN_TEST(testFetchEmptyAfterInit);
    RUN_TEST(testFetchWithMessages);
    RUN_TEST(testFetchLevelFilter);
    RUN_TEST(testInitAfterClose);
    RUN_TEST(testFetchCustomTuiCapacity);
    RUN_TEST(testCheckAndRestartNotInited);
    RUN_TEST(testCheckAndRestartWhenRunning);
    RUN_TEST(testZeroConfigUsesDefaults);
    RUN_TEST(testNullLogDirUsesDefault);
    RUN_TEST(testQueueOverflowNoCrash);
    RUN_TEST(testConcurrentLogging);
    RUN_TEST(testLongMessageBoundary);
    RUN_TEST(testTuiBufferFullDrop);
    RUN_TEST(testFetchDrainsBuffer);
    RUN_TEST(testFetchNullOutCount);
    RUN_TEST(testTuiRefillAfterDrain);

    return TEST_REPORT();
}
