/**
 * @file test_client_log.c
 * @brief Contract tests for the client log wrapper (clientLog.c).
 *
 * Verifies the thin wrapper correctly delegates to autoLog with
 * client-specific config (prefix="client", enableTuiBuffer=false),
 * that log files are created on disk, and that messages are persisted.
 *
 * @date 2026-06-20
 * @copyright GPLv3 License
 */

#include "client/clientLog.h"
#include "common/autoLog.h"
#include "test_utils.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

enum {
    LogSleepUs = 200000,
    LogRetryCount = 30,
    LogRetrySleepUs = 50000,
    ReadBufSize = 4096,
    ClientPrefixLen = 6,
    DateBufLen = 16,
    FilenameBufLen = 128,
};

/* ───────────────────────── cleanup helper ───────────────────────────────── */

static void removeLogDir(void) { rmdir("./logs"); }

static void getTodayDate(char *buf, size_t bufSize) {
    time_t now = time(NULL);
    struct tm utc = {0};
    gmtime_r(&now, &utc);
    strftime(buf, bufSize, "%Y-%m-%d", &utc);
}

/* ──────────── close without init ────────────────────────────────────────── */

static void testClientCloseWithoutInit(void) { clientLogClose(); }

/* ──────────── init + close ──────────────────────────────────────────────── */

static void testClientInitAndClose(void) {
    ASSERT_INT_EQ(clientLogInit(), 0);
    clientLogClose();
    removeLogDir();
}

/* ──────────── double init (re-entrant) ──────────────────────────────────── */

static void testClientInitDoubleCall(void) {
    ASSERT_INT_EQ(clientLogInit(), 0);
    ASSERT_INT_EQ(clientLogInit(), 0);
    clientLogClose();
    removeLogDir();
}

/* ──────────── init after close ──────────────────────────────────────────── */

static void testClientInitAfterClose(void) {
    ASSERT_INT_EQ(clientLogInit(), 0);
    clientLogClose();
    removeLogDir();

    ASSERT_INT_EQ(clientLogInit(), 0);
    clientLogClose();
    removeLogDir();
}

/* ──────────── close twice ───────────────────────────────────────────────── */

static void testClientCloseTwice(void) {
    ASSERT_INT_EQ(clientLogInit(), 0);
    clientLogClose();
    clientLogClose();
    removeLogDir();
}

/* ──────────── TUI fetch disabled ────────────────────────────────────────── */

static void testClientTuiDisabled(void) {
    ASSERT_INT_EQ(clientLogInit(), 0);

    usleep(LogSleepUs);

    char **lines = NULL;
    int count = 0;
    ASSERT_INT_EQ(autoLogFetch(LogLevelTrace, &lines, &count), -1);

    clientLogClose();
    removeLogDir();
}

/* ──────────── log directory created ─────────────────────────────────────── */

static void testClientLogDirCreated(void) {
    ASSERT_INT_EQ(clientLogInit(), 0);

    struct stat st;
    ASSERT_INT_EQ(stat("./logs", &st), 0);
    ASSERT_TRUE(S_ISDIR(st.st_mode));

    clientLogClose();
    removeLogDir();
}

/* ──────────── log file created and contains messages ────────────────────── */

static void testClientLogFileCreated(void) {
    ASSERT_INT_EQ(clientLogInit(), 0);

    LOG_INFO("client test message one");
    LOG_ERROR("client test message two");

    for (int attempt = 0; attempt < LogRetryCount; attempt++) {
        usleep(LogRetrySleepUs);
    }

    char today[DateBufLen];
    getTodayDate(today, sizeof(today));

    char filename[FilenameBufLen];
    int written =
        snprintf(filename, sizeof(filename), "./logs/client-%s.log", today);
    ASSERT_TRUE(written > 0 && (size_t)written < sizeof(filename));

    FILE *fp = fopen(filename, "r");
    ASSERT_NOT_NULL(fp);

    char buf[ReadBufSize];
    memset(buf, 0, sizeof(buf));
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);

    ASSERT_TRUE(n > 0);
    ASSERT_TRUE(strstr(buf, "client test message one") != NULL);
    ASSERT_TRUE(strstr(buf, "client test message two") != NULL);

    clientLogClose();
}

/* ──────────── file follows naming convention ─────────────────────────────── */

static void testClientLogFileNamePrefix(void) {
    ASSERT_INT_EQ(clientLogInit(), 0);

    LOG_INFO("prefix test");

    for (int attempt = 0; attempt < LogRetryCount; attempt++) {
        usleep(LogRetrySleepUs);
    }

    DIR *dir = opendir("./logs");
    ASSERT_NOT_NULL(dir);

    bool foundClient = false;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "client-", ClientPrefixLen + 1) == 0) {
            foundClient = true;
            break;
        }
    }
    closedir(dir);

    ASSERT_TRUE(foundClient);

    clientLogClose();
    removeLogDir();
}

/* ════════════════════════════════════════════════════════════════════════ */

int main(void) {
    printf("test_client_log:\n");

    RUN_TEST(testClientCloseWithoutInit);
    RUN_TEST(testClientInitAndClose);
    RUN_TEST(testClientInitDoubleCall);
    RUN_TEST(testClientInitAfterClose);
    RUN_TEST(testClientCloseTwice);
    RUN_TEST(testClientTuiDisabled);
    RUN_TEST(testClientLogDirCreated);
    RUN_TEST(testClientLogFileCreated);
    RUN_TEST(testClientLogFileNamePrefix);

    return TEST_REPORT();
}
