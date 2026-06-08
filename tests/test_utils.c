/**
 * @file test_utils.c
 * @brief Unit tests for the utils module (getCurrentTimestamp,
 * readPasswordMasked).
 *
 * @date 2026-06-08
 * @copyright GPLv3 License
 */

#include "utils.h"
#include "test_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ────────────────────────── test-local constants ────────────────────────── */

enum {
    BufSmall = 4,
    BufNormal = 32,
    BufLarge = 256,
    ZeroLen = 0,
    Zero = 0,
    One = 1,
    Base10 = 10,
    Timestamp2024 = 1704067200
};

/* ──────────────────── getCurrentTimestamp tests ─────────────────────────── */

static void testGetCurrentTimestampValid(void) {
    time_t now = getCurrentTimestamp();
    time_t minExpected = Timestamp2024; /* 2024-01-01 00:00:00 UTC */
    ASSERT_TRUE(now > minExpected);
}

static void testGetCurrentTimestampConsistency(void) {
    time_t t1 = getCurrentTimestamp();
    time_t t2 = getCurrentTimestamp();
    ASSERT_TRUE(t2 >= t1);
}

/* ──────────────── readPasswordMasked freopen helper ─────────────────────── */

/**
 * @brief Run @c readPasswordMasked with @p input fed via a tmpfile
 * redirected to stdin (non-terminal fallback path).
 */
static size_t runReadPassword(const char *input, size_t bufsize, char *outBuf) {
    /* Write input to named temp file, then freopen stdin from it.
     * freopen redirects both fd 0 and the FILE* stdin, so isatty(0)==0
     * and readPasswordMasked takes the non-blocking fgets fallback. */
    const char *tmpPath = "/tmp/pp_pwd_test.txt";
    FILE *tmp = fopen(tmpPath, "w+");
    if (tmp == NULL) {
        return 0;
    }
    if (input != NULL) {
        fputs(input, tmp);
    }
    fclose(tmp);

    freopen(tmpPath, "r", stdin);

    char buf[BufLarge];
    memset(buf, 0, sizeof(buf));
    size_t len = readPasswordMasked(
        buf, bufsize == 0 ? ZeroLen : bufsize);

    remove(tmpPath);

    if (outBuf != NULL) {
        strncpy(outBuf, buf, BufNormal);
        outBuf[BufNormal - 1] = '\0';
    }
    return len;
}

/* ──────────────────── readPasswordMasked tests ──────────────────────────── */

static void testReadPasswordNullBuf(void) {
    size_t ret = readPasswordMasked(NULL, BufNormal);
    ASSERT_UINT_EQ(ret, ZeroLen);
}

static void testReadPasswordZeroSize(void) {
    char buf[BufSmall];
    size_t ret = readPasswordMasked(buf, ZeroLen);
    ASSERT_UINT_EQ(ret, ZeroLen);
}

static void testReadPasswordNormal(void) {
    char out[BufNormal];
    memset(out, 0, sizeof(out));
    size_t len = runReadPassword("mypassword\n", BufNormal, out);
    ASSERT_UINT_EQ(len, strlen("mypassword"));
    ASSERT_STR_EQ(out, "mypassword");
}

static void testReadPasswordEmptyInput(void) {
    char out[BufNormal];
    memset(out, 0, sizeof(out));
    size_t len = runReadPassword("\n", BufNormal, out);
    ASSERT_UINT_EQ(len, ZeroLen);
    ASSERT_STR_EQ(out, "");
}

static void testReadPasswordBufferFull(void) {
    char out[BufNormal];
    memset(out, 0, sizeof(out));
    size_t len = runReadPassword("abcdefgh\n", BufSmall, out);
    ASSERT_UINT_EQ(len, (size_t)(BufSmall - 1));
    ASSERT_UINT_EQ(strlen(out), (size_t)(BufSmall - 1));
}

static void testReadPasswordNoNewline(void) {
    char out[BufNormal];
    memset(out, 0, sizeof(out));
    size_t len = runReadPassword("pass", BufNormal, out);
    ASSERT_UINT_EQ(len, strlen("pass"));
    ASSERT_STR_EQ(out, "pass");
}

static void testReadPasswordSpecialChars(void) {
    char out[BufNormal];
    memset(out, 0, sizeof(out));
    size_t len = runReadPassword("a!@#$%\n", BufNormal, out);
    ASSERT_UINT_EQ(len, strlen("a!@#$%"));
    ASSERT_STR_EQ(out, "a!@#$%");
}

/* ════════════════════════════════════════════════════════════════════════
   main
   ════════════════════════════════════════════════════════════════════════ */

int main(void) {
    printf("test_utils:\n");

    RUN_TEST(testGetCurrentTimestampValid);
    RUN_TEST(testGetCurrentTimestampConsistency);
    RUN_TEST(testReadPasswordNullBuf);
    RUN_TEST(testReadPasswordZeroSize);
    RUN_TEST(testReadPasswordNormal);
    RUN_TEST(testReadPasswordEmptyInput);
    RUN_TEST(testReadPasswordBufferFull);
    RUN_TEST(testReadPasswordNoNewline);
    RUN_TEST(testReadPasswordSpecialChars);

    return TEST_REPORT();
}
