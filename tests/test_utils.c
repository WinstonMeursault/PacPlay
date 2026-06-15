/**
 * @file test_utils.c
 * @brief Unit tests for the utils module (hexCharToNibble, clamp,
 * getCurrentTimestamp, readPasswordMasked, MAX/MIN macros).
 *
 * @date 2026-06-08
 * @copyright GPLv3 License
 */

#include "test_utils.h"
#include "utils.h"

#include <limits.h>
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
    Timestamp2024 = 1704067200,
    NibbleInvalid = -1,
    NibbleValA = 10,
    NibbleValB = 11,
    NibbleValC = 12,
    NibbleValD = 13,
    NibbleValE = 14,
    NibbleValF = 15,
    ClampLow = -100,
    ClampMin = -10,
    ClampMid = 5,
    ClampMax = 10,
    ClampHigh = 100,
    NegTwo = -2,
    NegOne = -1,
    Two = 2,
    Three = 3,
    Seven = 7,
    Nine = 9
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
    size_t len = readPasswordMasked(buf, bufsize == 0 ? ZeroLen : bufsize);

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

/* ──────────────────── hexCharToNibble tests ─────────────────────────────── */

static void testHexCharToNibbleDigits(void) {
    ASSERT_INT_EQ(hexCharToNibble('0'), Zero);
    ASSERT_INT_EQ(hexCharToNibble('1'), One);
    ASSERT_INT_EQ(hexCharToNibble('5'), ClampMid);
    ASSERT_INT_EQ(hexCharToNibble('9'), Nine);
}

static void testHexCharToNibbleLowerCase(void) {
    ASSERT_INT_EQ(hexCharToNibble('a'), NibbleValA);
    ASSERT_INT_EQ(hexCharToNibble('b'), NibbleValB);
    ASSERT_INT_EQ(hexCharToNibble('c'), NibbleValC);
    ASSERT_INT_EQ(hexCharToNibble('d'), NibbleValD);
    ASSERT_INT_EQ(hexCharToNibble('e'), NibbleValE);
    ASSERT_INT_EQ(hexCharToNibble('f'), NibbleValF);
}

static void testHexCharToNibbleUpperCase(void) {
    ASSERT_INT_EQ(hexCharToNibble('A'), NibbleValA);
    ASSERT_INT_EQ(hexCharToNibble('B'), NibbleValB);
    ASSERT_INT_EQ(hexCharToNibble('C'), NibbleValC);
    ASSERT_INT_EQ(hexCharToNibble('D'), NibbleValD);
    ASSERT_INT_EQ(hexCharToNibble('E'), NibbleValE);
    ASSERT_INT_EQ(hexCharToNibble('F'), NibbleValF);
}

static void testHexCharToNibbleBoundaryInvalid(void) {
    ASSERT_INT_EQ(hexCharToNibble('/'), NibbleInvalid);
    ASSERT_INT_EQ(hexCharToNibble(':'), NibbleInvalid);
    ASSERT_INT_EQ(hexCharToNibble('@'), NibbleInvalid);
    ASSERT_INT_EQ(hexCharToNibble('G'), NibbleInvalid);
    ASSERT_INT_EQ(hexCharToNibble('g'), NibbleInvalid);
    ASSERT_INT_EQ(hexCharToNibble('\0'), NibbleInvalid);
    ASSERT_INT_EQ(hexCharToNibble(' '), NibbleInvalid);
    ASSERT_INT_EQ(hexCharToNibble(0x7F), NibbleInvalid);
}

/* ──────────────────────── clamp tests ───────────────────────────────────── */

static void testClampBelowMin(void) {
    ASSERT_INT_EQ(clamp(ClampLow, ClampMin, ClampMax), ClampMin);
}

static void testClampAboveMax(void) {
    ASSERT_INT_EQ(clamp(ClampHigh, ClampMin, ClampMax), ClampMax);
}

static void testClampInRange(void) {
    ASSERT_INT_EQ(clamp(ClampMid, ClampMin, ClampMax), ClampMid);
}

static void testClampAtMin(void) {
    ASSERT_INT_EQ(clamp(ClampMin, ClampMin, ClampMax), ClampMin);
}

static void testClampAtMax(void) {
    ASSERT_INT_EQ(clamp(ClampMax, ClampMin, ClampMax), ClampMax);
}

static void testClampMinEqualsMax(void) {
    ASSERT_INT_EQ(clamp(ClampLow, ClampMid, ClampMid), ClampMid);
    ASSERT_INT_EQ(clamp(ClampHigh, ClampMid, ClampMid), ClampMid);
    ASSERT_INT_EQ(clamp(ClampMid, ClampMid, ClampMid), ClampMid);
}

static void testClampIntMinMax(void) {
    ASSERT_INT_EQ(clamp(INT_MIN, ClampMin, ClampMax), ClampMin);
    ASSERT_INT_EQ(clamp(INT_MAX, ClampMin, ClampMax), ClampMax);
    ASSERT_INT_EQ(clamp(Zero, INT_MIN, INT_MAX), Zero);
}

/* ──────────────────────── MAX/MIN macro tests ──────────────────────────── */

static void testMaxMacro(void) {
    ASSERT_INT_EQ(MAX(Three, Seven), Seven);
    ASSERT_INT_EQ(MAX(Seven, Three), Seven);
    ASSERT_INT_EQ(MAX(ClampMid, ClampMid), ClampMid);
    ASSERT_INT_EQ(MAX(NegTwo, Three), Three);
    ASSERT_INT_EQ(MAX(NegTwo, NegOne), NegOne);
}

static void testMinMacro(void) {
    ASSERT_INT_EQ(MIN(Three, Seven), Three);
    ASSERT_INT_EQ(MIN(Seven, Three), Three);
    ASSERT_INT_EQ(MIN(ClampMid, ClampMid), ClampMid);
    ASSERT_INT_EQ(MIN(NegTwo, Three), NegTwo);
    ASSERT_INT_EQ(MIN(NegTwo, NegOne), NegTwo);
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

    RUN_TEST(testHexCharToNibbleDigits);
    RUN_TEST(testHexCharToNibbleLowerCase);
    RUN_TEST(testHexCharToNibbleUpperCase);
    RUN_TEST(testHexCharToNibbleBoundaryInvalid);

    RUN_TEST(testClampBelowMin);
    RUN_TEST(testClampAboveMax);
    RUN_TEST(testClampInRange);
    RUN_TEST(testClampAtMin);
    RUN_TEST(testClampAtMax);
    RUN_TEST(testClampMinEqualsMax);
    RUN_TEST(testClampIntMinMax);

    RUN_TEST(testMaxMacro);
    RUN_TEST(testMinMacro);

    return TEST_REPORT();
}
