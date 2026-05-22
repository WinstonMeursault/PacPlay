/**
 * @file test_utils.h
 * @brief Lightweight macro-based test framework for PacPlay.
 *
 * Provides assertion macros, a test runner, and result reporting.
 * Each test source file that includes this header compiles into an
 * independent executable with its own pass/fail counters.
 *
 * @date 2026-05-17
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

#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int testsPassed = 0; /**< Number of tests that passed so far. */
static int testsFailed = 0; /**< Number of tests that failed so far. */

#define TEST_COLOR_GREEN "\033[92m" /**< @brief ANSI bright green. */
#define TEST_COLOR_RED "\033[91m"   /**< @brief ANSI bright red. */
#define TEST_COLOR_RESET "\033[0m"  /**< @brief ANSI reset sequence. */

/**
 * @brief Assert that two signed integer values are equal.
 *
 * @param actual   The value produced by the code under test.
 * @param expected The correct value to compare against.
 *
 * Both operands are cast to @c long @c long before comparison. On failure
 * the macro prints file, line, and both values to @c stderr, increments
 * testsFailed, and returns from the calling function immediately.
 */
#define ASSERT_INT_EQ(actual, expected)                                        \
    do {                                                                       \
        long long assertActual_ = (long long)(actual);                         \
        long long assertExpected_ = (long long)(expected);                     \
        if (assertActual_ != assertExpected_) {                                \
            fprintf(stderr,                                                    \
                    TEST_COLOR_RED                                             \
                    "  FAIL %s:%d: %s == %lld, expected %lld" TEST_COLOR_RESET \
                    "\n",                                                      \
                    __FILE__, __LINE__, #actual, assertActual_,                \
                    assertExpected_);                                          \
            testsFailed++;                                                     \
            return;                                                            \
        }                                                                      \
    } while (0)

/**
 * @brief Assert that two unsigned integer values are equal.
 *
 * @param actual   The value produced by the code under test.
 * @param expected The correct value to compare against.
 *
 * Both operands are cast to @c unsigned @c long @c long before comparison.
 * Suitable for @c uint32_t, @c size_t, @c sizeof expressions, and
 * @c offsetof results, avoiding signed/unsigned comparison warnings.
 * Failure behaviour is identical to ASSERT_INT_EQ.
 */
#define ASSERT_UINT_EQ(actual, expected)                                       \
    do {                                                                       \
        unsigned long long assertActual_ = (unsigned long long)(actual);       \
        unsigned long long assertExpected_ = (unsigned long long)(expected);   \
        if (assertActual_ != assertExpected_) {                                \
            fprintf(stderr,                                                    \
                    TEST_COLOR_RED                                             \
                    "  FAIL %s:%d: %s == %llu, expected %llu" TEST_COLOR_RESET \
                    "\n",                                                      \
                    __FILE__, __LINE__, #actual, assertActual_,                \
                    assertExpected_);                                          \
            testsFailed++;                                                     \
            return;                                                            \
        }                                                                      \
    } while (0)

/**
 * @brief Assert that an expression evaluates to true (non-zero).
 *
 * @param expr The expression to test.
 *
 * On failure the macro prints the stringified expression, increments
 * testsFailed, and returns from the calling function.
 */
#define ASSERT_TRUE(expr)                                                      \
    do {                                                                       \
        if (!(expr)) {                                                         \
            fprintf(stderr,                                                    \
                    TEST_COLOR_RED                                             \
                    "  FAIL %s:%d: %s is false" TEST_COLOR_RESET "\n",         \
                    __FILE__, __LINE__, #expr);                                \
            testsFailed++;                                                     \
            return;                                                            \
        }                                                                      \
    } while (0)

/**
 * @brief Assert that an expression evaluates to false (zero).
 *
 * @param expr The expression to test.
 *
 * On failure the macro prints the stringified expression, increments
 * testsFailed, and returns from the calling function.
 */
#define ASSERT_FALSE(expr)                                                     \
    do {                                                                       \
        if ((expr)) {                                                          \
            fprintf(stderr,                                                    \
                    TEST_COLOR_RED "  FAIL %s:%d: %s is true" TEST_COLOR_RESET \
                                   "\n",                                       \
                    __FILE__, __LINE__, #expr);                                \
            testsFailed++;                                                     \
            return;                                                            \
        }                                                                      \
    } while (0)

/**
 * @brief Assert that two memory regions of @p n bytes are identical.
 *
 * @param a First memory region pointer.
 * @param b Second memory region pointer.
 * @param n Number of bytes to compare.
 *
 * Uses @c memcmp internally. Suitable for verifying serialised output
 * or binary data. Failure behaviour is identical to the other assertion
 * macros.
 */
#define ASSERT_MEM_EQ(a, b, n)                                                 \
    do {                                                                       \
        if (memcmp((a), (b), (n)) != 0) {                                      \
            fprintf(stderr,                                                    \
                    TEST_COLOR_RED                                             \
                    "  FAIL %s:%d: memcmp(%s, %s, %zu)" TEST_COLOR_RESET "\n", \
                    __FILE__, __LINE__, #a, #b, (size_t)(n));                  \
            testsFailed++;                                                     \
            return;                                                            \
        }                                                                      \
    } while (0)

/**
 * @brief Assert that two C strings are equal.
 *
 * @param actual   The string produced by the code under test.
 * @param expected The correct string to compare against.
 *
 * Uses @c strcmp internally. On failure the macro prints both strings
 * to @c stderr so the mismatch is immediately visible.
 */
#define ASSERT_STR_EQ(actual, expected)                                        \
    do {                                                                       \
        const char *assertActual_ = (actual);                                  \
        const char *assertExpected_ = (expected);                              \
        if (strcmp(assertActual_, assertExpected_) != 0) {                     \
            fprintf(stderr,                                                    \
                    TEST_COLOR_RED "  FAIL %s:%d: %s == \"%s\", expected "     \
                                   "\"%s\"" TEST_COLOR_RESET "\n",             \
                    __FILE__, __LINE__, #actual, assertActual_,                \
                    assertExpected_);                                          \
            testsFailed++;                                                     \
            return;                                                            \
        }                                                                      \
    } while (0)

/**
 * @brief Execute a single test function and record the result.
 *
 * @param fn A @c void(void) test function to invoke.
 *
 * The macro snapshots testsFailed before calling @p fn. If testsFailed
 * is unchanged after the call the test is considered passed; otherwise
 * a failure was already reported by an assertion macro inside @p fn.
 */
#define RUN_TEST(fn)                                                           \
    do {                                                                       \
        int beforeFailed_ = testsFailed;                                       \
        fn();                                                                  \
        if (testsFailed == beforeFailed_) {                                    \
            printf(TEST_COLOR_GREEN "  PASS " TEST_COLOR_RESET "%s\n", #fn);   \
            testsPassed++;                                                     \
        }                                                                      \
    } while (0)

/**
 * @brief Print a summary line and return an exit code.
 *
 * @return 0 if all tests passed, 1 if any test failed.
 *
 * Must be used as the return value of @c main():
 * @code
 * return TEST_REPORT();
 * @endcode
 */
#define TEST_REPORT()                                                          \
    (printf("\n%d passed, %d failed\n\n", testsPassed, testsFailed),             \
     testsFailed > 0 ? 1 : 0)

#endif /* TEST_UTILS_H */
