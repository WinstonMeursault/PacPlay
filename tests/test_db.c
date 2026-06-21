/**
 * @file test_db.c
 * @brief Adversarial unit tests for the PacPlay common SQLite helpers.
 *
 * Covers dbExec and dbFinalize with boundary, invalid input, and
 * error-propagation scenarios.  Every test treats the module as buggy
 * until proven otherwise.
 *
 * @date 2026-06-07
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

#include "db.h"
#include "log.h"
#include "test_utils.h"

#include <stdlib.h>
#include <string.h>

/* ──────────────────────────── helper constants ──────────────────────────── */

enum { SentinelNull = 0 };

/* ────────────────────────────── dbExec tests ─────────────────────────────── */

/** @brief dbExec with NULL dbHandle returns DB_EXEC_FAIL. */
static void testDbExecNullHandle(void) {
    ASSERT_INT_EQ(dbExec(NULL, "SELECT 1;", "null handle test"),
                  DB_EXEC_FAIL);
}

/** @brief dbExec with NULL sql returns DB_EXEC_FAIL (precond failure). */
static void testDbExecNullSQL(void) {
    sqlite3 *db = NULL;
    int rc = sqlite3_open(":memory:", &db);
    ASSERT_INT_EQ(rc, SQLITE_OK);
    ASSERT_TRUE(db != NULL);

    ASSERT_INT_EQ(dbExec(db, NULL, "null SQL test"), DB_EXEC_FAIL);

    sqlite3_close(db);
}

/** @brief dbExec with a valid CREATE TABLE succeeds. */
static void testDbExecCreateTable(void) {
    sqlite3 *db = NULL;
    int rc = sqlite3_open(":memory:", &db);
    ASSERT_INT_EQ(rc, SQLITE_OK);
    ASSERT_TRUE(db != NULL);

    ASSERT_INT_EQ(
        dbExec(db, "CREATE TABLE IF NOT EXISTS test_t (id INTEGER PRIMARY "
                   "KEY, val TEXT);",
               "create table"),
        DB_EXEC_SUCC);

    /* Verify the table exists */
    sqlite3_stmt *stmt = NULL;
    rc = sqlite3_prepare_v2(
        db,
        "SELECT name FROM sqlite_master WHERE type='table' AND name='test_t';",
        -1, &stmt, NULL);
    ASSERT_INT_EQ(rc, SQLITE_OK);
    rc = sqlite3_step(stmt);
    ASSERT_INT_EQ(rc, SQLITE_ROW);
    sqlite3_finalize(stmt);

    sqlite3_close(db);
}

/** @brief dbExec with a valid INSERT succeeds. */
static void testDbExecInsert(void) {
    sqlite3 *db = NULL;
    int rc = sqlite3_open(":memory:", &db);
    ASSERT_INT_EQ(rc, SQLITE_OK);
    ASSERT_TRUE(db != NULL);

    ASSERT_INT_EQ(dbExec(db, "CREATE TABLE t (id INT);", "create"),
                  DB_EXEC_SUCC);
    ASSERT_INT_EQ(dbExec(db, "INSERT INTO t VALUES (42);", "insert"),
                  DB_EXEC_SUCC);

    sqlite3_stmt *stmt = NULL;
    rc = sqlite3_prepare_v2(db, "SELECT id FROM t;", -1, &stmt, NULL);
    ASSERT_INT_EQ(rc, SQLITE_OK);
    rc = sqlite3_step(stmt);
    ASSERT_INT_EQ(rc, SQLITE_ROW);
    ASSERT_INT_EQ(sqlite3_column_int(stmt, 0), 42);
    sqlite3_finalize(stmt);

    sqlite3_close(db);
}

/** @brief dbExec with a valid DROP TABLE succeeds. */
static void testDbExecDropTable(void) {
    sqlite3 *db = NULL;
    int rc = sqlite3_open(":memory:", &db);
    ASSERT_INT_EQ(rc, SQLITE_OK);
    ASSERT_TRUE(db != NULL);

    ASSERT_INT_EQ(dbExec(db, "CREATE TABLE t (id INT);", "create"),
                  DB_EXEC_SUCC);
    ASSERT_INT_EQ(dbExec(db, "DROP TABLE t;", "drop"), DB_EXEC_SUCC);

    /* Verify the table is gone */
    sqlite3_stmt *stmt = NULL;
    rc = sqlite3_prepare_v2(
        db,
        "SELECT name FROM sqlite_master WHERE type='table' AND name='t';", -1,
        &stmt, NULL);
    ASSERT_INT_EQ(rc, SQLITE_OK);
    rc = sqlite3_step(stmt);
    ASSERT_INT_EQ(rc, SQLITE_DONE);
    sqlite3_finalize(stmt);

    sqlite3_close(db);
}

/** @brief dbExec with SQL syntax error returns DB_EXEC_FAIL. */
static void testDbExecInvalidSQL(void) {
    sqlite3 *db = NULL;
    int rc = sqlite3_open(":memory:", &db);
    ASSERT_INT_EQ(rc, SQLITE_OK);
    ASSERT_TRUE(db != NULL);

    ASSERT_INT_EQ(dbExec(db, "FROBNICATE THE WIDGETS;", "bad syntax"),
                  DB_EXEC_FAIL);

    sqlite3_close(db);
}

/** @brief dbExec on a closed database handle should fail gracefully. */
static void testDbExecClosedHandle(void) {
    sqlite3 *db = NULL;
    int rc = sqlite3_open(":memory:", &db);
    ASSERT_INT_EQ(rc, SQLITE_OK);
    ASSERT_TRUE(db != NULL);
    sqlite3_close(db);

    /* Calling dbExec on a closed handle should not crash */
    int result = dbExec(db, "SELECT 1;", "closed handle");
    ASSERT_INT_EQ(result, DB_EXEC_FAIL);
}

/** @brief dbExec with multiple sequential statements succeeds. */
static void testDbExecSequential(void) {
    sqlite3 *db = NULL;
    int rc = sqlite3_open(":memory:", &db);
    ASSERT_INT_EQ(rc, SQLITE_OK);
    ASSERT_TRUE(db != NULL);

    ASSERT_INT_EQ(dbExec(db, "CREATE TABLE t (id INT);", "create"),
                  DB_EXEC_SUCC);
    ASSERT_INT_EQ(dbExec(db, "INSERT INTO t VALUES (1);", "insert1"),
                  DB_EXEC_SUCC);
    ASSERT_INT_EQ(dbExec(db, "INSERT INTO t VALUES (2);", "insert2"),
                  DB_EXEC_SUCC);
    ASSERT_INT_EQ(dbExec(db, "INSERT INTO t VALUES (3);", "insert3"),
                  DB_EXEC_SUCC);

    sqlite3_stmt *stmt = NULL;
    rc = sqlite3_prepare_v2(db, "SELECT count(*) FROM t;", -1, &stmt, NULL);
    ASSERT_INT_EQ(rc, SQLITE_OK);
    rc = sqlite3_step(stmt);
    ASSERT_INT_EQ(rc, SQLITE_ROW);
    ASSERT_INT_EQ(sqlite3_column_int(stmt, 0), 3);
    sqlite3_finalize(stmt);

    sqlite3_close(db);
}

/** @brief dbExec on a table that doesn't exist returns DB_EXEC_FAIL. */
static void testDbExecNonexistentTable(void) {
    sqlite3 *db = NULL;
    int rc = sqlite3_open(":memory:", &db);
    ASSERT_INT_EQ(rc, SQLITE_OK);
    ASSERT_TRUE(db != NULL);

    ASSERT_INT_EQ(
        dbExec(db, "SELECT * FROM nonexistent_table;", "no such table"),
        DB_EXEC_FAIL);

    sqlite3_close(db);
}

/* ──────────────────────────── dbFinalize tests ───────────────────────────── */

/** @brief dbFinalize on a valid prepared statement frees it and sets to NULL.
 */
static void testDbFinalizeValid(void) {
    sqlite3 *db = NULL;
    int rc = sqlite3_open(":memory:", &db);
    ASSERT_INT_EQ(rc, SQLITE_OK);
    ASSERT_TRUE(db != NULL);

    sqlite3_stmt *stmt = NULL;
    rc = sqlite3_prepare_v2(db, "SELECT 1;", -1, &stmt, NULL);
    ASSERT_INT_EQ(rc, SQLITE_OK);
    ASSERT_TRUE(stmt != NULL);

    dbFinalize(&stmt);
    ASSERT_TRUE(stmt == NULL);

    sqlite3_close(db);
}

/** @brief dbFinalize(NULL) does not crash (safe no-op). */
static void testDbFinalizeNullDoublePtr(void) {
    dbFinalize(NULL);
    ASSERT_TRUE(1); /* Reached here without segfault */
}

/** @brief dbFinalize on a pointer-to-NULL is safe. */
static void testDbFinalizeNullStmt(void) {
    sqlite3_stmt *stmt = NULL;
    dbFinalize(&stmt);
    ASSERT_TRUE(stmt == NULL);
}

/** @brief dbFinalize called twice on the same pointer is safe. */
static void testDbFinalizeDoubleCall(void) {
    sqlite3 *db = NULL;
    int rc = sqlite3_open(":memory:", &db);
    ASSERT_INT_EQ(rc, SQLITE_OK);
    ASSERT_TRUE(db != NULL);

    sqlite3_stmt *stmt = NULL;
    rc = sqlite3_prepare_v2(db, "SELECT 1;", -1, &stmt, NULL);
    ASSERT_INT_EQ(rc, SQLITE_OK);

    dbFinalize(&stmt);
    ASSERT_TRUE(stmt == NULL);

    /* Second call must not crash */
    dbFinalize(&stmt);
    ASSERT_TRUE(stmt == NULL);

    sqlite3_close(db);
}

/* ══════════════════════════════════ main ══════════════════════════════════ */

int main(void) {
    logSetQuiet(true);
    printf("test_db:\n");

    /* dbExec */
    RUN_TEST(testDbExecNullHandle);
    RUN_TEST(testDbExecNullSQL);
    RUN_TEST(testDbExecCreateTable);
    RUN_TEST(testDbExecInsert);
    RUN_TEST(testDbExecDropTable);
    RUN_TEST(testDbExecInvalidSQL);
    RUN_TEST(testDbExecClosedHandle);
    RUN_TEST(testDbExecSequential);
    RUN_TEST(testDbExecNonexistentTable);

    /* dbFinalize */
    RUN_TEST(testDbFinalizeValid);
    RUN_TEST(testDbFinalizeNullDoublePtr);
    RUN_TEST(testDbFinalizeNullStmt);
    RUN_TEST(testDbFinalizeDoubleCall);

    return TEST_REPORT();
}
