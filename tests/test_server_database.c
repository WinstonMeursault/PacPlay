/**
 * @file test_database.c
 * @brief Adversarial unit tests for the PacPlay database module.
 *
 * Tests cover dbInit/dbClose lifecycle, all user CRUD operations, and all
 * chat history operations.  Every test is written with the assumption that
 * the code is buggy until proven otherwise — boundary conditions, invalid
 * inputs, attack vectors (SQL injection, double-free, cross-type misuse,
 * credential enumeration), and memory safety are exercised aggressively.
 *
 * @date 2026-05-24
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

#include "crypto.h"
#include "log.h"
#include "server/database.h"
#include "test_utils.h"

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <openssl/crypto.h>

/* ──────────────────── helper constants for readability ──────────────────── */

enum { TestUidAlpha = 1000, TestUidBravo = 1001, TestUidCharlie = 1002 };
enum { TestUidDelta = 2000, TestUidMax = 0xFFFFFFFF };
enum { RoomTestA = 1, RoomTestB = 2, RoomTestC = 3 };
enum { RoomMaxVal = 0xFFFFFFFF };
enum { TimeBase = 1700000000, TimeOffset1 = 100, TimeOffset2 = 200 };
enum { TimeOffset3 = 300, TimeOffset4 = 400 };
enum { TimeOffset5 = 500 };
enum { LongStrLen = 1024, MaxUserLen31 = USERNAME_MAX_LEN - 1 };
enum { TimeSecsPerDay = 86400 };
enum { NonexistentUid = 99999 };
enum { TestSentinelPtr = 1 };
enum { TestCountSentinel = 999 };
enum { NonexistentMsgId = 999999 };
enum { LargeNonexistentMsgId = 99999999 };

/* ─────────────────────────── file-level helpers ─────────────────────────── */

/**
 * @brief Remove stale test database files so each test group starts clean.
 */
static void removeDBFiles(void) {
    remove("./db/user.db");
    remove("./db/user.db-wal");
    remove("./db/user.db-shm");
    remove("./db/chatHistory.db");
    remove("./db/chatHistory.db-wal");
    remove("./db/chatHistory.db-shm");
    remove("./db/game.db");
    remove("./db/game.db-wal");
    remove("./db/game.db-shm");
    remove("./db/server.db");
    remove("./db/server.db-wal");
    remove("./db/server.db-shm");
}

/** @brief All-zeros DEK for testing TOTP secret encryption. */
static const uint8_t testDek[AES_GCM_KEY_LEN];

/**
 * @brief Open a UserDB with the test DEK pre-set.
 *
 * Wraps @c dbInit(UserDB, NULL) and @c dbSetDekKey so that every test database
 * can encrypt / decrypt TOTP secrets without manual DEK plumbing.
 *
 * @return An open UserDB handle, or NULL on failure.
 */
static DB *testUserDB(void) {
    DB *db = dbInit(UserDB, NULL);
    if (db != NULL) {
        dbSetDekKey(db, testDek);
    }
    return db;
}

/**
 * @brief Free a dynamically allocated Chat result array.
 */
static void freeChatArray(Chat *arr, size_t count) {
    for (size_t i = 0; i < count; i++) {
        free(arr[i].message);
    }
    free(arr);
}

/* ══════════════════════════════ 1. Lifecycle ══════════════════════════════ */

/** @brief dbInit with invalid DBType returns NULL. */
static void testDbInitInvalidType(void) {
    enum { BadType = 999 };
    DB *db = dbInit((DBType)BadType, NULL);
    ASSERT_TRUE(db == NULL);
}

/** @brief dbInit for UserDB returns non-NULL. */
static void testDbInitUserDB(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    ASSERT_INT_EQ(db->type, UserDB);
    dbClose(db);
}

/** @brief dbInit for ChatHistoryDB returns non-NULL. */
static void testDbInitChatHistoryDB(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    ASSERT_INT_EQ(db->type, ChatHistoryDB);
    dbClose(db);
}

/** @brief dbClose(NULL) is a safe no-op (must not crash). */
static void testDbCloseNull(void) {
    dbClose(NULL);
    /* Reaching this point without crashing = pass */
}

/** @brief dbInit creates the db/ directory automatically. */
static void testDbInitCreatesDir(void) {
    /* Cleanly remove the directory to verify dbInit recreates it */
    removeDBFiles();
    rmdir("./db");
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    dbClose(db);
    /* Verify directory exists */
    struct stat st;
    ASSERT_TRUE(stat("./db", &st) == 0);
    ASSERT_TRUE(S_ISDIR(st.st_mode));
}

/** @brief dbInit called multiple times creates independent handles. */
static void testDbInitMultipleHandles(void) {
    removeDBFiles();
    DB *db1 = testUserDB();
    DB *db2 = testUserDB();
    ASSERT_TRUE(db1 != NULL);
    ASSERT_TRUE(db2 != NULL);
    ASSERT_TRUE(db1 != db2);
    dbClose(db1);
    dbClose(db2);
}

/* ═════════════════════════════ 2. createUser ══════════════════════════════ */

/** @brief createUser rejects NULL database. */
static void testCreateUserNullDB(void) {
    User u = {.username = "alice",
              .nickname = "TestNick",
              .uid = TestUidAlpha,
              .password = "plaintext"};
    ASSERT_INT_EQ(createUser(NULL, &u), DB_FAIL);
}

/** @brief createUser rejects NULL user pointer. */
static void testCreateUserNullUser(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    ASSERT_INT_EQ(createUser(db, NULL), DB_FAIL);
    dbClose(db);
}

/** @brief createUser rejects empty username. */
static void testCreateUserEmptyUsername(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    User u = {.username = "",
              .nickname = "TestNick",
              .uid = TestUidAlpha,
              .password = "pass"};
    ASSERT_INT_EQ(createUser(db, &u), DB_FAIL);
    dbClose(db);
}

/** @brief createUser rejects empty nickname. */
static void testCreateUserEmptyNickname(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    User u = {
        .username = "alice", .nickname = "", .uid = 0, .password = "pass"};
    ASSERT_INT_EQ(createUser(db, &u), DB_FAIL);
    dbClose(db);
}

/** @brief createUser rejects NULL password pointer. */
static void testCreateUserNullPassword(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    User u = {.username = "alice",
              .nickname = "TestNick",
              .uid = TestUidAlpha,
              .password = NULL};
    ASSERT_INT_EQ(createUser(db, &u), DB_FAIL);
    dbClose(db);
}

/** @brief createUser rejects empty password string. */
static void testCreateUserEmptyPassword(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    User u = {.username = "alice",
              .nickname = "TestNick",
              .uid = TestUidAlpha,
              .password = ""};
    ASSERT_INT_EQ(createUser(db, &u), DB_FAIL);
    dbClose(db);
}

/** @brief createUser rejects wrong database type. */
static void testCreateUserWrongDBType(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    User u = {.username = "alice",
              .nickname = "TestNick",
              .uid = TestUidAlpha,
              .password = "pass"};
    ASSERT_INT_EQ(createUser(db, &u), DB_FAIL);
    dbClose(db);
}

/** @brief createUser: basic successful creation. */
static void testCreateUserBasic(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    User u = {.username = "alice",
              .nickname = "TestNick",
              .uid = TestUidAlpha,
              .password = "secret123"};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    dbClose(db);
}

/** @brief createUser: duplicate uid (different username) now succeeds
 *  because uid is server-assigned — each call gets a unique random value. */
static void testCreateUserDuplicateUID(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    User u1 = {.username = "alice",
               .nickname = "TestNick",
               .uid = TestUidAlpha,
               .password = "pass1"};
    ASSERT_INT_EQ(createUser(db, &u1), DB_SUCC);
    User u2 = {.username = "bob",
               .nickname = "TestNick",
               .uid = TestUidAlpha,
               .password = "pass2"};
    ASSERT_INT_EQ(createUser(db, &u2), DB_SUCC);
    /* Verify both users independently */
    ASSERT_INT_EQ(verifyUser(db, &u1), DB_SUCC);
    ASSERT_INT_EQ(verifyUser(db, &u2), DB_SUCC);
    dbClose(db);
}

/** @brief createUser: duplicate username (different uid) must fail. */
static void testCreateUserDuplicateUsername(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    User u1 = {.username = "eve",
               .nickname = "TestNick",
               .uid = TestUidAlpha,
               .password = "pass1"};
    ASSERT_INT_EQ(createUser(db, &u1), DB_SUCC);
    User u2 = {.username = "eve",
               .nickname = "TestNick",
               .uid = TestUidBravo,
               .password = "pass2"};
    ASSERT_INT_EQ(createUser(db, &u2), DB_FAIL);
    dbClose(db);
}

/** @brief createUser: username at maximum length (31 non-NUL chars) works. */
static void testCreateUserMaxLenUsername(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    User u = {.uid = TestUidAlpha, .password = "pass", .nickname = "TestNick"};
    memset(u.username, 'X', (size_t)MaxUserLen31);
    u.username[MaxUserLen31] = '\0';
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    dbClose(db);
}

/** @brief createUser: nickname at maximum length (31 non-NUL chars) works. */
static void testCreateUserMaxLenNickname(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    enum { MaxNickLen31 = NICKNAME_MAX_LEN - 1 };
    User u = {.username = "nickmax", .uid = 0, .password = "pass"};
    memset(u.nickname, 'N', (size_t)MaxNickLen31);
    u.nickname[MaxNickLen31] = '\0';
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    dbClose(db);
}

/** @brief createUser: uid=0 is now valid — the server assigns a random
 *  non-zero uid and populates user->uid. */
static void testCreateUserUidZero(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    User u = {.username = "uidzero",
              .nickname = "TestNick",
              .uid = 0,
              .password = "pass"};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    ASSERT_TRUE(u.uid != 0);
    dbClose(db);
}

/** @brief createUser: uid = UINT32_MAX works. */
static void testCreateUserUidMax(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    User u = {.username = "uidmax",
              .nickname = "TestNick",
              .uid = TestUidMax,
              .password = "pass"};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    dbClose(db);
}

/** @brief createUser: 20 sequential calls all succeed with pairwise unique
 *  uids.  This validates the RAND_bytes + uniqueness-check retry loop
 *  under normal load and guarantees no collisions within a small set. */
static void testCreateUserMultipleUniqueUids(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    enum { UserCount = 20 };
    uint32_t uids[UserCount];
    for (int i = 0; i < UserCount; i++) {
        char nameBuf[USERNAME_MAX_LEN];
        snprintf(nameBuf, sizeof(nameBuf), "bulk%02d", i);
        User u = {.username = "",
                  .nickname = "TestNick",
                  .uid = 0,
                  .password = "pass"};
        memcpy(u.username, nameBuf, strlen(nameBuf) + 1);
        ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
        ASSERT_TRUE(u.uid != 0);
        uids[i] = u.uid;
    }
    /* Verify pairwise uniqueness */
    for (int i = 0; i < UserCount; i++) {
        for (int j = i + 1; j < UserCount; j++) {
            ASSERT_TRUE(uids[i] != uids[j]);
        }
    }
    dbClose(db);
}

/** @brief createUser: special characters in password are handled. */
static void testCreateUserSpecialCharsPassword(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    User u = {.username = "spec",
              .nickname = "TestNick",
              .uid = TestUidAlpha,
              .password = "!@#$%^&*()_+{}|:\"<>?`~[\\];',./\x01\x1F\x7F"};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    /* Verify we can still verify */
    ASSERT_INT_EQ(verifyUser(db, &u), DB_SUCC);
    dbClose(db);
}

/** @brief createUser: very long password does not crash or overflow. */
static void testCreateUserLongPassword(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    size_t passLen = (size_t)LongStrLen + 1;
    char *longPass = malloc(passLen);
    ASSERT_TRUE(longPass != NULL);
    memset(longPass, 'P', passLen - 1);
    longPass[passLen - 1] = '\0';
    User u = {.username = "longpass",
              .nickname = "TestNick",
              .uid = TestUidAlpha,
              .password = longPass};
    int result = createUser(db, &u);
    ASSERT_INT_EQ(result, DB_SUCC);
    /* Verify the long password works */
    ASSERT_INT_EQ(verifyUser(db, &u), DB_SUCC);
    OPENSSL_cleanse(longPass, (size_t)LongStrLen);
    free(longPass);
    dbClose(db);
}

/* ═════════════════════════════ 3. deleteUser ══════════════════════════════ */

/** @brief deleteUser rejects NULL database. */
static void testDeleteUserNullDB(void) {
    User u = {.username = "alice",
              .nickname = "TestNick",
              .uid = TestUidAlpha,
              .password = NULL};
    ASSERT_INT_EQ(deleteUser(NULL, &u), DB_FAIL);
}

/** @brief deleteUser rejects NULL user pointer. */
static void testDeleteUserNullUser(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    ASSERT_INT_EQ(deleteUser(db, NULL), DB_FAIL);
    dbClose(db);
}

/** @brief deleteUser rejects wrong database type. */
static void testDeleteUserWrongDBType(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    User u = {.username = "alice",
              .nickname = "TestNick",
              .uid = TestUidAlpha,
              .password = NULL};
    ASSERT_INT_EQ(deleteUser(db, &u), DB_FAIL);
    dbClose(db);
}

/** @brief deleteUser: non-existent uid returns DB_FAIL (strict mode). */
static void testDeleteUserNonexistent(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    User u = {.username = "ghost",
              .nickname = "TestNick",
              .uid = NonexistentUid,
              .password = NULL};
    ASSERT_INT_EQ(deleteUser(db, &u), DB_FAIL);
    dbClose(db);
}

/** @brief deleteUser: create then delete a user. */
static void testDeleteUserBasic(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    User u = {.username = "delme",
              .nickname = "TestNick",
              .uid = TestUidAlpha,
              .password = "pass"};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    ASSERT_INT_EQ(deleteUser(db, &u), DB_SUCC);
    dbClose(db);
}

/** @brief deleteUser twice: second call must fail. */
static void testDeleteUserTwice(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    User u = {.username = "delme2",
              .nickname = "TestNick",
              .uid = TestUidAlpha,
              .password = "pass"};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    ASSERT_INT_EQ(deleteUser(db, &u), DB_SUCC);
    ASSERT_INT_EQ(deleteUser(db, &u), DB_FAIL);
    dbClose(db);
}

/** @brief deleteUser: uid=0 is rejected at create time, so deletion
 *  of a uid=0 record (which cannot exist) must also fail. */
static void testDeleteUserUidZero(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    /* Create a valid user to ensure DB operations work, but uid=0 is rejected
     */
    User u = {.username = "valid",
              .nickname = "TestNick",
              .uid = TestUidAlpha,
              .password = "pass"};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    /* uid=0 cannot be created, so deletion must fail */
    User uZero = {.username = "zero",
                  .nickname = "TestNick",
                  .uid = 0,
                  .password = "pass"};
    ASSERT_INT_EQ(deleteUser(db, &uZero), DB_FAIL);
    dbClose(db);
}

/** @brief deleteUser: uid = UINT32_MAX works. */
static void testDeleteUserUidMax(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    User u = {.username = "max",
              .nickname = "TestNick",
              .uid = TestUidMax,
              .password = "pass"};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    ASSERT_INT_EQ(deleteUser(db, &u), DB_SUCC);
    dbClose(db);
}

/* ═════════════════════════════ 4. verifyUser ══════════════════════════════ */

/** @brief verifyUser rejects NULL database. */
static void testVerifyUserNullDB(void) {
    User u = {.username = "alice",
              .nickname = "TestNick",
              .uid = TestUidAlpha,
              .password = "pass"};
    ASSERT_INT_EQ(verifyUser(NULL, &u), DB_FAIL);
}

/** @brief verifyUser rejects NULL user pointer. */
static void testVerifyUserNullUser(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    ASSERT_INT_EQ(verifyUser(db, NULL), DB_FAIL);
    dbClose(db);
}

/** @brief verifyUser rejects empty username. */
static void testVerifyUserEmptyUsername(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    User u = {.username = "",
              .nickname = "TestNick",
              .uid = TestUidAlpha,
              .password = "pass"};
    ASSERT_INT_EQ(verifyUser(db, &u), DB_FAIL);
    dbClose(db);
}

/** @brief verifyUser rejects NULL password. */
static void testVerifyUserNullPassword(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    User u = {.username = "alice",
              .nickname = "TestNick",
              .uid = TestUidAlpha,
              .password = NULL};
    ASSERT_INT_EQ(verifyUser(db, &u), DB_FAIL);
    dbClose(db);
}

/** @brief verifyUser rejects empty password. */
static void testVerifyUserEmptyPassword(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    User u = {.username = "alice",
              .nickname = "TestNick",
              .uid = TestUidAlpha,
              .password = ""};
    ASSERT_INT_EQ(verifyUser(db, &u), DB_FAIL);
    dbClose(db);
}

/** @brief verifyUser rejects wrong database type. */
static void testVerifyUserWrongDBType(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    User u = {.username = "alice",
              .nickname = "TestNick",
              .uid = TestUidAlpha,
              .password = "pass"};
    ASSERT_INT_EQ(verifyUser(db, &u), DB_FAIL);
    dbClose(db);
}

/** @brief verifyUser: non-existent user fails. */
static void testVerifyUserNonexistent(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    User u = {.username = "ghost",
              .nickname = "TestNick",
              .uid = NonexistentUid,
              .password = "pass"};
    ASSERT_INT_EQ(verifyUser(db, &u), DB_FAIL);
    dbClose(db);
}

/** @brief verifyUser: wrong password fails. */
static void testVerifyUserWrongPassword(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    User u = {.username = "alice",
              .nickname = "TestNick",
              .uid = TestUidAlpha,
              .password = "correct"};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    u.password = "wrongpass";
    ASSERT_INT_EQ(verifyUser(db, &u), DB_FAIL);
    dbClose(db);
}

/** @brief verifyUser: correct uid but wrong username fails. */
static void testVerifyUserWrongUsername(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    User u = {.username = "alice",
              .nickname = "TestNick",
              .uid = TestUidAlpha,
              .password = "secret"};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    u.password = "secret";
    strncpy(u.username, "bob", sizeof(u.username));
    ASSERT_INT_EQ(verifyUser(db, &u), DB_FAIL);
    dbClose(db);
}

/** @brief verifyUser: UID is not part of authentication — changing uid
 *  while keeping correct username+password should still succeed. */
static void testVerifyUserWrongUID(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    User u = {.username = "alice",
              .nickname = "TestNick",
              .uid = TestUidAlpha,
              .password = "secret"};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    /* save the server-assigned uid so we can demonstrate it changed */
    uint32_t assignedUid = u.uid;
    u.password = "secret";
    u.uid = NonexistentUid;
    ASSERT_INT_EQ(verifyUser(db, &u), DB_SUCC);
    /* verifyUser must still return the canonical uid from the database */
    ASSERT_UINT_EQ(u.uid, assignedUid);
    dbClose(db);
}

/** @brief verifyUser: basic success. */
static void testVerifyUserBasic(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    User u = {.username = "alice",
              .nickname = "TestNick",
              .uid = TestUidAlpha,
              .password = "secret123"};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    ASSERT_INT_EQ(verifyUser(db, &u), DB_SUCC);
    dbClose(db);
}

/** @brief verifyUser must fail after user is deleted. */
static void testVerifyUserAfterDelete(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    User u = {.username = "todelete",
              .nickname = "TestNick",
              .uid = TestUidAlpha,
              .password = "pass"};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    ASSERT_INT_EQ(verifyUser(db, &u), DB_SUCC);
    ASSERT_INT_EQ(deleteUser(db, &u), DB_SUCC);
    /* Must fail after deletion */
    ASSERT_INT_EQ(verifyUser(db, &u), DB_FAIL);
    dbClose(db);
}

/** @brief verifyUser does NOT distinguish non-existent user from wrong pass. */
static void testVerifyUserNoEnumeration(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    User u = {.username = "alice",
              .nickname = "TestNick",
              .uid = TestUidAlpha,
              .password = "realpass"};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    /* Wrong password */
    u.password = "wrong";
    int resultWrong = verifyUser(db, &u);
    /* Non-existent user */
    User ghost = {.username = "ghost",
                  .nickname = "TestNick",
                  .uid = NonexistentUid,
                  .password = "any"};
    int resultGhost = verifyUser(db, &ghost);
    /* Both must return DB_FAIL; attacker cannot distinguish */
    ASSERT_INT_EQ(resultWrong, DB_FAIL);
    ASSERT_INT_EQ(resultGhost, DB_FAIL);
    dbClose(db);
}

/** @brief verifyUser: passwords that differ by one bit fail. */
static void testVerifyUserSimilarPassword(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    User u = {.username = "alice",
              .nickname = "TestNick",
              .uid = TestUidAlpha,
              .password = "Password123"};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    /* Case difference */
    u.password = "password123";
    ASSERT_INT_EQ(verifyUser(db, &u), DB_FAIL);
    /* One char difference */
    u.password = "Password124";
    ASSERT_INT_EQ(verifyUser(db, &u), DB_FAIL);
    /* Trailing space */
    u.password = "Password123 ";
    ASSERT_INT_EQ(verifyUser(db, &u), DB_FAIL);
    dbClose(db);
}

/* ══════════════════════════════ 5. storeChat ══════════════════════════════ */

/** @brief storeChat rejects NULL database. */
static void testStoreChatNullDB(void) {
    Chat ch = {TestUidAlpha, 0, "hello", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChat(NULL, RoomTestA, &ch), DB_FAIL);
}

/** @brief storeChat rejects NULL Chat pointer. */
static void testStoreChatNullChat(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    ASSERT_INT_EQ(storeChat(db, RoomTestA, NULL), DB_FAIL);
    dbClose(db);
}

/** @brief storeChat rejects NULL message. */
static void testStoreChatNullMessage(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    Chat ch = {TestUidAlpha, 0, NULL, (time_t)TimeBase};
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &ch), DB_FAIL);
    dbClose(db);
}

/** @brief storeChat rejects empty message. */
static void testStoreChatEmptyMessage(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    Chat ch = {TestUidAlpha, 0, "", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &ch), DB_FAIL);
    dbClose(db);
}

/** @brief storeChat rejects wrong database type. */
static void testStoreChatWrongDBType(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    Chat ch = {TestUidAlpha, 0, "msg", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &ch), DB_FAIL);
    dbClose(db);
}

/** @brief storeChat: basic success, msgId is populated. */
static void testStoreChatBasic(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    Chat ch = {TestUidAlpha, 0, "Hello, world!", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &ch), DB_SUCC);
    /* msgId must have been populated (non-zero) */
    ASSERT_TRUE(ch.msgId > 0);
    dbClose(db);
}

/** @brief storeChat: msgId is strictly monotonically increasing. */
static void testStoreChatMsgIdMonotonic(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    Chat ch1 = {TestUidAlpha, 0, "msg1", (time_t)TimeBase};
    Chat ch2 = {TestUidAlpha, 0, "msg2", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &ch1), DB_SUCC);
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &ch2), DB_SUCC);
    ASSERT_TRUE(ch2.msgId > ch1.msgId);
    dbClose(db);
}

/** @brief storeChat: msgId is unique across different rooms. */
static void testStoreChatCrossRoomUnique(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    Chat chA = {TestUidAlpha, 0, "roomA", (time_t)TimeBase};
    Chat chB = {TestUidAlpha, 0, "roomB", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &chA), DB_SUCC);
    ASSERT_INT_EQ(storeChat(db, RoomTestB, &chB), DB_SUCC);
    /* msgIds must be distinct */
    ASSERT_TRUE(chA.msgId != chB.msgId);
    dbClose(db);
}

/** @brief storeChat: roomId = 0 works. */
static void testStoreChatRoomIdZero(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    Chat ch = {TestUidAlpha, 0, "room zero", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChat(db, 0, &ch), DB_SUCC);
    ASSERT_TRUE(ch.msgId > 0);
    dbClose(db);
}

/** @brief storeChat: roomId = UINT32_MAX works. */
static void testStoreChatRoomIdMax(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    Chat ch = {TestUidAlpha, 0, "room max", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChat(db, RoomMaxVal, &ch), DB_SUCC);
    ASSERT_TRUE(ch.msgId > 0);
    dbClose(db);
}

/** @brief storeChat: special characters in message are preserved. */
static void testStoreChatSpecialChars(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    Chat ch = {TestUidAlpha, 0,
               "'; DROP TABLE users; -- \n\r\t\x01\x1F\x7F\xFF",
               (time_t)TimeBase};
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &ch), DB_SUCC);
    /* Verify roundtrip preserves the string */
    Chat retrieved;
    ASSERT_INT_EQ(queryChatByMsgId(db, RoomTestA, ch.msgId, &retrieved),
                  DB_SUCC);
    ASSERT_STR_EQ(retrieved.message,
                  "'; DROP TABLE users; -- \n\r\t\x01\x1F\x7F\xFF");
    free(retrieved.message);
    dbClose(db);
}

/** @brief storeChat: timestamp = 0 (epoch) is accepted. */
static void testStoreChatTimestampZero(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    Chat ch = {TestUidAlpha, 0, "epoch msg", (time_t)0};
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &ch), DB_SUCC);
    ASSERT_TRUE(ch.msgId > 0);
    dbClose(db);
}

/* ══════════════════════════ 6. queryChatByMsgId ═══════════════════════════ */

/** @brief queryChatByMsgId rejects NULL database. */
static void testQueryMsgIdNullDB(void) {
    Chat out;
    ASSERT_INT_EQ(queryChatByMsgId(NULL, RoomTestA, 1, &out), DB_FAIL);
}

/** @brief queryChatByMsgId rejects NULL out pointer. */
static void testQueryMsgIdNullOut(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    ASSERT_INT_EQ(queryChatByMsgId(db, RoomTestA, 1, NULL), DB_FAIL);
    dbClose(db);
}

/** @brief queryChatByMsgId rejects wrong database type. */
static void testQueryMsgIdWrongDBType(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    Chat out;
    ASSERT_INT_EQ(queryChatByMsgId(db, RoomTestA, 1, &out), DB_FAIL);
    dbClose(db);
}

/** @brief queryChatByMsgId: non-existent msgId returns DB_FAIL. */
static void testQueryMsgIdNonexistent(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    Chat out;
    ASSERT_INT_EQ(queryChatByMsgId(db, RoomTestA, LargeNonexistentMsgId, &out),
                  DB_FAIL);
    dbClose(db);
}

/** @brief queryChatByMsgId: non-existent room returns DB_FAIL. */
static void testQueryMsgIdNonexistentRoom(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    Chat out;
    ASSERT_INT_EQ(queryChatByMsgId(db, 9999, 1, &out), DB_FAIL);
    dbClose(db);
}

/** @brief queryChatByMsgId: store and retrieve roundtrip. */
static void testQueryMsgIdRoundtrip(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    Chat in = {TestUidAlpha, 0, "roundtrip test!", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &in), DB_SUCC);
    Chat out;
    ASSERT_INT_EQ(queryChatByMsgId(db, RoomTestA, in.msgId, &out), DB_SUCC);
    ASSERT_UINT_EQ(out.msgId, in.msgId);
    ASSERT_UINT_EQ(out.uid, in.uid);
    ASSERT_STR_EQ(out.message, "roundtrip test!");
    ASSERT_INT_EQ(out.timestamp, in.timestamp);
    free(out.message);
    dbClose(db);
}

/** @brief queryChatByMsgId: msgId = 0 finds a stored message. */
static void testQueryMsgIdZeroSearch(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    /* Store a message and note its msgId, then query by that exact id */
    Chat in = {TestUidAlpha, 0, "zero test", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &in), DB_SUCC);
    Chat out;
    ASSERT_INT_EQ(queryChatByMsgId(db, RoomTestA, in.msgId, &out), DB_SUCC);
    free(out.message);
    /* msgId=0 before any store should fail */
    removeDBFiles();
    DB *db2 = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db2 != NULL);
    Chat out2;
    ASSERT_INT_EQ(queryChatByMsgId(db2, RoomTestA, 0, &out2), DB_FAIL);
    dbClose(db2);
}

/** @brief queryChatByMsgId: UINT64_MAX msgId fails (does not crash). */
static void testQueryMsgIdMax(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    Chat out;
    ASSERT_INT_EQ(queryChatByMsgId(db, RoomTestA, UINT64_MAX, &out), DB_FAIL);
    dbClose(db);
}

/** @brief queryChatByMsgId: out->message is NULL on failure. */
static void testQueryMsgIdOutNotTouchedOnFailure(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    Chat out;
    memset(&out, 0, sizeof(out));
    ASSERT_INT_EQ(queryChatByMsgId(db, RoomTestA, NonexistentMsgId, &out),
                  DB_FAIL);
    /* out should not have been corrupted - message is still NULL */
    ASSERT_TRUE(out.message == NULL);
    dbClose(db);
}

/* ════════════════════════ 7. queryChatByTimeRange ═════════════════════════ */

/** @brief queryChatByTimeRange rejects NULL database. */
static void testQueryTimeNullDB(void) {
    Chat *out = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(queryChatByTimeRange(NULL, RoomTestA, 0, (time_t)0, (time_t)1,
                                       &out, &count),
                  DB_FAIL);
}

/** @brief queryChatByTimeRange rejects NULL out. */
static void testQueryTimeNullOut(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    size_t count = 0;
    ASSERT_INT_EQ(queryChatByTimeRange(db, RoomTestA, 0, (time_t)0, (time_t)1,
                                       NULL, &count),
                  DB_FAIL);
    dbClose(db);
}

/** @brief queryChatByTimeRange rejects NULL count. */
static void testQueryTimeNullCount(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    Chat *out = NULL;
    ASSERT_INT_EQ(queryChatByTimeRange(db, RoomTestA, 0, (time_t)0, (time_t)1,
                                       &out, NULL),
                  DB_FAIL);
    dbClose(db);
}

/** @brief queryChatByTimeRange rejects wrong database type. */
static void testQueryTimeWrongDBType(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    Chat *out = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(queryChatByTimeRange(db, RoomTestA, 0, (time_t)0, (time_t)1,
                                       &out, &count),
                  DB_FAIL);
    dbClose(db);
}

/** @brief queryChatByTimeRange: empty room returns DB_SUCC with count=0. */
static void testQueryTimeEmptyRoom(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    Chat *out = (Chat *)(uintptr_t)TestSentinelPtr;
    size_t count = TestCountSentinel;
    ASSERT_INT_EQ(queryChatByTimeRange(db, RoomTestA, 0, (time_t)0,
                                       (time_t)TimeBase + TimeOffset5, &out,
                                       &count),
                  DB_SUCC);
    ASSERT_UINT_EQ(count, (unsigned long long)0);
    ASSERT_TRUE(out == NULL);
    dbClose(db);
}

/** @brief queryChatByTimeRange: uid filter returns only matching user. */
static void testQueryTimeUIDFilter(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    /* Store messages from two different users */
    Chat ch1 = {TestUidAlpha, 0, "alpha msg", (time_t)TimeBase};
    Chat ch2 = {TestUidBravo, 0, "bravo msg", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &ch1), DB_SUCC);
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &ch2), DB_SUCC);
    /* Query only TestUidAlpha's messages */
    Chat *out = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(queryChatByTimeRange(db, RoomTestA, TestUidAlpha, (time_t)0,
                                       (time_t)TimeBase + TimeOffset5, &out,
                                       &count),
                  DB_SUCC);
    ASSERT_UINT_EQ(count, (unsigned long long)1);
    ASSERT_UINT_EQ(out[0].uid, TestUidAlpha);
    ASSERT_STR_EQ(out[0].message, "alpha msg");
    freeChatArray(out, count);
    dbClose(db);
}

/** @brief queryChatByTimeRange: uid=0 returns all users. */
static void testQueryTimeAllUids(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    Chat ch1 = {TestUidAlpha, 0, "A", (time_t)TimeBase};
    Chat ch2 = {TestUidBravo, 0, "B", (time_t)TimeBase};
    Chat ch3 = {TestUidCharlie, 0, "C", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &ch1), DB_SUCC);
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &ch2), DB_SUCC);
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &ch3), DB_SUCC);
    Chat *out = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(queryChatByTimeRange(db, RoomTestA, 0, (time_t)0,
                                       (time_t)TimeBase + TimeOffset5, &out,
                                       &count),
                  DB_SUCC);
    ASSERT_UINT_EQ(count, (unsigned long long)3);
    freeChatArray(out, count);
    dbClose(db);
}

/** @brief queryChatByTimeRange: time range with no match returns 0. */
static void testQueryTimeNoMatch(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    Chat ch = {TestUidAlpha, 0, "msg", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &ch), DB_SUCC);
    /* Query a time range entirely after the message */
    Chat *out = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(
        queryChatByTimeRange(db, RoomTestA, 0, (time_t)(TimeBase + TimeOffset5),
                             (time_t)(TimeBase + TimeOffset5 + TimeSecsPerDay),
                             &out, &count),
        DB_SUCC);
    ASSERT_UINT_EQ(count, (unsigned long long)0);
    ASSERT_TRUE(out == NULL);
    dbClose(db);
}

/** @brief queryChatByTimeRange: startTime > endTime returns empty result. */
static void testQueryTimeInvertedRange(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    Chat ch = {TestUidAlpha, 0, "msg", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &ch), DB_SUCC);
    Chat *out = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(
        queryChatByTimeRange(db, RoomTestA, 0, (time_t)TimeBase + TimeOffset2,
                             (time_t)TimeBase + TimeOffset1, &out, &count),
        DB_SUCC);
    ASSERT_UINT_EQ(count, (unsigned long long)0);
    ASSERT_TRUE(out == NULL);
    dbClose(db);
}

/** @brief queryChatByTimeRange: startTime == endTime (single-point range). */
static void testQueryTimeEqualRange(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    Chat ch1 = {TestUidAlpha, 0, "exact", (time_t)TimeBase};
    Chat ch2 = {TestUidAlpha, 0, "after", (time_t)(TimeBase + TimeOffset1)};
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &ch1), DB_SUCC);
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &ch2), DB_SUCC);
    Chat *out = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(queryChatByTimeRange(db, RoomTestA, 0, (time_t)TimeBase,
                                       (time_t)TimeBase, &out, &count),
                  DB_SUCC);
    ASSERT_UINT_EQ(count, (unsigned long long)1);
    ASSERT_STR_EQ(out[0].message, "exact");
    freeChatArray(out, count);
    dbClose(db);
}

/** @brief queryChatByTimeRange: results are ordered by msgId ASC. */
static void testQueryTimeOrdering(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    Chat ch1 = {TestUidAlpha, 0, "third", (time_t)(TimeBase + TimeOffset3)};
    Chat ch2 = {TestUidAlpha, 0, "first", (time_t)(TimeBase + TimeOffset1)};
    Chat ch3 = {TestUidAlpha, 0, "second", (time_t)(TimeBase + TimeOffset2)};
    /* Store out of timestamp order */
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &ch1), DB_SUCC);
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &ch2), DB_SUCC);
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &ch3), DB_SUCC);
    Chat *out = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(queryChatByTimeRange(db, RoomTestA, 0, (time_t)0,
                                       (time_t)TimeBase + TimeOffset5, &out,
                                       &count),
                  DB_SUCC);
    ASSERT_UINT_EQ(count, (unsigned long long)3);
    /* Results must be ordered by msgId ASC (which is insert order) */
    ASSERT_TRUE(out[0].msgId < out[1].msgId);
    ASSERT_TRUE(out[1].msgId < out[2].msgId);
    freeChatArray(out, count);
    dbClose(db);
}

/** @brief queryChatByTimeRange: large number of messages does not crash. */
static void testQueryTimeManyMessages(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    enum { MsgCount = 50 };
    for (int i = 0; i < MsgCount; i++) {
        Chat ch = {TestUidAlpha, 0, "msg",
                   (time_t)(TimeBase + i * TimeOffset1)};
        ASSERT_INT_EQ(storeChat(db, RoomTestA, &ch), DB_SUCC);
    }
    Chat *out = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(
        queryChatByTimeRange(db, RoomTestA, 0, (time_t)0,
                             (time_t)TimeBase + (time_t)MsgCount * TimeOffset1,
                             &out, &count),
        DB_SUCC);
    ASSERT_UINT_EQ(count, (unsigned long long)MsgCount);
    /* Verify each result has a non-NULL message */
    for (size_t i = 0; i < count; i++) {
        ASSERT_TRUE(out[i].message != NULL);
    }
    freeChatArray(out, count);
    dbClose(db);
}

/** @brief queryChatByTimeRange: cross-room isolation — different rooms are
 * independent. */
static void testQueryTimeCrossRoomIsolation(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    Chat chA = {TestUidAlpha, 0, "roomA", (time_t)TimeBase};
    Chat chB = {TestUidAlpha, 0, "roomB", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &chA), DB_SUCC);
    ASSERT_INT_EQ(storeChat(db, RoomTestB, &chB), DB_SUCC);
    /* Query room A — should NOT see room B's message */
    Chat *out = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(queryChatByTimeRange(db, RoomTestA, 0, (time_t)0,
                                       (time_t)TimeBase + TimeOffset5, &out,
                                       &count),
                  DB_SUCC);
    ASSERT_UINT_EQ(count, (unsigned long long)1);
    ASSERT_STR_EQ(out[0].message, "roomA");
    freeChatArray(out, count);
    dbClose(db);
}

/* ═════════════════════════════ 8. persistence ═════════════════════════════ */

/** @brief Data persists across dbClose / dbInit cycles. */
static void testPersistenceUserDB(void) {
    removeDBFiles();
    {
        DB *db = testUserDB();
        ASSERT_TRUE(db != NULL);
        User u = {.username = "persist",
                  .nickname = "TestNick",
                  .uid = TestUidAlpha,
                  .password = "mysecret"};
        ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
        dbClose(db);
    }
    {
        DB *db = testUserDB();
        ASSERT_TRUE(db != NULL);
        User u = {.username = "persist",
                  .nickname = "TestNick",
                  .uid = TestUidAlpha,
                  .password = "mysecret"};
        ASSERT_INT_EQ(verifyUser(db, &u), DB_SUCC);
        dbClose(db);
    }
}

/** @brief Chat data persists across dbClose / dbInit cycles. */
static void testPersistenceChatDB(void) {
    removeDBFiles();
    uint64_t savedMsgId = 0;
    {
        DB *db = dbInit(ChatHistoryDB, NULL);
        ASSERT_TRUE(db != NULL);
        Chat ch = {TestUidAlpha, 0, "persistent msg", (time_t)TimeBase};
        ASSERT_INT_EQ(storeChat(db, RoomTestA, &ch), DB_SUCC);
        savedMsgId = ch.msgId;
        dbClose(db);
    }
    {
        DB *db2 = dbInit(ChatHistoryDB, NULL);
        ASSERT_TRUE(db2 != NULL);
        Chat out;
        ASSERT_INT_EQ(queryChatByMsgId(db2, RoomTestA, savedMsgId, &out),
                      DB_SUCC);
        ASSERT_STR_EQ(out.message, "persistent msg");
        free(out.message);
        dbClose(db2);
    }
}

/** @brief msg_sequence continues from where it left off after reopen. */
static void testPersistenceMsgSeqContinues(void) {
    removeDBFiles();
    uint64_t lastBeforeClose = 0;
    {
        DB *db = dbInit(ChatHistoryDB, NULL);
        ASSERT_TRUE(db != NULL);
        Chat ch = {TestUidAlpha, 0, "pre-close", (time_t)TimeBase};
        ASSERT_INT_EQ(storeChat(db, RoomTestA, &ch), DB_SUCC);
        lastBeforeClose = ch.msgId;
        dbClose(db);
    }
    {
        DB *db = dbInit(ChatHistoryDB, NULL);
        ASSERT_TRUE(db != NULL);
        Chat ch = {TestUidAlpha, 0, "post-close", (time_t)TimeBase};
        ASSERT_INT_EQ(storeChat(db, RoomTestA, &ch), DB_SUCC);
        /* New msgId must be greater than the one before close */
        ASSERT_TRUE(ch.msgId > lastBeforeClose);
        dbClose(db);
    }
}

/* ══════════════════════ 9. security / attack vectors ══════════════════════ */

/**
 * @brief SQL injection attempt with malicious username string.
 *
 * Since all user input is bound via sqlite3_bind_* (prepared statements),
 * this must succeed (store the literal string) without any harmful side
 * effects.
 */
static void testSQLInjectionUsername(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    User u = {.username = "'; DROP TABLE users; --",
              .nickname = "TestNick",
              .uid = TestUidAlpha,
              .password = "pass"};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    /* Verify the exact string was stored */
    ASSERT_INT_EQ(verifyUser(db, &u), DB_SUCC);
    /* The users table must still exist (no DROP was executed) */
    User v = {.username = "normal",
              .nickname = "TestNick",
              .uid = TestUidBravo,
              .password = "pass"};
    ASSERT_INT_EQ(createUser(db, &v), DB_SUCC);
    dbClose(db);
}

/**
 * @brief SQL injection attempt with malicious message string.
 *
 * Inject SQL keywords in message — they must be stored as literal text.
 */
static void testSQLInjectionMessage(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    Chat ch = {TestUidAlpha, 0,
               "'); DELETE FROM room_1; INSERT INTO room_1 "
               "VALUES(9999,1,'hacked',0); --",
               (time_t)TimeBase};
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &ch), DB_SUCC);
    /* Retrieve and verify exact string */
    Chat out;
    ASSERT_INT_EQ(queryChatByMsgId(db, RoomTestA, ch.msgId, &out), DB_SUCC);
    ASSERT_STR_EQ(out.message, "'); DELETE FROM room_1; INSERT INTO room_1 "
                               "VALUES(9999,1,'hacked',0); --");
    free(out.message);
    /* The original message should still exist (no SQL was injected) */
    dbClose(db);
}

/**
 * @brief Calling all Chat operations on a UserDB handle must fail.
 */
static void testCrossTypeChatOnUserDB(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    Chat ch = {TestUidAlpha, 0, "msg", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &ch), DB_FAIL);
    Chat out;
    ASSERT_INT_EQ(queryChatByMsgId(db, RoomTestA, 1, &out), DB_FAIL);
    Chat *arr = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(queryChatByTimeRange(db, RoomTestA, 0, (time_t)0, (time_t)1,
                                       &arr, &count),
                  DB_FAIL);
    dbClose(db);
}

/**
 * @brief Calling all User operations on a ChatHistoryDB handle must fail.
 */
static void testCrossTypeUserOnChatDB(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    User u = {.username = "alice",
              .nickname = "TestNick",
              .uid = TestUidAlpha,
              .password = "pass"};
    ASSERT_INT_EQ(createUser(db, &u), DB_FAIL);
    ASSERT_INT_EQ(deleteUser(db, &u), DB_FAIL);
    ASSERT_INT_EQ(verifyUser(db, &u), DB_FAIL);
    dbClose(db);
}

/** @brief Username with embedded NUL byte (using username[0] = '\0'). */
static void testUsernameEmbeddedNul(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    /* First char \0 → empty string, must be rejected */
    User u = {.username = "\0hidden",
              .nickname = "TestNick",
              .uid = TestUidAlpha,
              .password = "pass"};
    ASSERT_INT_EQ(createUser(db, &u), DB_FAIL);
    dbClose(db);
}

/** @brief dbInit handles directory busy (file exists where dir expected). */
static void testDbInitFileWhereDirExpected(void) {
    /* Create a regular file named "./db" after cleaning up */
    removeDBFiles();
    rmdir("./db");
    FILE *f = fopen("./db", "w");
    if (f != NULL) {
        fclose(f);
        /* dbInit should fail because "./db" is a file, not a directory */
        DB *db = testUserDB();
        /* It may or may not return NULL depending on implementation;
         * the important thing is that it does not crash or produce UB */
        if (db != NULL) {
            dbClose(db);
        }
        remove("./db");
    }
}

/* ═══════════════════════════ 10. hash password ════════════════════════════ */

/** @brief password hash stored in database is not the plaintext. */
static void testPasswordNotPlaintextInDB(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    User u = {.username = "alice",
              .nickname = "TestNick",
              .uid = TestUidAlpha,
              .password = "secret123"};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    /* Directly query the raw stored password — must NOT equal plaintext.
     * Use the uid that createUser assigned (no longer TestUidAlpha). */
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db->handle,
                                "SELECT password FROM users WHERE uid = ?;", -1,
                                &stmt, NULL);
    ASSERT_INT_EQ(rc, SQLITE_OK);
    rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)u.uid);
    ASSERT_INT_EQ(rc, SQLITE_OK);
    rc = sqlite3_step(stmt);
    ASSERT_INT_EQ(rc, SQLITE_ROW);
    const char *stored = (const char *)sqlite3_column_text(stmt, 0);
    ASSERT_TRUE(stored != NULL);
    /* The stored string must NOT equal the original plaintext */
    ASSERT_TRUE(strcmp(stored, "secret123") != 0);
    /* It must have the salt:hash colon format */
    ASSERT_TRUE(strchr(stored, ':') != NULL);
    sqlite3_finalize(stmt);
    dbClose(db);
}

/** @brief Two users with the same password can both be verified.
 *
 * Each hashPassword() call generates an independent random salt. Both
 * stored hashes must therefore be independently usable for verification
 * via verifyPassword(), which extracts the salt from each stored hash.
 */
static void testPasswordHashSamePasswordDifferentUsers(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    User u1 = {.username = "hash1",
               .nickname = "TestNick",
               .uid = TestUidAlpha,
               .password = "samepass"};
    User u2 = {.username = "hash2",
               .nickname = "TestNick",
               .uid = TestUidBravo,
               .password = "samepass"};
    ASSERT_INT_EQ(createUser(db, &u1), DB_SUCC);
    ASSERT_INT_EQ(createUser(db, &u2), DB_SUCC);
    /* Both users can verify independently with the same password */
    ASSERT_INT_EQ(verifyUser(db, &u1), DB_SUCC);
    ASSERT_INT_EQ(verifyUser(db, &u2), DB_SUCC);
    /* u1 cannot verify with a different password */
    u1.password = "different";
    ASSERT_INT_EQ(verifyUser(db, &u1), DB_FAIL);
    /* Restore correct password to confirm u1 still works */
    u1.password = "samepass";
    ASSERT_INT_EQ(verifyUser(db, &u1), DB_SUCC);
    dbClose(db);
}

/* ══════════════════════ 11. additional coverage gaps ══════════════════════ */

/** @brief uid=0 users are now allowed — the server generates a random
 *  uid and verifyUser returns the canonical uid from the database. */
static void testVerifyUserUidZero(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    User u = {.username = "zero",
              .nickname = "TestNick",
              .uid = 0,
              .password = "pass"};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    ASSERT_TRUE(u.uid != 0);
    ASSERT_INT_EQ(verifyUser(db, &u), DB_SUCC);
    dbClose(db);
}

/** @brief verifyUser returns the same canonical uid from the database
 *  on repeated calls, and fills the nickname field from the stored record. */
static void testVerifyUserUidConsistency(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    User u = {.username = "stable",
              .nickname = "TestNick",
              .uid = 0,
              .password = "stablepw"};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    uint32_t firstUid = u.uid;
    ASSERT_TRUE(firstUid != 0);
    /* First verifyUser call must return the canonical uid from DB */
    ASSERT_INT_EQ(verifyUser(db, &u), DB_SUCC);
    ASSERT_UINT_EQ(u.uid, firstUid);
    ASSERT_STR_EQ(u.nickname, "TestNick");
    /* Second call must also return the same uid */
    ASSERT_INT_EQ(verifyUser(db, &u), DB_SUCC);
    ASSERT_UINT_EQ(u.uid, firstUid);
    dbClose(db);
}

/** @brief createUser stores and verifyUser retrieves a non-NULL totpSecret. */
static void testCreateUserWithTotpSecret(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    User u = {.username = "totpuser",
              .nickname = "TOTP",
              .uid = 0,
              .password = "totppw",
              .totpSecret = "JBSWY3DPEHPK3PXP"};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    ASSERT_INT_EQ(verifyUser(db, &u), DB_SUCC);
    ASSERT_TRUE(u.totpSecret != NULL);
    ASSERT_STR_EQ(u.totpSecret, "JBSWY3DPEHPK3PXP");
    free(u.totpSecret);
    dbClose(db);
}

/** @brief createUser stores a NULL totpSecret; verifyUser returns NULL. */
static void testCreateUserTotpSecretNull(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    User u = {.username = "nototp",
              .nickname = "NoTOTP",
              .uid = 0,
              .password = "nopw",
              .totpSecret = NULL};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    ASSERT_INT_EQ(verifyUser(db, &u), DB_SUCC);
    ASSERT_TRUE(u.totpSecret == NULL);
    dbClose(db);
}

/** @brief TOTP secret survives database close / reopen. */
static void testTotpSecretPersistence(void) {
    removeDBFiles();
    {
        DB *db = testUserDB();
        ASSERT_TRUE(db != NULL);
        User u = {.username = "persisttotp",
                  .nickname = "PTotp",
                  .uid = 0,
                  .password = "ppw",
                  .totpSecret = "GEZDGNBVGY3TQOJQ"};
        ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
        dbClose(db);
    }
    {
        DB *db = testUserDB();
        ASSERT_TRUE(db != NULL);
        User u = {.username = "persisttotp",
                  .nickname = "PTotp",
                  .uid = 0,
                  .password = "ppw",
                  .totpSecret = NULL};
        ASSERT_INT_EQ(verifyUser(db, &u), DB_SUCC);
        ASSERT_TRUE(u.totpSecret != NULL);
        ASSERT_STR_EQ(u.totpSecret, "GEZDGNBVGY3TQOJQ");
        free(u.totpSecret);
        dbClose(db);
    }
}

static void testSetTotpSecretBasic(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    User u = {
        .username = "settotp", .nickname = "Set", .uid = 0, .password = "pw"};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);

    ASSERT_INT_EQ(setTOTPSecret(db, &u, "JBSWY3DPEHPK3PXP"), DB_SUCC);

    ASSERT_INT_EQ(verifyUser(db, &u), DB_SUCC);
    ASSERT_TRUE(u.totpSecret != NULL);
    ASSERT_STR_EQ(u.totpSecret, "JBSWY3DPEHPK3PXP");
    free(u.totpSecret);
    dbClose(db);
}

static void testSetTotpSecretOverwrite(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    User u = {.username = "ovrwrtotp",
              .nickname = "Over",
              .uid = 0,
              .password = "pw",
              .totpSecret = "AAAAAAAAAAAA"};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);

    ASSERT_INT_EQ(setTOTPSecret(db, &u, "GEZDGNBVGY3TQOJQ"), DB_SUCC);

    ASSERT_INT_EQ(verifyUser(db, &u), DB_SUCC);
    ASSERT_TRUE(u.totpSecret != NULL);
    ASSERT_STR_EQ(u.totpSecret, "GEZDGNBVGY3TQOJQ");
    free(u.totpSecret);
    dbClose(db);
}

static void testSetTotpSecretClear(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    User u = {.username = "cleartotp",
              .nickname = "Clear",
              .uid = 0,
              .password = "pw",
              .totpSecret = "JBSWY3DPEHPK3PXP"};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);

    ASSERT_INT_EQ(setTOTPSecret(db, &u, NULL), DB_SUCC);

    ASSERT_INT_EQ(verifyUser(db, &u), DB_SUCC);
    ASSERT_TRUE(u.totpSecret == NULL);
    dbClose(db);
}

static void testSetTotpSecretClearEmpty(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    User u = {.username = "clearempty",
              .nickname = "ClrE",
              .uid = 0,
              .password = "pw",
              .totpSecret = "JBSWY3DPEHPK3PXP"};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);

    ASSERT_INT_EQ(setTOTPSecret(db, &u, ""), DB_SUCC);

    ASSERT_INT_EQ(verifyUser(db, &u), DB_SUCC);
    ASSERT_TRUE(u.totpSecret == NULL);
    dbClose(db);
}

static void testSetTotpSecretNullDB(void) {
    ASSERT_INT_EQ(setTOTPSecret(NULL, NULL, NULL), DB_FAIL);
}

static void testSetTotpSecretWrongDBType(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    User u = {
        .username = "wrongdb", .nickname = "W", .uid = 1, .password = "pw"};
    ASSERT_INT_EQ(setTOTPSecret(db, &u, "AAAA"), DB_FAIL);
    dbClose(db);
}

static void testSetTotpSecretNonexistentUser(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    enum { NonexistentUid = 9999 };
    User u = {.username = "ghost",
              .nickname = "G",
              .uid = NonexistentUid,
              .password = "pw"};
    ASSERT_INT_EQ(setTOTPSecret(db, &u, "AAAA"), DB_FAIL);
    dbClose(db);
}

static void testTOTPSecretEncryptedInDB(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    User u = {.username = "encrypted",
              .nickname = "Enc",
              .uid = 0,
              .password = "pw",
              .totpSecret = "JBSWY3DPEHPK3PXP"};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db->handle,
                                "SELECT totp_secret FROM users WHERE uid = ?;",
                                -1, &stmt, NULL);
    ASSERT_INT_EQ(rc, SQLITE_OK);
    rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)u.uid);
    ASSERT_INT_EQ(rc, SQLITE_OK);
    rc = sqlite3_step(stmt);
    ASSERT_INT_EQ(rc, SQLITE_ROW);

    const void *blob = sqlite3_column_blob(stmt, 0);
    int blobLen = sqlite3_column_bytes(stmt, 0);
    ASSERT_TRUE(blob != NULL);
    /* Must be nonce(12) + ciphertext(16) + tag(16) = 44 bytes */
    ASSERT_TRUE(blobLen > 0);
    /* Must NOT equal the plaintext Base32 string */
    ASSERT_TRUE(memcmp(blob, "JBSWY3DPEHPK3PXP", 16) != 0);
    sqlite3_finalize(stmt);
    dbClose(db);
}

static void testTOTPSecretWrongDEKFails(void) {
    removeDBFiles();
    {
        DB *db = testUserDB();
        ASSERT_TRUE(db != NULL);
        User u = {.username = "wrongdek",
                  .nickname = "WD",
                  .uid = 0,
                  .password = "pw",
                  .totpSecret = "JBSWY3DPEHPK3PXP"};
        ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
        dbClose(db);
    }
    {
        DB *db = dbInit(UserDB, NULL);
        ASSERT_TRUE(db != NULL);
        enum { BadDekVal = 0xFF };
        uint8_t badDek[AES_GCM_KEY_LEN];
        memset(badDek, BadDekVal, sizeof(badDek));
        dbSetDekKey(db, badDek);

        User u = {.username = "wrongdek",
                  .nickname = "WD",
                  .uid = 0,
                  .password = "pw",
                  .totpSecret = NULL};
        ASSERT_INT_EQ(verifyUser(db, &u), DB_FAIL);
        dbClose(db);
    }
}

static void testTOTPSecretDEKUnsetFails(void) {
    removeDBFiles();
    {
        DB *db = dbInit(UserDB, NULL);
        ASSERT_TRUE(db != NULL);
        enum { TestDekByte = 0xAA };
        uint8_t customDek[AES_GCM_KEY_LEN];
        memset(customDek, TestDekByte, sizeof(customDek));
        dbSetDekKey(db, customDek);

        User u = {.username = "nodek",
                  .nickname = "ND",
                  .uid = 0,
                  .password = "pw",
                  .totpSecret = "JBSWY3DPEHPK3PXP"};
        ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
        dbClose(db);
    }
    {
        DB *db = dbInit(UserDB, NULL);
        ASSERT_TRUE(db != NULL);
        /* DEK is all-zeros from calloc — different from encrypt DEK */
        User u = {.username = "nodek",
                  .nickname = "ND",
                  .uid = 0,
                  .password = "pw",
                  .totpSecret = NULL};
        ASSERT_INT_EQ(verifyUser(db, &u), DB_FAIL);
        dbClose(db);
    }
}

static void testGetTOTPSecretNoTOTP(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    User u = {.username = "nototpg",
              .nickname = "NT",
              .uid = 0,
              .password = "pw",
              .totpSecret = NULL};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    char *result = getTOTPSecret(db, &u);
    ASSERT_TRUE(result == NULL);
    free(result);
    dbClose(db);
}

static void testGetTOTPSecretNonexistent(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    enum { GhostUid = 88888 };
    User u = {.username = "ghost",
              .nickname = "G",
              .uid = GhostUid,
              .password = "pw",
              .totpSecret = NULL};
    char *result = getTOTPSecret(db, &u);
    ASSERT_TRUE(result == NULL);
    free(result);
    dbClose(db);
}

static void testGetTOTPSecretWithSecret(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    User u = {.username = "withtotp",
              .nickname = "WT",
              .uid = 0,
              .password = "pw",
              .totpSecret = "GEZDGNBVGY3TQOJQ"};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    char *result = getTOTPSecret(db, &u);
    ASSERT_TRUE(result != NULL);
    ASSERT_STR_EQ(result, "GEZDGNBVGY3TQOJQ");
    free(result);
    dbClose(db);
}

/** @brief getCDBKey rejects NULL database. */
static void testGetCDBKeyNullDB(void) {
    uint8_t outKey[DB_ENC_KEY_LEN];
    ASSERT_INT_EQ(getCDBKey(NULL, 1, outKey), DB_FAIL);
}

/** @brief getCDBKey rejects wrong database type. */
static void testGetCDBKeyWrongDBType(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    uint8_t outKey[DB_ENC_KEY_LEN];
    ASSERT_INT_EQ(getCDBKey(db, 1, outKey), DB_FAIL);
    dbClose(db);
}

/** @brief getCDBKey for nonexistent uid returns DB_FAIL. */
static void testGetCDBKeyNonexistentUser(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    enum { GhostUid = 99999 };
    uint8_t outKey[DB_ENC_KEY_LEN];
    ASSERT_INT_EQ(getCDBKey(db, GhostUid, outKey), DB_FAIL);
    dbClose(db);
}

/** @brief getCDBKey basic roundtrip: create user, retrieve key, it is
 *  non-zero and consistent. */
static void testGetCDBKeyBasic(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);

    User u = {.username = "cdbuser",
              .nickname = "CDB",
              .uid = 0,
              .password = "pw",
              .totpSecret = NULL};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    ASSERT_TRUE(u.uid != 0);

    uint8_t outKey[DB_ENC_KEY_LEN];
    ASSERT_INT_EQ(getCDBKey(db, u.uid, outKey), DB_SUCC);

    /* Key must be non-zero */
    static const uint8_t zeros[DB_ENC_KEY_LEN];
    ASSERT_TRUE(memcmp(outKey, zeros, DB_ENC_KEY_LEN) != 0);

    /* Second retrieval must return the same key */
    uint8_t outKey2[DB_ENC_KEY_LEN];
    ASSERT_INT_EQ(getCDBKey(db, u.uid, outKey2), DB_SUCC);
    ASSERT_MEM_EQ(outKey, outKey2, DB_ENC_KEY_LEN);

    OPENSSL_cleanse(outKey, sizeof(outKey));
    OPENSSL_cleanse(outKey2, sizeof(outKey2));
    dbClose(db);
}

/** @brief getCDBKey with wrong DEK fails (decryption auth fail). */
static void testGetCDBKeyWrongDEK(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);

    User u = {.username = "cdbdek",
              .nickname = "DEK",
              .uid = 0,
              .password = "pw",
              .totpSecret = NULL};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    ASSERT_TRUE(u.uid != 0);
    dbClose(db);

    /* Reopen with wrong DEK */
    DB *db2 = dbInit(UserDB, NULL);
    ASSERT_TRUE(db2 != NULL);
    enum { BadDekVal = 0xFF };
    uint8_t badDek[AES_GCM_KEY_LEN];
    memset(badDek, BadDekVal, sizeof(badDek));
    dbSetDekKey(db2, badDek);

    uint8_t outKey[DB_ENC_KEY_LEN];
    ASSERT_INT_EQ(getCDBKey(db2, u.uid, outKey), DB_FAIL);
    dbClose(db2);
}

/** @brief getCDBKey with all-zero DEK (unset) fails. */
static void testGetCDBKeyDEKUnset(void) {
    removeDBFiles();
    {
        DB *db = dbInit(UserDB, NULL);
        ASSERT_TRUE(db != NULL);
        enum { CustomDekByte = 0xCC };
        uint8_t customDek[AES_GCM_KEY_LEN];
        memset(customDek, CustomDekByte, sizeof(customDek));
        dbSetDekKey(db, customDek);

        User u = {.username = "nodekcdb",
                  .nickname = "ND",
                  .uid = 0,
                  .password = "pw",
                  .totpSecret = NULL};
        ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
        dbClose(db);
    }
    {
        /* Reopen without setting DEK → all-zeros from calloc */
        DB *db = dbInit(UserDB, NULL);
        ASSERT_TRUE(db != NULL);
        uint8_t outKey[DB_ENC_KEY_LEN];
        ASSERT_INT_EQ(getCDBKey(db, 1, outKey), DB_FAIL);
        dbClose(db);
    }
}

/** @brief getCDBKey for uid=0 returns DB_FAIL. */
static void testGetCDBKeyUidZero(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    uint8_t outKey[DB_ENC_KEY_LEN];
    ASSERT_INT_EQ(getCDBKey(db, 0, outKey), DB_FAIL);
    dbClose(db);
}

static void testSetServerKeyBasic(void) {
    removeDBFiles();
    DB *db = dbInit(ServerDB, NULL);
    ASSERT_TRUE(db != NULL);

    const uint8_t val[] = {0xDE, 0xAD, 0xBE, 0xEF};
    ASSERT_INT_EQ(setServerKey(db, "signing_key", val, sizeof(val)), DB_SUCC);

    uint8_t *out = NULL;
    size_t outLen = 0;
    ASSERT_INT_EQ(getServerKey(db, "signing_key", &out, &outLen), DB_SUCC);
    ASSERT_UINT_EQ(outLen, sizeof(val));
    ASSERT_MEM_EQ(out, val, sizeof(val));
    free(out);
    dbClose(db);
}

static void testSetServerKeyOverwrite(void) {
    removeDBFiles();
    DB *db = dbInit(ServerDB, NULL);
    ASSERT_TRUE(db != NULL);

    const uint8_t old[] = {0x01, 0x02};
    ASSERT_INT_EQ(setServerKey(db, "overwrite", old, sizeof(old)), DB_SUCC);

    const uint8_t newVal[] = {0xFF, 0xFE};
    ASSERT_INT_EQ(setServerKey(db, "overwrite", newVal, sizeof(newVal)),
                  DB_SUCC);

    uint8_t *out = NULL;
    size_t outLen = 0;
    ASSERT_INT_EQ(getServerKey(db, "overwrite", &out, &outLen), DB_SUCC);
    ASSERT_UINT_EQ(outLen, sizeof(newVal));
    ASSERT_MEM_EQ(out, newVal, sizeof(newVal));
    free(out);
    dbClose(db);
}

static void testSetServerKeyEmptyBlob(void) {
    removeDBFiles();
    DB *db = dbInit(ServerDB, NULL);
    ASSERT_TRUE(db != NULL);

    ASSERT_INT_EQ(setServerKey(db, "empty", NULL, 0), DB_SUCC);

    uint8_t *out = NULL;
    size_t outLen = 0;
    ASSERT_INT_EQ(getServerKey(db, "empty", &out, &outLen), DB_SUCC);
    ASSERT_UINT_EQ(outLen, 0);
    ASSERT_TRUE(out == NULL);
    free(out);
    dbClose(db);
}

static void testGetServerKeyNotFound(void) {
    removeDBFiles();
    DB *db = dbInit(ServerDB, NULL);
    ASSERT_TRUE(db != NULL);

    uint8_t *out = NULL;
    size_t outLen = 0;
    ASSERT_INT_EQ(getServerKey(db, "nonexistent", &out, &outLen), DB_SUCC);
    ASSERT_TRUE(out == NULL);
    ASSERT_UINT_EQ(outLen, 0);
    free(out);
    dbClose(db);
}

static void testSetServerKeyNullDB(void) {
    ASSERT_INT_EQ(setServerKey(NULL, "k", NULL, 0), DB_FAIL);
}

static void testSetServerKeyWrongDBType(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    ASSERT_INT_EQ(setServerKey(db, "k", NULL, 0), DB_FAIL);
    dbClose(db);
}

static void testSetServerKeyEmptyName(void) {
    removeDBFiles();
    DB *db = dbInit(ServerDB, NULL);
    ASSERT_TRUE(db != NULL);
    ASSERT_INT_EQ(setServerKey(db, "", NULL, 0), DB_FAIL);
    dbClose(db);
}

static void testGetServerKeyEmptyName(void) {
    removeDBFiles();
    DB *db = dbInit(ServerDB, NULL);
    ASSERT_TRUE(db != NULL);
    uint8_t *out = NULL;
    size_t outLen = 0;
    ASSERT_INT_EQ(getServerKey(db, "", &out, &outLen), DB_FAIL);
    dbClose(db);
}

/** @brief storeChat: negative timestamp (time_t)-1 works. */
static void testStoreChatTimestampNegative(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    Chat ch = {TestUidAlpha, 0, "neg time", (time_t)-1};
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &ch), DB_SUCC);
    Chat out;
    ASSERT_INT_EQ(queryChatByMsgId(db, RoomTestA, ch.msgId, &out), DB_SUCC);
    ASSERT_INT_EQ(out.timestamp, (time_t)-1);
    free(out.message);
    dbClose(db);
}

/** @brief storeChat: LONG_MAX timestamp works. */
static void testStoreChatTimestampLongMax(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    Chat ch = {TestUidAlpha, 0, "max time", (time_t)LONG_MAX};
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &ch), DB_SUCC);
    Chat out;
    ASSERT_INT_EQ(queryChatByMsgId(db, RoomTestA, ch.msgId, &out), DB_SUCC);
    ASSERT_INT_EQ(out.timestamp, (time_t)LONG_MAX);
    free(out.message);
    dbClose(db);
}

/** @brief storeChat: UINT32_MAX uid works. */
static void testStoreChatUidMax(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    Chat ch = {TestUidMax, 0, "max uid msg", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &ch), DB_SUCC);
    Chat out;
    ASSERT_INT_EQ(queryChatByMsgId(db, RoomTestA, ch.msgId, &out), DB_SUCC);
    ASSERT_UINT_EQ(out.uid, TestUidMax);
    free(out.message);
    dbClose(db);
}

/** @brief msgId is globally unique across 5 different rooms. */
static void testStoreChatCrossRoomUniqueMulti(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    enum { MultiRoomCount = 5 };
    uint64_t msgIds[MultiRoomCount];
    for (uint32_t r = 0; r < MultiRoomCount; r++) {
        Chat ch = {TestUidAlpha, 0, "multi", (time_t)TimeBase};
        ASSERT_INT_EQ(storeChat(db, r, &ch), DB_SUCC);
        msgIds[r] = ch.msgId;
    }
    /* All msgIds must be pairwise distinct */
    for (uint32_t i = 0; i < MultiRoomCount; i++) {
        for (uint32_t j = i + 1; j < MultiRoomCount; j++) {
            ASSERT_TRUE(msgIds[i] != msgIds[j]);
        }
    }
    dbClose(db);
}

/** @brief queryChatByTimeRange handles exactly QUERY_INITIAL_CAPACITY (16)
 * results. */
static void testQueryTimeExactCapacity(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    enum { InitCap = 16, /* matches database.c QUERY_INITIAL_CAPACITY */ };
    enum { ExactCount = InitCap };
    for (int i = 0; i < ExactCount; i++) {
        Chat ch = {TestUidAlpha, 0, "exact cap", (time_t)(TimeBase + i)};
        ASSERT_INT_EQ(storeChat(db, RoomTestA, &ch), DB_SUCC);
    }
    Chat *out = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(queryChatByTimeRange(db, RoomTestA, 0, (time_t)0,
                                       (time_t)TimeBase + ExactCount, &out,
                                       &count),
                  DB_SUCC);
    ASSERT_UINT_EQ(count, (unsigned long long)ExactCount);
    freeChatArray(out, count);
    dbClose(db);
}

/* ══════════════════════ 7b. queryChatByUserAllRooms ═══════════════════════ */

/** @brief queryChatByUserAllRooms rejects NULL database. */
static void testQueryUserAllNullDB(void) {
    Chat *out = (Chat *)(uintptr_t)TestSentinelPtr;
    size_t count = TestCountSentinel;
    ASSERT_INT_EQ(queryChatByUserAllRooms(NULL, TestUidAlpha, (time_t)0,
                                          (time_t)1, &out, &count),
                  DB_FAIL);
    ASSERT_TRUE(out == (Chat *)(uintptr_t)TestSentinelPtr);
    ASSERT_UINT_EQ(count, (unsigned long long)TestCountSentinel);
}

/** @brief queryChatByUserAllRooms rejects NULL out. */
static void testQueryUserAllNullOut(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    size_t count = TestCountSentinel;
    ASSERT_INT_EQ(queryChatByUserAllRooms(db, TestUidAlpha, (time_t)0,
                                          (time_t)1, NULL, &count),
                  DB_FAIL);
    ASSERT_UINT_EQ(count, (unsigned long long)TestCountSentinel);
    dbClose(db);
}

/** @brief queryChatByUserAllRooms rejects NULL count. */
static void testQueryUserAllNullCount(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    Chat *out = (Chat *)(uintptr_t)TestSentinelPtr;
    ASSERT_INT_EQ(queryChatByUserAllRooms(db, TestUidAlpha, (time_t)0,
                                          (time_t)1, &out, NULL),
                  DB_FAIL);
    ASSERT_TRUE(out == (Chat *)(uintptr_t)TestSentinelPtr);
    dbClose(db);
}

/** @brief queryChatByUserAllRooms rejects wrong database type. */
static void testQueryUserAllWrongDBType(void) {
    removeDBFiles();
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    Chat *out = (Chat *)(uintptr_t)TestSentinelPtr;
    size_t count = TestCountSentinel;
    ASSERT_INT_EQ(queryChatByUserAllRooms(db, TestUidAlpha, (time_t)0,
                                          (time_t)1, &out, &count),
                  DB_FAIL);
    ASSERT_TRUE(out == (Chat *)(uintptr_t)TestSentinelPtr);
    ASSERT_UINT_EQ(count, (unsigned long long)TestCountSentinel);
    dbClose(db);
}

/** @brief queryChatByUserAllRooms rejects uid=0. */
static void testQueryUserAllUidZero(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    Chat *out = (Chat *)(uintptr_t)TestSentinelPtr;
    size_t count = TestCountSentinel;
    ASSERT_INT_EQ(
        queryChatByUserAllRooms(db, 0, (time_t)0, (time_t)1, &out, &count),
        DB_FAIL);
    ASSERT_TRUE(out == (Chat *)(uintptr_t)TestSentinelPtr);
    ASSERT_UINT_EQ(count, (unsigned long long)TestCountSentinel);
    dbClose(db);
}

/** @brief queryChatByUserAllRooms: no rooms exist → empty result (SUCC). */
static void testQueryUserAllNoRooms(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    Chat *out = (Chat *)(uintptr_t)TestSentinelPtr;
    size_t count = TestCountSentinel;
    ASSERT_INT_EQ(queryChatByUserAllRooms(db, TestUidAlpha, (time_t)0,
                                          (time_t)1, &out, &count),
                  DB_SUCC);
    ASSERT_UINT_EQ(count, (unsigned long long)0);
    ASSERT_TRUE(out == NULL);
    dbClose(db);
}

/** @brief queryChatByUserAllRooms: rooms exist but no user messages →
 *  empty result. */
static void testQueryUserAllNoMatch(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    /* Store messages for TestUidBravo only */
    Chat ch = {TestUidBravo, 0, "bravo msg", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &ch), DB_SUCC);
    /* Query TestUidAlpha — none of their messages exist */
    Chat *out = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(queryChatByUserAllRooms(db, TestUidAlpha, (time_t)0,
                                          (time_t)TimeBase + TimeOffset5, &out,
                                          &count),
                  DB_SUCC);
    ASSERT_UINT_EQ(count, (unsigned long long)0);
    ASSERT_TRUE(out == NULL);
    dbClose(db);
}

/** @brief queryChatByUserAllRooms: single room — results match
 *  queryChatByTimeRange. */
static void testQueryUserAllSingleRoom(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    /* Store 3 messages from same user in one room */
    Chat ch1 = {TestUidAlpha, 0, "first", (time_t)TimeBase};
    Chat ch2 = {TestUidAlpha, 0, "second", (time_t)(TimeBase + TimeOffset1)};
    Chat ch3 = {TestUidAlpha, 0, "third", (time_t)(TimeBase + TimeOffset2)};
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &ch1), DB_SUCC);
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &ch2), DB_SUCC);
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &ch3), DB_SUCC);

    Chat *outAll = NULL;
    size_t countAll = 0;
    ASSERT_INT_EQ(queryChatByUserAllRooms(db, TestUidAlpha, (time_t)0,
                                          (time_t)TimeBase + TimeOffset5,
                                          &outAll, &countAll),
                  DB_SUCC);
    ASSERT_UINT_EQ(countAll, (unsigned long long)3);

    /* Compare with per-room query */
    Chat *outRoom = NULL;
    size_t countRoom = 0;
    ASSERT_INT_EQ(queryChatByTimeRange(db, RoomTestA, TestUidAlpha, (time_t)0,
                                       (time_t)TimeBase + TimeOffset5, &outRoom,
                                       &countRoom),
                  DB_SUCC);
    ASSERT_UINT_EQ(countRoom, (unsigned long long)3);
    ASSERT_UINT_EQ(outAll[0].msgId, outRoom[0].msgId);
    ASSERT_UINT_EQ(outAll[1].msgId, outRoom[1].msgId);
    ASSERT_UINT_EQ(outAll[2].msgId, outRoom[2].msgId);

    freeChatArray(outAll, countAll);
    freeChatArray(outRoom, countRoom);
    dbClose(db);
}

/** @brief queryChatByUserAllRooms: multiple rooms — aggregates all user
 *  messages. */
static void testQueryUserAllMultiRoom(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    /* Store TestUidAlpha messages in 3 different rooms */
    Chat chA = {TestUidAlpha, 0, "room-A", (time_t)(TimeBase)};
    Chat chB = {TestUidAlpha, 0, "room-B", (time_t)(TimeBase)};
    Chat chC = {TestUidAlpha, 0, "room-C", (time_t)(TimeBase)};
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &chA), DB_SUCC);
    ASSERT_INT_EQ(storeChat(db, RoomTestB, &chB), DB_SUCC);
    ASSERT_INT_EQ(storeChat(db, RoomTestC, &chC), DB_SUCC);

    Chat *out = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(queryChatByUserAllRooms(db, TestUidAlpha, (time_t)0,
                                          (time_t)TimeBase + TimeOffset5, &out,
                                          &count),
                  DB_SUCC);
    ASSERT_UINT_EQ(count, (unsigned long long)3);
    /* All uids must be TestUidAlpha */
    for (size_t i = 0; i < count; i++) {
        ASSERT_UINT_EQ(out[i].uid, TestUidAlpha);
    }
    /* At least one message from each room should be present */
    enum { ExpectedMatchCount = 3 };
    int match = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(out[i].message, "room-A") == 0 ||
            strcmp(out[i].message, "room-B") == 0 ||
            strcmp(out[i].message, "room-C") == 0) {
            match++;
        }
    }
    ASSERT_INT_EQ(match, ExpectedMatchCount);
    freeChatArray(out, count);
    dbClose(db);
}

/** @brief queryChatByUserAllRooms: only target user's messages; other
 *  users' are excluded. */
static void testQueryUserAllUidIsolation(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    /* Interleave messages from 3 users across 2 rooms */
    Chat chA1 = {TestUidAlpha, 0, "A-room1", (time_t)TimeBase};
    Chat chA2 = {TestUidAlpha, 0, "A-room2", (time_t)TimeBase};
    Chat chB1 = {TestUidBravo, 0, "B-room1", (time_t)TimeBase};
    Chat chC1 = {TestUidCharlie, 0, "C-room1", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &chA1), DB_SUCC);
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &chB1), DB_SUCC);
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &chC1), DB_SUCC);
    ASSERT_INT_EQ(storeChat(db, RoomTestB, &chA2), DB_SUCC);

    Chat *out = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(queryChatByUserAllRooms(db, TestUidAlpha, (time_t)0,
                                          (time_t)TimeBase + TimeOffset5, &out,
                                          &count),
                  DB_SUCC);
    ASSERT_UINT_EQ(count, (unsigned long long)2);
    enum { RoomPrefixLen = 5 };
    for (size_t i = 0; i < count; i++) {
        ASSERT_UINT_EQ(out[i].uid, TestUidAlpha);
        ASSERT_TRUE(strncmp(out[i].message, "A-room", (size_t)RoomPrefixLen) ==
                    0);
    }
    freeChatArray(out, count);
    dbClose(db);
}

/** @brief queryChatByUserAllRooms: results sorted globally by msgId ASC. */
static void testQueryUserAllOrdering(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    /* Store messages across rooms in non-ordered room sequence */
    Chat ch1 = {TestUidAlpha, 0, "m1", (time_t)(TimeBase + TimeOffset3)};
    Chat ch2 = {TestUidAlpha, 0, "m2", (time_t)(TimeBase + TimeOffset1)};
    Chat ch3 = {TestUidAlpha, 0, "m3", (time_t)(TimeBase + TimeOffset2)};
    ASSERT_INT_EQ(storeChat(db, RoomTestB, &ch1), DB_SUCC);
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &ch2), DB_SUCC);
    ASSERT_INT_EQ(storeChat(db, RoomTestC, &ch3), DB_SUCC);

    Chat *out = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(queryChatByUserAllRooms(db, TestUidAlpha, (time_t)0,
                                          (time_t)TimeBase + TimeOffset5, &out,
                                          &count),
                  DB_SUCC);
    ASSERT_UINT_EQ(count, (unsigned long long)3);
    /* msgId must be strictly ascending */
    ASSERT_TRUE(out[0].msgId < out[1].msgId);
    ASSERT_TRUE(out[1].msgId < out[2].msgId);
    freeChatArray(out, count);
    dbClose(db);
}

/** @brief queryChatByUserAllRooms: time range filters correctly. */
static void testQueryUserAllTimeRange(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    Chat inside = {TestUidAlpha, 0, "inside", (time_t)(TimeBase + TimeOffset1)};
    Chat before = {TestUidAlpha, 0, "before",
                   (time_t)(TimeBase - TimeSecsPerDay)};
    Chat after = {TestUidAlpha, 0, "after",
                  (time_t)(TimeBase + TimeSecsPerDay)};
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &inside), DB_SUCC);
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &before), DB_SUCC);
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &after), DB_SUCC);

    Chat *out = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(queryChatByUserAllRooms(db, TestUidAlpha, (time_t)TimeBase,
                                          (time_t)(TimeBase + TimeOffset5),
                                          &out, &count),
                  DB_SUCC);
    ASSERT_UINT_EQ(count, (unsigned long long)1);
    ASSERT_STR_EQ(out[0].message, "inside");
    freeChatArray(out, count);
    dbClose(db);
}

/** @brief queryChatByUserAllRooms: startTime == endTime (single-point). */
static void testQueryUserAllEqualRange(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    Chat exact = {TestUidAlpha, 0, "exact", (time_t)TimeBase};
    Chat near = {TestUidAlpha, 0, "near", (time_t)(TimeBase + TimeOffset1)};
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &exact), DB_SUCC);
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &near), DB_SUCC);

    Chat *out = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(queryChatByUserAllRooms(db, TestUidAlpha, (time_t)TimeBase,
                                          (time_t)TimeBase, &out, &count),
                  DB_SUCC);
    ASSERT_UINT_EQ(count, (unsigned long long)1);
    ASSERT_STR_EQ(out[0].message, "exact");
    freeChatArray(out, count);
    dbClose(db);
}

/** @brief queryChatByUserAllRooms: startTime > endTime → empty result. */
static void testQueryUserAllInvertedRange(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    Chat ch = {TestUidAlpha, 0, "msg", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &ch), DB_SUCC);

    Chat *out = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(queryChatByUserAllRooms(
                      db, TestUidAlpha, (time_t)(TimeBase + TimeOffset2),
                      (time_t)(TimeBase + TimeOffset1), &out, &count),
                  DB_SUCC);
    ASSERT_UINT_EQ(count, (unsigned long long)0);
    ASSERT_TRUE(out == NULL);
    dbClose(db);
}

/** @brief queryChatByUserAllRooms: message in matching time range but
 *  different room — must be found. */
static void testQueryUserAllCrossRoomTimeMatch(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    Chat chA = {TestUidAlpha, 0, "roomA-ts1", (time_t)(TimeBase + TimeOffset1)};
    Chat chB = {TestUidAlpha, 0, "roomB-ts2", (time_t)(TimeBase + TimeOffset2)};
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &chA), DB_SUCC);
    ASSERT_INT_EQ(storeChat(db, RoomTestB, &chB), DB_SUCC);

    /* Range covers both */
    Chat *out = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(queryChatByUserAllRooms(db, TestUidAlpha, (time_t)TimeBase,
                                          (time_t)(TimeBase + TimeOffset5),
                                          &out, &count),
                  DB_SUCC);
    ASSERT_UINT_EQ(count, (unsigned long long)2);
    freeChatArray(out, count);
    dbClose(db);
}

/** @brief queryChatByUserAllRooms: large number of messages across rooms. */
static void testQueryUserAllManyMessages(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    enum { MsgPerRoom = 20, RoomCount = 3, TotalMsgs = MsgPerRoom * RoomCount };
    for (uint32_t r = 0; r < RoomCount; r++) {
        for (int m = 0; m < MsgPerRoom; m++) {
            Chat ch = {TestUidAlpha, 0, "bulk", (time_t)(TimeBase + m)};
            ASSERT_INT_EQ(storeChat(db, r, &ch), DB_SUCC);
        }
    }
    Chat *out = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(queryChatByUserAllRooms(db, TestUidAlpha, (time_t)0,
                                          (time_t)(TimeBase + MsgPerRoom), &out,
                                          &count),
                  DB_SUCC);
    ASSERT_UINT_EQ(count, (unsigned long long)TotalMsgs);
    /* Verify all messages have non-NULL payload and correct uid */
    for (size_t i = 0; i < count; i++) {
        ASSERT_TRUE(out[i].message != NULL);
        ASSERT_UINT_EQ(out[i].uid, TestUidAlpha);
    }
    /* Global msgId ordering */
    for (size_t i = 1; i < count; i++) {
        ASSERT_TRUE(out[i - 1].msgId < out[i].msgId);
    }
    freeChatArray(out, count);
    dbClose(db);
}

/** @brief queryChatByUserAllRooms: output is correctly set on success
 *  even when results exist. */
static void testQueryUserAllOutputSetOnSuccess(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    Chat ch = {TestUidAlpha, 0, "msg", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &ch), DB_SUCC);

    Chat *out = (Chat *)(uintptr_t)TestSentinelPtr;
    size_t count = TestCountSentinel;
    ASSERT_INT_EQ(queryChatByUserAllRooms(db, TestUidAlpha, (time_t)0,
                                          (time_t)TimeBase + TimeOffset5, &out,
                                          &count),
                  DB_SUCC);
    ASSERT_TRUE(out != NULL);
    ASSERT_TRUE(out != (Chat *)(uintptr_t)TestSentinelPtr);
    ASSERT_UINT_EQ(count, (unsigned long long)1);
    ASSERT_STR_EQ(out[0].message, "msg");
    freeChatArray(out, count);
    dbClose(db);
}

/** @brief queryChatByUserAllRooms: roomId=0 and roomId=UINT32_MAX rooms
 *  are discoverable. */
static void testQueryUserAllRoomIdBoundaries(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    enum { RoomZero = 0 };
    Chat chZero = {TestUidAlpha, 0, "rm-zero", (time_t)TimeBase};
    Chat chMax = {TestUidAlpha, 0, "rm-max", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChat(db, RoomZero, &chZero), DB_SUCC);
    ASSERT_INT_EQ(storeChat(db, RoomMaxVal, &chMax), DB_SUCC);

    Chat *out = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(queryChatByUserAllRooms(db, TestUidAlpha, (time_t)0,
                                          (time_t)TimeBase + TimeOffset5, &out,
                                          &count),
                  DB_SUCC);
    ASSERT_UINT_EQ(count, (unsigned long long)2);
    enum { ExpectedMatchCount = 2 };
    int match = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(out[i].message, "rm-zero") == 0 ||
            strcmp(out[i].message, "rm-max") == 0) {
            match++;
        }
    }
    ASSERT_INT_EQ(match, ExpectedMatchCount);
    freeChatArray(out, count);
    dbClose(db);
}

/** @brief queryChatByUserAllRooms: empty message text is not stored but
 *  if other rooms have data, result is correct. */
static void testQueryUserAllOneRoomEmpty(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    /* Room A has messages, Room B has none (table never created) */
    Chat chA = {TestUidAlpha, 0, "only-roomA", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &chA), DB_SUCC);

    Chat *out = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(queryChatByUserAllRooms(db, TestUidAlpha, (time_t)0,
                                          (time_t)TimeBase + TimeOffset5, &out,
                                          &count),
                  DB_SUCC);
    ASSERT_UINT_EQ(count, (unsigned long long)1);
    ASSERT_STR_EQ(out[0].message, "only-roomA");
    freeChatArray(out, count);
    dbClose(db);
}

/** @brief queryChatByUserAllRooms: handles multiple users simultaneously
 *  querying across rooms without cross-contamination. */
static void testQueryUserAllMultiUserCrossRoom(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    /* Alice in rooms A and B; Bob in room B only */
    Chat aA = {TestUidAlpha, 0, "A-in-A", (time_t)TimeBase};
    Chat aB = {TestUidAlpha, 0, "A-in-B", (time_t)TimeBase};
    Chat bB = {TestUidBravo, 0, "B-in-B", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &aA), DB_SUCC);
    ASSERT_INT_EQ(storeChat(db, RoomTestB, &aB), DB_SUCC);
    ASSERT_INT_EQ(storeChat(db, RoomTestB, &bB), DB_SUCC);

    /* Alice's query */
    Chat *outA = NULL;
    size_t countA = 0;
    ASSERT_INT_EQ(queryChatByUserAllRooms(db, TestUidAlpha, (time_t)0,
                                          (time_t)TimeBase + TimeOffset5, &outA,
                                          &countA),
                  DB_SUCC);
    ASSERT_UINT_EQ(countA, (unsigned long long)2);
    for (size_t i = 0; i < countA; i++) {
        ASSERT_UINT_EQ(outA[i].uid, TestUidAlpha);
        ASSERT_TRUE(strstr(outA[i].message, "A-in") == outA[i].message);
    }
    freeChatArray(outA, countA);

    /* Bob's query */
    Chat *outB = NULL;
    size_t countB = 0;
    ASSERT_INT_EQ(queryChatByUserAllRooms(db, TestUidBravo, (time_t)0,
                                          (time_t)TimeBase + TimeOffset5, &outB,
                                          &countB),
                  DB_SUCC);
    ASSERT_UINT_EQ(countB, (unsigned long long)1);
    ASSERT_UINT_EQ(outB[0].uid, TestUidBravo);
    ASSERT_STR_EQ(outB[0].message, "B-in-B");
    freeChatArray(outB, countB);
    dbClose(db);
}

/**
 * @brief Hash table collision: rooms with the same bucket index work
 * independently via the chained-list lookup.
 */
static void testRoomStmtCacheCollision(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    /* room 0 and ROOM_STMT_BUCKETS share bucket index 0 */
    enum { CollideA = 0, CollideB = ROOM_STMT_BUCKETS };
    Chat chA = {TestUidAlpha, 0, "room A", (time_t)TimeBase};
    Chat chB = {TestUidBravo, 0, "room B", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChat(db, CollideA, &chA), DB_SUCC);
    ASSERT_INT_EQ(storeChat(db, CollideB, &chB), DB_SUCC);
    /* Both independently retrievable */
    Chat outA, outB;
    ASSERT_INT_EQ(queryChatByMsgId(db, CollideA, chA.msgId, &outA), DB_SUCC);
    ASSERT_INT_EQ(queryChatByMsgId(db, CollideB, chB.msgId, &outB), DB_SUCC);
    ASSERT_STR_EQ(outA.message, "room A");
    ASSERT_STR_EQ(outB.message, "room B");
    ASSERT_UINT_EQ(outA.uid, TestUidAlpha);
    ASSERT_UINT_EQ(outB.uid, TestUidBravo);
    free(outA.message);
    free(outB.message);
    /* Time range query also respects room isolation */
    Chat *arr = NULL;
    size_t n = 0;
    ASSERT_INT_EQ(queryChatByTimeRange(db, CollideA, 0, (time_t)0,
                                       (time_t)TimeBase + TimeOffset5, &arr,
                                       &n),
                  DB_SUCC);
    ASSERT_UINT_EQ(n, (unsigned long long)1);
    ASSERT_STR_EQ(arr[0].message, "room A");
    freeChatArray(arr, n);
    dbClose(db);
}

/**
 * @brief Verify that room tables and msg_sequence are actually created in
 * the database with correct names.
 */
static void testChatSchemaExists(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    /* Store a message which triggers room table creation */
    Chat ch = {TestUidAlpha, 0, "schema", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChat(db, RoomTestA, &ch), DB_SUCC);
    /* Verify msg_sequence exists */
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(
        db->handle,
        "SELECT name FROM sqlite_master WHERE type='table' AND "
        "name='msg_sequence';",
        -1, &stmt, NULL);
    ASSERT_INT_EQ(rc, SQLITE_OK);
    rc = sqlite3_step(stmt);
    ASSERT_INT_EQ(rc, SQLITE_ROW);
    sqlite3_finalize(stmt);
    /* Verify room_1 table exists */
    rc = sqlite3_prepare_v2(
        db->handle,
        "SELECT name FROM sqlite_master WHERE type='table' AND "
        "name='room_1';",
        -1, &stmt, NULL);
    ASSERT_INT_EQ(rc, SQLITE_OK);
    rc = sqlite3_step(stmt);
    ASSERT_INT_EQ(rc, SQLITE_ROW);
    sqlite3_finalize(stmt);
    /* Verify index on room_1 exists */
    rc = sqlite3_prepare_v2(
        db->handle,
        "SELECT name FROM sqlite_master WHERE type='index' AND "
        "tbl_name='room_1';",
        -1, &stmt, NULL);
    ASSERT_INT_EQ(rc, SQLITE_OK);
    rc = sqlite3_step(stmt);
    ASSERT_INT_EQ(rc, SQLITE_ROW);
    sqlite3_finalize(stmt);
    dbClose(db);
}

/* ═════════════════════ GameDB: room persistence tests ═════════════════════ */

static void testGameDbInitBasic(void) {
    DB *db = dbInit(GameDB, NULL);
    ASSERT_TRUE(db != NULL);
    ASSERT_INT_EQ(db->type, GameDB);
    dbClose(db);
}

static void testGameDbInitInvalidType(void) {
    DB *db = dbInit((DBType)(-1), NULL);
    ASSERT_TRUE(db == NULL);
}

static void testCreateRoomBasic(void) {
    DB *db = dbInit(GameDB, NULL);
    ASSERT_TRUE(db != NULL);

    ASSERT_INT_EQ(createRoom(db, 1001, 42), DB_SUCC);
    ASSERT_INT_EQ(roomExists(db, 1001), DB_SUCC);

    dbClose(db);
}

static void testCreateRoomDuplicateRejected(void) {
    DB *db = dbInit(GameDB, NULL);
    ASSERT_TRUE(db != NULL);

    ASSERT_INT_EQ(createRoom(db, 2001, 42), DB_SUCC);
    ASSERT_INT_EQ(createRoom(db, 2001, 99), DB_FAIL);

    dbClose(db);
}

static void testCreateRoomNullDB(void) {
    ASSERT_INT_EQ(createRoom(NULL, 1001, 42), DB_FAIL);
}

static void testCreateRoomWrongDBType(void) {
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    ASSERT_INT_EQ(createRoom(db, 1001, 42), DB_FAIL);
    dbClose(db);
}

static void testCreateRoomIdZero(void) {
    DB *db = dbInit(GameDB, NULL);
    ASSERT_TRUE(db != NULL);
    ASSERT_INT_EQ(createRoom(db, 0, 42), DB_FAIL);
    dbClose(db);
}

static void testDeleteRoomBasic(void) {
    DB *db = dbInit(GameDB, NULL);
    ASSERT_TRUE(db != NULL);

    ASSERT_INT_EQ(createRoom(db, 3001, 42), DB_SUCC);
    ASSERT_INT_EQ(deleteRoom(db, 3001), DB_SUCC);
    ASSERT_INT_EQ(roomExists(db, 3001), DB_FAIL);

    dbClose(db);
}

static void testDeleteRoomNonexistent(void) {
    DB *db = dbInit(GameDB, NULL);
    ASSERT_TRUE(db != NULL);

    ASSERT_INT_EQ(deleteRoom(db, 9999), DB_FAIL);

    dbClose(db);
}

static void testListRoomsEmpty(void) {
    removeDBFiles();
    DB *db = dbInit(GameDB, NULL);
    ASSERT_TRUE(db != NULL);

    uint32_t *ids = (uint32_t *)(uintptr_t)1;
    size_t count = 1;
    int ret = listRooms(db, &ids, &count);
    ASSERT_INT_EQ(ret, DB_SUCC);
    ASSERT_UINT_EQ(count, (size_t)0);
    ASSERT_TRUE(ids == NULL);

    dbClose(db);
}

static void testListRoomsSingle(void) {
    removeDBFiles();
    DB *db = dbInit(GameDB, NULL);
    ASSERT_TRUE(db != NULL);

    ASSERT_INT_EQ(createRoom(db, 4001, 42), DB_SUCC);

    uint32_t *ids = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(listRooms(db, &ids, &count), DB_SUCC);
    ASSERT_UINT_EQ(count, (size_t)1);
    ASSERT_UINT_EQ(ids[0], (uint32_t)4001);
    free(ids);

    dbClose(db);
}

static void testListRoomsMultiple(void) {
    removeDBFiles();
    DB *db = dbInit(GameDB, NULL);
    ASSERT_TRUE(db != NULL);

    ASSERT_INT_EQ(createRoom(db, 5001, 42), DB_SUCC);
    ASSERT_INT_EQ(createRoom(db, 5003, 42), DB_SUCC);
    ASSERT_INT_EQ(createRoom(db, 5002, 42), DB_SUCC);

    uint32_t *ids = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(listRooms(db, &ids, &count), DB_SUCC);
    ASSERT_UINT_EQ(count, (size_t)3);
    /* Verify sorted order */
    ASSERT_UINT_EQ(ids[0], (uint32_t)5001);
    ASSERT_UINT_EQ(ids[1], (uint32_t)5002);
    ASSERT_UINT_EQ(ids[2], (uint32_t)5003);
    free(ids);

    dbClose(db);
}

static void testListRoomsNullOut(void) {
    DB *db = dbInit(GameDB, NULL);
    ASSERT_TRUE(db != NULL);
    ASSERT_INT_EQ(listRooms(db, NULL, NULL), DB_FAIL);
    dbClose(db);
}

static void testListRoomsWrongDBType(void) {
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    uint32_t *ids = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(listRooms(db, &ids, &count), DB_FAIL);
    dbClose(db);
}

static void testRoomExistsBasic(void) {
    DB *db = dbInit(GameDB, NULL);
    ASSERT_TRUE(db != NULL);

    ASSERT_INT_EQ(createRoom(db, 6001, 42), DB_SUCC);
    ASSERT_INT_EQ(roomExists(db, 6001), DB_SUCC);

    dbClose(db);
}

static void testRoomExistsNotFound(void) {
    DB *db = dbInit(GameDB, NULL);
    ASSERT_TRUE(db != NULL);

    ASSERT_INT_EQ(roomExists(db, 9999), DB_FAIL);
    ASSERT_INT_EQ(roomExists(db, 0), DB_FAIL);

    dbClose(db);
}

static void testCreateDeleteRecreate(void) {
    DB *db = dbInit(GameDB, NULL);
    ASSERT_TRUE(db != NULL);

    ASSERT_INT_EQ(createRoom(db, 7001, 42), DB_SUCC);
    ASSERT_INT_EQ(deleteRoom(db, 7001), DB_SUCC);
    ASSERT_INT_EQ(createRoom(db, 7001, 99), DB_SUCC);
    ASSERT_INT_EQ(roomExists(db, 7001), DB_SUCC);

    dbClose(db);
}

/** @brief deleteRoom rejects NULL database. */
static void testDeleteRoomNullDB(void) {
    ASSERT_INT_EQ(deleteRoom(NULL, 1001), DB_FAIL);
}

/** @brief deleteRoom rejects wrong database type (UserDB). */
static void testDeleteRoomWrongDBType(void) {
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    ASSERT_INT_EQ(deleteRoom(db, 1001), DB_FAIL);
    dbClose(db);
}

/** @brief Deleting same room twice fails on second attempt. */
static void testDeleteRoomTwice(void) {
    DB *db = dbInit(GameDB, NULL);
    ASSERT_TRUE(db != NULL);
    ASSERT_INT_EQ(createRoom(db, 8001, 42), DB_SUCC);
    ASSERT_INT_EQ(deleteRoom(db, 8001), DB_SUCC);
    ASSERT_INT_EQ(deleteRoom(db, 8001), DB_FAIL);
    dbClose(db);
}

/** @brief roomExists rejects NULL database. */
static void testRoomExistsNullDB(void) {
    ASSERT_INT_EQ(roomExists(NULL, 1001), DB_FAIL);
}

/** @brief roomExists rejects wrong database type (UserDB). */
static void testRoomExistsWrongDBType(void) {
    DB *db = testUserDB();
    ASSERT_TRUE(db != NULL);
    ASSERT_INT_EQ(roomExists(db, 1001), DB_FAIL);
    dbClose(db);
}

/** @brief RoomExists returns DB_FAIL for deleted room. */
static void testRoomExistsAfterDelete(void) {
    DB *db = dbInit(GameDB, NULL);
    ASSERT_TRUE(db != NULL);
    ASSERT_INT_EQ(createRoom(db, 9001, 42), DB_SUCC);
    ASSERT_INT_EQ(deleteRoom(db, 9001), DB_SUCC);
    ASSERT_INT_EQ(roomExists(db, 9001), DB_FAIL);
    dbClose(db);
}

/** @brief GameDB persists rooms across close and reopen. */
static void testGameDBPersistence(void) {
    removeDBFiles();
    DB *db = dbInit(GameDB, NULL);
    ASSERT_TRUE(db != NULL);
    ASSERT_INT_EQ(createRoom(db, 11001, 42), DB_SUCC);
    ASSERT_INT_EQ(createRoom(db, 11002, 99), DB_SUCC);
    dbClose(db);

    DB *db2 = dbInit(GameDB, NULL);
    ASSERT_TRUE(db2 != NULL);
    ASSERT_INT_EQ(roomExists(db2, 11001), DB_SUCC);
    ASSERT_INT_EQ(roomExists(db2, 11002), DB_SUCC);
    ASSERT_INT_EQ(roomExists(db2, 9999), DB_FAIL);
    dbClose(db2);
}

/** @brief createRoom fails on ChatHistoryDB (cross-type misuse). */
static void testCreateRoomOnChatHistoryDB(void) {
    DB *db = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(db != NULL);
    ASSERT_INT_EQ(createRoom(db, 1001, 42), DB_FAIL);
    dbClose(db);
}

/** @brief listRooms reflects deletions. */
static void testListRoomsAfterDelete(void) {
    removeDBFiles();
    DB *db = dbInit(GameDB, NULL);
    ASSERT_TRUE(db != NULL);
    ASSERT_INT_EQ(createRoom(db, 12001, 42), DB_SUCC);
    ASSERT_INT_EQ(createRoom(db, 12002, 99), DB_SUCC);
    ASSERT_INT_EQ(createRoom(db, 12003, 42), DB_SUCC);
    ASSERT_INT_EQ(deleteRoom(db, 12002), DB_SUCC);
    uint32_t *ids = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(listRooms(db, &ids, &count), DB_SUCC);
    ASSERT_UINT_EQ(count, (size_t)2);
    ASSERT_UINT_EQ(ids[0], (uint32_t)12001);
    ASSERT_UINT_EQ(ids[1], (uint32_t)12003);
    free(ids);
    dbClose(db);
}

/** @brief listRooms triggers realloc when exceeding QUERY_INITIAL_CAPACITY. */
static void testListRoomsReallocTrigger(void) {
    removeDBFiles();
    DB *db = dbInit(GameDB, NULL);
    ASSERT_TRUE(db != NULL);
    enum { RoomCount = 20, BaseRoomRealloc = 13001 };
    for (uint32_t i = 0; i < RoomCount; i++) {
        ASSERT_INT_EQ(createRoom(db, BaseRoomRealloc + i, 42), DB_SUCC);
    }
    uint32_t *ids = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(listRooms(db, &ids, &count), DB_SUCC);
    ASSERT_UINT_EQ(count, (size_t)RoomCount);
    for (size_t i = 0; i < RoomCount; i++) {
        ASSERT_UINT_EQ(ids[i], BaseRoomRealloc + (uint32_t)i);
    }
    free(ids);
    dbClose(db);
}

/* ═════════════════════════════ dbEncKey tests ═════════════════════════════ */

/** @brief DB_ENC_KEY_LEN must be 256-bit (32 bytes). */
static void testDbEncKeyLen(void) { ASSERT_UINT_EQ(DB_ENC_KEY_LEN, 32U); }

/** @brief dbSetDbEncKey(NULL, ...) is a safe no-op. */
static void testDbSetDbEncKeyNullDB(void) {
    enum { TestByte = 0xAA };
    uint8_t dummy[DB_ENC_KEY_LEN];
    memset(dummy, TestByte, sizeof(dummy));
    dbSetDbEncKey(NULL, dummy); /* must not crash */
}

/** @brief dbSetDbEncKey(db, NULL) zeros the dbEncKey field. */
static void testDbSetDbEncKeyNullKey(void) {
    removeDBFiles();
    DB *db = dbInit(UserDB, NULL);
    ASSERT_TRUE(db != NULL);

    enum { FillByte = 0xCC };
    uint8_t key[DB_ENC_KEY_LEN];
    memset(key, FillByte, sizeof(key));
    dbSetDbEncKey(db, key);
    dbSetDbEncKey(db, NULL);

    static const uint8_t zeros[DB_ENC_KEY_LEN];
    ASSERT_MEM_EQ(db->dbEncKey, zeros, DB_ENC_KEY_LEN);
    dbClose(db);
}

/** @brief dbSetDbEncKey correctly copies a key into the handle. */
static void testDbSetDbEncKeyBasic(void) {
    removeDBFiles();
    DB *db = dbInit(UserDB, NULL);
    ASSERT_TRUE(db != NULL);

    uint8_t key[DB_ENC_KEY_LEN];
    enum { FirstByte = 0xDE, SecondByte = 0xAD, MaskByte = 0xFFU };
    key[0] = FirstByte;
    key[1] = SecondByte;
    for (size_t i = 2; i < DB_ENC_KEY_LEN; i++) {
        key[i] = (uint8_t)(i & MaskByte);
    }
    dbSetDbEncKey(db, key);
    ASSERT_MEM_EQ(db->dbEncKey, key, DB_ENC_KEY_LEN);
    dbClose(db);
}

/** @brief dbInit passes encKey through to dbEncKey (non-NULL and NULL). */
static void testDbInitEncKeyParam(void) {
    removeDBFiles();
    uint8_t key[DB_ENC_KEY_LEN];
    enum { NonZeroByte = 0x5A };
    memset(key, NonZeroByte, sizeof(key));

    /* Non-NULL key */
    DB *db1 = dbInit(UserDB, key);
    ASSERT_TRUE(db1 != NULL);
    ASSERT_MEM_EQ(db1->dbEncKey, key, DB_ENC_KEY_LEN);
    dbClose(db1);

    /* NULL key (dbEncKey stays zero from calloc)
     * Note: re-create the DB since the previous call encrypted it. */
    removeDBFiles();
    DB *db2 = dbInit(UserDB, NULL);
    ASSERT_TRUE(db2 != NULL);
    static const uint8_t zeros[DB_ENC_KEY_LEN];
    ASSERT_MEM_EQ(db2->dbEncKey, zeros, DB_ENC_KEY_LEN);
    dbClose(db2);
}

/* ══════════════════════════════════ main ══════════════════════════════════ */

int main(void) {
    /* Suppress expected error logs from adversarial tests */
    logSetLevel(LogLevelFatal);

    printf("test_database:\n");

    /* ─────────────────────────────── lifecycle
     * ──────────────────────────────── */
    RUN_TEST(testDbInitInvalidType);
    RUN_TEST(testDbInitUserDB);
    RUN_TEST(testDbInitChatHistoryDB);
    RUN_TEST(testDbCloseNull);
    RUN_TEST(testDbInitCreatesDir);
    RUN_TEST(testDbInitMultipleHandles);

    /* ─────────────────────────────── createUser
     * ─────────────────────────────── */
    RUN_TEST(testCreateUserNullDB);
    RUN_TEST(testCreateUserNullUser);
    RUN_TEST(testCreateUserEmptyUsername);
    RUN_TEST(testCreateUserEmptyNickname);
    RUN_TEST(testCreateUserNullPassword);
    RUN_TEST(testCreateUserEmptyPassword);
    RUN_TEST(testCreateUserWrongDBType);
    RUN_TEST(testCreateUserBasic);
    RUN_TEST(testCreateUserDuplicateUID);
    RUN_TEST(testCreateUserDuplicateUsername);
    RUN_TEST(testCreateUserMaxLenUsername);
    RUN_TEST(testCreateUserMaxLenNickname);
    RUN_TEST(testCreateUserUidZero);
    RUN_TEST(testCreateUserUidMax);
    RUN_TEST(testCreateUserMultipleUniqueUids);
    RUN_TEST(testCreateUserSpecialCharsPassword);
    RUN_TEST(testCreateUserLongPassword);

    /* ─────────────────────────────── deleteUser
     * ─────────────────────────────── */
    RUN_TEST(testDeleteUserNullDB);
    RUN_TEST(testDeleteUserNullUser);
    RUN_TEST(testDeleteUserWrongDBType);
    RUN_TEST(testDeleteUserNonexistent);
    RUN_TEST(testDeleteUserBasic);
    RUN_TEST(testDeleteUserTwice);
    RUN_TEST(testDeleteUserUidZero);
    RUN_TEST(testDeleteUserUidMax);

    /* ─────────────────────────────── verifyUser
     * ─────────────────────────────── */
    RUN_TEST(testVerifyUserNullDB);
    RUN_TEST(testVerifyUserNullUser);
    RUN_TEST(testVerifyUserEmptyUsername);
    RUN_TEST(testVerifyUserNullPassword);
    RUN_TEST(testVerifyUserEmptyPassword);
    RUN_TEST(testVerifyUserWrongDBType);
    RUN_TEST(testVerifyUserNonexistent);
    RUN_TEST(testVerifyUserWrongPassword);
    RUN_TEST(testVerifyUserWrongUsername);
    RUN_TEST(testVerifyUserWrongUID);
    RUN_TEST(testVerifyUserBasic);
    RUN_TEST(testVerifyUserAfterDelete);
    RUN_TEST(testVerifyUserNoEnumeration);
    RUN_TEST(testVerifyUserSimilarPassword);
    RUN_TEST(testVerifyUserUidZero);
    RUN_TEST(testVerifyUserUidConsistency);
    RUN_TEST(testCreateUserWithTotpSecret);
    RUN_TEST(testCreateUserTotpSecretNull);
    RUN_TEST(testTotpSecretPersistence);
    RUN_TEST(testSetTotpSecretBasic);
    RUN_TEST(testSetTotpSecretOverwrite);
    RUN_TEST(testSetTotpSecretClear);
    RUN_TEST(testSetTotpSecretClearEmpty);
    RUN_TEST(testSetTotpSecretNullDB);
    RUN_TEST(testSetTotpSecretWrongDBType);
    RUN_TEST(testSetTotpSecretNonexistentUser);
    RUN_TEST(testTOTPSecretEncryptedInDB);
    RUN_TEST(testTOTPSecretWrongDEKFails);
    RUN_TEST(testTOTPSecretDEKUnsetFails);
    RUN_TEST(testGetTOTPSecretNoTOTP);
    RUN_TEST(testGetTOTPSecretNonexistent);
    RUN_TEST(testGetTOTPSecretWithSecret);

    /* ────────────────────────────── getCDBKey
     * ─────────────────────────────── */
    RUN_TEST(testGetCDBKeyNullDB);
    RUN_TEST(testGetCDBKeyWrongDBType);
    RUN_TEST(testGetCDBKeyNonexistentUser);
    RUN_TEST(testGetCDBKeyBasic);
    RUN_TEST(testGetCDBKeyWrongDEK);
    RUN_TEST(testGetCDBKeyDEKUnset);
    RUN_TEST(testGetCDBKeyUidZero);

    /* ────────────────────────────── server keys
     * ─────────────────────────────── */
    RUN_TEST(testSetServerKeyBasic);
    RUN_TEST(testSetServerKeyOverwrite);
    RUN_TEST(testSetServerKeyEmptyBlob);
    RUN_TEST(testGetServerKeyNotFound);
    RUN_TEST(testSetServerKeyNullDB);
    RUN_TEST(testSetServerKeyWrongDBType);
    RUN_TEST(testSetServerKeyEmptyName);
    RUN_TEST(testGetServerKeyEmptyName);

    /* ─────────────────────────────── storeChat
     * ──────────────────────────────── */
    RUN_TEST(testStoreChatNullDB);
    RUN_TEST(testStoreChatNullChat);
    RUN_TEST(testStoreChatNullMessage);
    RUN_TEST(testStoreChatEmptyMessage);
    RUN_TEST(testStoreChatWrongDBType);
    RUN_TEST(testStoreChatBasic);
    RUN_TEST(testStoreChatMsgIdMonotonic);
    RUN_TEST(testStoreChatCrossRoomUnique);
    RUN_TEST(testStoreChatRoomIdZero);
    RUN_TEST(testStoreChatRoomIdMax);
    RUN_TEST(testStoreChatSpecialChars);
    RUN_TEST(testStoreChatTimestampZero);
    RUN_TEST(testStoreChatTimestampNegative);
    RUN_TEST(testStoreChatTimestampLongMax);
    RUN_TEST(testStoreChatUidMax);
    RUN_TEST(testStoreChatCrossRoomUniqueMulti);

    /* ──────────────────────────── queryChatByMsgId
     * ──────────────────────────── */
    RUN_TEST(testQueryMsgIdNullDB);
    RUN_TEST(testQueryMsgIdNullOut);
    RUN_TEST(testQueryMsgIdWrongDBType);
    RUN_TEST(testQueryMsgIdNonexistent);
    RUN_TEST(testQueryMsgIdNonexistentRoom);
    RUN_TEST(testQueryMsgIdRoundtrip);
    RUN_TEST(testQueryMsgIdZeroSearch);
    RUN_TEST(testQueryMsgIdMax);
    RUN_TEST(testQueryMsgIdOutNotTouchedOnFailure);

    /* ────────────────────────── queryChatByTimeRange
     * ────────────────────────── */
    RUN_TEST(testQueryTimeNullDB);
    RUN_TEST(testQueryTimeNullOut);
    RUN_TEST(testQueryTimeNullCount);
    RUN_TEST(testQueryTimeWrongDBType);
    RUN_TEST(testQueryTimeEmptyRoom);
    RUN_TEST(testQueryTimeUIDFilter);
    RUN_TEST(testQueryTimeAllUids);
    RUN_TEST(testQueryTimeNoMatch);
    RUN_TEST(testQueryTimeInvertedRange);
    RUN_TEST(testQueryTimeEqualRange);
    RUN_TEST(testQueryTimeOrdering);
    RUN_TEST(testQueryTimeManyMessages);
    RUN_TEST(testQueryTimeCrossRoomIsolation);
    RUN_TEST(testQueryTimeExactCapacity);

    /* ──────────────────────── queryChatByUserAllRooms
     * ───────────────────────── */
    RUN_TEST(testQueryUserAllNullDB);
    RUN_TEST(testQueryUserAllNullOut);
    RUN_TEST(testQueryUserAllNullCount);
    RUN_TEST(testQueryUserAllWrongDBType);
    RUN_TEST(testQueryUserAllUidZero);
    RUN_TEST(testQueryUserAllNoRooms);
    RUN_TEST(testQueryUserAllNoMatch);
    RUN_TEST(testQueryUserAllSingleRoom);
    RUN_TEST(testQueryUserAllMultiRoom);
    RUN_TEST(testQueryUserAllUidIsolation);
    RUN_TEST(testQueryUserAllOrdering);
    RUN_TEST(testQueryUserAllTimeRange);
    RUN_TEST(testQueryUserAllEqualRange);
    RUN_TEST(testQueryUserAllInvertedRange);
    RUN_TEST(testQueryUserAllCrossRoomTimeMatch);
    RUN_TEST(testQueryUserAllManyMessages);
    RUN_TEST(testQueryUserAllOutputSetOnSuccess);
    RUN_TEST(testQueryUserAllRoomIdBoundaries);
    RUN_TEST(testQueryUserAllOneRoomEmpty);
    RUN_TEST(testQueryUserAllMultiUserCrossRoom);

    /* ────────────────────────────── persistence
     * ─────────────────────────────── */
    RUN_TEST(testPersistenceUserDB);
    RUN_TEST(testPersistenceChatDB);
    RUN_TEST(testPersistenceMsgSeqContinues);

    /* ─────────────────────── security / attack vectors
     * ──────────────────────── */
    RUN_TEST(testSQLInjectionUsername);
    RUN_TEST(testSQLInjectionMessage);
    RUN_TEST(testCrossTypeChatOnUserDB);
    RUN_TEST(testCrossTypeUserOnChatDB);
    RUN_TEST(testUsernameEmbeddedNul);
    RUN_TEST(testDbInitFileWhereDirExpected);
    RUN_TEST(testPasswordNotPlaintextInDB);
    RUN_TEST(testPasswordHashSamePasswordDifferentUsers);
    RUN_TEST(testRoomStmtCacheCollision);
    RUN_TEST(testChatSchemaExists);

    /* ──────────────────────── GameDB: room persistence
     * ──────────────────────── */
    removeDBFiles();
    RUN_TEST(testGameDbInitBasic);
    RUN_TEST(testGameDbInitInvalidType);

    /* List rooms must run first (on empty DB) */
    RUN_TEST(testListRoomsEmpty);
    RUN_TEST(testListRoomsSingle);
    RUN_TEST(testListRoomsMultiple);
    RUN_TEST(testListRoomsNullOut);
    RUN_TEST(testListRoomsWrongDBType);

    RUN_TEST(testCreateRoomBasic);
    RUN_TEST(testCreateRoomDuplicateRejected);
    RUN_TEST(testCreateRoomNullDB);
    RUN_TEST(testCreateRoomWrongDBType);
    RUN_TEST(testCreateRoomIdZero);
    RUN_TEST(testDeleteRoomBasic);
    RUN_TEST(testDeleteRoomNonexistent);
    RUN_TEST(testRoomExistsBasic);
    RUN_TEST(testRoomExistsNotFound);
    RUN_TEST(testCreateDeleteRecreate);
    RUN_TEST(testDeleteRoomNullDB);
    RUN_TEST(testDeleteRoomWrongDBType);
    RUN_TEST(testDeleteRoomTwice);
    RUN_TEST(testRoomExistsNullDB);
    RUN_TEST(testRoomExistsWrongDBType);
    RUN_TEST(testRoomExistsAfterDelete);
    RUN_TEST(testGameDBPersistence);
    RUN_TEST(testCreateRoomOnChatHistoryDB);
    RUN_TEST(testListRoomsAfterDelete);
    RUN_TEST(testListRoomsReallocTrigger);

    /* ──────────────────────────────── dbEncKey
     * ──────────────────────────────── */
    RUN_TEST(testDbEncKeyLen);
    RUN_TEST(testDbSetDbEncKeyNullDB);
    RUN_TEST(testDbSetDbEncKeyNullKey);
    RUN_TEST(testDbSetDbEncKeyBasic);
    RUN_TEST(testDbInitEncKeyParam);

    removeDBFiles();

    return TEST_REPORT();
}
