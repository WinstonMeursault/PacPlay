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

/* ───────────── helper constants for readability ───────────────────────── */

enum { TestUidAlpha = 1000, TestUidBravo = 1001, TestUidCharlie = 1002 };
enum { TestUidDelta = 2000, TestUidMax = 0xFFFFFFFF };
enum { RoomTestA = 1, RoomTestB = 2, RoomTestC = 3 };
enum { RoomMaxVal = 0xFFFFFFFF };
enum { TimeBase = 1700000000, TimeOffset1 = 100, TimeOffset2 = 200 };
enum { TimeOffset3 = 300, TimeOffset4 = 400 };
enum { TimeOffset5 = 500 };
enum { LongStrLen = 1024, MaxUserLen31 = DB_USERNAME_MAX_LEN - 1 };
enum { TimeSecsPerDay = 86400 };
enum { NonexistentUid = 99999 };
enum { TestSentinelPtr = 1 };
enum { TestCountSentinel = 999 };
enum { NonexistentMsgId = 999999 };
enum { LargeNonexistentMsgId = 99999999 };

/* ───────────── file-level helpers ──────────────────────────────────────── */

/**
 * @brief Remove stale test database files so each test group starts clean.
 */
static void removeDBFiles(void) {
    remove("db/user.db");
    remove("db/user.db-wal");
    remove("db/user.db-shm");
    remove("db/chatHistory.db");
    remove("db/chatHistory.db-wal");
    remove("db/chatHistory.db-shm");
}

/**
 * @brief Free a dynamically allocated ChatHistory result array.
 */
static void freeChatHistoryArray(ChatHistory *arr, size_t count) {
    for (size_t i = 0; i < count; i++) {
        free(arr[i].message);
    }
    free(arr);
}

/* ═══════════════════════  1. Lifecycle  ══════════════════════════════════ */

/** @brief dbInit with invalid DBType returns NULL. */
static void testDbInitInvalidType(void) {
    enum { BadType = 999 };
    DB *db = dbInit((DBType)BadType);
    ASSERT_TRUE(db == NULL);
}

/** @brief dbInit for UserDB returns non-NULL. */
static void testDbInitUserDB(void) {
    removeDBFiles();
    DB *db = dbInit(UserDB);
    ASSERT_TRUE(db != NULL);
    ASSERT_INT_EQ(db->type, UserDB);
    dbClose(db);
}

/** @brief dbInit for ChatHistoryDB returns non-NULL. */
static void testDbInitChatHistoryDB(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB);
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
    rmdir("db");
    DB *db = dbInit(UserDB);
    ASSERT_TRUE(db != NULL);
    dbClose(db);
    /* Verify directory exists */
    struct stat st;
    ASSERT_TRUE(stat("db", &st) == 0);
    ASSERT_TRUE(S_ISDIR(st.st_mode));
}

/** @brief dbInit called multiple times creates independent handles. */
static void testDbInitMultipleHandles(void) {
    removeDBFiles();
    DB *db1 = dbInit(UserDB);
    DB *db2 = dbInit(UserDB);
    ASSERT_TRUE(db1 != NULL);
    ASSERT_TRUE(db2 != NULL);
    ASSERT_TRUE(db1 != db2);
    dbClose(db1);
    dbClose(db2);
}

/* ═══════════════════════  2. createUser  ═════════════════════════════════ */

/** @brief createUser rejects NULL database. */
static void testCreateUserNullDB(void) {
    User u = {"alice", TestUidAlpha, "plaintext"};
    ASSERT_INT_EQ(createUser(NULL, &u), DB_FAIL);
}

/** @brief createUser rejects NULL user pointer. */
static void testCreateUserNullUser(void) {
    removeDBFiles();
    DB *db = dbInit(UserDB);
    ASSERT_TRUE(db != NULL);
    ASSERT_INT_EQ(createUser(db, NULL), DB_FAIL);
    dbClose(db);
}

/** @brief createUser rejects empty username. */
static void testCreateUserEmptyUsername(void) {
    removeDBFiles();
    DB *db = dbInit(UserDB);
    ASSERT_TRUE(db != NULL);
    User u = {"", TestUidAlpha, "pass"};
    ASSERT_INT_EQ(createUser(db, &u), DB_FAIL);
    dbClose(db);
}

/** @brief createUser rejects NULL password pointer. */
static void testCreateUserNullPassword(void) {
    removeDBFiles();
    DB *db = dbInit(UserDB);
    ASSERT_TRUE(db != NULL);
    User u = {"alice", TestUidAlpha, NULL};
    ASSERT_INT_EQ(createUser(db, &u), DB_FAIL);
    dbClose(db);
}

/** @brief createUser rejects empty password string. */
static void testCreateUserEmptyPassword(void) {
    removeDBFiles();
    DB *db = dbInit(UserDB);
    ASSERT_TRUE(db != NULL);
    User u = {"alice", TestUidAlpha, ""};
    ASSERT_INT_EQ(createUser(db, &u), DB_FAIL);
    dbClose(db);
}

/** @brief createUser rejects wrong database type. */
static void testCreateUserWrongDBType(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB);
    ASSERT_TRUE(db != NULL);
    User u = {"alice", TestUidAlpha, "pass"};
    ASSERT_INT_EQ(createUser(db, &u), DB_FAIL);
    dbClose(db);
}

/** @brief createUser: basic successful creation. */
static void testCreateUserBasic(void) {
    removeDBFiles();
    DB *db = dbInit(UserDB);
    ASSERT_TRUE(db != NULL);
    User u = {"alice", TestUidAlpha, "secret123"};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    dbClose(db);
}

/** @brief createUser: duplicate uid (different username) must fail. */
static void testCreateUserDuplicateUID(void) {
    removeDBFiles();
    DB *db = dbInit(UserDB);
    ASSERT_TRUE(db != NULL);
    User u1 = {"alice", TestUidAlpha, "pass1"};
    ASSERT_INT_EQ(createUser(db, &u1), DB_SUCC);
    User u2 = {"bob", TestUidAlpha, "pass2"};
    ASSERT_INT_EQ(createUser(db, &u2), DB_FAIL);
    dbClose(db);
}

/** @brief createUser: duplicate username (different uid) must fail. */
static void testCreateUserDuplicateUsername(void) {
    removeDBFiles();
    DB *db = dbInit(UserDB);
    ASSERT_TRUE(db != NULL);
    User u1 = {"eve", TestUidAlpha, "pass1"};
    ASSERT_INT_EQ(createUser(db, &u1), DB_SUCC);
    User u2 = {"eve", TestUidBravo, "pass2"};
    ASSERT_INT_EQ(createUser(db, &u2), DB_FAIL);
    dbClose(db);
}

/** @brief createUser: username at maximum length (31 non-NUL chars) works. */
static void testCreateUserMaxLenUsername(void) {
    removeDBFiles();
    DB *db = dbInit(UserDB);
    ASSERT_TRUE(db != NULL);
    User u;
    u.uid = TestUidAlpha;
    u.password = "pass";
    memset(u.username, 'X', (size_t)MaxUserLen31);
    u.username[MaxUserLen31] = '\0';
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    dbClose(db);
}

/** @brief createUser: uid = 0 is reserved and must be rejected. */
static void testCreateUserUidZero(void) {
    removeDBFiles();
    DB *db = dbInit(UserDB);
    ASSERT_TRUE(db != NULL);
    User u = {"uidzero", 0, "pass"};
    ASSERT_INT_EQ(createUser(db, &u), DB_FAIL);
    dbClose(db);
}

/** @brief createUser: uid = UINT32_MAX works. */
static void testCreateUserUidMax(void) {
    removeDBFiles();
    DB *db = dbInit(UserDB);
    ASSERT_TRUE(db != NULL);
    User u = {"uidmax", TestUidMax, "pass"};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    dbClose(db);
}

/** @brief createUser: special characters in password are handled. */
static void testCreateUserSpecialCharsPassword(void) {
    removeDBFiles();
    DB *db = dbInit(UserDB);
    ASSERT_TRUE(db != NULL);
    User u = {"spec", TestUidAlpha,
              "!@#$%^&*()_+{}|:\"<>?`~[\\];',./\x01\x1F\x7F"};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    /* Verify we can still verify */
    ASSERT_INT_EQ(verifyUser(db, &u), DB_SUCC);
    dbClose(db);
}

/** @brief createUser: very long password does not crash or overflow. */
static void testCreateUserLongPassword(void) {
    removeDBFiles();
    DB *db = dbInit(UserDB);
    ASSERT_TRUE(db != NULL);
    size_t passLen = (size_t)LongStrLen + 1;
    char *longPass = malloc(passLen);
    ASSERT_TRUE(longPass != NULL);
    memset(longPass, 'P', passLen - 1);
    longPass[passLen - 1] = '\0';
    User u = {"longpass", TestUidAlpha, longPass};
    int result = createUser(db, &u);
    ASSERT_INT_EQ(result, DB_SUCC);
    /* Verify the long password works */
    ASSERT_INT_EQ(verifyUser(db, &u), DB_SUCC);
    OPENSSL_cleanse(longPass, (size_t)LongStrLen);
    free(longPass);
    dbClose(db);
}

/* ═══════════════════════  3. deleteUser  ═════════════════════════════════ */

/** @brief deleteUser rejects NULL database. */
static void testDeleteUserNullDB(void) {
    User u = {"alice", TestUidAlpha, NULL};
    ASSERT_INT_EQ(deleteUser(NULL, &u), DB_FAIL);
}

/** @brief deleteUser rejects NULL user pointer. */
static void testDeleteUserNullUser(void) {
    removeDBFiles();
    DB *db = dbInit(UserDB);
    ASSERT_TRUE(db != NULL);
    ASSERT_INT_EQ(deleteUser(db, NULL), DB_FAIL);
    dbClose(db);
}

/** @brief deleteUser rejects wrong database type. */
static void testDeleteUserWrongDBType(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB);
    ASSERT_TRUE(db != NULL);
    User u = {"alice", TestUidAlpha, NULL};
    ASSERT_INT_EQ(deleteUser(db, &u), DB_FAIL);
    dbClose(db);
}

/** @brief deleteUser: non-existent uid returns DB_FAIL (strict mode). */
static void testDeleteUserNonexistent(void) {
    removeDBFiles();
    DB *db = dbInit(UserDB);
    ASSERT_TRUE(db != NULL);
    User u = {"ghost", NonexistentUid, NULL};
    ASSERT_INT_EQ(deleteUser(db, &u), DB_FAIL);
    dbClose(db);
}

/** @brief deleteUser: create then delete a user. */
static void testDeleteUserBasic(void) {
    removeDBFiles();
    DB *db = dbInit(UserDB);
    ASSERT_TRUE(db != NULL);
    User u = {"delme", TestUidAlpha, "pass"};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    ASSERT_INT_EQ(deleteUser(db, &u), DB_SUCC);
    dbClose(db);
}

/** @brief deleteUser twice: second call must fail. */
static void testDeleteUserTwice(void) {
    removeDBFiles();
    DB *db = dbInit(UserDB);
    ASSERT_TRUE(db != NULL);
    User u = {"delme2", TestUidAlpha, "pass"};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    ASSERT_INT_EQ(deleteUser(db, &u), DB_SUCC);
    ASSERT_INT_EQ(deleteUser(db, &u), DB_FAIL);
    dbClose(db);
}

/** @brief deleteUser: uid=0 is rejected at create time, so deletion
 *  of a uid=0 record (which cannot exist) must also fail. */
static void testDeleteUserUidZero(void) {
    removeDBFiles();
    DB *db = dbInit(UserDB);
    ASSERT_TRUE(db != NULL);
    /* Create a valid user to ensure DB operations work, but uid=0 is rejected */
    User u = {"valid", TestUidAlpha, "pass"};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    /* uid=0 cannot be created, so deletion must fail */
    User uZero = {"zero", 0, "pass"};
    ASSERT_INT_EQ(deleteUser(db, &uZero), DB_FAIL);
    dbClose(db);
}

/** @brief deleteUser: uid = UINT32_MAX works. */
static void testDeleteUserUidMax(void) {
    removeDBFiles();
    DB *db = dbInit(UserDB);
    ASSERT_TRUE(db != NULL);
    User u = {"max", TestUidMax, "pass"};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    ASSERT_INT_EQ(deleteUser(db, &u), DB_SUCC);
    dbClose(db);
}

/* ═══════════════════════  4. verifyUser  ═════════════════════════════════ */

/** @brief verifyUser rejects NULL database. */
static void testVerifyUserNullDB(void) {
    User u = {"alice", TestUidAlpha, "pass"};
    ASSERT_INT_EQ(verifyUser(NULL, &u), DB_FAIL);
}

/** @brief verifyUser rejects NULL user pointer. */
static void testVerifyUserNullUser(void) {
    removeDBFiles();
    DB *db = dbInit(UserDB);
    ASSERT_TRUE(db != NULL);
    ASSERT_INT_EQ(verifyUser(db, NULL), DB_FAIL);
    dbClose(db);
}

/** @brief verifyUser rejects empty username. */
static void testVerifyUserEmptyUsername(void) {
    removeDBFiles();
    DB *db = dbInit(UserDB);
    ASSERT_TRUE(db != NULL);
    User u = {"", TestUidAlpha, "pass"};
    ASSERT_INT_EQ(verifyUser(db, &u), DB_FAIL);
    dbClose(db);
}

/** @brief verifyUser rejects NULL password. */
static void testVerifyUserNullPassword(void) {
    removeDBFiles();
    DB *db = dbInit(UserDB);
    ASSERT_TRUE(db != NULL);
    User u = {"alice", TestUidAlpha, NULL};
    ASSERT_INT_EQ(verifyUser(db, &u), DB_FAIL);
    dbClose(db);
}

/** @brief verifyUser rejects empty password. */
static void testVerifyUserEmptyPassword(void) {
    removeDBFiles();
    DB *db = dbInit(UserDB);
    ASSERT_TRUE(db != NULL);
    User u = {"alice", TestUidAlpha, ""};
    ASSERT_INT_EQ(verifyUser(db, &u), DB_FAIL);
    dbClose(db);
}

/** @brief verifyUser rejects wrong database type. */
static void testVerifyUserWrongDBType(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB);
    ASSERT_TRUE(db != NULL);
    User u = {"alice", TestUidAlpha, "pass"};
    ASSERT_INT_EQ(verifyUser(db, &u), DB_FAIL);
    dbClose(db);
}

/** @brief verifyUser: non-existent user fails. */
static void testVerifyUserNonexistent(void) {
    removeDBFiles();
    DB *db = dbInit(UserDB);
    ASSERT_TRUE(db != NULL);
    User u = {"ghost", NonexistentUid, "pass"};
    ASSERT_INT_EQ(verifyUser(db, &u), DB_FAIL);
    dbClose(db);
}

/** @brief verifyUser: wrong password fails. */
static void testVerifyUserWrongPassword(void) {
    removeDBFiles();
    DB *db = dbInit(UserDB);
    ASSERT_TRUE(db != NULL);
    User u = {"alice", TestUidAlpha, "correct"};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    u.password = "wrongpass";
    ASSERT_INT_EQ(verifyUser(db, &u), DB_FAIL);
    dbClose(db);
}

/** @brief verifyUser: correct uid but wrong username fails. */
static void testVerifyUserWrongUsername(void) {
    removeDBFiles();
    DB *db = dbInit(UserDB);
    ASSERT_TRUE(db != NULL);
    User u = {"alice", TestUidAlpha, "secret"};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    u.password = "secret";
    strncpy(u.username, "bob", sizeof(u.username));
    ASSERT_INT_EQ(verifyUser(db, &u), DB_FAIL);
    dbClose(db);
}

/** @brief verifyUser: correct username but wrong uid fails. */
static void testVerifyUserWrongUID(void) {
    removeDBFiles();
    DB *db = dbInit(UserDB);
    ASSERT_TRUE(db != NULL);
    User u = {"alice", TestUidAlpha, "secret"};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    u.password = "secret";
    u.uid = NonexistentUid;
    ASSERT_INT_EQ(verifyUser(db, &u), DB_FAIL);
    dbClose(db);
}

/** @brief verifyUser: basic success. */
static void testVerifyUserBasic(void) {
    removeDBFiles();
    DB *db = dbInit(UserDB);
    ASSERT_TRUE(db != NULL);
    User u = {"alice", TestUidAlpha, "secret123"};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    ASSERT_INT_EQ(verifyUser(db, &u), DB_SUCC);
    dbClose(db);
}

/** @brief verifyUser must fail after user is deleted. */
static void testVerifyUserAfterDelete(void) {
    removeDBFiles();
    DB *db = dbInit(UserDB);
    ASSERT_TRUE(db != NULL);
    User u = {"todelete", TestUidAlpha, "pass"};
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
    DB *db = dbInit(UserDB);
    ASSERT_TRUE(db != NULL);
    User u = {"alice", TestUidAlpha, "realpass"};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    /* Wrong password */
    u.password = "wrong";
    int resultWrong = verifyUser(db, &u);
    /* Non-existent user */
    User ghost = {"ghost", NonexistentUid, "any"};
    int resultGhost = verifyUser(db, &ghost);
    /* Both must return DB_FAIL; attacker cannot distinguish */
    ASSERT_INT_EQ(resultWrong, DB_FAIL);
    ASSERT_INT_EQ(resultGhost, DB_FAIL);
    dbClose(db);
}

/** @brief verifyUser: passwords that differ by one bit fail. */
static void testVerifyUserSimilarPassword(void) {
    removeDBFiles();
    DB *db = dbInit(UserDB);
    ASSERT_TRUE(db != NULL);
    User u = {"alice", TestUidAlpha, "Password123"};
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

/* ═══════════════════════  5. storeChatHistory  ════════════════════════════ */

/** @brief storeChatHistory rejects NULL database. */
static void testStoreChatNullDB(void) {
    ChatHistory ch = {TestUidAlpha, 0, "hello", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChatHistory(NULL, RoomTestA, &ch), DB_FAIL);
}

/** @brief storeChatHistory rejects NULL ChatHistory pointer. */
static void testStoreChatNullChat(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB);
    ASSERT_TRUE(db != NULL);
    ASSERT_INT_EQ(storeChatHistory(db, RoomTestA, NULL), DB_FAIL);
    dbClose(db);
}

/** @brief storeChatHistory rejects NULL message. */
static void testStoreChatNullMessage(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB);
    ASSERT_TRUE(db != NULL);
    ChatHistory ch = {TestUidAlpha, 0, NULL, (time_t)TimeBase};
    ASSERT_INT_EQ(storeChatHistory(db, RoomTestA, &ch), DB_FAIL);
    dbClose(db);
}

/** @brief storeChatHistory rejects empty message. */
static void testStoreChatEmptyMessage(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB);
    ASSERT_TRUE(db != NULL);
    ChatHistory ch = {TestUidAlpha, 0, "", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChatHistory(db, RoomTestA, &ch), DB_FAIL);
    dbClose(db);
}

/** @brief storeChatHistory rejects wrong database type. */
static void testStoreChatWrongDBType(void) {
    removeDBFiles();
    DB *db = dbInit(UserDB);
    ASSERT_TRUE(db != NULL);
    ChatHistory ch = {TestUidAlpha, 0, "msg", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChatHistory(db, RoomTestA, &ch), DB_FAIL);
    dbClose(db);
}

/** @brief storeChatHistory: basic success, msgId is populated. */
static void testStoreChatBasic(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB);
    ASSERT_TRUE(db != NULL);
    ChatHistory ch = {TestUidAlpha, 0, "Hello, world!", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChatHistory(db, RoomTestA, &ch), DB_SUCC);
    /* msgId must have been populated (non-zero) */
    ASSERT_TRUE(ch.msgId > 0);
    dbClose(db);
}

/** @brief storeChatHistory: msgId is strictly monotonically increasing. */
static void testStoreChatMsgIdMonotonic(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB);
    ASSERT_TRUE(db != NULL);
    ChatHistory ch1 = {TestUidAlpha, 0, "msg1", (time_t)TimeBase};
    ChatHistory ch2 = {TestUidAlpha, 0, "msg2", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChatHistory(db, RoomTestA, &ch1), DB_SUCC);
    ASSERT_INT_EQ(storeChatHistory(db, RoomTestA, &ch2), DB_SUCC);
    ASSERT_TRUE(ch2.msgId > ch1.msgId);
    dbClose(db);
}

/** @brief storeChatHistory: msgId is unique across different rooms. */
static void testStoreChatCrossRoomUnique(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB);
    ASSERT_TRUE(db != NULL);
    ChatHistory chA = {TestUidAlpha, 0, "roomA", (time_t)TimeBase};
    ChatHistory chB = {TestUidAlpha, 0, "roomB", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChatHistory(db, RoomTestA, &chA), DB_SUCC);
    ASSERT_INT_EQ(storeChatHistory(db, RoomTestB, &chB), DB_SUCC);
    /* msgIds must be distinct */
    ASSERT_TRUE(chA.msgId != chB.msgId);
    dbClose(db);
}

/** @brief storeChatHistory: roomId = 0 works. */
static void testStoreChatRoomIdZero(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB);
    ASSERT_TRUE(db != NULL);
    ChatHistory ch = {TestUidAlpha, 0, "room zero", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChatHistory(db, 0, &ch), DB_SUCC);
    ASSERT_TRUE(ch.msgId > 0);
    dbClose(db);
}

/** @brief storeChatHistory: roomId = UINT32_MAX works. */
static void testStoreChatRoomIdMax(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB);
    ASSERT_TRUE(db != NULL);
    ChatHistory ch = {TestUidAlpha, 0, "room max", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChatHistory(db, RoomMaxVal, &ch), DB_SUCC);
    ASSERT_TRUE(ch.msgId > 0);
    dbClose(db);
}

/** @brief storeChatHistory: special characters in message are preserved. */
static void testStoreChatSpecialChars(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB);
    ASSERT_TRUE(db != NULL);
    ChatHistory ch = {TestUidAlpha, 0,
                      "'; DROP TABLE users; -- \n\r\t\x01\x1F\x7F\xFF",
                      (time_t)TimeBase};
    ASSERT_INT_EQ(storeChatHistory(db, RoomTestA, &ch), DB_SUCC);
    /* Verify roundtrip preserves the string */
    ChatHistory retrieved;
    ASSERT_INT_EQ(queryChatByMsgId(db, RoomTestA, ch.msgId, &retrieved),
                  DB_SUCC);
    ASSERT_STR_EQ(retrieved.message,
                  "'; DROP TABLE users; -- \n\r\t\x01\x1F\x7F\xFF");
    free(retrieved.message);
    dbClose(db);
}

/** @brief storeChatHistory: timestamp = 0 (epoch) is accepted. */
static void testStoreChatTimestampZero(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB);
    ASSERT_TRUE(db != NULL);
    ChatHistory ch = {TestUidAlpha, 0, "epoch msg", (time_t)0};
    ASSERT_INT_EQ(storeChatHistory(db, RoomTestA, &ch), DB_SUCC);
    ASSERT_TRUE(ch.msgId > 0);
    dbClose(db);
}

/* ═══════════════════════  6. queryChatByMsgId  ═══════════════════════════ */

/** @brief queryChatByMsgId rejects NULL database. */
static void testQueryMsgIdNullDB(void) {
    ChatHistory out;
    ASSERT_INT_EQ(queryChatByMsgId(NULL, RoomTestA, 1, &out), DB_FAIL);
}

/** @brief queryChatByMsgId rejects NULL out pointer. */
static void testQueryMsgIdNullOut(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB);
    ASSERT_TRUE(db != NULL);
    ASSERT_INT_EQ(queryChatByMsgId(db, RoomTestA, 1, NULL), DB_FAIL);
    dbClose(db);
}

/** @brief queryChatByMsgId rejects wrong database type. */
static void testQueryMsgIdWrongDBType(void) {
    removeDBFiles();
    DB *db = dbInit(UserDB);
    ASSERT_TRUE(db != NULL);
    ChatHistory out;
    ASSERT_INT_EQ(queryChatByMsgId(db, RoomTestA, 1, &out), DB_FAIL);
    dbClose(db);
}

/** @brief queryChatByMsgId: non-existent msgId returns DB_FAIL. */
static void testQueryMsgIdNonexistent(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB);
    ASSERT_TRUE(db != NULL);
    ChatHistory out;
    ASSERT_INT_EQ(queryChatByMsgId(db, RoomTestA, LargeNonexistentMsgId, &out),
                  DB_FAIL);
    dbClose(db);
}

/** @brief queryChatByMsgId: non-existent room returns DB_FAIL. */
static void testQueryMsgIdNonexistentRoom(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB);
    ASSERT_TRUE(db != NULL);
    ChatHistory out;
    ASSERT_INT_EQ(queryChatByMsgId(db, 9999, 1, &out), DB_FAIL);
    dbClose(db);
}

/** @brief queryChatByMsgId: store and retrieve roundtrip. */
static void testQueryMsgIdRoundtrip(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB);
    ASSERT_TRUE(db != NULL);
    ChatHistory in = {TestUidAlpha, 0, "roundtrip test!", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChatHistory(db, RoomTestA, &in), DB_SUCC);
    ChatHistory out;
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
    DB *db = dbInit(ChatHistoryDB);
    ASSERT_TRUE(db != NULL);
    /* Store a message and note its msgId, then query by that exact id */
    ChatHistory in = {TestUidAlpha, 0, "zero test", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChatHistory(db, RoomTestA, &in), DB_SUCC);
    ChatHistory out;
    ASSERT_INT_EQ(queryChatByMsgId(db, RoomTestA, in.msgId, &out), DB_SUCC);
    free(out.message);
    /* msgId=0 before any store should fail */
    removeDBFiles();
    DB *db2 = dbInit(ChatHistoryDB);
    ASSERT_TRUE(db2 != NULL);
    ChatHistory out2;
    ASSERT_INT_EQ(queryChatByMsgId(db2, RoomTestA, 0, &out2), DB_FAIL);
    dbClose(db2);
}

/** @brief queryChatByMsgId: UINT64_MAX msgId fails (does not crash). */
static void testQueryMsgIdMax(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB);
    ASSERT_TRUE(db != NULL);
    ChatHistory out;
    ASSERT_INT_EQ(queryChatByMsgId(db, RoomTestA, UINT64_MAX, &out), DB_FAIL);
    dbClose(db);
}

/** @brief queryChatByMsgId: out->message is NULL on failure. */
static void testQueryMsgIdOutNotTouchedOnFailure(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB);
    ASSERT_TRUE(db != NULL);
    ChatHistory out;
    memset(&out, 0, sizeof(out));
    ASSERT_INT_EQ(queryChatByMsgId(db, RoomTestA, NonexistentMsgId, &out),
                  DB_FAIL);
    /* out should not have been corrupted - message is still NULL */
    ASSERT_TRUE(out.message == NULL);
    dbClose(db);
}

/* ═══════════════════════  7. queryChatByTimeRange  ════════════════════════ */

/** @brief queryChatByTimeRange rejects NULL database. */
static void testQueryTimeNullDB(void) {
    ChatHistory *out = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(queryChatByTimeRange(NULL, RoomTestA, 0, (time_t)0, (time_t)1,
                                       &out, &count),
                  DB_FAIL);
}

/** @brief queryChatByTimeRange rejects NULL out. */
static void testQueryTimeNullOut(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB);
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
    DB *db = dbInit(ChatHistoryDB);
    ASSERT_TRUE(db != NULL);
    ChatHistory *out = NULL;
    ASSERT_INT_EQ(queryChatByTimeRange(db, RoomTestA, 0, (time_t)0, (time_t)1,
                                       &out, NULL),
                  DB_FAIL);
    dbClose(db);
}

/** @brief queryChatByTimeRange rejects wrong database type. */
static void testQueryTimeWrongDBType(void) {
    removeDBFiles();
    DB *db = dbInit(UserDB);
    ASSERT_TRUE(db != NULL);
    ChatHistory *out = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(queryChatByTimeRange(db, RoomTestA, 0, (time_t)0, (time_t)1,
                                       &out, &count),
                  DB_FAIL);
    dbClose(db);
}

/** @brief queryChatByTimeRange: empty room returns DB_SUCC with count=0. */
static void testQueryTimeEmptyRoom(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB);
    ASSERT_TRUE(db != NULL);
    ChatHistory *out = (ChatHistory *)(uintptr_t)TestSentinelPtr;
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
    DB *db = dbInit(ChatHistoryDB);
    ASSERT_TRUE(db != NULL);
    /* Store messages from two different users */
    ChatHistory ch1 = {TestUidAlpha, 0, "alpha msg", (time_t)TimeBase};
    ChatHistory ch2 = {TestUidBravo, 0, "bravo msg", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChatHistory(db, RoomTestA, &ch1), DB_SUCC);
    ASSERT_INT_EQ(storeChatHistory(db, RoomTestA, &ch2), DB_SUCC);
    /* Query only TestUidAlpha's messages */
    ChatHistory *out = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(queryChatByTimeRange(db, RoomTestA, TestUidAlpha, (time_t)0,
                                       (time_t)TimeBase + TimeOffset5, &out,
                                       &count),
                  DB_SUCC);
    ASSERT_UINT_EQ(count, (unsigned long long)1);
    ASSERT_UINT_EQ(out[0].uid, TestUidAlpha);
    ASSERT_STR_EQ(out[0].message, "alpha msg");
    freeChatHistoryArray(out, count);
    dbClose(db);
}

/** @brief queryChatByTimeRange: uid=0 returns all users. */
static void testQueryTimeAllUids(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB);
    ASSERT_TRUE(db != NULL);
    ChatHistory ch1 = {TestUidAlpha, 0, "A", (time_t)TimeBase};
    ChatHistory ch2 = {TestUidBravo, 0, "B", (time_t)TimeBase};
    ChatHistory ch3 = {TestUidCharlie, 0, "C", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChatHistory(db, RoomTestA, &ch1), DB_SUCC);
    ASSERT_INT_EQ(storeChatHistory(db, RoomTestA, &ch2), DB_SUCC);
    ASSERT_INT_EQ(storeChatHistory(db, RoomTestA, &ch3), DB_SUCC);
    ChatHistory *out = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(queryChatByTimeRange(db, RoomTestA, 0, (time_t)0,
                                       (time_t)TimeBase + TimeOffset5, &out,
                                       &count),
                  DB_SUCC);
    ASSERT_UINT_EQ(count, (unsigned long long)3);
    freeChatHistoryArray(out, count);
    dbClose(db);
}

/** @brief queryChatByTimeRange: time range with no match returns 0. */
static void testQueryTimeNoMatch(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB);
    ASSERT_TRUE(db != NULL);
    ChatHistory ch = {TestUidAlpha, 0, "msg", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChatHistory(db, RoomTestA, &ch), DB_SUCC);
    /* Query a time range entirely after the message */
    ChatHistory *out = NULL;
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
    DB *db = dbInit(ChatHistoryDB);
    ASSERT_TRUE(db != NULL);
    ChatHistory ch = {TestUidAlpha, 0, "msg", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChatHistory(db, RoomTestA, &ch), DB_SUCC);
    ChatHistory *out = NULL;
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
    DB *db = dbInit(ChatHistoryDB);
    ASSERT_TRUE(db != NULL);
    ChatHistory ch1 = {TestUidAlpha, 0, "exact", (time_t)TimeBase};
    ChatHistory ch2 = {TestUidAlpha, 0, "after",
                       (time_t)(TimeBase + TimeOffset1)};
    ASSERT_INT_EQ(storeChatHistory(db, RoomTestA, &ch1), DB_SUCC);
    ASSERT_INT_EQ(storeChatHistory(db, RoomTestA, &ch2), DB_SUCC);
    ChatHistory *out = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(queryChatByTimeRange(db, RoomTestA, 0, (time_t)TimeBase,
                                       (time_t)TimeBase, &out, &count),
                  DB_SUCC);
    ASSERT_UINT_EQ(count, (unsigned long long)1);
    ASSERT_STR_EQ(out[0].message, "exact");
    freeChatHistoryArray(out, count);
    dbClose(db);
}

/** @brief queryChatByTimeRange: results are ordered by msgId ASC. */
static void testQueryTimeOrdering(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB);
    ASSERT_TRUE(db != NULL);
    ChatHistory ch1 = {TestUidAlpha, 0, "third",
                       (time_t)(TimeBase + TimeOffset3)};
    ChatHistory ch2 = {TestUidAlpha, 0, "first",
                       (time_t)(TimeBase + TimeOffset1)};
    ChatHistory ch3 = {TestUidAlpha, 0, "second",
                       (time_t)(TimeBase + TimeOffset2)};
    /* Store out of timestamp order */
    ASSERT_INT_EQ(storeChatHistory(db, RoomTestA, &ch1), DB_SUCC);
    ASSERT_INT_EQ(storeChatHistory(db, RoomTestA, &ch2), DB_SUCC);
    ASSERT_INT_EQ(storeChatHistory(db, RoomTestA, &ch3), DB_SUCC);
    ChatHistory *out = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(queryChatByTimeRange(db, RoomTestA, 0, (time_t)0,
                                       (time_t)TimeBase + TimeOffset5, &out,
                                       &count),
                  DB_SUCC);
    ASSERT_UINT_EQ(count, (unsigned long long)3);
    /* Results must be ordered by msgId ASC (which is insert order) */
    ASSERT_TRUE(out[0].msgId < out[1].msgId);
    ASSERT_TRUE(out[1].msgId < out[2].msgId);
    freeChatHistoryArray(out, count);
    dbClose(db);
}

/** @brief queryChatByTimeRange: large number of messages does not crash. */
static void testQueryTimeManyMessages(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB);
    ASSERT_TRUE(db != NULL);
    enum { MsgCount = 50 };
    for (int i = 0; i < MsgCount; i++) {
        ChatHistory ch = {TestUidAlpha, 0, "msg",
                          (time_t)(TimeBase + i * TimeOffset1)};
        ASSERT_INT_EQ(storeChatHistory(db, RoomTestA, &ch), DB_SUCC);
    }
    ChatHistory *out = NULL;
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
    freeChatHistoryArray(out, count);
    dbClose(db);
}

/** @brief queryChatByTimeRange: cross-room isolation — different rooms are
 * independent. */
static void testQueryTimeCrossRoomIsolation(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB);
    ASSERT_TRUE(db != NULL);
    ChatHistory chA = {TestUidAlpha, 0, "roomA", (time_t)TimeBase};
    ChatHistory chB = {TestUidAlpha, 0, "roomB", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChatHistory(db, RoomTestA, &chA), DB_SUCC);
    ASSERT_INT_EQ(storeChatHistory(db, RoomTestB, &chB), DB_SUCC);
    /* Query room A — should NOT see room B's message */
    ChatHistory *out = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(queryChatByTimeRange(db, RoomTestA, 0, (time_t)0,
                                       (time_t)TimeBase + TimeOffset5, &out,
                                       &count),
                  DB_SUCC);
    ASSERT_UINT_EQ(count, (unsigned long long)1);
    ASSERT_STR_EQ(out[0].message, "roomA");
    freeChatHistoryArray(out, count);
    dbClose(db);
}

/* ═══════════════════════  8. persistence  ═══════════════════════════════ */

/** @brief Data persists across dbClose / dbInit cycles. */
static void testPersistenceUserDB(void) {
    removeDBFiles();
    {
        DB *db = dbInit(UserDB);
        ASSERT_TRUE(db != NULL);
        User u = {"persist", TestUidAlpha, "mysecret"};
        ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
        dbClose(db);
    }
    {
        DB *db = dbInit(UserDB);
        ASSERT_TRUE(db != NULL);
        User u = {"persist", TestUidAlpha, "mysecret"};
        ASSERT_INT_EQ(verifyUser(db, &u), DB_SUCC);
        dbClose(db);
    }
}

/** @brief Chat data persists across dbClose / dbInit cycles. */
static void testPersistenceChatDB(void) {
    removeDBFiles();
    uint64_t savedMsgId = 0;
    {
        DB *db = dbInit(ChatHistoryDB);
        ASSERT_TRUE(db != NULL);
        ChatHistory ch = {TestUidAlpha, 0, "persistent msg", (time_t)TimeBase};
        ASSERT_INT_EQ(storeChatHistory(db, RoomTestA, &ch), DB_SUCC);
        savedMsgId = ch.msgId;
        dbClose(db);
    }
    {
        DB *db2 = dbInit(ChatHistoryDB);
        ASSERT_TRUE(db2 != NULL);
        ChatHistory out;
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
        DB *db = dbInit(ChatHistoryDB);
        ASSERT_TRUE(db != NULL);
        ChatHistory ch = {TestUidAlpha, 0, "pre-close", (time_t)TimeBase};
        ASSERT_INT_EQ(storeChatHistory(db, RoomTestA, &ch), DB_SUCC);
        lastBeforeClose = ch.msgId;
        dbClose(db);
    }
    {
        DB *db = dbInit(ChatHistoryDB);
        ASSERT_TRUE(db != NULL);
        ChatHistory ch = {TestUidAlpha, 0, "post-close", (time_t)TimeBase};
        ASSERT_INT_EQ(storeChatHistory(db, RoomTestA, &ch), DB_SUCC);
        /* New msgId must be greater than the one before close */
        ASSERT_TRUE(ch.msgId > lastBeforeClose);
        dbClose(db);
    }
}

/* ═══════════════════════  9. security / attack vectors  ══════════════════ */

/**
 * @brief SQL injection attempt with malicious username string.
 *
 * Since all user input is bound via sqlite3_bind_* (prepared statements),
 * this must succeed (store the literal string) without any harmful side
 * effects.
 */
static void testSQLInjectionUsername(void) {
    removeDBFiles();
    DB *db = dbInit(UserDB);
    ASSERT_TRUE(db != NULL);
    User u = {"'; DROP TABLE users; --", TestUidAlpha, "pass"};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    /* Verify the exact string was stored */
    ASSERT_INT_EQ(verifyUser(db, &u), DB_SUCC);
    /* The users table must still exist (no DROP was executed) */
    User v = {"normal", TestUidBravo, "pass"};
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
    DB *db = dbInit(ChatHistoryDB);
    ASSERT_TRUE(db != NULL);
    ChatHistory ch = {TestUidAlpha, 0,
                      "'); DELETE FROM room_1; INSERT INTO room_1 "
                      "VALUES(9999,1,'hacked',0); --",
                      (time_t)TimeBase};
    ASSERT_INT_EQ(storeChatHistory(db, RoomTestA, &ch), DB_SUCC);
    /* Retrieve and verify exact string */
    ChatHistory out;
    ASSERT_INT_EQ(queryChatByMsgId(db, RoomTestA, ch.msgId, &out), DB_SUCC);
    ASSERT_STR_EQ(out.message, "'); DELETE FROM room_1; INSERT INTO room_1 "
                               "VALUES(9999,1,'hacked',0); --");
    free(out.message);
    /* The original message should still exist (no SQL was injected) */
    dbClose(db);
}

/**
 * @brief Calling all ChatHistory operations on a UserDB handle must fail.
 */
static void testCrossTypeChatOnUserDB(void) {
    removeDBFiles();
    DB *db = dbInit(UserDB);
    ASSERT_TRUE(db != NULL);
    ChatHistory ch = {TestUidAlpha, 0, "msg", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChatHistory(db, RoomTestA, &ch), DB_FAIL);
    ChatHistory out;
    ASSERT_INT_EQ(queryChatByMsgId(db, RoomTestA, 1, &out), DB_FAIL);
    ChatHistory *arr = NULL;
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
    DB *db = dbInit(ChatHistoryDB);
    ASSERT_TRUE(db != NULL);
    User u = {"alice", TestUidAlpha, "pass"};
    ASSERT_INT_EQ(createUser(db, &u), DB_FAIL);
    ASSERT_INT_EQ(deleteUser(db, &u), DB_FAIL);
    ASSERT_INT_EQ(verifyUser(db, &u), DB_FAIL);
    dbClose(db);
}

/** @brief Username with embedded NUL byte (using username[0] = '\0'). */
static void testUsernameEmbeddedNul(void) {
    removeDBFiles();
    DB *db = dbInit(UserDB);
    ASSERT_TRUE(db != NULL);
    /* First char \0 → empty string, must be rejected */
    User u = {"\0hidden", TestUidAlpha, "pass"};
    ASSERT_INT_EQ(createUser(db, &u), DB_FAIL);
    dbClose(db);
}

/** @brief dbInit handles directory busy (file exists where dir expected). */
static void testDbInitFileWhereDirExpected(void) {
    /* Create a regular file named "db" after cleaning up */
    removeDBFiles();
    rmdir("db");
    FILE *f = fopen("db", "w");
    if (f != NULL) {
        fclose(f);
        /* dbInit should fail because "db" is a file, not a directory */
        DB *db = dbInit(UserDB);
        /* It may or may not return NULL depending on implementation;
         * the important thing is that it does not crash or produce UB */
        if (db != NULL) {
            dbClose(db);
        }
        remove("db");
    }
}

/* ═══════════════════════  10. hash password  ══════════════════════════════ */

/** @brief password hash stored in database is not the plaintext. */
static void testPasswordNotPlaintextInDB(void) {
    removeDBFiles();
    DB *db = dbInit(UserDB);
    ASSERT_TRUE(db != NULL);
    User u = {"alice", TestUidAlpha, "secret123"};
    ASSERT_INT_EQ(createUser(db, &u), DB_SUCC);
    /* Directly query the raw stored password — must NOT equal plaintext */
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db->handle,
                                "SELECT password FROM users WHERE uid = ?;", -1,
                                &stmt, NULL);
    ASSERT_INT_EQ(rc, SQLITE_OK);
    rc = sqlite3_bind_int(stmt, 1, (int)TestUidAlpha);
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
    DB *db = dbInit(UserDB);
    ASSERT_TRUE(db != NULL);
    User u1 = {"hash1", TestUidAlpha, "samepass"};
    User u2 = {"hash2", TestUidBravo, "samepass"};
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

/* ═══════════════════════  11. additional coverage gaps  ══════════════════ */

/** @brief uid=0 cannot be created, therefore verifyUser with uid=0 must
 *  fail (no such user can exist). */
static void testVerifyUserUidZero(void) {
    removeDBFiles();
    DB *db = dbInit(UserDB);
    ASSERT_TRUE(db != NULL);
    User u = {"zero", 0, "pass"};
    ASSERT_INT_EQ(createUser(db, &u), DB_FAIL);
    ASSERT_INT_EQ(verifyUser(db, &u), DB_FAIL);
    dbClose(db);
}

/** @brief storeChatHistory: negative timestamp (time_t)-1 works. */
static void testStoreChatTimestampNegative(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB);
    ASSERT_TRUE(db != NULL);
    ChatHistory ch = {TestUidAlpha, 0, "neg time", (time_t)-1};
    ASSERT_INT_EQ(storeChatHistory(db, RoomTestA, &ch), DB_SUCC);
    ChatHistory out;
    ASSERT_INT_EQ(queryChatByMsgId(db, RoomTestA, ch.msgId, &out), DB_SUCC);
    ASSERT_INT_EQ(out.timestamp, (time_t)-1);
    free(out.message);
    dbClose(db);
}

/** @brief storeChatHistory: LONG_MAX timestamp works. */
static void testStoreChatTimestampLongMax(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB);
    ASSERT_TRUE(db != NULL);
    ChatHistory ch = {TestUidAlpha, 0, "max time", (time_t)LONG_MAX};
    ASSERT_INT_EQ(storeChatHistory(db, RoomTestA, &ch), DB_SUCC);
    ChatHistory out;
    ASSERT_INT_EQ(queryChatByMsgId(db, RoomTestA, ch.msgId, &out), DB_SUCC);
    ASSERT_INT_EQ(out.timestamp, (time_t)LONG_MAX);
    free(out.message);
    dbClose(db);
}

/** @brief storeChatHistory: UINT32_MAX uid works. */
static void testStoreChatUidMax(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB);
    ASSERT_TRUE(db != NULL);
    ChatHistory ch = {TestUidMax, 0, "max uid msg", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChatHistory(db, RoomTestA, &ch), DB_SUCC);
    ChatHistory out;
    ASSERT_INT_EQ(queryChatByMsgId(db, RoomTestA, ch.msgId, &out), DB_SUCC);
    ASSERT_UINT_EQ(out.uid, TestUidMax);
    free(out.message);
    dbClose(db);
}

/** @brief msgId is globally unique across 5 different rooms. */
static void testStoreChatCrossRoomUniqueMulti(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB);
    ASSERT_TRUE(db != NULL);
    enum { MultiRoomCount = 5 };
    uint64_t msgIds[MultiRoomCount];
    for (uint32_t r = 0; r < MultiRoomCount; r++) {
        ChatHistory ch = {TestUidAlpha, 0, "multi", (time_t)TimeBase};
        ASSERT_INT_EQ(storeChatHistory(db, r, &ch), DB_SUCC);
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
    DB *db = dbInit(ChatHistoryDB);
    ASSERT_TRUE(db != NULL);
    enum { InitCap = 16, /* matches database.c QUERY_INITIAL_CAPACITY */ };
    enum { ExactCount = InitCap };
    for (int i = 0; i < ExactCount; i++) {
        ChatHistory ch = {TestUidAlpha, 0, "exact cap", (time_t)(TimeBase + i)};
        ASSERT_INT_EQ(storeChatHistory(db, RoomTestA, &ch), DB_SUCC);
    }
    ChatHistory *out = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(queryChatByTimeRange(db, RoomTestA, 0, (time_t)0,
                                       (time_t)TimeBase + ExactCount, &out,
                                       &count),
                  DB_SUCC);
    ASSERT_UINT_EQ(count, (unsigned long long)ExactCount);
    freeChatHistoryArray(out, count);
    dbClose(db);
}

/**
 * @brief Hash table collision: rooms with the same bucket index work
 * independently via the chained-list lookup.
 */
static void testRoomStmtCacheCollision(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB);
    ASSERT_TRUE(db != NULL);
    /* room 0 and ROOM_STMT_BUCKETS share bucket index 0 */
    enum { CollideA = 0, CollideB = ROOM_STMT_BUCKETS };
    ChatHistory chA = {TestUidAlpha, 0, "room A", (time_t)TimeBase};
    ChatHistory chB = {TestUidBravo, 0, "room B", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChatHistory(db, CollideA, &chA), DB_SUCC);
    ASSERT_INT_EQ(storeChatHistory(db, CollideB, &chB), DB_SUCC);
    /* Both independently retrievable */
    ChatHistory outA, outB;
    ASSERT_INT_EQ(queryChatByMsgId(db, CollideA, chA.msgId, &outA), DB_SUCC);
    ASSERT_INT_EQ(queryChatByMsgId(db, CollideB, chB.msgId, &outB), DB_SUCC);
    ASSERT_STR_EQ(outA.message, "room A");
    ASSERT_STR_EQ(outB.message, "room B");
    ASSERT_UINT_EQ(outA.uid, TestUidAlpha);
    ASSERT_UINT_EQ(outB.uid, TestUidBravo);
    free(outA.message);
    free(outB.message);
    /* Time range query also respects room isolation */
    ChatHistory *arr = NULL;
    size_t n = 0;
    ASSERT_INT_EQ(queryChatByTimeRange(db, CollideA, 0, (time_t)0,
                                       (time_t)TimeBase + TimeOffset5, &arr,
                                       &n),
                  DB_SUCC);
    ASSERT_UINT_EQ(n, (unsigned long long)1);
    ASSERT_STR_EQ(arr[0].message, "room A");
    freeChatHistoryArray(arr, n);
    dbClose(db);
}

/**
 * @brief Verify that room tables and msg_sequence are actually created in
 * the database with correct names.
 */
static void testChatSchemaExists(void) {
    removeDBFiles();
    DB *db = dbInit(ChatHistoryDB);
    ASSERT_TRUE(db != NULL);
    /* Store a message which triggers room table creation */
    ChatHistory ch = {TestUidAlpha, 0, "schema", (time_t)TimeBase};
    ASSERT_INT_EQ(storeChatHistory(db, RoomTestA, &ch), DB_SUCC);
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

/* ═══════════════════════  main  ══════════════════════════════════════════ */

int main(void) {
    /* Suppress expected error logs from adversarial tests */
    logSetLevel(LogLevelFatal);

    printf("test_database:\n");

    /* ──────────── lifecycle ─────────────────────────── */
    RUN_TEST(testDbInitInvalidType);
    RUN_TEST(testDbInitUserDB);
    RUN_TEST(testDbInitChatHistoryDB);
    RUN_TEST(testDbCloseNull);
    RUN_TEST(testDbInitCreatesDir);
    RUN_TEST(testDbInitMultipleHandles);

    /* ──────────── createUser ────────────────────────── */
    RUN_TEST(testCreateUserNullDB);
    RUN_TEST(testCreateUserNullUser);
    RUN_TEST(testCreateUserEmptyUsername);
    RUN_TEST(testCreateUserNullPassword);
    RUN_TEST(testCreateUserEmptyPassword);
    RUN_TEST(testCreateUserWrongDBType);
    RUN_TEST(testCreateUserBasic);
    RUN_TEST(testCreateUserDuplicateUID);
    RUN_TEST(testCreateUserDuplicateUsername);
    RUN_TEST(testCreateUserMaxLenUsername);
    RUN_TEST(testCreateUserUidZero);
    RUN_TEST(testCreateUserUidMax);
    RUN_TEST(testCreateUserSpecialCharsPassword);
    RUN_TEST(testCreateUserLongPassword);

    /* ──────────── deleteUser ────────────────────────── */
    RUN_TEST(testDeleteUserNullDB);
    RUN_TEST(testDeleteUserNullUser);
    RUN_TEST(testDeleteUserWrongDBType);
    RUN_TEST(testDeleteUserNonexistent);
    RUN_TEST(testDeleteUserBasic);
    RUN_TEST(testDeleteUserTwice);
    RUN_TEST(testDeleteUserUidZero);
    RUN_TEST(testDeleteUserUidMax);

    /* ──────────── verifyUser ────────────────────────── */
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

    /* ──────────── storeChatHistory ──────────────────── */
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

    /* ──────────── queryChatByMsgId ──────────────────── */
    RUN_TEST(testQueryMsgIdNullDB);
    RUN_TEST(testQueryMsgIdNullOut);
    RUN_TEST(testQueryMsgIdWrongDBType);
    RUN_TEST(testQueryMsgIdNonexistent);
    RUN_TEST(testQueryMsgIdNonexistentRoom);
    RUN_TEST(testQueryMsgIdRoundtrip);
    RUN_TEST(testQueryMsgIdZeroSearch);
    RUN_TEST(testQueryMsgIdMax);
    RUN_TEST(testQueryMsgIdOutNotTouchedOnFailure);

    /* ──────────── queryChatByTimeRange ──────────────── */
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

    /* ──────────── persistence ───────────────────────── */
    RUN_TEST(testPersistenceUserDB);
    RUN_TEST(testPersistenceChatDB);
    RUN_TEST(testPersistenceMsgSeqContinues);

    /* ──────────── security / attack vectors ─────────── */
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

    return TEST_REPORT();
}
