/**
 * @file test_private_chat_db.c
 * @brief Adversarial unit tests for the PacPlay PrivateChatDB module.
 *
 * Tests cover dbInit lifecycle, message store, deliver pending, chat
 * history pagination, and last message timestamp operations.
 *
 * @date 2026-06-21
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
#include "server/database/internal.h"
#include "server/server.h"
#include "test_utils.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* ──────────────────── helper constants for readability ──────────────────── */

enum { TestUidA = 100, TestUidB = 101, TestUidC = 102 };
enum { TestTimestamp = 1700000000 };
enum { TestTimestamp2 = 1700000001 };
enum { TestTimestamp3 = 1700000002 };
enum { TestTimestamp4 = 1700000003 };
enum { TestTimestamp5 = 1700000004 };
enum { DefaultLimit = 50 };
enum { SmallLimit = 2 };
enum { TestSentinelPtr = 1, TestMessageCount = 5 };
enum { TestCountSentinel = 999 };

/* ──────────────────── file-level helpers ──────────────────── */

static void removePrivateChatDBFiles(void) {
    remove(PRIVATE_CHAT_DB_PATH);
    remove(PRIVATE_CHAT_DB_PATH "-wal");
    remove(PRIVATE_CHAT_DB_PATH "-shm");
}

static const uint8_t testEncKey[DB_ENC_KEY_LEN];

static DB *testPrivateChatDB(void) { return dbInit(PrivateChatDB, testEncKey); }

static void freeChatArray(Chat *arr, size_t count) {
    for (size_t i = 0; i < count; i++) {
        free(arr[i].message);
    }
    free(arr);
}

/* ═══════════════════════════ 1. Schema Init ═══════════════════════════════ */

static void testPrivateChatDBSchemaInit(void) {
    removePrivateChatDBFiles();
    DB *db = testPrivateChatDB();
    ASSERT_NOT_NULL(db);
    ASSERT_INT_EQ(db->type, PrivateChatDB);
    dbClose(db);
}

/* ═══════════════════════════ 2. Store Message ═════════════════════════════ */

static void testPrivateChatStore(void) {
    removePrivateChatDBFiles();
    DB *db = testPrivateChatDB();
    ASSERT_NOT_NULL(db);
    uint32_t msgId = 0;
    ASSERT_INT_EQ(privateChatStore(db, TestUidA, TestUidB,
                                   (const uint8_t *)"Hello",
                                   (uint64_t)TestTimestamp, &msgId),
                  DB_SUCC);
    ASSERT_TRUE(msgId > 0);
    dbClose(db);
}

static void testPrivateChatStoreEmptyMessage(void) {
    removePrivateChatDBFiles();
    DB *db = testPrivateChatDB();
    ASSERT_NOT_NULL(db);
    uint32_t msgId = 0;
    ASSERT_INT_EQ(privateChatStore(db, TestUidA, TestUidB, (const uint8_t *)"",
                                   (uint64_t)TestTimestamp, &msgId),
                  DB_FAIL);
    dbClose(db);
}

/* ═══════════════════════════ 3. Deliver Pending ═══════════════════════════ */

static void testPrivateChatDeliverPending(void) {
    removePrivateChatDBFiles();
    DB *db = testPrivateChatDB();
    ASSERT_NOT_NULL(db);
    ASSERT_INT_EQ(privateChatStore(db, TestUidA, TestUidB,
                                   (const uint8_t *)"Pending msg",
                                   (uint64_t)TestTimestamp, NULL),
                  DB_SUCC);
    Chat *out = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(privateChatDeliverPending(db, TestUidB, &out, &count),
                  DB_SUCC);
    ASSERT_UINT_EQ(count, 1);
    ASSERT_NOT_NULL(out);
    ASSERT_STR_EQ(out[0].message, "Pending msg");
    ASSERT_UINT_EQ(out[0].uid, TestUidA);
    freeChatArray(out, count);
    ASSERT_INT_EQ(privateChatDeliverPending(db, TestUidB, &out, &count),
                  DB_SUCC);
    ASSERT_UINT_EQ(count, 0);
    ASSERT_NULL(out);
    dbClose(db);
}

static void testPrivateChatDeliverPendingNone(void) {
    removePrivateChatDBFiles();
    DB *db = testPrivateChatDB();
    ASSERT_NOT_NULL(db);
    Chat *out = (Chat *)(uintptr_t)TestSentinelPtr;
    size_t count = TestCountSentinel;
    ASSERT_INT_EQ(privateChatDeliverPending(db, TestUidB, &out, &count),
                  DB_SUCC);
    ASSERT_UINT_EQ(count, 0);
    ASSERT_NULL(out);
    dbClose(db);
}

/* ═══════════════════════════ 4. Chat History ══════════════════════════════ */

static void testPrivateChatHistory(void) {
    removePrivateChatDBFiles();
    DB *db = testPrivateChatDB();
    ASSERT_NOT_NULL(db);
    ASSERT_INT_EQ(privateChatStore(db, TestUidA, TestUidB,
                                   (const uint8_t *)"Msg1",
                                   (uint64_t)TestTimestamp, NULL),
                  DB_SUCC);
    ASSERT_INT_EQ(privateChatStore(db, TestUidB, TestUidA,
                                   (const uint8_t *)"Msg2",
                                   (uint64_t)TestTimestamp2, NULL),
                  DB_SUCC);
    ASSERT_INT_EQ(privateChatStore(db, TestUidA, TestUidB,
                                   (const uint8_t *)"Msg3",
                                   (uint64_t)TestTimestamp3, NULL),
                  DB_SUCC);
    Chat *out = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(privateChatHistory(db, TestUidA, TestUidB, 0, DefaultLimit,
                                     &out, &count),
                  DB_SUCC);
    ASSERT_UINT_EQ(count, 3);
    ASSERT_NOT_NULL(out);
    /* Messages ordered by msgId descending: Msg3, Msg2, Msg1 */
    ASSERT_STR_EQ(out[0].message, "Msg3");
    ASSERT_STR_EQ(out[1].message, "Msg2");
    ASSERT_STR_EQ(out[2].message, "Msg1");
    freeChatArray(out, count);
    dbClose(db);
}

static void testPrivateChatHistoryLimit(void) {
    removePrivateChatDBFiles();
    DB *db = testPrivateChatDB();
    ASSERT_NOT_NULL(db);
    uint32_t msgId = 0;
    for (int i = 0; i < TestMessageCount; i++) {
        ASSERT_INT_EQ(privateChatStore(db, TestUidA, TestUidB,
                                       (const uint8_t *)"Msg",
                                       (uint64_t)(TestTimestamp + i), &msgId),
                      DB_SUCC);
    }
    Chat *out = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(
        privateChatHistory(db, TestUidA, TestUidB, 0, SmallLimit, &out, &count),
        DB_SUCC);
    ASSERT_UINT_EQ(count, 2);
    ASSERT_NOT_NULL(out);
    freeChatArray(out, count);
    dbClose(db);
}

static void testPrivateChatHistoryBeforeMsgId(void) {
    removePrivateChatDBFiles();
    DB *db = testPrivateChatDB();
    ASSERT_NOT_NULL(db);
    uint32_t msgId1 = 0, msgId2 = 0, msgId3 = 0;
    ASSERT_INT_EQ(privateChatStore(db, TestUidA, TestUidB,
                                   (const uint8_t *)"Msg1",
                                   (uint64_t)TestTimestamp, &msgId1),
                  DB_SUCC);
    ASSERT_INT_EQ(privateChatStore(db, TestUidB, TestUidA,
                                   (const uint8_t *)"Msg2",
                                   (uint64_t)TestTimestamp2, &msgId2),
                  DB_SUCC);
    ASSERT_INT_EQ(privateChatStore(db, TestUidA, TestUidB,
                                   (const uint8_t *)"Msg3",
                                   (uint64_t)TestTimestamp3, &msgId3),
                  DB_SUCC);
    (void)msgId3;
    Chat *out = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(privateChatHistory(db, TestUidA, TestUidB, msgId2,
                                     DefaultLimit, &out, &count),
                  DB_SUCC);
    ASSERT_UINT_EQ(count, 1);
    ASSERT_NOT_NULL(out);
    ASSERT_UINT_EQ(out[0].msgId, msgId1);
    ASSERT_STR_EQ(out[0].message, "Msg1");
    freeChatArray(out, count);
    dbClose(db);
}

/* ═══════════════════════ 5. Last Message Timestamp ════════════════════════ */

static void testPrivateChatLastMsgTimestamp(void) {
    removePrivateChatDBFiles();
    DB *db = testPrivateChatDB();
    ASSERT_NOT_NULL(db);
    ASSERT_INT_EQ(privateChatStore(db, TestUidA, TestUidB,
                                   (const uint8_t *)"Hello",
                                   (uint64_t)TestTimestamp, NULL),
                  DB_SUCC);
    uint64_t outTs = 0;
    ASSERT_INT_EQ(privateChatLastMsgTimestamp(db, TestUidA, TestUidB, &outTs),
                  DB_SUCC);
    ASSERT_UINT_EQ(outTs, (uint64_t)TestTimestamp);
    dbClose(db);
}

static void testPrivateChatLastMsgTimestampEmpty(void) {
    removePrivateChatDBFiles();
    DB *db = testPrivateChatDB();
    ASSERT_NOT_NULL(db);
    uint64_t outTs = 1;
    ASSERT_INT_EQ(privateChatLastMsgTimestamp(db, TestUidA, TestUidB, &outTs),
                  DB_SUCC);
    ASSERT_UINT_EQ(outTs, 0);
    dbClose(db);
}

/* ════════════════════════════════ main ════════════════════════════════════ */

int main(void) {
    logSetLevel(LogLevelFatal);

    printf("test_private_chat_db:\n");

    RUN_TEST(testPrivateChatDBSchemaInit);
    RUN_TEST(testPrivateChatStore);
    RUN_TEST(testPrivateChatStoreEmptyMessage);
    RUN_TEST(testPrivateChatDeliverPending);
    RUN_TEST(testPrivateChatDeliverPendingNone);
    RUN_TEST(testPrivateChatHistory);
    RUN_TEST(testPrivateChatHistoryLimit);
    RUN_TEST(testPrivateChatHistoryBeforeMsgId);
    RUN_TEST(testPrivateChatLastMsgTimestamp);
    RUN_TEST(testPrivateChatLastMsgTimestampEmpty);

    removePrivateChatDBFiles();

    return TEST_REPORT();
}
