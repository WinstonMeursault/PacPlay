/**
 * @file test_group_db.c
 * @brief Adversarial unit tests for the PacPlay GroupDB module.
 *
 * Tests cover dbInit lifecycle, group create/delete, member management,
 * chat storage, history pagination, and last message timestamp operations.
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

enum { TestGroupId = 1, TestGroupId2 = 2 };
enum { TestOwnerUid = 1, TestMemberUid = 5, TestMemberUid2 = 7 };
enum { TestTimestamp = 1700000000 };
enum { TestTimestamp2 = 1700000001 };
enum { TestTimestamp3 = 1700000002 };
enum { DefaultLimit = 50 };
enum { SmallLimit = 2 };
enum { TestSentinelPtr = 1, TestMsgInsertCount = 5 };
enum { TestCountSentinel = 999 };

/* ──────────────────── file-level helpers ──────────────────── */

static void removeGroupDBFiles(void) {
    remove(GROUP_DB_PATH);
    remove(GROUP_DB_PATH "-wal");
    remove(GROUP_DB_PATH "-shm");
}

static const uint8_t testEncKey[DB_ENC_KEY_LEN];

static DB *testGroupDB(void) { return dbInit(GroupDB, testEncKey); }

static void freeChatArray(Chat *arr, size_t count) {
    for (size_t i = 0; i < count; i++) {
        free(arr[i].message);
    }
    free(arr);
}

/* ═══════════════════════════ 1. Schema Init ═══════════════════════════════ */

static void testGroupDBSchemaInit(void) {
    removeGroupDBFiles();
    DB *db = testGroupDB();
    ASSERT_NOT_NULL(db);
    ASSERT_INT_EQ(db->type, GroupDB);
    dbClose(db);
}

/* ═══════════════════════════ 2. Group Create / Delete ═════════════════════ */

static void testGroupCreate(void) {
    removeGroupDBFiles();
    DB *db = testGroupDB();
    ASSERT_NOT_NULL(db);
    ASSERT_INT_EQ(groupCreate(db, TestGroupId, "TestGroup", TestOwnerUid),
                  DB_SUCC);
    GroupInfo info;
    memset(&info, 0, sizeof(info));
    ASSERT_INT_EQ(groupGetInfo(db, TestGroupId, &info), DB_SUCC);
    ASSERT_STR_EQ(info.groupName, "TestGroup");
    ASSERT_UINT_EQ(info.ownerUid, TestOwnerUid);
    ASSERT_UINT_EQ(info.groupId, TestGroupId);
    dbClose(db);
}

static void testGroupDelete(void) {
    removeGroupDBFiles();
    DB *db = testGroupDB();
    ASSERT_NOT_NULL(db);
    ASSERT_INT_EQ(groupCreate(db, TestGroupId, "DelGroup", TestOwnerUid),
                  DB_SUCC);
    ASSERT_INT_EQ(groupDelete(db, TestGroupId), DB_SUCC);
    GroupInfo info;
    ASSERT_INT_EQ(groupGetInfo(db, TestGroupId, &info), DB_FAIL);
    dbClose(db);
}

/* ═══════════════════════════ 3. Member Management ═════════════════════════ */

static void testGroupAddMember(void) {
    removeGroupDBFiles();
    DB *db = testGroupDB();
    ASSERT_NOT_NULL(db);
    ASSERT_INT_EQ(groupCreate(db, TestGroupId, "MemGroup", TestOwnerUid),
                  DB_SUCC);
    ASSERT_INT_EQ(groupAddMember(db, TestGroupId, TestMemberUid), DB_SUCC);
    ASSERT_INT_EQ(groupIsMember(db, TestGroupId, TestMemberUid), DB_SUCC);
    uint32_t *uids = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(groupMemberList(db, TestGroupId, &uids, &count), DB_SUCC);
    ASSERT_UINT_EQ(count, 1);
    ASSERT_NOT_NULL(uids);
    ASSERT_UINT_EQ(uids[0], TestMemberUid);
    free(uids);
    dbClose(db);
}

static void testGroupRemoveMember(void) {
    removeGroupDBFiles();
    DB *db = testGroupDB();
    ASSERT_NOT_NULL(db);
    ASSERT_INT_EQ(groupCreate(db, TestGroupId, "RemGroup", TestOwnerUid),
                  DB_SUCC);
    ASSERT_INT_EQ(groupAddMember(db, TestGroupId, TestMemberUid), DB_SUCC);
    ASSERT_INT_EQ(groupRemoveMember(db, TestGroupId, TestMemberUid), DB_SUCC);
    ASSERT_INT_EQ(groupIsMember(db, TestGroupId, TestMemberUid), DB_FAIL);
    dbClose(db);
}

static void testGroupAddMemberDuplicate(void) {
    removeGroupDBFiles();
    DB *db = testGroupDB();
    ASSERT_NOT_NULL(db);
    ASSERT_INT_EQ(groupCreate(db, TestGroupId, "DupGroup", TestOwnerUid),
                  DB_SUCC);
    ASSERT_INT_EQ(groupAddMember(db, TestGroupId, TestMemberUid), DB_SUCC);
    /* Duplicate add: implementation returns DB_FAIL (UNIQUE constraint);
     * verify member is still present and count is 1. */
    groupAddMember(db, TestGroupId, TestMemberUid);
    ASSERT_INT_EQ(groupIsMember(db, TestGroupId, TestMemberUid), DB_SUCC);
    uint32_t *uids = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(groupMemberList(db, TestGroupId, &uids, &count), DB_SUCC);
    ASSERT_UINT_EQ(count, 1);
    free(uids);
    dbClose(db);
}

/* ═══════════════════════════ 4. Group Listing ═════════════════════════════ */

static void testGroupListAll(void) {
    removeGroupDBFiles();
    DB *db = testGroupDB();
    ASSERT_NOT_NULL(db);
    ASSERT_INT_EQ(groupCreate(db, TestGroupId, "GroupA", TestOwnerUid),
                  DB_SUCC);
    ASSERT_INT_EQ(groupCreate(db, TestGroupId2, "GroupB", TestOwnerUid),
                  DB_SUCC);
    GroupInfo *groups = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(groupListAll(db, &groups, &count), DB_SUCC);
    ASSERT_UINT_EQ(count, 2);
    ASSERT_NOT_NULL(groups);
    free(groups);
    dbClose(db);
}

/* ═══════════════════════════ 5. Group Chat ════════════════════════════════ */

static void testGroupStoreChat(void) {
    removeGroupDBFiles();
    DB *db = testGroupDB();
    ASSERT_NOT_NULL(db);
    ASSERT_INT_EQ(groupCreate(db, TestGroupId, "ChatGroup", TestOwnerUid),
                  DB_SUCC);
    uint64_t msgId = 0;
    ASSERT_INT_EQ(groupStoreChat(db, TestGroupId, TestOwnerUid, "Hello group",
                                 (int64_t)TestTimestamp, &msgId),
                  DB_SUCC);
    ASSERT_TRUE(msgId > 0);
    dbClose(db);
}

static void testGroupChatHistory(void) {
    removeGroupDBFiles();
    DB *db = testGroupDB();
    ASSERT_NOT_NULL(db);
    ASSERT_INT_EQ(groupCreate(db, TestGroupId, "HistGroup", TestOwnerUid),
                  DB_SUCC);
    uint64_t msgIdDummy = 0;
    ASSERT_INT_EQ(groupStoreChat(db, TestGroupId, TestOwnerUid, "Msg1",
                                 (int64_t)TestTimestamp, &msgIdDummy),
                  DB_SUCC);
    ASSERT_INT_EQ(groupStoreChat(db, TestGroupId, TestMemberUid, "Msg2",
                                 (int64_t)TestTimestamp2, &msgIdDummy),
                  DB_SUCC);
    ASSERT_INT_EQ(groupStoreChat(db, TestGroupId, TestOwnerUid, "Msg3",
                                 (int64_t)TestTimestamp3, &msgIdDummy),
                  DB_SUCC);
    Chat *out = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(groupChatHistory(db, TestGroupId, UINT32_MAX, DefaultLimit,
                                   &out, &count),
                  DB_SUCC);
    ASSERT_UINT_EQ(count, 3);
    ASSERT_NOT_NULL(out);
    /* groupChatHistory reverses to ASC (chronological) order */
    ASSERT_STR_EQ(out[0].message, "Msg1");
    ASSERT_STR_EQ(out[1].message, "Msg2");
    ASSERT_STR_EQ(out[2].message, "Msg3");
    freeChatArray(out, count);
    dbClose(db);
}

static void testGroupChatHistoryLimit(void) {
    removeGroupDBFiles();
    DB *db = testGroupDB();
    ASSERT_NOT_NULL(db);
    ASSERT_INT_EQ(groupCreate(db, TestGroupId, "LimGroup", TestOwnerUid),
                  DB_SUCC);
    uint64_t msgIdDummy = 0;
    for (int i = 0; i < TestMsgInsertCount; i++) {
        ASSERT_INT_EQ(groupStoreChat(db, TestGroupId, TestOwnerUid, "Msg",
                                     (int64_t)(TestTimestamp + i), &msgIdDummy),
                      DB_SUCC);
    }
    Chat *out = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(
        groupChatHistory(db, TestGroupId, UINT32_MAX, SmallLimit, &out, &count),
        DB_SUCC);
    ASSERT_UINT_EQ(count, 2);
    ASSERT_NOT_NULL(out);
    freeChatArray(out, count);
    dbClose(db);
}

/* ═══════════════════════ 6. Last Message Timestamp ════════════════════════ */

static void testGroupLastMsgTimestamp(void) {
    removeGroupDBFiles();
    DB *db = testGroupDB();
    ASSERT_NOT_NULL(db);
    ASSERT_INT_EQ(groupCreate(db, TestGroupId, "TsGroup", TestOwnerUid),
                  DB_SUCC);
    uint64_t msgIdDummy = 0;
    ASSERT_INT_EQ(groupStoreChat(db, TestGroupId, TestOwnerUid, "Hello",
                                 (int64_t)TestTimestamp, &msgIdDummy),
                  DB_SUCC);
    uint64_t outTs = 0;
    ASSERT_INT_EQ(groupLastMsgTimestamp(db, TestGroupId, &outTs), DB_SUCC);
    ASSERT_UINT_EQ(outTs, (uint64_t)TestTimestamp);
    dbClose(db);
}

static void testGroupLastMsgTimestampEmpty(void) {
    removeGroupDBFiles();
    DB *db = testGroupDB();
    ASSERT_NOT_NULL(db);
    ASSERT_INT_EQ(groupCreate(db, TestGroupId, "EmptyGroup", TestOwnerUid),
                  DB_SUCC);
    uint64_t outTs = 1;
    ASSERT_INT_EQ(groupLastMsgTimestamp(db, TestGroupId, &outTs), DB_SUCC);
    ASSERT_UINT_EQ(outTs, 0);
    dbClose(db);
}

/* ════════════════════════════════ main ════════════════════════════════════ */

int main(void) {
    logSetLevel(LogLevelFatal);

    printf("test_group_db:\n");

    RUN_TEST(testGroupDBSchemaInit);
    RUN_TEST(testGroupCreate);
    RUN_TEST(testGroupDelete);
    RUN_TEST(testGroupAddMember);
    RUN_TEST(testGroupRemoveMember);
    RUN_TEST(testGroupAddMemberDuplicate);
    RUN_TEST(testGroupListAll);
    RUN_TEST(testGroupStoreChat);
    RUN_TEST(testGroupChatHistory);
    RUN_TEST(testGroupChatHistoryLimit);
    RUN_TEST(testGroupLastMsgTimestamp);
    RUN_TEST(testGroupLastMsgTimestampEmpty);

    removeGroupDBFiles();

    return TEST_REPORT();
}
