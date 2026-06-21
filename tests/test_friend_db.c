/**
 * @file test_friend_db.c
 * @brief Adversarial unit tests for the PacPlay FriendDB module.
 *
 * Tests cover dbInit/dbClose lifecycle, friend request CRUD,
 * acceptance/rejection flow, friendship deletion, friend listing,
 * pending request listing, and edge cases (duplicate requests,
 * self-requests, empty lists, non-friend checks).
 *
 * Each test opens a fresh FriendDB in ./db/friend.db and cleans up
 * afterwards.
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

#include "log.h"
#include "server/database.h"
#include "test_utils.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ──────────────────── helper constants for readability ──────────────────── */

enum {
    TestUidAlice = 1000,
    TestUidBob = 2000,
    TestUidCharlie = 3000,
    TestUidDave = 4000
};

/* ─────────────────────────── file-level helpers ─────────────────────────── */

/** @brief Remove stale FriendDB test files so each test starts clean. */
static void removeFriendDBFiles(void) {
    remove("./db/friend.db");
    remove("./db/friend.db-wal");
    remove("./db/friend.db-shm");
}

/**
 * @brief Open a fresh FriendDB for testing.
 *
 * Removes any stale FriendDB files, calls dbInit(FriendDB, NULL),
 * and validates the handle.  Returns NULL on failure.
 */
static DB *testFriendDB(void) {
    removeFriendDBFiles();
    return dbInit(FriendDB, NULL);
}

/** @brief Free a FriendInfo array returned by friendListGet or
 * friendRequestPendingList. */
static void freeFriendInfoArray(FriendInfo *arr, size_t count) {
    (void)count;
    free(arr);
}

/* ═══════════════════════════ 1. Schema Init ═══════════════════════════════ */

/** @brief dbInit with FriendDB type succeeds and returns correct type. */
static void testFriendDBSchemaInit(void) {
    removeFriendDBFiles();
    DB *db = dbInit(FriendDB, NULL);
    ASSERT_NOT_NULL(db);
    ASSERT_INT_EQ(db->type, FriendDB);
    dbClose(db);
}

/** @brief dbInit with FriendDB is idempotent (multiple calls work). */
static void testFriendDBInitIdempotent(void) {
    removeFriendDBFiles();
    DB *db1 = dbInit(FriendDB, NULL);
    ASSERT_NOT_NULL(db1);
    DB *db2 = dbInit(FriendDB, NULL);
    ASSERT_NOT_NULL(db2);
    ASSERT_TRUE(db1 != db2);
    dbClose(db1);
    dbClose(db2);
}

/* ═══════════════════════ 2. Friend Request Create ═════════════════════════ */

/** @brief friendRequestCreate rejects NULL database. */
static void testFriendRequestCreateNullDB(void) {
    ASSERT_INT_EQ(friendRequestCreate(NULL, TestUidAlice, TestUidBob), DB_FAIL);
}

/** @brief friendRequestCreate with valid arguments succeeds. */
static void testFriendRequestCreateSuccess(void) {
    DB *db = testFriendDB();
    ASSERT_NOT_NULL(db);
    ASSERT_INT_EQ(friendRequestCreate(db, TestUidAlice, TestUidBob), DB_SUCC);
    dbClose(db);
}

/** @brief friendRequestCreate from self to self is rejected. */
static void testFriendRequestSelfRequest(void) {
    DB *db = testFriendDB();
    ASSERT_NOT_NULL(db);
    ASSERT_INT_EQ(friendRequestCreate(db, TestUidAlice, TestUidAlice), DB_FAIL);
    dbClose(db);
}

/** @brief friendRequestCreate with duplicate (same fromUid, toUid) fails. */
static void testFriendRequestDuplicate(void) {
    DB *db = testFriendDB();
    ASSERT_NOT_NULL(db);
    ASSERT_INT_EQ(friendRequestCreate(db, TestUidAlice, TestUidBob), DB_SUCC);
    ASSERT_INT_EQ(friendRequestCreate(db, TestUidAlice, TestUidBob), DB_FAIL);
    dbClose(db);
}

/* ═══════════════════════ 3. Friend Request Accept ═════════════════════════ */

/** @brief Accepting a friend request makes both users friends. */
static void testFriendRequestCreateAndAccept(void) {
    DB *db = testFriendDB();
    ASSERT_NOT_NULL(db);

    ASSERT_INT_EQ(friendRequestCreate(db, TestUidAlice, TestUidBob), DB_SUCC);
    ASSERT_INT_EQ(friendRequestAccept(db, TestUidAlice, TestUidBob), DB_SUCC);

    ASSERT_INT_EQ(friendIsFriend(db, TestUidAlice, TestUidBob), DB_SUCC);
    ASSERT_INT_EQ(friendIsFriend(db, TestUidBob, TestUidAlice), DB_SUCC);

    dbClose(db);
}

/** @brief Accept clears the request from the pending list. */
static void testFriendRequestAcceptClearsPending(void) {
    DB *db = testFriendDB();
    ASSERT_NOT_NULL(db);

    ASSERT_INT_EQ(friendRequestCreate(db, TestUidAlice, TestUidBob), DB_SUCC);
    ASSERT_INT_EQ(friendRequestAccept(db, TestUidAlice, TestUidBob), DB_SUCC);

    FriendInfo *pending = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(friendRequestPendingList(db, TestUidBob, &pending, &count),
                  DB_SUCC);
    ASSERT_UINT_EQ(count, 0);
    ASSERT_NULL(pending);

    dbClose(db);
}

/* ═══════════════════════ 4. Friend Request Reject ═════════════════════════ */

/** @brief Rejecting a friend request does not create a friendship. */
static void testFriendRequestReject(void) {
    DB *db = testFriendDB();
    ASSERT_NOT_NULL(db);

    ASSERT_INT_EQ(friendRequestCreate(db, TestUidAlice, TestUidBob), DB_SUCC);
    ASSERT_INT_EQ(friendRequestReject(db, TestUidAlice, TestUidBob), DB_SUCC);

    ASSERT_INT_EQ(friendIsFriend(db, TestUidAlice, TestUidBob), DB_FAIL);
    ASSERT_INT_EQ(friendIsFriend(db, TestUidBob, TestUidAlice), DB_FAIL);

    dbClose(db);
}

/** @brief Reject clears the request from the pending list. */
static void testFriendRequestRejectClearsPending(void) {
    DB *db = testFriendDB();
    ASSERT_NOT_NULL(db);

    ASSERT_INT_EQ(friendRequestCreate(db, TestUidAlice, TestUidBob), DB_SUCC);
    ASSERT_INT_EQ(friendRequestReject(db, TestUidAlice, TestUidBob), DB_SUCC);

    FriendInfo *pending = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(friendRequestPendingList(db, TestUidBob, &pending, &count),
                  DB_SUCC);
    ASSERT_UINT_EQ(count, 0);
    ASSERT_NULL(pending);

    dbClose(db);
}

/* ═══════════════════════ 5. Friend Delete ═════════════════════════════════ */

/** @brief Deleting a friendship after accept removes both directions. */
static void testFriendDelete(void) {
    DB *db = testFriendDB();
    ASSERT_NOT_NULL(db);

    ASSERT_INT_EQ(friendRequestCreate(db, TestUidAlice, TestUidBob), DB_SUCC);
    ASSERT_INT_EQ(friendRequestAccept(db, TestUidAlice, TestUidBob), DB_SUCC);
    ASSERT_INT_EQ(friendIsFriend(db, TestUidAlice, TestUidBob), DB_SUCC);

    ASSERT_INT_EQ(friendDelete(db, TestUidAlice, TestUidBob), DB_SUCC);
    ASSERT_INT_EQ(friendIsFriend(db, TestUidAlice, TestUidBob), DB_FAIL);
    ASSERT_INT_EQ(friendIsFriend(db, TestUidBob, TestUidAlice), DB_FAIL);

    dbClose(db);
}

/* ═══════════════════════ 6. Friend List Get ═══════════════════════════════ */

/** @brief After accepting 2 requests, friendListGet returns 2 entries. */
static void testFriendListGet(void) {
    DB *db = testFriendDB();
    ASSERT_NOT_NULL(db);

    ASSERT_INT_EQ(friendRequestCreate(db, TestUidAlice, TestUidBob), DB_SUCC);
    ASSERT_INT_EQ(friendRequestAccept(db, TestUidAlice, TestUidBob), DB_SUCC);

    ASSERT_INT_EQ(friendRequestCreate(db, TestUidCharlie, TestUidBob), DB_SUCC);
    ASSERT_INT_EQ(friendRequestAccept(db, TestUidCharlie, TestUidBob), DB_SUCC);

    FriendInfo *friends = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(friendListGet(db, TestUidBob, &friends, &count), DB_SUCC);
    ASSERT_NOT_NULL(friends);
    ASSERT_UINT_EQ(count, 2);

    uint32_t friendUids[2] = {0, 0};
    for (size_t i = 0; i < count; i++) {
        friendUids[i] = friends[i].uid;
    }

    int foundAlice = 0;
    int foundCharlie = 0;
    for (size_t i = 0; i < count; i++) {
        if (friendUids[i] == TestUidAlice) {
            foundAlice = 1;
        }
        if (friendUids[i] == TestUidCharlie) {
            foundCharlie = 1;
        }
    }
    ASSERT_TRUE(foundAlice);
    ASSERT_TRUE(foundCharlie);

    freeFriendInfoArray(friends, count);
    dbClose(db);
}

/** @brief A new user with no friends has an empty friend list. */
static void testFriendListEmpty(void) {
    DB *db = testFriendDB();
    ASSERT_NOT_NULL(db);

    FriendInfo *friends = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(friendListGet(db, TestUidAlice, &friends, &count), DB_SUCC);
    ASSERT_UINT_EQ(count, 0);
    ASSERT_NULL(friends);

    dbClose(db);
}

/* ═══════════════════ 7. Friend Request Pending List ═══════════════════════ */

/** @brief Pending list shows incoming requests. */
static void testFriendRequestPendingList(void) {
    DB *db = testFriendDB();
    ASSERT_NOT_NULL(db);

    ASSERT_INT_EQ(friendRequestCreate(db, TestUidAlice, TestUidBob), DB_SUCC);

    FriendInfo *pending = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(friendRequestPendingList(db, TestUidBob, &pending, &count),
                  DB_SUCC);
    ASSERT_NOT_NULL(pending);
    ASSERT_UINT_EQ(count, 1);
    ASSERT_UINT_EQ(pending[0].uid, TestUidAlice);

    freeFriendInfoArray(pending, count);
    dbClose(db);
}

/** @brief Pending list for a user with no requests is empty. */
static void testFriendRequestPendingListEmpty(void) {
    DB *db = testFriendDB();
    ASSERT_NOT_NULL(db);

    FriendInfo *pending = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(friendRequestPendingList(db, TestUidAlice, &pending, &count),
                  DB_SUCC);
    ASSERT_UINT_EQ(count, 0);
    ASSERT_NULL(pending);

    dbClose(db);
}

/* ════════════════════════ 8. Friend Is Friend ═════════════════════════════ */

/** @brief friendIsFriend returns DB_SUCC after accept, DB_FAIL before. */
static void testFriendIsFriend(void) {
    DB *db = testFriendDB();
    ASSERT_NOT_NULL(db);

    ASSERT_INT_EQ(friendIsFriend(db, TestUidAlice, TestUidBob), DB_FAIL);

    ASSERT_INT_EQ(friendRequestCreate(db, TestUidAlice, TestUidBob), DB_SUCC);
    ASSERT_INT_EQ(friendIsFriend(db, TestUidAlice, TestUidBob), DB_FAIL);

    ASSERT_INT_EQ(friendRequestAccept(db, TestUidAlice, TestUidBob), DB_SUCC);
    ASSERT_INT_EQ(friendIsFriend(db, TestUidAlice, TestUidBob), DB_SUCC);
    ASSERT_INT_EQ(friendIsFriend(db, TestUidBob, TestUidAlice), DB_SUCC);

    dbClose(db);
}

/* ════════════════════════ 9. Edge Cases ═══════════════════════════════════ */

/** @brief Re-accepting an already accepted request is a no-op on the
 *  friendships table (INSERT OR IGNORE). */
static void testFriendAcceptTwice(void) {
    DB *db = testFriendDB();
    ASSERT_NOT_NULL(db);

    ASSERT_INT_EQ(friendRequestCreate(db, TestUidAlice, TestUidBob), DB_SUCC);
    ASSERT_INT_EQ(friendRequestAccept(db, TestUidAlice, TestUidBob), DB_SUCC);
    /* Accepting again: the UPDATE won't match (status != 0), but we still
     * check it returns without crashing. The INSERT OR IGNORE prevents
     * duplicate rows. */
    ASSERT_INT_EQ(friendRequestAccept(db, TestUidAlice, TestUidBob), DB_SUCC);
    ASSERT_INT_EQ(friendIsFriend(db, TestUidAlice, TestUidBob), DB_SUCC);

    dbClose(db);
}

/** @brief Deleting a non-existent friendship is a no-op. */
static void testFriendDeleteNonExistent(void) {
    DB *db = testFriendDB();
    ASSERT_NOT_NULL(db);

    ASSERT_INT_EQ(friendDelete(db, TestUidAlice, TestUidBob), DB_SUCC);
    ASSERT_INT_EQ(friendIsFriend(db, TestUidAlice, TestUidBob), DB_FAIL);

    dbClose(db);
}

/** @brief Accepting a friend request with reversed (uid1, uid2) — the
 *  accept API expects (fromUid, toUid) matching the original request. */
static void testFriendRequestAcceptReversed(void) {
    DB *db = testFriendDB();
    ASSERT_NOT_NULL(db);

    ASSERT_INT_EQ(friendRequestCreate(db, TestUidAlice, TestUidBob), DB_SUCC);
    /* Accept with reversed order — the UPDATE won't match, so step
     * returns SQLITE_DONE (0 rows changed) but still succeeds. */
    ASSERT_INT_EQ(friendRequestAccept(db, TestUidBob, TestUidAlice), DB_SUCC);
    /* INSERT OR IGNORE creates the friendship regardless. */
    ASSERT_INT_EQ(friendIsFriend(db, TestUidAlice, TestUidBob), DB_SUCC);

    dbClose(db);
}

/* ═══════════════════════════════ main ══════════════════════════════════════
 */

int main(void) {
    printf("\n=== FriendDB Tests ===\n\n");

    /* 1. Schema Init */
    RUN_TEST(testFriendDBSchemaInit);
    RUN_TEST(testFriendDBInitIdempotent);

    /* 2. Friend Request Create */
    RUN_TEST(testFriendRequestCreateNullDB);
    RUN_TEST(testFriendRequestCreateSuccess);
    RUN_TEST(testFriendRequestSelfRequest);
    RUN_TEST(testFriendRequestDuplicate);

    /* 3. Friend Request Accept */
    RUN_TEST(testFriendRequestCreateAndAccept);
    RUN_TEST(testFriendRequestAcceptClearsPending);

    /* 4. Friend Request Reject */
    RUN_TEST(testFriendRequestReject);
    RUN_TEST(testFriendRequestRejectClearsPending);

    /* 5. Friend Delete */
    RUN_TEST(testFriendDelete);

    /* 6. Friend List Get */
    RUN_TEST(testFriendListGet);
    RUN_TEST(testFriendListEmpty);

    /* 7. Friend Request Pending List */
    RUN_TEST(testFriendRequestPendingList);
    RUN_TEST(testFriendRequestPendingListEmpty);

    /* 8. Friend Is Friend */
    RUN_TEST(testFriendIsFriend);

    /* 9. Edge Cases */
    RUN_TEST(testFriendAcceptTwice);
    RUN_TEST(testFriendDeleteNonExistent);
    RUN_TEST(testFriendRequestAcceptReversed);

    return TEST_REPORT();
}
