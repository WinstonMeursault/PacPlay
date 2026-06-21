/**
 * @file test_online_tracker.c
 * @brief Unit tests for the OnlineTracker session tracking module.
 *
 * Pure unit tests — no DB, no sockets, no I/O.
 *
 * @date 2026-06-21
 * @copyright GPLv3 License
 */

#include "server/onlineTracker.h"
#include "server/server.h"
#include "test_utils.h"

#include <stdlib.h>
#include <string.h>

/* ──────────────────────────── test-local constants ──────────────────────── */

enum {
    TestUid = 100,
    UidA = 10,
    UidB = 20,
    UidC = 30,
    UidD = 40,
    UidE = 50,
    MultiUserCount = 5,
    NonexistentUid = 99999
};

/* ─────────────────────────────── test cases ─────────────────────────────── */

static void testCreateDestroy(void) {
    OnlineTracker *trk = onlineTrackerCreate();
    ASSERT_NOT_NULL(trk);
    onlineTrackerDestroy(trk);
}

static void testAddAndFind(void) {
    OnlineTracker *trk = onlineTrackerCreate();
    ASSERT_NOT_NULL(trk);

    ClientSession cs;
    memset(&cs, 0, sizeof(cs));
    cs.currentUser.uid = TestUid;

    onlineTrackerAdd(trk, TestUid, &cs);
    ClientSession *found = onlineTrackerFind(trk, TestUid);
    ASSERT_NOT_NULL(found);
    ASSERT_UINT_EQ(found->currentUser.uid, (uint32_t)TestUid);

    onlineTrackerDestroy(trk);
}

static void testAddAndIsOnline(void) {
    OnlineTracker *trk = onlineTrackerCreate();
    ASSERT_NOT_NULL(trk);

    ClientSession cs;
    memset(&cs, 0, sizeof(cs));
    cs.currentUser.uid = TestUid;

    onlineTrackerAdd(trk, TestUid, &cs);
    ASSERT_TRUE(onlineTrackerIsOnline(trk, TestUid));

    onlineTrackerDestroy(trk);
}

static void testRemove(void) {
    OnlineTracker *trk = onlineTrackerCreate();
    ASSERT_NOT_NULL(trk);

    ClientSession cs;
    memset(&cs, 0, sizeof(cs));
    cs.currentUser.uid = TestUid;

    onlineTrackerAdd(trk, TestUid, &cs);
    ASSERT_TRUE(onlineTrackerIsOnline(trk, TestUid));
    onlineTrackerRemove(trk, TestUid);
    ASSERT_FALSE(onlineTrackerIsOnline(trk, TestUid));

    onlineTrackerDestroy(trk);
}

static void testRemoveNonexistent(void) {
    OnlineTracker *trk = onlineTrackerCreate();
    ASSERT_NOT_NULL(trk);

    onlineTrackerRemove(trk, NonexistentUid);

    onlineTrackerDestroy(trk);
}

static void testFindNonexistent(void) {
    OnlineTracker *trk = onlineTrackerCreate();
    ASSERT_NOT_NULL(trk);

    ASSERT_NULL(onlineTrackerFind(trk, NonexistentUid));
    ASSERT_FALSE(onlineTrackerIsOnline(trk, NonexistentUid));

    onlineTrackerDestroy(trk);
}

static void testMultipleUsers(void) {
    OnlineTracker *trk = onlineTrackerCreate();
    ASSERT_NOT_NULL(trk);

    uint32_t uids[MultiUserCount] = {UidA, UidB, UidC, UidD, UidE};
    ClientSession sessions[MultiUserCount];

    for (int i = 0; i < MultiUserCount; i++) {
        memset(&sessions[i], 0, sizeof(sessions[i]));
        sessions[i].currentUser.uid = uids[i];
        onlineTrackerAdd(trk, uids[i], &sessions[i]);
    }

    for (int i = 0; i < MultiUserCount; i++) {
        ASSERT_TRUE(onlineTrackerIsOnline(trk, uids[i]));
        ClientSession *found = onlineTrackerFind(trk, uids[i]);
        ASSERT_NOT_NULL(found);
        ASSERT_UINT_EQ(found->currentUser.uid, uids[i]);
    }

    onlineTrackerDestroy(trk);
}

static void testAddTwiceOverwrites(void) {
    OnlineTracker *trk = onlineTrackerCreate();
    ASSERT_NOT_NULL(trk);

    ClientSession csA;
    memset(&csA, 0, sizeof(csA));
    csA.currentUser.uid = TestUid;
    csA.fd = 1;

    ClientSession csB;
    memset(&csB, 0, sizeof(csB));
    csB.currentUser.uid = TestUid;
    csB.fd = 2;

    onlineTrackerAdd(trk, TestUid, &csA);
    onlineTrackerAdd(trk, TestUid, &csB);
    ClientSession *found = onlineTrackerFind(trk, TestUid);
    ASSERT_NOT_NULL(found);
    ASSERT_INT_EQ(found->fd, csB.fd);

    onlineTrackerDestroy(trk);
}

static void testDestroyNull(void) { onlineTrackerDestroy(NULL); }

static void testAddNullTracker(void) {
    ClientSession cs;
    memset(&cs, 0, sizeof(cs));
    cs.currentUser.uid = TestUid;
    onlineTrackerAdd(NULL, TestUid, &cs);
}

static void testAddNullSession(void) {
    OnlineTracker *trk = onlineTrackerCreate();
    ASSERT_NOT_NULL(trk);

    onlineTrackerAdd(trk, TestUid, NULL);
    ASSERT_FALSE(onlineTrackerIsOnline(trk, TestUid));

    onlineTrackerDestroy(trk);
}

static void testFindNullTracker(void) {
    ASSERT_NULL(onlineTrackerFind(NULL, TestUid));
    ASSERT_FALSE(onlineTrackerIsOnline(NULL, TestUid));
}

static void testRemoveNullTracker(void) { onlineTrackerRemove(NULL, TestUid); }

/* ══════════════════════════════════ main ══════════════════════════════════ */

int main(void) {
    printf("test_online_tracker:\n");

    RUN_TEST(testCreateDestroy);
    RUN_TEST(testAddAndFind);
    RUN_TEST(testAddAndIsOnline);
    RUN_TEST(testRemove);
    RUN_TEST(testRemoveNonexistent);
    RUN_TEST(testFindNonexistent);
    RUN_TEST(testMultipleUsers);
    RUN_TEST(testAddTwiceOverwrites);
    RUN_TEST(testDestroyNull);
    RUN_TEST(testAddNullTracker);
    RUN_TEST(testAddNullSession);
    RUN_TEST(testFindNullTracker);
    RUN_TEST(testRemoveNullTracker);

    return TEST_REPORT();
}
