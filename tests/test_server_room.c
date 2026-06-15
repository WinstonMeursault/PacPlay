/**
 * @file test_server_room.c
 * @brief Thorough unit tests for the ActiveRoom lifecycle helpers in room.c.
 *
 * Focuses on capacity growth (realloc triggers), array boundary operations,
 * multi-member management, and edge-case room IDs.
 *
 * @date 2026-06-15
 * @copyright GPLv3 License
 */

#include "server/room.h"
#include "server/server.h"
#include "test_utils.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ────────────────────────── test-local constants ────────────────────────── */

enum {
    RoomA = 1,
    RoomB = 2,
    RoomC = 3,
    RoomD = 4,
    RoomE = 5,
    RoomZero = 0,
    RoomGrowCount = 20,
    RoomRemoveTarget = 99,
    InitCap = 4,
    MembersTwo = 2,
    MembersThree = 3
};

static const uint32_t roomMax = UINT32_MAX;

/* ───────────────────────────── test helpers ─────────────────────────────── */

static Server makeTestServer(int capacity) {
    Server s;
    memset(&s, 0, sizeof(s));
    s.activeRoomCapacity = capacity;
    s.activeRooms =
        (ActiveRoom **)calloc((size_t)capacity, sizeof(ActiveRoom *));
    return s;
}

static void freeTestServer(Server *s) {
    for (int i = 0; i < s->activeRoomCount; i++) {
        free(s->activeRooms[i]);
    }
    free((void *)s->activeRooms);
    s->activeRooms = NULL;
    s->activeRoomCount = 0;
    s->activeRoomCapacity = 0;
}

/* ─────────────── capacity growth (realloc trigger) tests ────────────────── */

static void testCapacityGrowthTriggerRealloc(void) {
    Server s = makeTestServer(InitCap);
    ASSERT_TRUE(s.activeRooms != NULL);

    for (int i = 0; i < RoomGrowCount; i++) {
        ActiveRoom *room =
            serverGetOrCreateActiveRoom(&s, (uint32_t)(RoomA + i));
        ASSERT_TRUE(room != NULL);
        ASSERT_UINT_EQ(room->roomId, (uint32_t)(RoomA + i));
    }
    ASSERT_INT_EQ(s.activeRoomCount, RoomGrowCount);
    ASSERT_TRUE(s.activeRoomCapacity >= RoomGrowCount);

    for (int i = 0; i < RoomGrowCount; i++) {
        ActiveRoom *found = serverFindActiveRoom(&s, (uint32_t)(RoomA + i));
        ASSERT_TRUE(found != NULL);
        ASSERT_UINT_EQ(found->roomId, (uint32_t)(RoomA + i));
    }

    freeTestServer(&s);
}

static void testFindAfterCapacityGrowth(void) {
    Server s = makeTestServer(InitCap);
    ASSERT_TRUE(s.activeRooms != NULL);

    serverGetOrCreateActiveRoom(&s, RoomA);
    serverGetOrCreateActiveRoom(&s, RoomB);
    serverGetOrCreateActiveRoom(&s, RoomC);
    serverGetOrCreateActiveRoom(&s, RoomD);
    serverGetOrCreateActiveRoom(&s, RoomE);
    ASSERT_TRUE(s.activeRoomCapacity > InitCap);

    ASSERT_TRUE(serverFindActiveRoom(&s, RoomA) != NULL);
    ASSERT_TRUE(serverFindActiveRoom(&s, RoomE) != NULL);
    ASSERT_TRUE(serverFindActiveRoom(&s, RoomRemoveTarget) == NULL);

    freeTestServer(&s);
}

/* ──────────── remove array boundary tests (first/last/only) ─────────────── */

static void testRemoveFirstElement(void) {
    Server s = makeTestServer(SERVER_INITIAL_CAPACITY);
    ASSERT_TRUE(s.activeRooms != NULL);

    serverGetOrCreateActiveRoom(&s, RoomA);
    serverGetOrCreateActiveRoom(&s, RoomB);
    serverGetOrCreateActiveRoom(&s, RoomC);
    ASSERT_INT_EQ(s.activeRoomCount, MembersThree);

    serverRemoveActiveRoom(&s, RoomA);
    ASSERT_INT_EQ(s.activeRoomCount, MembersTwo);
    ASSERT_TRUE(serverFindActiveRoom(&s, RoomA) == NULL);
    ASSERT_TRUE(serverFindActiveRoom(&s, RoomB) != NULL);
    ASSERT_TRUE(serverFindActiveRoom(&s, RoomC) != NULL);

    freeTestServer(&s);
}

static void testRemoveLastElement(void) {
    Server s = makeTestServer(SERVER_INITIAL_CAPACITY);
    ASSERT_TRUE(s.activeRooms != NULL);

    serverGetOrCreateActiveRoom(&s, RoomA);
    serverGetOrCreateActiveRoom(&s, RoomB);
    serverGetOrCreateActiveRoom(&s, RoomC);

    serverRemoveActiveRoom(&s, RoomC);
    ASSERT_INT_EQ(s.activeRoomCount, MembersTwo);
    ASSERT_TRUE(serverFindActiveRoom(&s, RoomC) == NULL);
    ASSERT_TRUE(serverFindActiveRoom(&s, RoomA) != NULL);
    ASSERT_TRUE(serverFindActiveRoom(&s, RoomB) != NULL);

    freeTestServer(&s);
}

static void testRemoveOnlyElement(void) {
    Server s = makeTestServer(SERVER_INITIAL_CAPACITY);
    ASSERT_TRUE(s.activeRooms != NULL);

    serverGetOrCreateActiveRoom(&s, RoomA);
    ASSERT_INT_EQ(s.activeRoomCount, 1);

    serverRemoveActiveRoom(&s, RoomA);
    ASSERT_INT_EQ(s.activeRoomCount, 0);
    ASSERT_TRUE(serverFindActiveRoom(&s, RoomA) == NULL);

    freeTestServer(&s);
}

static void testDoubleRemoveSameRoom(void) {
    Server s = makeTestServer(SERVER_INITIAL_CAPACITY);
    ASSERT_TRUE(s.activeRooms != NULL);

    serverGetOrCreateActiveRoom(&s, RoomA);
    serverGetOrCreateActiveRoom(&s, RoomB);
    ASSERT_INT_EQ(s.activeRoomCount, MembersTwo);

    serverRemoveActiveRoom(&s, RoomA);
    ASSERT_INT_EQ(s.activeRoomCount, 1);
    serverRemoveActiveRoom(&s, RoomA);
    ASSERT_INT_EQ(s.activeRoomCount, 1);
    ASSERT_TRUE(serverFindActiveRoom(&s, RoomB) != NULL);

    freeTestServer(&s);
}

/* ────────────────────── room ID edge cases ──────────────────────────────── */

static void testRoomIdZero(void) {
    Server s = makeTestServer(SERVER_INITIAL_CAPACITY);
    ASSERT_TRUE(s.activeRooms != NULL);

    ActiveRoom *room = serverGetOrCreateActiveRoom(&s, RoomZero);
    ASSERT_TRUE(room != NULL);
    ASSERT_UINT_EQ(room->roomId, (uint32_t)RoomZero);
    ASSERT_TRUE(serverFindActiveRoom(&s, RoomZero) != NULL);

    serverRemoveActiveRoom(&s, RoomZero);
    ASSERT_INT_EQ(s.activeRoomCount, 0);

    freeTestServer(&s);
}

static void testRoomIdMax(void) {
    Server s = makeTestServer(SERVER_INITIAL_CAPACITY);
    ASSERT_TRUE(s.activeRooms != NULL);

    ActiveRoom *room = serverGetOrCreateActiveRoom(&s, roomMax);
    ASSERT_TRUE(room != NULL);
    ASSERT_UINT_EQ(room->roomId, roomMax);
    ASSERT_TRUE(serverFindActiveRoom(&s, roomMax) != NULL);

    serverRemoveActiveRoom(&s, roomMax);
    ASSERT_INT_EQ(s.activeRoomCount, 0);

    freeTestServer(&s);
}

/* ──────────── removeClientFromRoom: multi-member management ─────────────── */

static void testRemoveClientMultipleMembers(void) {
    Server s = makeTestServer(SERVER_INITIAL_CAPACITY);
    ASSERT_TRUE(s.activeRooms != NULL);

    ActiveRoom *room = serverGetOrCreateActiveRoom(&s, RoomA);
    ASSERT_TRUE(room != NULL);

    ClientSession cs1, cs2, cs3;
    memset(&cs1, 0, sizeof(cs1));
    memset(&cs2, 0, sizeof(cs2));
    memset(&cs3, 0, sizeof(cs3));
    cs1.currentRoomId = RoomA;
    cs2.currentRoomId = RoomA;
    cs3.currentRoomId = RoomA;

    room->members[0] = &cs1;
    room->members[1] = &cs2;
    room->members[2] = &cs3;
    room->memberCount = MembersThree;

    serverRemoveClientFromRoom(&s, &cs2);
    ASSERT_UINT_EQ(cs2.currentRoomId, (uint32_t)RoomZero);
    ASSERT_INT_EQ(room->memberCount, MembersTwo);
    ASSERT_TRUE(room->members[0] == &cs1);
    ASSERT_TRUE(room->members[1] == &cs3);
    ASSERT_INT_EQ(s.activeRoomCount, 1);

    freeTestServer(&s);
}

static void testRemoveClientAllMembersLeave(void) {
    Server s = makeTestServer(SERVER_INITIAL_CAPACITY);
    ASSERT_TRUE(s.activeRooms != NULL);

    ActiveRoom *room = serverGetOrCreateActiveRoom(&s, RoomA);
    ASSERT_TRUE(room != NULL);

    ClientSession cs1, cs2;
    memset(&cs1, 0, sizeof(cs1));
    memset(&cs2, 0, sizeof(cs2));
    cs1.currentRoomId = RoomA;
    cs2.currentRoomId = RoomA;
    room->members[0] = &cs1;
    room->members[1] = &cs2;
    room->memberCount = MembersTwo;

    serverRemoveClientFromRoom(&s, &cs1);
    ASSERT_UINT_EQ(cs1.currentRoomId, (uint32_t)RoomZero);
    ASSERT_INT_EQ(s.activeRoomCount, 1);

    serverRemoveClientFromRoom(&s, &cs2);
    ASSERT_UINT_EQ(cs2.currentRoomId, (uint32_t)RoomZero);
    ASSERT_INT_EQ(s.activeRoomCount, 0);

    freeTestServer(&s);
}

static void testRemoveClientNotInMembersList(void) {
    Server s = makeTestServer(SERVER_INITIAL_CAPACITY);
    ASSERT_TRUE(s.activeRooms != NULL);

    ActiveRoom *room = serverGetOrCreateActiveRoom(&s, RoomA);
    ASSERT_TRUE(room != NULL);

    ClientSession csInRoom, csOrphan;
    memset(&csInRoom, 0, sizeof(csInRoom));
    memset(&csOrphan, 0, sizeof(csOrphan));
    csInRoom.currentRoomId = RoomA;
    csOrphan.currentRoomId = RoomA;

    room->members[0] = &csInRoom;
    room->memberCount = 1;

    serverRemoveClientFromRoom(&s, &csOrphan);
    ASSERT_UINT_EQ(csOrphan.currentRoomId, (uint32_t)RoomZero);
    ASSERT_INT_EQ(room->memberCount, 1);
    ASSERT_TRUE(room->members[0] == &csInRoom);
    ASSERT_INT_EQ(s.activeRoomCount, 1);

    freeTestServer(&s);
}

static void testRemoveClientRoomNotFound(void) {
    Server s = makeTestServer(SERVER_INITIAL_CAPACITY);
    ASSERT_TRUE(s.activeRooms != NULL);

    ClientSession cs;
    memset(&cs, 0, sizeof(cs));
    cs.currentRoomId = RoomRemoveTarget;

    serverRemoveClientFromRoom(&s, &cs);
    ASSERT_UINT_EQ(cs.currentRoomId, (uint32_t)RoomZero);

    freeTestServer(&s);
}

/* ──────────── bulk create + remove stress test ──────────────────────────── */

static void testCreateManyRoomsThenRemoveAll(void) {
    Server s = makeTestServer(InitCap);
    ASSERT_TRUE(s.activeRooms != NULL);

    for (int i = 0; i < RoomGrowCount; i++) {
        ASSERT_TRUE(serverGetOrCreateActiveRoom(&s, (uint32_t)(RoomA + i)) !=
                    NULL);
    }
    ASSERT_INT_EQ(s.activeRoomCount, RoomGrowCount);

    for (int i = RoomGrowCount - 1; i >= 0; i--) {
        serverRemoveActiveRoom(&s, (uint32_t)(RoomA + i));
    }
    ASSERT_INT_EQ(s.activeRoomCount, 0);

    freeTestServer(&s);
}

/* ════════════════════════════════════════════════════════════════════════
   main
   ════════════════════════════════════════════════════════════════════════ */

int main(void) {
    printf("test_server_room:\n");

    RUN_TEST(testCapacityGrowthTriggerRealloc);
    RUN_TEST(testFindAfterCapacityGrowth);

    RUN_TEST(testRemoveFirstElement);
    RUN_TEST(testRemoveLastElement);
    RUN_TEST(testRemoveOnlyElement);
    RUN_TEST(testDoubleRemoveSameRoom);

    RUN_TEST(testRoomIdZero);
    RUN_TEST(testRoomIdMax);

    RUN_TEST(testRemoveClientMultipleMembers);
    RUN_TEST(testRemoveClientAllMembersLeave);
    RUN_TEST(testRemoveClientNotInMembersList);
    RUN_TEST(testRemoveClientRoomNotFound);

    RUN_TEST(testCreateManyRoomsThenRemoveAll);

    return TEST_REPORT();
}
