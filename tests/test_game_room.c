#include "server/gameRoom.h"
#include "server/server.h"
#include "test_utils.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    InitCap = 4,
    GrowCount = 10,
    RoomIdA = 100,
    RoomIdB = 200,
    RoomIdC = 300,
    GameIdA = 1,
    GameIdB = 2,
    HostUidA = 10,
    HostUidB = 20,
    MemberUid = 30
};

static Server makeTestServer(int capacity) {
    Server s;
    memset(&s, 0, sizeof(s));
    s.activeGameRoomCapacity = capacity;
    s.activeGameRooms =
        (ActiveGameRoom **)calloc((size_t)capacity, sizeof(ActiveGameRoom *));
    return s;
}

static void freeTestServer(Server *s) {
    for (int i = 0; i < s->activeGameRoomCount; i++) {
        free(s->activeGameRooms[i]);
    }
    free((void *)s->activeGameRooms);
    s->activeGameRooms = NULL;
    s->activeGameRoomCount = 0;
    s->activeGameRoomCapacity = 0;
}

static void testFindEmpty(void) {
    Server s = makeTestServer(InitCap);
    ASSERT_NOT_NULL(s.activeGameRooms);

    ActiveGameRoom *result = serverFindActiveGameRoom(&s, RoomIdA);
    ASSERT_NULL(result);

    freeTestServer(&s);
}

static void testGetOrCreate(void) {
    Server s = makeTestServer(InitCap);
    ASSERT_NOT_NULL(s.activeGameRooms);

    ActiveGameRoom *gr1 =
        serverGetOrCreateActiveGameRoom(&s, RoomIdA, GameIdA, HostUidA);
    ASSERT_NOT_NULL(gr1);
    ASSERT_UINT_EQ(gr1->gameRoomId, (uint32_t)RoomIdA);
    ASSERT_UINT_EQ(gr1->gameId, (uint32_t)GameIdA);
    ASSERT_UINT_EQ(gr1->hostUid, (uint32_t)HostUidA);
    ASSERT_INT_EQ(gr1->state, GameRoomLobby);
    ASSERT_INT_EQ(s.activeGameRoomCount, 1);

    ActiveGameRoom *gr2 =
        serverGetOrCreateActiveGameRoom(&s, RoomIdA, GameIdB, HostUidB);
    ASSERT_TRUE(gr2 == gr1);
    ASSERT_INT_EQ(s.activeGameRoomCount, 1);

    freeTestServer(&s);
}

static void testRemove(void) {
    Server s = makeTestServer(InitCap);
    ASSERT_NOT_NULL(s.activeGameRooms);

    serverGetOrCreateActiveGameRoom(&s, RoomIdA, GameIdA, HostUidA);
    serverGetOrCreateActiveGameRoom(&s, RoomIdB, GameIdA, HostUidA);
    serverGetOrCreateActiveGameRoom(&s, RoomIdC, GameIdA, HostUidA);
    ASSERT_INT_EQ(s.activeGameRoomCount, 3);

    serverRemoveActiveGameRoom(&s, RoomIdB);
    ASSERT_INT_EQ(s.activeGameRoomCount, 2);
    ASSERT_NULL(serverFindActiveGameRoom(&s, RoomIdB));
    ASSERT_NOT_NULL(serverFindActiveGameRoom(&s, RoomIdA));
    ASSERT_NOT_NULL(serverFindActiveGameRoom(&s, RoomIdC));

    freeTestServer(&s);
}

static void testRemoveFirst(void) {
    Server s = makeTestServer(InitCap);
    ASSERT_NOT_NULL(s.activeGameRooms);

    serverGetOrCreateActiveGameRoom(&s, RoomIdA, GameIdA, HostUidA);
    serverGetOrCreateActiveGameRoom(&s, RoomIdB, GameIdA, HostUidA);
    serverGetOrCreateActiveGameRoom(&s, RoomIdC, GameIdA, HostUidA);

    serverRemoveActiveGameRoom(&s, RoomIdA);
    ASSERT_INT_EQ(s.activeGameRoomCount, 2);
    ASSERT_NULL(serverFindActiveGameRoom(&s, RoomIdA));
    ASSERT_NOT_NULL(serverFindActiveGameRoom(&s, RoomIdB));
    ASSERT_NOT_NULL(serverFindActiveGameRoom(&s, RoomIdC));

    freeTestServer(&s);
}

static void testRemoveLast(void) {
    Server s = makeTestServer(InitCap);
    ASSERT_NOT_NULL(s.activeGameRooms);

    serverGetOrCreateActiveGameRoom(&s, RoomIdA, GameIdA, HostUidA);
    serverGetOrCreateActiveGameRoom(&s, RoomIdB, GameIdA, HostUidA);
    serverGetOrCreateActiveGameRoom(&s, RoomIdC, GameIdA, HostUidA);

    serverRemoveActiveGameRoom(&s, RoomIdC);
    ASSERT_INT_EQ(s.activeGameRoomCount, 2);
    ASSERT_NULL(serverFindActiveGameRoom(&s, RoomIdC));
    ASSERT_NOT_NULL(serverFindActiveGameRoom(&s, RoomIdA));
    ASSERT_NOT_NULL(serverFindActiveGameRoom(&s, RoomIdB));

    freeTestServer(&s);
}

static void testRemoveOnly(void) {
    Server s = makeTestServer(InitCap);
    ASSERT_NOT_NULL(s.activeGameRooms);

    serverGetOrCreateActiveGameRoom(&s, RoomIdA, GameIdA, HostUidA);
    ASSERT_INT_EQ(s.activeGameRoomCount, 1);

    serverRemoveActiveGameRoom(&s, RoomIdA);
    ASSERT_INT_EQ(s.activeGameRoomCount, 0);
    ASSERT_NULL(serverFindActiveGameRoom(&s, RoomIdA));

    freeTestServer(&s);
}

static void testRemoveNonExisting(void) {
    Server s = makeTestServer(InitCap);
    ASSERT_NOT_NULL(s.activeGameRooms);

    serverGetOrCreateActiveGameRoom(&s, RoomIdA, GameIdA, HostUidA);
    serverGetOrCreateActiveGameRoom(&s, RoomIdB, GameIdA, HostUidA);
    ASSERT_INT_EQ(s.activeGameRoomCount, 2);

    serverRemoveActiveGameRoom(&s, RoomIdC);
    ASSERT_INT_EQ(s.activeGameRoomCount, 2);

    freeTestServer(&s);
}

static void testCapacityGrowth(void) {
    Server s = makeTestServer(InitCap);
    ASSERT_NOT_NULL(s.activeGameRooms);

    for (int i = 0; i < GrowCount; i++) {
        ActiveGameRoom *gr = serverGetOrCreateActiveGameRoom(
            &s, (uint32_t)(RoomIdA + i), GameIdA, HostUidA);
        ASSERT_NOT_NULL(gr);
        ASSERT_UINT_EQ(gr->gameRoomId, (uint32_t)(RoomIdA + i));
    }
    ASSERT_INT_EQ(s.activeGameRoomCount, GrowCount);
    ASSERT_TRUE(s.activeGameRoomCapacity >= GrowCount);

    for (int i = 0; i < GrowCount; i++) {
        ASSERT_NOT_NULL(serverFindActiveGameRoom(&s, (uint32_t)(RoomIdA + i)));
    }

    freeTestServer(&s);
}

static void testRemoveClientNonMember(void) {
    Server s = makeTestServer(InitCap);
    ASSERT_NOT_NULL(s.activeGameRooms);

    ClientSession cs;
    memset(&cs, 0, sizeof(cs));
    cs.currentGameRoomId = 0;

    serverRemoveClientFromGameRoom(&s, &cs);
    ASSERT_UINT_EQ(cs.currentGameRoomId, (uint32_t)0);

    freeTestServer(&s);
}

static void testRemoveClientRegularMember(void) {
    Server s = makeTestServer(InitCap);
    ASSERT_NOT_NULL(s.activeGameRooms);

    ActiveGameRoom *gr =
        serverGetOrCreateActiveGameRoom(&s, RoomIdA, GameIdA, HostUidA);
    ASSERT_NOT_NULL(gr);

    ClientSession host, member;
    memset(&host, 0, sizeof(host));
    memset(&member, 0, sizeof(member));
    host.currentUser.uid = HostUidA;
    host.currentGameRoomId = RoomIdA;
    host.state = SessionGameRoomLobby;
    member.currentUser.uid = MemberUid;
    member.currentGameRoomId = RoomIdA;
    member.state = SessionGameRoomLobby;

    gr->members[0] = &host;
    gr->members[1] = &member;
    gr->memberCount = 2;

    serverRemoveClientFromGameRoom(&s, &member);
    ASSERT_UINT_EQ(member.currentGameRoomId, (uint32_t)0);
    ASSERT_INT_EQ(member.state, SessionRoom);
    ASSERT_INT_EQ(gr->memberCount, 1);
    ASSERT_TRUE(gr->members[0] == &host);
    ASSERT_INT_EQ(s.activeGameRoomCount, 1);

    freeTestServer(&s);
}

static void testRemoveClientHost(void) {
    Server s = makeTestServer(InitCap);
    ASSERT_NOT_NULL(s.activeGameRooms);

    ActiveGameRoom *gr =
        serverGetOrCreateActiveGameRoom(&s, RoomIdA, GameIdA, HostUidA);
    ASSERT_NOT_NULL(gr);

    ClientSession host, member1, member2;
    memset(&host, 0, sizeof(host));
    memset(&member1, 0, sizeof(member1));
    memset(&member2, 0, sizeof(member2));
    host.currentUser.uid = HostUidA;
    host.currentGameRoomId = RoomIdA;
    host.state = SessionGameRoomLobby;
    member1.currentUser.uid = MemberUid;
    member1.currentGameRoomId = RoomIdA;
    member1.state = SessionGameRoomLobby;
    member2.currentUser.uid = MemberUid + 1;
    member2.currentGameRoomId = RoomIdA;
    member2.state = SessionGameRoomLobby;

    gr->members[0] = &host;
    gr->members[1] = &member1;
    gr->members[2] = &member2;
    gr->memberCount = 3;

    serverRemoveClientFromGameRoom(&s, &host);
    ASSERT_UINT_EQ(host.currentGameRoomId, (uint32_t)0);
    ASSERT_INT_EQ(host.state, SessionRoom);
    ASSERT_UINT_EQ(member1.currentGameRoomId, (uint32_t)0);
    ASSERT_INT_EQ(member1.state, SessionRoom);
    ASSERT_UINT_EQ(member2.currentGameRoomId, (uint32_t)0);
    ASSERT_INT_EQ(member2.state, SessionRoom);
    ASSERT_INT_EQ(s.activeGameRoomCount, 0);

    freeTestServer(&s);
}

static void testDoubleRemove(void) {
    enum { Cap = 4, RoomId = 42, GameId = 100, HostUid = 200 };
    Server s = makeTestServer(Cap);

    serverGetOrCreateActiveGameRoom(&s, RoomId, GameId, HostUid);
    ASSERT_INT_EQ(s.activeGameRoomCount, 1);

    serverRemoveActiveGameRoom(&s, RoomId);
    ASSERT_INT_EQ(s.activeGameRoomCount, 0);

    serverRemoveActiveGameRoom(&s, RoomId);
    ASSERT_INT_EQ(s.activeGameRoomCount, 0);

    freeTestServer(&s);
}

static void testGetOrCreateMultipleDifferent(void) {
    enum {
        Cap = 4,
        GameId1 = 10,
        GameId2 = 20,
        GameId3 = 30,
        HostUid1 = 100,
        HostUid2 = 200,
        HostUid3 = 300
    };
    Server s = makeTestServer(Cap);

    ActiveGameRoom *gr1 =
        serverGetOrCreateActiveGameRoom(&s, 1, GameId1, HostUid1);
    ActiveGameRoom *gr2 =
        serverGetOrCreateActiveGameRoom(&s, 2, GameId2, HostUid2);
    ActiveGameRoom *gr3 =
        serverGetOrCreateActiveGameRoom(&s, 3, GameId3, HostUid3);

    ASSERT_NOT_NULL(gr1);
    ASSERT_NOT_NULL(gr2);
    ASSERT_NOT_NULL(gr3);
    ASSERT_TRUE(gr1 != gr2);
    ASSERT_TRUE(gr2 != gr3);
    ASSERT_INT_EQ(s.activeGameRoomCount, 3);

    ASSERT_TRUE(serverFindActiveGameRoom(&s, 1) == gr1);
    ASSERT_TRUE(serverFindActiveGameRoom(&s, 2) == gr2);
    ASSERT_TRUE(serverFindActiveGameRoom(&s, 3) == gr3);

    freeTestServer(&s);
}

/* ═══════ Supplementary tests — boundary, security, state transitions ════ */

static void testMaxClientsPerRoomBoundary(void) {
    Server s = makeTestServer(InitCap);
    ASSERT_NOT_NULL(s.activeGameRooms);

    ActiveGameRoom *gr =
        serverGetOrCreateActiveGameRoom(&s, RoomIdA, GameIdA, HostUidA);
    ASSERT_NOT_NULL(gr);

    ClientSession sessions[MAX_CLIENTS_PER_ROOM];
    for (int i = 0; i < MAX_CLIENTS_PER_ROOM; i++) {
        memset(&sessions[i], 0, sizeof(ClientSession));
        sessions[i].currentUser.uid = (uint32_t)(HostUidA + i);
        sessions[i].currentGameRoomId = RoomIdA;
        sessions[i].state = SessionGameRoomLobby;
        gr->members[i] = &sessions[i];
    }
    gr->memberCount = MAX_CLIENTS_PER_ROOM;

    ASSERT_INT_EQ(gr->memberCount, MAX_CLIENTS_PER_ROOM);
    ASSERT_NOT_NULL(serverFindActiveGameRoom(&s, RoomIdA));

    freeTestServer(&s);
}

static void testRemoveClientFromNonexistentRoom(void) {
    Server s = makeTestServer(InitCap);
    ASSERT_NOT_NULL(s.activeGameRooms);

    ClientSession cs;
    memset(&cs, 0, sizeof(cs));
    cs.currentGameRoomId = RoomIdC;
    cs.state = SessionGameRoomLobby;

    serverRemoveClientFromGameRoom(&s, &cs);
    ASSERT_UINT_EQ(cs.currentGameRoomId, (uint32_t)0);
    ASSERT_INT_EQ(cs.state, SessionRoom);

    freeTestServer(&s);
}

static void testDissolveNonexistentRoom(void) {
    Server s = makeTestServer(InitCap);
    ASSERT_NOT_NULL(s.activeGameRooms);

    serverGetOrCreateActiveGameRoom(&s, RoomIdA, GameIdA, HostUidA);
    ASSERT_INT_EQ(s.activeGameRoomCount, 1);

    serverDissolveGameRoom(&s, RoomIdC, NULL);
    ASSERT_INT_EQ(s.activeGameRoomCount, 1);
    ASSERT_NOT_NULL(serverFindActiveGameRoom(&s, RoomIdA));

    freeTestServer(&s);
}

static void testRemoveClientStateTransitionToRoom(void) {
    Server s = makeTestServer(InitCap);
    ASSERT_NOT_NULL(s.activeGameRooms);

    ActiveGameRoom *gr =
        serverGetOrCreateActiveGameRoom(&s, RoomIdA, GameIdA, HostUidA);
    ASSERT_NOT_NULL(gr);

    ClientSession host, member;
    memset(&host, 0, sizeof(host));
    memset(&member, 0, sizeof(member));
    host.currentUser.uid = HostUidA;
    host.currentGameRoomId = RoomIdA;
    host.state = SessionGameRoomPlay;
    member.currentUser.uid = MemberUid;
    member.currentGameRoomId = RoomIdA;
    member.state = SessionGameRoomPlay;

    gr->members[0] = &host;
    gr->members[1] = &member;
    gr->memberCount = 2;

    serverRemoveClientFromGameRoom(&s, &member);
    ASSERT_INT_EQ(member.state, SessionRoom);
    ASSERT_UINT_EQ(member.currentGameRoomId, (uint32_t)0);

    freeTestServer(&s);
}

static void testGetOrCreateZeroId(void) {
    Server s = makeTestServer(InitCap);
    ASSERT_NOT_NULL(s.activeGameRooms);

    ActiveGameRoom *gr =
        serverGetOrCreateActiveGameRoom(&s, 0, GameIdA, HostUidA);
    ASSERT_NOT_NULL(gr);
    ASSERT_UINT_EQ(gr->gameRoomId, (uint32_t)0);
    ASSERT_INT_EQ(s.activeGameRoomCount, 1);

    freeTestServer(&s);
}

static void testDissolveAllMembersGetReset(void) {
    enum { MemberCount = 4, BaseUid = 50 };
    Server s = makeTestServer(InitCap);
    ASSERT_NOT_NULL(s.activeGameRooms);

    ActiveGameRoom *gr =
        serverGetOrCreateActiveGameRoom(&s, RoomIdA, GameIdA, HostUidA);
    ASSERT_NOT_NULL(gr);

    ClientSession sessions[MemberCount];
    for (int i = 0; i < MemberCount; i++) {
        memset(&sessions[i], 0, sizeof(ClientSession));
        sessions[i].currentUser.uid = (uint32_t)(BaseUid + i);
        sessions[i].currentGameRoomId = RoomIdA;
        sessions[i].state = SessionGameRoomLobby;
        gr->members[i] = &sessions[i];
    }
    gr->memberCount = MemberCount;

    serverDissolveGameRoom(&s, RoomIdA, NULL);

    for (int i = 0; i < MemberCount; i++) {
        ASSERT_UINT_EQ(sessions[i].currentGameRoomId, (uint32_t)0);
        ASSERT_INT_EQ(sessions[i].state, SessionRoom);
    }
    ASSERT_INT_EQ(s.activeGameRoomCount, 0);

    freeTestServer(&s);
}

static void testRemoveLastMemberDeletesRoom(void) {
    Server s = makeTestServer(InitCap);
    ASSERT_NOT_NULL(s.activeGameRooms);

    ActiveGameRoom *gr =
        serverGetOrCreateActiveGameRoom(&s, RoomIdA, GameIdA, HostUidA);
    ASSERT_NOT_NULL(gr);

    ClientSession member;
    memset(&member, 0, sizeof(member));
    member.currentUser.uid = MemberUid;
    member.currentGameRoomId = RoomIdA;
    member.state = SessionGameRoomLobby;

    gr->members[0] = &member;
    gr->memberCount = 1;
    gr->hostUid = HostUidA;

    serverRemoveClientFromGameRoom(&s, &member);
    ASSERT_UINT_EQ(member.currentGameRoomId, (uint32_t)0);
    ASSERT_INT_EQ(s.activeGameRoomCount, 0);

    freeTestServer(&s);
}

int main(void) {
    printf("test_game_room:\n");

    RUN_TEST(testFindEmpty);
    RUN_TEST(testGetOrCreate);
    RUN_TEST(testRemove);
    RUN_TEST(testRemoveFirst);
    RUN_TEST(testRemoveLast);
    RUN_TEST(testRemoveOnly);
    RUN_TEST(testRemoveNonExisting);
    RUN_TEST(testCapacityGrowth);
    RUN_TEST(testRemoveClientNonMember);
    RUN_TEST(testRemoveClientRegularMember);
    RUN_TEST(testRemoveClientHost);
    RUN_TEST(testDoubleRemove);
    RUN_TEST(testGetOrCreateMultipleDifferent);
    RUN_TEST(testMaxClientsPerRoomBoundary);
    RUN_TEST(testRemoveClientFromNonexistentRoom);
    RUN_TEST(testDissolveNonexistentRoom);
    RUN_TEST(testRemoveClientStateTransitionToRoom);
    RUN_TEST(testGetOrCreateZeroId);
    RUN_TEST(testDissolveAllMembersGetReset);
    RUN_TEST(testRemoveLastMemberDeletesRoom);

    return TEST_REPORT();
}
