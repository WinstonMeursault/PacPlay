/**
 * @file test_pacman_server.c
 * @brief Tests for PacMan server game logic.
 *
 * @date 2026-06-17
 * @copyright GPLv3 License
 * @section LICENSE
 * PacPlay
 * Copyright (C) 2026 Winston Meursault & Kiraterin
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "pacman_server.h"
#include "test_utils.h"
#include <string.h>

enum {
    TestMapCells = 800,
    TestMaxPlayers = 4,
    TestGhostCount = 4,
    TestStartLives = 3,
    TestDuration = 180,
    TestInvalidDir = 99,
    TestInvalidPlayer = 99,
    TestSeqNum = 42,
    TestPosX = 10,
    TestPosY = 5,
    TestScore0 = 100,
    TestScore1 = 200,
};

static void testServerCreateDestroy(void) {
    PacManServer *srv = pacmanServerCreate();
    ASSERT_NOT_NULL(srv);
    pacmanServerDestroy(srv);
}

static void testServerCreateDestroyNull(void) { pacmanServerDestroy(NULL); }

static void testServerInit(void) {
    PacManServer *srv = pacmanServerCreate();
    ASSERT_NOT_NULL(srv);
    pacmanServerInit(srv);
    ASSERT_TRUE(srv->beanCount > 0);
    ASSERT_UINT_EQ(srv->playerCount, 0);
    ASSERT_UINT_EQ(srv->playersAlive, 0);
    ASSERT_FALSE(srv->gameStarted);
    ASSERT_FALSE(srv->gameOver);
    ASSERT_UINT_EQ(srv->timeLeftSec, TestDuration);
    ASSERT_UINT_EQ(srv->seqNum, 0);
    pacmanServerDestroy(srv);
}

static void testInitOnNull(void) { pacmanServerInit(NULL); }

static void testAddPlayer(void) {
    PacManServer *srv = pacmanServerCreate();
    ASSERT_NOT_NULL(srv);
    pacmanServerInit(srv);

    int pid0 = pacmanServerAddPlayer(srv);
    ASSERT_INT_EQ(pid0, 0);
    ASSERT_UINT_EQ(srv->playerCount, 1);
    ASSERT_UINT_EQ(srv->playersAlive, 1);
    ASSERT_UINT_EQ(srv->players[0].playerId, 0);
    ASSERT_UINT_EQ(srv->players[0].lives, TestStartLives);
    ASSERT_UINT_EQ(srv->players[0].score, 0);
    ASSERT_UINT_EQ(srv->players[0].alive, 1);

    int pid1 = pacmanServerAddPlayer(srv);
    ASSERT_INT_EQ(pid1, 1);
    ASSERT_UINT_EQ(srv->playerCount, 2);

    pacmanServerDestroy(srv);
}

static void testAddPlayerNull(void) {
    int pid = pacmanServerAddPlayer(NULL);
    ASSERT_INT_EQ(pid, -1);
}

static void testAddPlayerMax(void) {
    PacManServer *srv = pacmanServerCreate();
    int i;
    ASSERT_NOT_NULL(srv);
    pacmanServerInit(srv);
    for (i = 0; i < TestMaxPlayers; i++) {
        int pid = pacmanServerAddPlayer(srv);
        ASSERT_INT_EQ(pid, i);
    }
    {
        int pid = pacmanServerAddPlayer(srv);
        ASSERT_INT_EQ(pid, -1);
    }
    pacmanServerDestroy(srv);
}

static void testHandleMove(void) {
    PacManServer *srv = pacmanServerCreate();
    ASSERT_NOT_NULL(srv);
    pacmanServerInit(srv);
    pacmanServerAddPlayer(srv);

    pacmanServerHandleMove(srv, 0, PacManDirDown);
    ASSERT_UINT_EQ(srv->players[0].direction, PacManDirDown);

    pacmanServerHandleMove(srv, 0, PacManDirLeft);
    ASSERT_UINT_EQ(srv->players[0].direction, PacManDirLeft);

    pacmanServerDestroy(srv);
}

static void testHandleMoveInvalid(void) {
    PacManServer *srv = pacmanServerCreate();
    ASSERT_NOT_NULL(srv);
    pacmanServerInit(srv);
    pacmanServerAddPlayer(srv);

    pacmanServerHandleMove(srv, 0, TestInvalidDir);
    ASSERT_UINT_EQ(srv->players[0].direction, PacManDirRight);

    pacmanServerHandleMove(NULL, 0, PacManDirUp);
    pacmanServerHandleMove(srv, TestInvalidPlayer, PacManDirUp);

    pacmanServerDestroy(srv);
}

static void testBuildStartMsg(void) {
    PacManServer *srv = pacmanServerCreate();
    ASSERT_NOT_NULL(srv);
    pacmanServerInit(srv);
    pacmanServerAddPlayer(srv);
    pacmanServerAddPlayer(srv);

    PacManStartMsg msg;
    pacmanServerBuildStartMsg(srv, 1, &msg);
    ASSERT_UINT_EQ(msg.msgType, PacManMsgStart);
    ASSERT_UINT_EQ(msg.playerId, 1);
    ASSERT_UINT_EQ(msg.playerCount, 2);

    pacmanServerDestroy(srv);
}

static void testBuildStartMsgNull(void) {
    PacManStartMsg msg;
    pacmanServerBuildStartMsg(NULL, 0, &msg);
    pacmanServerBuildStartMsg(NULL, 0, NULL);
}

static void testBuildStateMsg(void) {
    PacManServer *srv = pacmanServerCreate();
    ASSERT_NOT_NULL(srv);
    pacmanServerInit(srv);
    pacmanServerAddPlayer(srv);
    srv->seqNum = TestSeqNum;
    srv->players[0].posX = TestPosX;
    srv->players[0].posY = TestPosY;

    PacManStateMsg msg;
    pacmanServerBuildStateMsg(srv, &msg);
    ASSERT_UINT_EQ(msg.msgType, PacManMsgState);
    ASSERT_UINT_EQ(msg.seqNum, TestSeqNum);
    ASSERT_UINT_EQ(msg.playerCount, 1);
    ASSERT_UINT_EQ(msg.players[0].posX, TestPosX);
    ASSERT_UINT_EQ(msg.players[0].posY, TestPosY);

    pacmanServerDestroy(srv);
}

static void testBuildGameOverMsg(void) {
    PacManServer *srv = pacmanServerCreate();
    ASSERT_NOT_NULL(srv);
    pacmanServerInit(srv);
    pacmanServerAddPlayer(srv);
    pacmanServerAddPlayer(srv);
    srv->players[0].score = TestScore0;
    srv->players[1].score = TestScore1;
    srv->players[0].alive = 0;
    srv->players[1].alive = 1;

    PacManGameOverMsg msg;
    pacmanServerBuildGameOverMsg(srv, &msg);
    ASSERT_UINT_EQ(msg.msgType, PacManMsgGameOver);
    ASSERT_UINT_EQ(msg.playerCount, 2);
    ASSERT_UINT_EQ(msg.rankings[0], 1);
    ASSERT_UINT_EQ(msg.scores[0], 100);
    ASSERT_UINT_EQ(msg.scores[1], 200);

    pacmanServerDestroy(srv);
}

static void testTickIncrementsSeq(void) {
    PacManServer *srv = pacmanServerCreate();
    ASSERT_NOT_NULL(srv);
    pacmanServerInit(srv);
    pacmanServerAddPlayer(srv);

    uint32_t before = srv->seqNum;
    bool running = pacmanServerTick(srv);
    ASSERT_TRUE(running);
    ASSERT_UINT_EQ(srv->seqNum, before + 1);

    pacmanServerDestroy(srv);
}

static void testTickNullSafe(void) {
    bool running = pacmanServerTick(NULL);
    ASSERT_FALSE(running);
}

int main(void) {
    printf("test_pacman_server:\n");
    RUN_TEST(testServerCreateDestroy);
    RUN_TEST(testServerCreateDestroyNull);
    RUN_TEST(testServerInit);
    RUN_TEST(testInitOnNull);
    RUN_TEST(testAddPlayer);
    RUN_TEST(testAddPlayerNull);
    RUN_TEST(testAddPlayerMax);
    RUN_TEST(testHandleMove);
    RUN_TEST(testHandleMoveInvalid);
    RUN_TEST(testBuildStartMsg);
    RUN_TEST(testBuildStartMsgNull);
    RUN_TEST(testBuildStateMsg);
    RUN_TEST(testBuildGameOverMsg);
    RUN_TEST(testTickIncrementsSeq);
    RUN_TEST(testTickNullSafe);
    return TEST_REPORT();
}
