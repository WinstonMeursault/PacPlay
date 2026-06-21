/**
 * @file test_pacman_common.c
 * @brief Tests for PacMan common protocol definitions.
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

#include "pacman_common.h"
#include "test_utils.h"
#include <stddef.h>
#include <stdio.h>
#include <string.h>

enum {
    TestMapCells = 800,
    TestMaxPlayers = 4,
    TestGhostCount = 4,
    TestBeanScore = 10,
    TestPowerScore = 50,
    TestGhostEat = 200,
    TestStartingLives = 3,
    TestPlayerId = 2,
    TestPlayerCount = 4,
    TestMapIdxPath = 42,
    TestMapIdxBean = 100,
    TestMapIdxPower = 200,
    TestSeqNum = 12345,
    TestTimeLeft = 120,
    TestBeanCount = 80,
    TestPosX = 5,
    TestPosY = 6,
    TestScore = 150,
    TestGhostX = 20,
    TestGhostY = 10,
};

static void testConstants(void) {
    ASSERT_UINT_EQ(PACMAN_MAP_WIDTH, 40);
    ASSERT_UINT_EQ(PACMAN_MAP_HEIGHT, 20);
    ASSERT_UINT_EQ(PACMAN_MAP_CELLS, TestMapCells);
    ASSERT_UINT_EQ(PACMAN_MAX_PLAYERS, TestMaxPlayers);
    ASSERT_UINT_EQ(PACMAN_GHOST_COUNT, TestGhostCount);
    ASSERT_UINT_EQ(PACMAN_BEAN_SCORE, TestBeanScore);
    ASSERT_UINT_EQ(PACMAN_POWER_BEAN_SCORE, TestPowerScore);
    ASSERT_UINT_EQ(PACMAN_GHOST_EAT_SCORE, TestGhostEat);
    ASSERT_UINT_EQ(PACMAN_STARTING_LIVES, TestStartingLives);
    ASSERT_UINT_EQ(PACMAN_GAME_DURATION_SEC, 180);
    ASSERT_UINT_EQ(PACMAN_TICK_MS, 100);
}

static void testMsgTypeValues(void) {
    ASSERT_UINT_EQ(PacManMsgJoin, 1);
    ASSERT_UINT_EQ(PacManMsgMove, 2);
    ASSERT_UINT_EQ(PacManMsgStart, 3);
    ASSERT_UINT_EQ(PacManMsgState, 4);
    ASSERT_UINT_EQ(PacManMsgGameOver, 5);
}

static void testDirValues(void) {
    ASSERT_UINT_EQ(PacManDirUp, 0);
    ASSERT_UINT_EQ(PacManDirDown, 1);
    ASSERT_UINT_EQ(PacManDirLeft, 2);
    ASSERT_UINT_EQ(PacManDirRight, 3);
}

static void testCellValues(void) {
    ASSERT_UINT_EQ(PacManCellWall, 0);
    ASSERT_UINT_EQ(PacManCellPath, 1);
    ASSERT_UINT_EQ(PacManCellBean, 2);
    ASSERT_UINT_EQ(PacManCellPowerBean, 3);
}

static void testGhostModeValues(void) {
    ASSERT_UINT_EQ(PacManGhostScatter, 0);
    ASSERT_UINT_EQ(PacManGhostChase, 1);
    ASSERT_UINT_EQ(PacManGhostFrightened, 2);
    ASSERT_UINT_EQ(PacManGhostEaten, 3);
}

static void testMoveMsgLayout(void) {
    PacManMoveMsg msg;
    ASSERT_UINT_EQ(sizeof(msg), 2);
    memset(&msg, 0, sizeof(msg));
    ASSERT_UINT_EQ(offsetof(PacManMoveMsg, msgType), 0);
    ASSERT_UINT_EQ(offsetof(PacManMoveMsg, direction), 1);
    msg.msgType = PacManMsgMove;
    msg.direction = PacManDirRight;
    ASSERT_UINT_EQ(msg.msgType, PacManMsgMove);
    ASSERT_UINT_EQ(msg.direction, PacManDirRight);
}

static void testPlayerInfoLayout(void) {
    PacManPlayerInfo info;
    ASSERT_UINT_EQ(sizeof(info), 12);
    ASSERT_UINT_EQ(offsetof(PacManPlayerInfo, playerId), 0);
    ASSERT_UINT_EQ(offsetof(PacManPlayerInfo, posX), 1);
    ASSERT_UINT_EQ(offsetof(PacManPlayerInfo, posY), 3);
    ASSERT_UINT_EQ(offsetof(PacManPlayerInfo, direction), 5);
    ASSERT_UINT_EQ(offsetof(PacManPlayerInfo, lives), 6);
    ASSERT_UINT_EQ(offsetof(PacManPlayerInfo, score), 7);
    ASSERT_UINT_EQ(offsetof(PacManPlayerInfo, alive), 11);
}

static void testGhostInfoLayout(void) {
    PacManGhostInfo info;
    ASSERT_UINT_EQ(sizeof(info), 7);
    ASSERT_UINT_EQ(offsetof(PacManGhostInfo, ghostId), 0);
    ASSERT_UINT_EQ(offsetof(PacManGhostInfo, posX), 1);
    ASSERT_UINT_EQ(offsetof(PacManGhostInfo, posY), 3);
    ASSERT_UINT_EQ(offsetof(PacManGhostInfo, direction), 5);
    ASSERT_UINT_EQ(offsetof(PacManGhostInfo, mode), 6);
}

static void testStartMsgLayout(void) {
    PacManStartMsg msg;
    ASSERT_UINT_EQ(sizeof(msg), 803);
    ASSERT_UINT_EQ(offsetof(PacManStartMsg, msgType), 0);
    ASSERT_UINT_EQ(offsetof(PacManStartMsg, playerId), 1);
    ASSERT_UINT_EQ(offsetof(PacManStartMsg, playerCount), 2);
    ASSERT_UINT_EQ(offsetof(PacManStartMsg, mapData), 3);
}

static void testStateMsgLayout(void) {
    PacManStateMsg msg;
    ASSERT_UINT_EQ(sizeof(msg), 87);
    ASSERT_UINT_EQ(offsetof(PacManStateMsg, msgType), 0);
    ASSERT_UINT_EQ(offsetof(PacManStateMsg, seqNum), 1);
    ASSERT_UINT_EQ(offsetof(PacManStateMsg, timeLeftSec), 5);
    ASSERT_UINT_EQ(offsetof(PacManStateMsg, playerCount), 9);
    ASSERT_UINT_EQ(offsetof(PacManStateMsg, beanCount), 10);
    ASSERT_UINT_EQ(offsetof(PacManStateMsg, players), 11);
    ASSERT_UINT_EQ(offsetof(PacManStateMsg, ghosts), 59);
}

static void testGameOverMsgLayout(void) {
    PacManGameOverMsg msg;
    ASSERT_UINT_EQ(sizeof(msg), 22);
    ASSERT_UINT_EQ(offsetof(PacManGameOverMsg, msgType), 0);
    ASSERT_UINT_EQ(offsetof(PacManGameOverMsg, playerCount), 1);
    ASSERT_UINT_EQ(offsetof(PacManGameOverMsg, rankings), 2);
    ASSERT_UINT_EQ(offsetof(PacManGameOverMsg, scores), 6);
}

static void testRoundtripMoveMsg(void) {
    PacManMoveMsg send = {PacManMsgMove, PacManDirDown};
    PacManMoveMsg recv;
    memcpy(&recv, &send, sizeof(send));
    ASSERT_UINT_EQ(recv.msgType, PacManMsgMove);
    ASSERT_UINT_EQ(recv.direction, PacManDirDown);
}

static void testRoundtripStartMsg(void) {
    PacManStartMsg send;
    send.msgType = PacManMsgStart;
    send.playerId = TestPlayerId;
    send.playerCount = TestPlayerCount;
    memset(send.mapData, PacManCellWall, PACMAN_MAP_CELLS);
    send.mapData[TestMapIdxPath] = PacManCellPath;
    send.mapData[TestMapIdxBean] = PacManCellBean;
    send.mapData[TestMapIdxPower] = PacManCellPowerBean;

    PacManStartMsg recv;
    memcpy(&recv, &send, sizeof(send));
    ASSERT_UINT_EQ(recv.msgType, PacManMsgStart);
    ASSERT_UINT_EQ(recv.playerId, TestPlayerId);
    ASSERT_UINT_EQ(recv.playerCount, TestPlayerCount);
    ASSERT_UINT_EQ(recv.mapData[0], PacManCellWall);
    ASSERT_UINT_EQ(recv.mapData[TestMapIdxPath], PacManCellPath);
    ASSERT_UINT_EQ(recv.mapData[TestMapIdxBean], PacManCellBean);
    ASSERT_UINT_EQ(recv.mapData[TestMapIdxPower], PacManCellPowerBean);
}

static void testRoundtripStateMsg(void) {
    PacManStateMsg send;
    memset(&send, 0, sizeof(send));
    send.msgType = PacManMsgState;
    send.seqNum = TestSeqNum;
    send.timeLeftSec = TestTimeLeft;
    send.playerCount = 2;
    send.beanCount = TestBeanCount;
    send.players[0].playerId = 0;
    send.players[0].posX = TestPosX;
    send.players[0].posY = TestPosY;
    send.players[0].direction = PacManDirUp;
    send.players[0].lives = 2;
    send.players[0].score = TestScore;
    send.players[0].alive = 1;
    send.ghosts[0].ghostId = 0;
    send.ghosts[0].posX = TestGhostX;
    send.ghosts[0].posY = TestGhostY;
    send.ghosts[0].mode = PacManGhostChase;

    PacManStateMsg recv;
    memcpy(&recv, &send, sizeof(send));
    ASSERT_UINT_EQ(recv.seqNum, TestSeqNum);
    ASSERT_UINT_EQ(recv.timeLeftSec, TestTimeLeft);
    ASSERT_UINT_EQ(recv.playerCount, 2);
    ASSERT_UINT_EQ(recv.beanCount, TestBeanCount);
    ASSERT_UINT_EQ(recv.players[0].posX, TestPosX);
    ASSERT_UINT_EQ(recv.players[0].posY, TestPosY);
    ASSERT_UINT_EQ(recv.players[0].score, TestScore);
    ASSERT_UINT_EQ(recv.ghosts[0].posX, TestGhostX);
    ASSERT_UINT_EQ(recv.ghosts[0].posY, TestGhostY);
}

int main(void) {
    printf("test_pacman_common:\n");
    RUN_TEST(testConstants);
    RUN_TEST(testMsgTypeValues);
    RUN_TEST(testDirValues);
    RUN_TEST(testCellValues);
    RUN_TEST(testGhostModeValues);
    RUN_TEST(testMoveMsgLayout);
    RUN_TEST(testPlayerInfoLayout);
    RUN_TEST(testGhostInfoLayout);
    RUN_TEST(testStartMsgLayout);
    RUN_TEST(testStateMsgLayout);
    RUN_TEST(testGameOverMsgLayout);
    RUN_TEST(testRoundtripMoveMsg);
    RUN_TEST(testRoundtripStartMsg);
    RUN_TEST(testRoundtripStateMsg);
    return TEST_REPORT();
}
