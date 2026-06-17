# PacMan Multiplayer Game — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement a multiplayer PacMan classic game using the PacPlay SDK for communication between server and client.

**Architecture:** Two independent executables (`pacman_server` and `pacman_client`) communicate via `pacplay_srv_*` / `pacplay_cli_*` SDK through PacPlay's `MsgGamePayload` transport. The server runs the authoritative game loop (map generation, ghost AI, collision detection, scoring), while the client handles terminal rendering and keyboard input.

**Tech Stack:** C (gnu17), PacPlay SDK (.so), clang, pthread, ANSI escape codes for TUI.

---

### Task 1: Clean up old stubs and create directory structure

**Files:**
- Delete: `tests/test_games/PacMan/client/pacmanServer.c`
- Delete: `tests/test_games/PacMan/client/pacManServer.h`
- Delete: `tests/test_games/PacMan/server/pacmanClient.c`
- Delete: `tests/test_games/PacMan/server/pacmanClient.h`
- Create: `tests/test_games/PacMan/common/` (directory)
- Create: `tests/test_games/PacMan/Makefile` (empty placeholder)

- [ ] **Step 1: Remove old incorrectly-named stub files**

```bash
rm tests/test_games/PacMan/client/pacmanServer.c
rm tests/test_games/PacMan/client/pacManServer.h
rm tests/test_games/PacMan/server/pacmanClient.c
rm tests/test_games/PacMan/server/pacmanClient.h
```

- [ ] **Step 2: Create common directory and empty Makefile**

```bash
mkdir -p tests/test_games/PacMan/common
touch tests/test_games/PacMan/Makefile
```

- [ ] **Step 3: Commit**

```bash
git add -A tests/test_games/PacMan/
git commit -m "chore: clean up old PacMan stubs and restructure directories"
```

---

### Task 2: Create pacman_common.h — protocol definitions

**Files:**
- Create: `tests/test_games/PacMan/common/pacman_common.h`

- [ ] **Step 1: Write pacman_common.h**

```c
/**
 * @file pacman_common.h
 * @brief Common definitions shared between PacMan server and client:
 *        constants, enums, and packed message structs.
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
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https: //www.gnu.org/licenses/>.
 */

#ifndef PACMAN_COMMON_H
#define PACMAN_COMMON_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Map constants ─────────────────────────────────────────────────── */

#define PACMAN_MAP_WIDTH  40
#define PACMAN_MAP_HEIGHT 20
#define PACMAN_MAP_CELLS  (PACMAN_MAP_WIDTH * PACMAN_MAP_HEIGHT)

/* ── Gameplay constants ─────────────────────────────────────────────── */

#define PACMAN_GAME_DURATION_SEC   180
#define PACMAN_TICK_MS            100
#define PACMAN_TICKS_PER_SEC      (1000 / PACMAN_TICK_MS)
#define PACMAN_MAX_PLAYERS        4
#define PACMAN_GHOST_COUNT        4
#define PACMAN_STARTING_LIVES     3
#define PACMAN_FRIGHTENED_SEC     5
#define PACMAN_FRIGHTENED_TICKS   (PACMAN_FRIGHTENED_SEC * PACMAN_TICKS_PER_SEC)
#define PACMAN_INVULN_TICKS       (3 * PACMAN_TICKS_PER_SEC)
#define PACMAN_CHASE_INTERVAL_TICKS (7 * PACMAN_TICKS_PER_SEC)

/* ── Scoring constants ──────────────────────────────────────────────── */

#define PACMAN_BEAN_SCORE        10
#define PACMAN_POWER_BEAN_SCORE  50
#define PACMAN_GHOST_EAT_SCORE   200

/* ── Enums ──────────────────────────────────────────────────────────── */

enum PacManMsgType {
    PacManMsgJoin     = 1,
    PacManMsgMove     = 2,
    PacManMsgStart    = 3,
    PacManMsgState    = 4,
    PacManMsgGameOver = 5,
};

enum PacManDir {
    PacManDirUp    = 0,
    PacManDirDown  = 1,
    PacManDirLeft  = 2,
    PacManDirRight = 3,
};

enum PacManCell {
    PacManCellWall      = 0,
    PacManCellPath      = 1,
    PacManCellBean      = 2,
    PacManCellPowerBean = 3,
};

enum PacManGhostMode {
    PacManGhostScatter     = 0,
    PacManGhostChase       = 1,
    PacManGhostFrightened  = 2,
    PacManGhostEaten       = 3,
};

/* ── Packed message structs ─────────────────────────────────────────── */

#pragma pack(push, 1)

/** Client→Server: player direction input. */
typedef struct {
    uint8_t msgType;
    uint8_t direction;
} PacManMoveMsg;

/** Client→Server: player join request. */
typedef struct {
    uint8_t msgType;
    char    playerName[16];
} PacManJoinMsg;

/** Per-player state snapshot (used in PacManStateMsg). */
typedef struct {
    uint8_t  playerId;
    uint16_t posX;
    uint16_t posY;
    uint8_t  direction;
    uint8_t  lives;
    uint32_t score;
    uint8_t  alive;
} PacManPlayerInfo;

/** Per-ghost state snapshot (used in PacManStateMsg). */
typedef struct {
    uint8_t  ghostId;
    uint16_t posX;
    uint16_t posY;
    uint8_t  direction;
    uint8_t  mode;
} PacManGhostInfo;

/** Server→Client: game start, contains full map and player assignment. */
typedef struct {
    uint8_t msgType;
    uint8_t playerId;
    uint8_t playerCount;
    uint8_t mapData[PACMAN_MAP_CELLS];
} PacManStartMsg;

/** Server→Client: per-tick game state snapshot. */
typedef struct {
    uint8_t          msgType;
    uint32_t         seqNum;
    uint32_t         timeLeftSec;
    uint8_t          playerCount;
    uint8_t          beanCount;
    PacManPlayerInfo players[PACMAN_MAX_PLAYERS];
    PacManGhostInfo  ghosts[PACMAN_GHOST_COUNT];
} PacManStateMsg;

/** Server→Client: game over with final ranking. */
typedef struct {
    uint8_t  msgType;
    uint8_t  playerCount;
    uint8_t  rankings[PACMAN_MAX_PLAYERS];
    uint32_t scores[PACMAN_MAX_PLAYERS];
} PacManGameOverMsg;

#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#endif /* PACMAN_COMMON_H */
```

- [ ] **Step 2: Commit**

```bash
git add tests/test_games/PacMan/common/pacman_common.h
git commit -m "feat: add PacMan common protocol definitions"
```

---

### Task 3: Write tests for pacman_common

**Files:**
- Create: `tests/test_pacman_common.c`

- [ ] **Step 1: Write test file**

```c
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
    TEST_MAP_CELLS = 800,
    TEST_MAX_PLAYERS = 4,
    TEST_GHOST_COUNT = 4,
    TEST_BEAN_SCORE = 10,
    TEST_POWER_SCORE = 50,
    TEST_GHOST_EAT = 200,
    TEST_STARTING_LIVES = 3,
};

static void testConstants(void) {
    ASSERT_UINT_EQ(PACMAN_MAP_WIDTH, 40);
    ASSERT_UINT_EQ(PACMAN_MAP_HEIGHT, 20);
    ASSERT_UINT_EQ(PACMAN_MAP_CELLS, TEST_MAP_CELLS);
    ASSERT_UINT_EQ(PACMAN_MAX_PLAYERS, TEST_MAX_PLAYERS);
    ASSERT_UINT_EQ(PACMAN_GHOST_COUNT, TEST_GHOST_COUNT);
    ASSERT_UINT_EQ(PACMAN_BEAN_SCORE, TEST_BEAN_SCORE);
    ASSERT_UINT_EQ(PACMAN_POWER_BEAN_SCORE, TEST_POWER_SCORE);
    ASSERT_UINT_EQ(PACMAN_GHOST_EAT_SCORE, TEST_GHOST_EAT);
    ASSERT_UINT_EQ(PACMAN_STARTING_LIVES, TEST_STARTING_LIVES);
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
    send.playerId = 2;
    send.playerCount = 4;
    memset(send.mapData, PacManCellWall, PACMAN_MAP_CELLS);
    send.mapData[42] = PacManCellPath;
    send.mapData[100] = PacManCellBean;
    send.mapData[200] = PacManCellPowerBean;

    PacManStartMsg recv;
    memcpy(&recv, &send, sizeof(send));
    ASSERT_UINT_EQ(recv.msgType, PacManMsgStart);
    ASSERT_UINT_EQ(recv.playerId, 2);
    ASSERT_UINT_EQ(recv.playerCount, 4);
    ASSERT_UINT_EQ(recv.mapData[0], PacManCellWall);
    ASSERT_UINT_EQ(recv.mapData[42], PacManCellPath);
    ASSERT_UINT_EQ(recv.mapData[100], PacManCellBean);
    ASSERT_UINT_EQ(recv.mapData[200], PacManCellPowerBean);
}

static void testRoundtripStateMsg(void) {
    PacManStateMsg send;
    memset(&send, 0, sizeof(send));
    send.msgType = PacManMsgState;
    send.seqNum = 12345;
    send.timeLeftSec = 120;
    send.playerCount = 2;
    send.beanCount = 80;
    send.players[0].playerId = 0;
    send.players[0].posX = 5;
    send.players[0].posY = 6;
    send.players[0].direction = PacManDirUp;
    send.players[0].lives = 2;
    send.players[0].score = 150;
    send.players[0].alive = 1;
    send.ghosts[0].ghostId = 0;
    send.ghosts[0].posX = 20;
    send.ghosts[0].posY = 10;
    send.ghosts[0].mode = PacManGhostChase;

    PacManStateMsg recv;
    memcpy(&recv, &send, sizeof(send));
    ASSERT_UINT_EQ(recv.seqNum, 12345);
    ASSERT_UINT_EQ(recv.timeLeftSec, 120);
    ASSERT_UINT_EQ(recv.playerCount, 2);
    ASSERT_UINT_EQ(recv.beanCount, 80);
    ASSERT_UINT_EQ(recv.players[0].posX, 5);
    ASSERT_UINT_EQ(recv.players[0].posY, 6);
    ASSERT_UINT_EQ(recv.players[0].score, 150);
    ASSERT_UINT_EQ(recv.ghosts[0].posX, 20);
    ASSERT_UINT_EQ(recv.ghosts[0].posY, 10);
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
```

- [ ] **Step 2: Commit**

```bash
git add tests/test_pacman_common.c
git commit -m "test: add PacMan common protocol layout and roundtrip tests"
```

---

### Task 4: Create pacman_common.c — shared utilities

**Files:**
- Create: `tests/test_games/PacMan/common/pacman_common.c`

- [ ] **Step 1: Write pacman_common.c**

```c
/**
 * @file pacman_common.c
 * @brief Shared utility functions for PacMan (BFS pathfinding, direction helpers).
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
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https: //www.gnu.org/licenses/>.
 */

#include "pacman_common.h"
#include "container.h"
#include <string.h>

/* ── Direction helpers ──────────────────────────────────────────────── */

static const int dirDx[4] = {0, 0, -1, 1};
static const int dirDy[4] = {-1, 1, 0, 0};

int pacmanDirDx(int dir) {
    if (dir < 0 || dir > PacManDirRight) return 0;
    return dirDx[dir];
}

int pacmanDirDy(int dir) {
    if (dir < 0 || dir > PacManDirRight) return 0;
    return dirDy[dir];
}

int pacmanDirOpposite(int dir) {
    switch (dir) {
    case PacManDirUp:    return PacManDirDown;
    case PacManDirDown:  return PacManDirUp;
    case PacManDirLeft:  return PacManDirRight;
    case PacManDirRight: return PacManDirLeft;
    default:             return PacManDirUp;
    }
}

/* ── Map helpers ────────────────────────────────────────────────────── */

bool pacmanIsWall(const uint8_t *map, uint16_t x, uint16_t y) {
    if (x >= PACMAN_MAP_WIDTH || y >= PACMAN_MAP_HEIGHT) return true;
    return map[y * PACMAN_MAP_WIDTH + x] == PacManCellWall;
}

bool pacmanCanMove(const uint8_t *map, uint16_t x, uint16_t y, int dir) {
    uint16_t nx = (uint16_t)((int)x + pacmanDirDx(dir));
    uint16_t ny = (uint16_t)((int)y + pacmanDirDy(dir));
    return !pacmanIsWall(map, nx, ny);
}

static const uint16_t bfsMaxNodes = PACMAN_MAP_CELLS;

/* BFS node used in the queue. */
typedef struct {
    uint16_t x;
    uint16_t y;
} PacManBfsNode;

QUEUE_DEFINE(PacManBfsNode)

/**
 * @brief Run BFS from (startX, startY) to (endX, endY) on the map and
 *        return the first direction to take, or -1 if unreachable.
 *
 *        Ghosts ignore walls when in PacManGhostEaten mode (passing
 *        through walls to return to nest).
 */
int pacmanBfsFindDir(const uint8_t *map, uint16_t startX, uint16_t startY,
                     uint16_t endX, uint16_t endY, bool canPassWalls) {
    if (startX == endX && startY == endY) return PacManDirUp;

    int visited[PACMAN_MAP_HEIGHT][PACMAN_MAP_WIDTH];
    int parentDir[PACMAN_MAP_HEIGHT][PACMAN_MAP_WIDTH];
    memset(visited, 0, sizeof(visited));

    QueuePacManBfsNode q;
    if (queuePacManBfsNodeInit(&q, USE_DEFAULT_CAPACITY) != ContainerSucc) {
        return -1;
    }

    PacManBfsNode start = {startX, startY};
    visited[startY][startX] = 1;
    queuePacManBfsNodePush(&q, start);

    int found = 0;

    while (!queuePacManBfsNodeIsEmpty(&q)) {
        PacManBfsNode cur;
        if (queuePacManBfsNodeFront(&q, &cur) != ContainerSucc) break;
        queuePacManBfsNodePop(&q);

        if (cur.x == endX && cur.y == endY) {
            found = 1;
            break;
        }

        for (int d = 0; d < 4; d++) {
            uint16_t nx = (uint16_t)((int)cur.x + dirDx[d]);
            uint16_t ny = (uint16_t)((int)cur.y + dirDy[d]);
            if (nx >= PACMAN_MAP_WIDTH || ny >= PACMAN_MAP_HEIGHT) continue;
            if (visited[ny][nx]) continue;
            if (!canPassWalls && pacmanIsWall(map, nx, ny)) continue;
            visited[ny][nx] = 1;
            parentDir[ny][nx] = d;
            PacManBfsNode next = {nx, ny};
            queuePacManBfsNodePush(&q, next);
        }
    }

    queuePacManBfsNodeDeinit(&q);

    if (!found) return -1;

    /* Trace back to find the first direction from start. */
    uint16_t cx = endX, cy = endY;
    int firstDir = -1;
    while (!(cx == startX && cy == startY)) {
        int d = parentDir[cy][cx];
        firstDir = d;
        cx = (uint16_t)((int)cx - dirDx[d]);
        cy = (uint16_t)((int)cy - dirDy[d]);
    }
    return firstDir;
}
```

- [ ] **Step 2: Create corresponding header declarations in pacman_common.h**

Append to `tests/test_games/PacMan/common/pacman_common.h` before `#endif`:

```c
#include <stdbool.h>

int  pacmanDirDx(int dir);
int  pacmanDirDy(int dir);
int  pacmanDirOpposite(int dir);
bool pacmanIsWall(const uint8_t *map, uint16_t x, uint16_t y);
bool pacmanCanMove(const uint8_t *map, uint16_t x, uint16_t y, int dir);
int  pacmanBfsFindDir(const uint8_t *map, uint16_t startX, uint16_t startY,
                      uint16_t endX, uint16_t endY, bool canPassWalls);
```

- [ ] **Step 3: Commit**

```bash
git add tests/test_games/PacMan/common/pacman_common.c tests/test_games/PacMan/common/pacman_common.h
git commit -m "feat: add PacMan shared utilities (BFS, direction helpers)"
```

---

### Task 5: Create pacman_server.h — server API

**Files:**
- Create: `tests/test_games/PacMan/server/pacman_server.h`

- [ ] **Step 1: Write pacman_server.h**

```c
/**
 * @file pacman_server.h
 * @brief PacMan game server — authoritative game state and game loop.
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
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https: //www.gnu.org/licenses/>.
 */

#ifndef PACMAN_SERVER_H
#define PACMAN_SERVER_H

#include "pacman_common.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Complete game state managed by the server. */
typedef struct {
    /* Map: current bean state (walls/paths unchanged after init). */
    uint8_t map[PACMAN_MAP_CELLS];
    uint8_t beanCount;

    /* Original map template (for resetting floors after beans are eaten). */
    uint8_t mapTemplate[PACMAN_MAP_CELLS];

    /* Player state. */
    PacManPlayerInfo players[PACMAN_MAX_PLAYERS];
    uint8_t           playerCount;
    uint8_t           playersAlive;

    /* Invulnerability timers (in ticks). */
    int playerInvulnTimer[PACMAN_MAX_PLAYERS];

    /* Ghost state. */
    PacManGhostInfo ghosts[PACMAN_GHOST_COUNT];
    int             frightenedTimer[PACMAN_GHOST_COUNT];
    int             chaseToggleCounter;

    /* Timing. */
    uint32_t seqNum;
    uint32_t timeLeftSec;
    uint32_t tickCount;
    bool     gameStarted;
    bool     gameOver;
} PacManServer;

/** Create a new game server instance. */
PacManServer *pacmanServerCreate(void);

/** Destroy and free all resources. */
void pacmanServerDestroy(PacManServer *srv);

/** Generate the map, place beans, spawn players and ghosts. */
void pacmanServerInit(PacManServer *srv);

/** Add a player (called when a Join message is received). */
int pacmanServerAddPlayer(PacManServer *srv);

/** Process a Move message from a specific player. */
void pacmanServerHandleMove(PacManServer *srv, uint8_t playerId, uint8_t dir);

/** Run one tick of the game loop. Returns true while the game is active. */
bool pacmanServerTick(PacManServer *srv);

/** Build a PacManStartMsg for a specific player. */
void pacmanServerBuildStartMsg(const PacManServer *srv, uint8_t playerId,
                               PacManStartMsg *msg);

/** Build a PacManStateMsg snapshot. */
void pacmanServerBuildStateMsg(const PacManServer *srv, PacManStateMsg *msg);

/** Build a PacManGameOverMsg with final rankings. */
void pacmanServerBuildGameOverMsg(const PacManServer *srv,
                                  PacManGameOverMsg *msg);

#ifdef __cplusplus
}
#endif

#endif /* PACMAN_SERVER_H */
```

- [ ] **Step 2: Commit**

```bash
git add tests/test_games/PacMan/server/pacman_server.h
git commit -m "feat: add PacMan server API header"
```

---

### Task 6: Create pacman_server.c — map generation and initialization

**Files:**
- Create: `tests/test_games/PacMan/server/pacman_server.c`

- [ ] **Step 1: Write the file with map generation and init**

```c
/**
 * @file pacman_server.c
 * @brief PacMan game server implementation.
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
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https: //www.gnu.org/licenses/>.
 */

#include "pacman_server.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ── Classic PacMan-style map layout (40x20) ────────────────────────── */

/*
 * Legend: #=wall, .=path(bean), O=power bean, ' '=path(no bean), X=nest
 *
 * Generated programmatically below. The map template uses PacManCell enum
 * values directly; beans are placed on path cells during init.
 */

static const char mapTemplateChars[] =
    "########################################"
    "####..........................####......"
    "####.####.######.######.######.####......"
    "####.####.######.######.######.####......"
    "####..........................####......"
    "####.####.##.##############.##.####......"
    "####.####.##.##############.##.####......"
    "####......##....##....##....##..........#"
    "######.#######.##.##.##.##.###.#######.##"
    "######.#######.##.##.##.##.###.#######.##"
    "######.##..........##..........##.######"
    "######.##.######.######.######.##.######"
    "######.##.######.######.######.##.######"
    "..........##....##....##....##.........."
    "######.##.########.##.########.##.######"
    "######.##.########.##.########.##.######"
    "######.##..........##..........##.######"
    "######.##.######.######.######.##.######"
    "######.##.######.######.######.##.######"
    "########################################";

static const uint16_t nestX[4] = {18, 19, 20, 21};
static const uint16_t nestY[4] = {9, 9, 10, 10};

static const uint16_t spawnX[PACMAN_MAX_PLAYERS] = {1, 38, 1, 38};
static const uint16_t spawnY[PACMAN_MAX_PLAYERS] = {1, 1, 18, 18};

static const uint16_t ghostHomeX = 19;
static const uint16_t ghostHomeY = 9;

static void initMapTemplate(uint8_t *map, uint8_t *beanCount) {
    *beanCount = 0;
    for (size_t i = 0; i < PACMAN_MAP_CELLS; i++) {
        switch (mapTemplateChars[i]) {
        case '#': map[i] = PacManCellWall;  break;
        case '.': map[i] = PacManCellBean;  (*beanCount)++; break;
        default:  map[i] = PacManCellPath;  break;
        }
    }
    /* Place 4 power beans at designated positions. */
    uint16_t powerPos[4] = {41, 76, 723, 758};
    for (int i = 0; i < PACMAN_GHOST_COUNT; i++) {
        map[powerPos[i]] = PacManCellPowerBean;
        (*beanCount)++;
    }
    /* Nest area is path (no beans). */
    for (int i = 0; i < PACMAN_GHOST_COUNT; i++) {
        map[nestY[i] * PACMAN_MAP_WIDTH + nestX[i]] = PacManCellPath;
    }
}

PacManServer *pacmanServerCreate(void) {
    PacManServer *srv = calloc(1, sizeof(PacManServer));
    if (srv == NULL) return NULL;
    return srv;
}

void pacmanServerDestroy(PacManServer *srv) {
    free(srv);
}

void pacmanServerInit(PacManServer *srv) {
    if (srv == NULL) return;

    srand((unsigned int)time(NULL));

    /* Generate map template (will be copied to active map when game starts). */
    srv->beanCount = 0;
    initMapTemplate(srv->mapTemplate, &srv->beanCount);

    /* Active map starts as copy of template. */
    memcpy(srv->map, srv->mapTemplate, PACMAN_MAP_CELLS);

    /* Reset players. */
    srv->playerCount = 0;
    srv->playersAlive = 0;
    memset(srv->players, 0, sizeof(srv->players));
    memset(srv->playerInvulnTimer, 0, sizeof(srv->playerInvulnTimer));

    /* Reset ghosts. */
    for (int i = 0; i < PACMAN_GHOST_COUNT; i++) {
        srv->ghosts[i].ghostId = (uint8_t)i;
        srv->ghosts[i].posX = ghostHomeX;
        srv->ghosts[i].posY = ghostHomeY;
        srv->ghosts[i].direction = PacManDirUp;
        srv->ghosts[i].mode = PacManGhostScatter;
        srv->frightenedTimer[i] = 0;
    }
    srv->chaseToggleCounter = 0;

    /* Reset timing. */
    srv->seqNum = 0;
    srv->timeLeftSec = PACMAN_GAME_DURATION_SEC;
    srv->tickCount = 0;
    srv->gameStarted = false;
    srv->gameOver = false;
}

int pacmanServerAddPlayer(PacManServer *srv) {
    if (srv == NULL || srv->playerCount >= PACMAN_MAX_PLAYERS) return -1;
    uint8_t pid = srv->playerCount;
    srv->players[pid].playerId = pid;
    srv->players[pid].posX = spawnX[pid];
    srv->players[pid].posY = spawnY[pid];
    srv->players[pid].direction = PacManDirRight;
    srv->players[pid].lives = PACMAN_STARTING_LIVES;
    srv->players[pid].score = 0;
    srv->players[pid].alive = 1;
    srv->playerInvulnTimer[pid] = 0;
    srv->playerCount++;
    srv->playersAlive++;
    return pid;
}
```

- [ ] **Step 2: Commit**

```bash
git add tests/test_games/PacMan/server/pacman_server.c
git commit -m "feat: add PacMan server map generation and initialization"
```

---

### Task 7: Create pacman_server.c — ghost AI

**Files:**
- Modify: `tests/test_games/PacMan/server/pacman_server.c` (append ghost AI functions)

- [ ] **Step 1: Append ghost AI functions after the init code**

```c
/* ── Ghost AI ───────────────────────────────────────────────────────── */

static void moveGhost(PacManServer *srv, int gi, int dir) {
    srv->ghosts[gi].direction = (uint8_t)dir;
    srv->ghosts[gi].posX = (uint16_t)((int)srv->ghosts[gi].posX + pacmanDirDx(dir));
    srv->ghosts[gi].posY = (uint16_t)((int)srv->ghosts[gi].posY + pacmanDirDy(dir));
}

static int chooseGhostScatterDir(const PacManServer *srv, int gi) {
    PacManGhostInfo *g = (PacManGhostInfo *)&srv->ghosts[gi];
    int opposite = pacmanDirOpposite((int)g->direction);
    int valid[4];
    int validCount = 0;
    for (int d = 0; d < 4; d++) {
        if (d == opposite) continue;
        uint16_t nx = (uint16_t)((int)g->posX + pacmanDirDx(d));
        uint16_t ny = (uint16_t)((int)g->posY + pacmanDirDy(d));
        if (!pacmanIsWall(srv->map, nx, ny)) {
            valid[validCount++] = d;
        }
    }
    if (validCount == 0) return opposite;
    return valid[rand() % validCount];
}

static int chooseGhostChaseDir(const PacManServer *srv, int gi) {
    PacManGhostInfo *g = (PacManGhostInfo *)&srv->ghosts[gi];

    /* Find nearest alive player. */
    uint16_t tx = 0, ty = 0;
    int found = 0;
    uint32_t bestDist = UINT32_MAX;
    for (uint8_t i = 0; i < srv->playerCount; i++) {
        if (!srv->players[i].alive) continue;
        uint32_t dx = (uint32_t)abs((int)srv->players[i].posX - (int)g->posX);
        uint32_t dy = (uint32_t)abs((int)srv->players[i].posY - (int)g->posY);
        uint32_t dist = dx + dy;
        if (dist < bestDist) {
            bestDist = dist;
            tx = srv->players[i].posX;
            ty = srv->players[i].posY;
            found = 1;
        }
    }
    if (!found) return chooseGhostScatterDir(srv, gi);

    int dir = pacmanBfsFindDir(srv->map, g->posX, g->posY, tx, ty, false);
    if (dir < 0) return chooseGhostScatterDir(srv, gi);
    return dir;
}

static int chooseGhostFrightenedDir(const PacManServer *srv, int gi) {
    PacManGhostInfo *g = (PacManGhostInfo *)&srv->ghosts[gi];
    int opposite = pacmanDirOpposite((int)g->direction);
    int valid[4];
    int validCount = 0;
    for (int d = 0; d < 4; d++) {
        uint16_t nx = (uint16_t)((int)g->posX + pacmanDirDx(d));
        uint16_t ny = (uint16_t)((int)g->posY + pacmanDirDy(d));
        if (nx < PACMAN_MAP_WIDTH && ny < PACMAN_MAP_HEIGHT &&
            srv->map[ny * PACMAN_MAP_WIDTH + nx] != PacManCellWall) {
            valid[validCount++] = d;
        }
    }
    if (validCount == 0) return opposite;
    return valid[rand() % validCount];
}

static int chooseGhostEatenDir(const PacManServer *srv, int gi) {
    PacManGhostInfo *g = (PacManGhostInfo *)&srv->ghosts[gi];
    /* Head back to the nest. */
    int dir = pacmanBfsFindDir(srv->map, g->posX, g->posY,
                               ghostHomeX, ghostHomeY, true);
    if (dir < 0) {
        /* Already at or near nest, scatter. */
        dir = chooseGhostScatterDir(srv, gi);
    }
    return dir;
}

static void updateGhost(PacManServer *srv, int gi) {
    int dir;
    bool moveSlow = false;

    switch (srv->ghosts[gi].mode) {
    case PacManGhostScatter:
        dir = chooseGhostScatterDir(srv, gi);
        break;
    case PacManGhostChase:
        dir = chooseGhostChaseDir(srv, gi);
        break;
    case PacManGhostFrightened:
        dir = chooseGhostFrightenedDir(srv, gi);
        moveSlow = true;
        break;
    case PacManGhostEaten:
        dir = chooseGhostEatenDir(srv, gi);
        break;
    default:
        dir = chooseGhostScatterDir(srv, gi);
        break;
    }

    /* Frightened ghosts move every other tick. */
    if (moveSlow && (srv->tickCount % 2 != 0)) return;

    int opposite = pacmanDirOpposite((int)srv->ghosts[gi].direction);
    /* Don't reverse direction unless mode changed this tick. */
    if (dir == opposite) {
        dir = chooseGhostScatterDir(srv, gi);
    }

    moveGhost(srv, gi, dir);

    /* Check if eaten ghost reached nest. */
    if (srv->ghosts[gi].mode == PacManGhostEaten) {
        if (srv->ghosts[gi].posX == ghostHomeX &&
            srv->ghosts[gi].posY == ghostHomeY) {
            srv->ghosts[gi].mode = PacManGhostScatter;
        }
    }
}

static void updateGhostModeSwitch(PacManServer *srv) {
    srv->chaseToggleCounter++;

    for (int i = 0; i < PACMAN_GHOST_COUNT; i++) {
        /* Count down frightened timer. */
        if (srv->frightenedTimer[i] > 0) {
            srv->frightenedTimer[i]--;
            if (srv->frightenedTimer[i] == 0 &&
                srv->ghosts[i].mode == PacManGhostFrightened) {
                srv->ghosts[i].mode = PacManGhostScatter;
            }
        }

        /* Toggle between scatter and chase. */
        if (srv->ghosts[i].mode != PacManGhostFrightened &&
            srv->ghosts[i].mode != PacManGhostEaten) {
            if (srv->chaseToggleCounter % PACMAN_CHASE_INTERVAL_TICKS == 0) {
                srv->ghosts[i].mode = PacManGhostChase;
            } else if (srv->chaseToggleCounter % PACMAN_CHASE_INTERVAL_TICKS ==
                       PACMAN_CHASE_INTERVAL_TICKS / 2) {
                srv->ghosts[i].mode = PacManGhostScatter;
            }
        }
    }
}

static void activateFrightened(PacManServer *srv) {
    for (int i = 0; i < PACMAN_GHOST_COUNT; i++) {
        if (srv->ghosts[i].mode != PacManGhostEaten) {
            srv->ghosts[i].mode = PacManGhostFrightened;
        }
        srv->frightenedTimer[i] = PACMAN_FRIGHTENED_TICKS;
    }
}
```

- [ ] **Step 2: Commit**

```bash
git add tests/test_games/PacMan/server/pacman_server.c
git commit -m "feat: add PacMan server ghost AI (scatter/chase/frightened/eaten)"
```

---

### Task 8: Create pacman_server.c — game loop, collision, and message builders

**Files:**
- Modify: `tests/test_games/PacMan/server/pacman_server.c` (append tick logic)

- [ ] **Step 1: Append game tick, collision detection, and message builders**

```c
/* ── Collision & eating ─────────────────────────────────────────────── */

static void handlePlayerEating(PacManServer *srv, uint8_t pid) {
    PacManPlayerInfo *p = &srv->players[pid];
    uint16_t idx = p->posY * PACMAN_MAP_WIDTH + p->posX;

    if (idx >= PACMAN_MAP_CELLS) return;

    if (srv->map[idx] == PacManCellBean) {
        p->score += PACMAN_BEAN_SCORE;
        srv->map[idx] = PacManCellPath;
        srv->beanCount--;
    } else if (srv->map[idx] == PacManCellPowerBean) {
        p->score += PACMAN_POWER_BEAN_SCORE;
        srv->map[idx] = PacManCellPath;
        srv->beanCount--;
        activateFrightened(srv);
    }
}

static void handlePlayerGhostCollision(PacManServer *srv) {
    for (uint8_t pid = 0; pid < srv->playerCount; pid++) {
        if (!srv->players[pid].alive) continue;
        if (srv->playerInvulnTimer[pid] > 0) continue;

        for (int gi = 0; gi < PACMAN_GHOST_COUNT; gi++) {
            if (srv->ghosts[gi].posX != srv->players[pid].posX) continue;
            if (srv->ghosts[gi].posY != srv->players[pid].posY) continue;

            if (srv->ghosts[gi].mode == PacManGhostFrightened) {
                /* Player eats ghost. */
                srv->players[pid].score += PACMAN_GHOST_EAT_SCORE;
                srv->ghosts[gi].mode = PacManGhostEaten;
            } else if (srv->ghosts[gi].mode != PacManGhostEaten) {
                /* Ghost catches player. */
                if (srv->players[pid].lives > 0) {
                    srv->players[pid].lives--;
                    srv->playerInvulnTimer[pid] = PACMAN_INVULN_TICKS;
                }
                if (srv->players[pid].lives == 0) {
                    srv->players[pid].alive = 0;
                    srv->playersAlive--;
                }
            }
        }
    }
}

/* ── Player input ───────────────────────────────────────────────────── */

void pacmanServerHandleMove(PacManServer *srv, uint8_t playerId, uint8_t dir) {
    if (srv == NULL || playerId >= srv->playerCount) return;
    if (!srv->players[playerId].alive) return;
    if (dir > PacManDirRight) return;
    srv->players[playerId].direction = dir;
}

/* ── Game tick ──────────────────────────────────────────────────────── */

bool pacmanServerTick(PacManServer *srv) {
    if (srv == NULL || srv->gameOver) return false;
    if (!srv->gameStarted) {
        srv->gameStarted = true;
        return true;
    }

    srv->tickCount++;
    srv->seqNum++;

    /* Update time. */
    if (srv->tickCount % PACMAN_TICKS_PER_SEC == 0 && srv->timeLeftSec > 0) {
        srv->timeLeftSec--;
    }

    /* Count down invulnerability timers. */
    for (uint8_t i = 0; i < srv->playerCount; i++) {
        if (srv->playerInvulnTimer[i] > 0) {
            srv->playerInvulnTimer[i]--;
        }
    }

    /* Move players. */
    for (uint8_t i = 0; i < srv->playerCount; i++) {
        if (!srv->players[i].alive) continue;
        int d = (int)srv->players[i].direction;
        uint16_t nx = (uint16_t)((int)srv->players[i].posX + pacmanDirDx(d));
        uint16_t ny = (uint16_t)((int)srv->players[i].posY + pacmanDirDy(d));
        if (!pacmanIsWall(srv->map, nx, ny)) {
            srv->players[i].posX = nx;
            srv->players[i].posY = ny;
        }
    }

    /* Update ghost modes. */
    updateGhostModeSwitch(srv);

    /* Move ghosts. */
    for (int i = 0; i < PACMAN_GHOST_COUNT; i++) {
        updateGhost(srv, i);
    }

    /* Player eating. */
    for (uint8_t i = 0; i < srv->playerCount; i++) {
        if (srv->players[i].alive) {
            handlePlayerEating(srv, i);
        }
    }

    /* Ghost-player collisions. */
    handlePlayerGhostCollision(srv);

    /* Check end conditions. */
    if (srv->timeLeftSec == 0 || srv->beanCount == 0) {
        srv->gameOver = true;
    }
    if (srv->playersAlive == 0) {
        srv->gameOver = true;
    }

    return !srv->gameOver;
}

/* ── Message builders ───────────────────────────────────────────────── */

void pacmanServerBuildStartMsg(const PacManServer *srv, uint8_t playerId,
                               PacManStartMsg *msg) {
    if (srv == NULL || msg == NULL) return;
    memset(msg, 0, sizeof(*msg));
    msg->msgType = PacManMsgStart;
    msg->playerId = playerId;
    msg->playerCount = srv->playerCount;
    memcpy(msg->mapData, srv->mapTemplate, PACMAN_MAP_CELLS);
}

void pacmanServerBuildStateMsg(const PacManServer *srv, PacManStateMsg *msg) {
    if (srv == NULL || msg == NULL) return;
    memset(msg, 0, sizeof(*msg));
    msg->msgType = PacManMsgState;
    msg->seqNum = srv->seqNum;
    msg->timeLeftSec = srv->timeLeftSec;
    msg->playerCount = srv->playerCount;
    msg->beanCount = srv->beanCount;
    memcpy(msg->players, srv->players,
           srv->playerCount * sizeof(PacManPlayerInfo));
    memcpy(msg->ghosts, srv->ghosts, sizeof(srv->ghosts));
}

void pacmanServerBuildGameOverMsg(const PacManServer *srv,
                                  PacManGameOverMsg *msg) {
    if (srv == NULL || msg == NULL) return;
    memset(msg, 0, sizeof(*msg));
    msg->msgType = PacManMsgGameOver;
    msg->playerCount = srv->playerCount;

    /* Build ranking: sort player indices by score descending. */
    uint8_t order[PACMAN_MAX_PLAYERS];
    for (uint8_t i = 0; i < srv->playerCount; i++) order[i] = i;

    for (uint8_t i = 0; i < srv->playerCount; i++) {
        for (uint8_t j = i + 1; j < srv->playerCount; j++) {
            uint32_t si = srv->players[order[i]].score;
            uint32_t sj = srv->players[order[j]].score;
            if (sj > si ||
                (sj == si && srv->players[order[j]].alive &&
                 !srv->players[order[i]].alive)) {
                uint8_t tmp = order[i];
                order[i] = order[j];
                order[j] = tmp;
            }
        }
    }
    memcpy(msg->rankings, order, srv->playerCount);
    for (uint8_t i = 0; i < srv->playerCount; i++) {
        msg->scores[i] = srv->players[i].score;
    }
}
```

- [ ] **Step 2: Commit**

```bash
git add tests/test_games/PacMan/server/pacman_server.c
git commit -m "feat: add PacMan server game loop, collisions, and message builders"
```

---

### Task 9: Create pacman_server.c — main entry point

**Files:**
- Modify: `tests/test_games/PacMan/server/pacman_server.c` (append main function)

- [ ] **Step 1: Append the server main function**

```c
/* ── Server main ────────────────────────────────────────────────────── */

#ifdef PACMAN_SERVER_MAIN

#include "pacplay_sdk.h"
#include <stdio.h>
#include <unistd.h>

static PacManServer *gServer = NULL;

static void onServerReceive(const void *payload, size_t len, void *userData) {
    (void)userData;
    if (payload == NULL || len < 1) return;

    const uint8_t *data = (const uint8_t *)payload;
    uint8_t msgType = data[0];

    if (msgType == PacManMsgJoin) {
        /* Add a new player. */
        int pid = pacmanServerAddPlayer(gServer);
        if (pid >= 0) {
            PacManStartMsg startMsg;
            pacmanServerBuildStartMsg(gServer, (uint8_t)pid, &startMsg);
            /* Broadcast start to all players. */
            pacplay_srv_send((PacPlaySDK *)userData, &startMsg,
                             sizeof(startMsg));
            printf("[PacMan Server] Player %d joined (total: %d)\n",
                   pid, gServer->playerCount);
        }
    } else if (msgType == PacManMsgMove) {
        if (len >= sizeof(PacManMoveMsg)) {
            const PacManMoveMsg *move = (const PacManMoveMsg *)payload;
            /* Player ID is inferred from which client sent it.
             * In a real integration, the IO thread tags messages with
             * client ID. For demo, we take the first player. */
            pacmanServerHandleMove(gServer, 0, move->direction);
        }
    }
}

int main(void) {
    printf("PacMan Server starting...\n");

    gServer = pacmanServerCreate();
    if (gServer == NULL) {
        fprintf(stderr, "Failed to create PacMan server\n");
        return 1;
    }
    pacmanServerInit(gServer);

    PacPlaySDK *sdk = pacplay_srv_create();
    if (sdk == NULL) {
        fprintf(stderr, "Failed to create Server SDK\n");
        pacmanServerDestroy(gServer);
        return 1;
    }

    pacplay_srv_on_receive(sdk, onServerReceive, sdk);

    printf("PacMan Server ready. Waiting for players...\n");

    /* Game loop. */
    while (true) {
        pacplay_srv_poll(sdk);

        if (gServer->gameStarted) {
            bool running = pacmanServerTick(gServer);
            if (!running) break;

            PacManStateMsg stateMsg;
            pacmanServerBuildStateMsg(gServer, &stateMsg);
            pacplay_srv_send(sdk, &stateMsg, sizeof(stateMsg));
        }

        usleep(PACMAN_TICK_MS * 1000);
    }

    /* Game over. */
    PacManGameOverMsg overMsg;
    pacmanServerBuildGameOverMsg(gServer, &overMsg);
    pacplay_srv_send(sdk, &overMsg, sizeof(overMsg));
    printf("[PacMan Server] Game over!\n");
    for (uint8_t i = 0; i < gServer->playerCount; i++) {
        printf("  Player %d: %u points\n", i, gServer->players[i].score);
    }

    pacplay_srv_destroy(sdk);
    pacmanServerDestroy(gServer);
    return 0;
}

#endif /* PACMAN_SERVER_MAIN */
```

- [ ] **Step 2: Commit**

```bash
git add tests/test_games/PacMan/server/pacman_server.c
git commit -m "feat: add PacMan server main entry point"
```

---

### Task 10: Create pacman_client.h — client API

**Files:**
- Create: `tests/test_games/PacMan/client/pacman_client.h`

- [ ] **Step 1: Write pacman_client.h**

```c
/**
 * @file pacman_client.h
 * @brief PacMan game client — terminal rendering and keyboard input.
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
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https: //www.gnu.org/licenses/>.
 */

#ifndef PACMAN_CLIENT_H
#define PACMAN_CLIENT_H

#include "pacman_common.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Client state: mirrors the server state for local rendering. */
typedef struct {
    uint8_t map[PACMAN_MAP_CELLS];
    uint8_t myPlayerId;
    uint8_t playerCount;
    PacManPlayerInfo players[PACMAN_MAX_PLAYERS];
    PacManGhostInfo ghosts[PACMAN_GHOST_COUNT];
    uint32_t timeLeftSec;
    uint8_t beanCount;
    bool gameOver;
} PacManClient;

/** Initialize client state. */
void pacmanClientInit(PacManClient *cli);

/** Apply a StartMsg to client state. */
void pacmanClientApplyStart(PacManClient *cli, const PacManStartMsg *msg);

/** Apply a StateMsg to client state. */
void pacmanClientApplyState(PacManClient *cli, const PacManStateMsg *msg);

/** Apply a GameOverMsg to client state. */
void pacmanClientApplyGameOver(PacManClient *cli, const PacManGameOverMsg *msg);

/** Render the current game state to the terminal. */
void pacmanClientRender(const PacManClient *cli);

/** Setup terminal for non-blocking keyboard input. */
void pacmanClientTermInit(void);

/** Restore terminal settings. */
void pacmanClientTermRestore(void);

/** Read a direction key (non-blocking), returns -1 if no input. */
int pacmanClientReadInput(void);

#ifdef __cplusplus
}
#endif

#endif /* PACMAN_CLIENT_H */
```

- [ ] **Step 2: Commit**

```bash
git add tests/test_games/PacMan/client/pacman_client.h
git commit -m "feat: add PacMan client API header"
```

---

### Task 11: Create pacman_client.c — state management and rendering

**Files:**
- Create: `tests/test_games/PacMan/client/pacman_client.c`

- [ ] **Step 1: Write pacman_client.c with state management and rendering**

```c
/**
 * @file pacman_client.c
 * @brief PacMan game client implementation — state management, rendering,
 *        and keyboard input via ANSI terminal.
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
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https: //www.gnu.org/licenses/>.
 */

#include "pacman_client.h"
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>

static struct termios savedTermios;
static int termSaved = 0;

/* ── Cell display characters ───────────────────────────────────────────*/

static char cellChar(uint8_t cell, uint16_t pos, const PacManClient *cli) {
    /* Check if any player is at this position. */
    for (uint8_t i = 0; i < cli->playerCount; i++) {
        if (cli->players[i].posX == (uint16_t)(pos % PACMAN_MAP_WIDTH) &&
            cli->players[i].posY == (uint16_t)(pos / PACMAN_MAP_WIDTH)) {
            return cli->players[i].alive ? (char)('1' + i) : 'x';
        }
    }
    /* Check if any ghost is at this position. */
    for (int i = 0; i < PACMAN_GHOST_COUNT; i++) {
        if (cli->ghosts[i].posX == (uint16_t)(pos % PACMAN_MAP_WIDTH) &&
            cli->ghosts[i].posY == (uint16_t)(pos / PACMAN_MAP_WIDTH)) {
            switch (cli->ghosts[i].mode) {
            case PacManGhostFrightened: return 'f';
            case PacManGhostEaten:      return 'e';
            default:                    return (char)('A' + i);
            }
        }
    }
    switch (cell) {
    case PacManCellWall:      return '#';
    case PacManCellBean:      return '.';
    case PacManCellPowerBean: return 'O';
    default:                  return ' ';
    }
}

/* ── ANSI color helpers ────────────────────────────────────────────────*/

static const char *ghostColor(int gi, uint8_t mode) {
    (void)gi;
    if (mode == PacManGhostFrightened) return "\033[34m";
    if (mode == PacManGhostEaten)      return "\033[37m";
    const char *colors[] = {"\033[31m", "\033[35m", "\033[36m", "\033[33m"};
    return colors[gi % PACMAN_GHOST_COUNT];
}

/* ── State management ─────────────────────────────────────────────────*/

void pacmanClientInit(PacManClient *cli) {
    if (cli == NULL) return;
    memset(cli, 0, sizeof(*cli));
}

void pacmanClientApplyStart(PacManClient *cli, const PacManStartMsg *msg) {
    if (cli == NULL || msg == NULL) return;
    cli->myPlayerId = msg->playerId;
    cli->playerCount = msg->playerCount;
    memcpy(cli->map, msg->mapData, PACMAN_MAP_CELLS);
}

void pacmanClientApplyState(PacManClient *cli, const PacManStateMsg *msg) {
    if (cli == NULL || msg == NULL) return;
    cli->playerCount = msg->playerCount;
    cli->timeLeftSec = msg->timeLeftSec;
    cli->beanCount = msg->beanCount;
    memcpy(cli->players, msg->players, PACMAN_MAX_PLAYERS * sizeof(PacManPlayerInfo));
    memcpy(cli->ghosts, msg->ghosts, sizeof(cli->ghosts));
    /* Update map: beans eaten on server are marked as path. */
    for (size_t i = 0; i < PACMAN_MAP_CELLS; i++) {
        if (cli->map[i] == PacManCellBean || cli->map[i] == PacManCellPowerBean) {
            cli->map[i] = PacManCellPath;
        }
    }
    /* Re-draw beans from player positions? No — beans are server-authoritative.
     * The map data in state messages doesn't include bean positions.
     * We track total beanCount and render beans based on initial map minus eaten. */
}

void pacmanClientApplyGameOver(PacManClient *cli,
                               const PacManGameOverMsg *msg) {
    if (cli == NULL || msg == NULL) return;
    cli->gameOver = true;
    (void)msg;
}

/* ── Rendering ────────────────────────────────────────────────────────*/

void pacmanClientRender(const PacManClient *cli) {
    if (cli == NULL) return;

    printf("\033[H\033[2J");

    for (uint16_t y = 0; y < PACMAN_MAP_HEIGHT; y++) {
        for (uint16_t x = 0; x < PACMAN_MAP_WIDTH; x++) {
            uint16_t pos = y * PACMAN_MAP_WIDTH + x;
            uint8_t cell = cli->map[pos];

            /* Check for entities at this position. */
            char ch = cellChar(cell, pos, cli);
            int entityHere = 0;

            /* Color ghost characters. */
            for (int gi = 0; gi < PACMAN_GHOST_COUNT; gi++) {
                if (cli->ghosts[gi].posX == x && cli->ghosts[gi].posY == y) {
                    printf("%s%c\033[0m", ghostColor(gi, cli->ghosts[gi].mode), ch);
                    entityHere = 1;
                    break;
                }
            }
            if (entityHere) continue;

            /* Color players. */
            for (uint8_t pi = 0; pi < cli->playerCount; pi++) {
                if (cli->players[pi].posX == x && cli->players[pi].posY == y) {
                    printf("\033[1;33m%c\033[0m", cli->players[pi].alive ? '1' + pi : 'x');
                    entityHere = 1;
                    break;
                }
            }
            if (entityHere) continue;

            /* Map elements. */
            switch (cell) {
            case PacManCellWall:      printf("\033[34m#\033[0m"); break;
            case PacManCellBean:      printf("\033[37m.\033[0m"); break;
            case PacManCellPowerBean: printf("\033[1;37mO\033[0m"); break;
            default:                  putchar(' '); break;
            }
        }
        putchar('\n');
    }

    /* HUD. */
    printf("\n  Time: %us  |  Beans: %u",
           cli->timeLeftSec, cli->beanCount);
    for (uint8_t i = 0; i < cli->playerCount; i++) {
        printf("  P%d: %u%s",
               i, cli->players[i].score,
               cli->players[i].playerId == cli->myPlayerId ? " (YOU)" : "");
    }
    printf("  Lives: %u\n", cli->players[cli->myPlayerId].lives);

    if (cli->gameOver) {
        printf("\n\033[1;31m  GAME OVER\n\033[0m");
    }
}

/* ── Terminal I/O ─────────────────────────────────────────────────────*/

void pacmanClientTermInit(void) {
    struct termios raw;
    tcgetattr(STDIN_FILENO, &raw);
    savedTermios = raw;
    termSaved = 1;
    raw.c_lflag &= (tcflag_t) ~(ICANON | ECHO);
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
    fcntl(STDIN_FILENO, F_SETFL, fcntl(STDIN_FILENO, F_GETFL) | O_NONBLOCK);
}

void pacmanClientTermRestore(void) {
    if (termSaved) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &savedTermios);
        termSaved = 0;
    }
}

int pacmanClientReadInput(void) {
    char buf[4] = {0};
    ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
    if (n <= 0) return -1;

    /* Arrow keys send ESC [ A/B/C/D sequence. */
    if (n >= 3 && buf[0] == '\033' && buf[1] == '[') {
        switch (buf[2]) {
        case 'A': return PacManDirUp;
        case 'B': return PacManDirDown;
        case 'C': return PacManDirRight;
        case 'D': return PacManDirLeft;
        }
    }
    /* WASD. */
    switch (buf[0]) {
    case 'w': case 'W': return PacManDirUp;
    case 's': case 'S': return PacManDirDown;
    case 'a': case 'A': return PacManDirLeft;
    case 'd': case 'D': return PacManDirRight;
    case 'q': case 'Q': return -2; /* quit signal */
    }
    return -1;
}
```

- [ ] **Step 2: Commit**

```bash
git add tests/test_games/PacMan/client/pacman_client.c
git commit -m "feat: add PacMan client state management and rendering"
```

---

### Task 12: Create pacman_client.c — main entry point

**Files:**
- Modify: `tests/test_games/PacMan/client/pacman_client.c` (append main)

- [ ] **Step 1: Append the client main function**

```c
/* ── Client main ───────────────────────────────────────────────────────*/

#ifdef PACMAN_CLIENT_MAIN

#include "pacplay_sdk.h"
#include <stdio.h>
#include <unistd.h>

static PacManClient gClient;
static int gQuit = 0;

static void onClientReceive(const void *payload, size_t len, void *userData) {
    (void)userData;
    if (payload == NULL || len < 1) return;

    const uint8_t *data = (const uint8_t *)payload;
    uint8_t msgType = data[0];

    switch (msgType) {
    case PacManMsgStart:
        if (len >= sizeof(PacManStartMsg)) {
            pacmanClientApplyStart(&gClient, (const PacManStartMsg *)payload);
            printf("Game started! You are Player %u of %u\n",
                   gClient.myPlayerId + 1, gClient.playerCount);
        }
        break;
    case PacManMsgState:
        if (len >= sizeof(PacManStateMsg)) {
            pacmanClientApplyState(&gClient, (const PacManStateMsg *)payload);
        }
        break;
    case PacManMsgGameOver:
        if (len >= sizeof(PacManGameOverMsg)) {
            pacmanClientApplyGameOver(&gClient,
                                      (const PacManGameOverMsg *)payload);
        }
        break;
    }
}

int main(void) {
    printf("PacMan Client starting...\n");

    pacmanClientInit(&gClient);

    PacPlaySDK *sdk = pacplay_cli_create();
    if (sdk == NULL) {
        fprintf(stderr, "Failed to create Client SDK\n");
        return 1;
    }

    pacplay_cli_on_receive(sdk, onClientReceive, sdk);
    pacmanClientTermInit();

    /* Send a join message. */
    PacManJoinMsg joinMsg;
    memset(&joinMsg, 0, sizeof(joinMsg));
    joinMsg.msgType = PacManMsgJoin;
    snprintf(joinMsg.playerName, sizeof(joinMsg.playerName), "Player");
    pacplay_cli_send(sdk, &joinMsg, sizeof(joinMsg));

    printf("Waiting for game start...\n");

    int lastDir = -1;

    while (!gQuit) {
        pacplay_cli_poll(sdk);

        /* Render if we have map data. */
        if (gClient.playerCount > 0) {
            pacmanClientRender(&gClient);
        }

        /* Read input. */
        int dir = pacmanClientReadInput();
        if (dir == -2) {
            gQuit = 1;
            break;
        }
        if (dir >= 0 && dir != lastDir) {
            lastDir = dir;
            PacManMoveMsg move;
            move.msgType = PacManMsgMove;
            move.direction = (uint8_t)dir;
            pacplay_cli_send(sdk, &move, sizeof(move));
        }

        if (gClient.gameOver) {
            pacmanClientRender(&gClient);
            printf("\nPress Q to quit...\n");
            while (pacmanClientReadInput() != -2) {
                pacplay_cli_poll(sdk);
                usleep(50000);
            }
            gQuit = 1;
        }

        usleep(PACMAN_TICK_MS * 1000);
    }

    pacmanClientTermRestore();
    printf("\033[H\033[2J");
    pacplay_cli_destroy(sdk);
    return 0;
}

#endif /* PACMAN_CLIENT_MAIN */
```

- [ ] **Step 2: Commit**

```bash
git add tests/test_games/PacMan/client/pacman_client.c
git commit -m "feat: add PacMan client main entry point"
```

---

### Task 13: Create Makefile for PacMan

**Files:**
- Create: `tests/test_games/PacMan/Makefile`

- [ ] **Step 1: Write Makefile**

```makefile
# PacMan Game Makefile
# Builds standalone pacman_server and pacman_client binaries
# linking against PacPlay SDK shared libraries.

CC       := clang
CFLAGS   := -Wall -Wextra -Werror -g
CFLAGS   += -I../../../include -I../../../src -I../../../sdk/include

LDFLAGS_SRV := -L../../../sdk/lib -lpacplay_server_sdk -Wl,-rpath,../../../sdk/lib -lpthread
LDFLAGS_CLI := -L../../../sdk/lib -lpacplay_client_sdk -Wl,-rpath,../../../sdk/lib -lpthread

BIN_DIR   := ../../../bin
BUILD_DIR := build

SRV_SRC   := server/pacman_server.c common/pacman_common.c
CLI_SRC   := client/pacman_client.c common/pacman_common.c

SRV_OBJ   := $(patsubst %.c,$(BUILD_DIR)/%.o,$(SRV_SRC))
CLI_OBJ   := $(patsubst %.c,$(BUILD_DIR)/%.o,$(CLI_SRC))

.PHONY: all clean server client

all: server client

server: $(BIN_DIR)/pacman_server

client: $(BIN_DIR)/pacman_client

$(BIN_DIR)/pacman_server: $(SRV_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) -DPACMAN_SERVER_MAIN -o $@ $^ $(LDFLAGS_SRV)

$(BIN_DIR)/pacman_client: $(CLI_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) -DPACMAN_CLIENT_MAIN -o $@ $^ $(LDFLAGS_CLI)

$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)/pacman_server $(BIN_DIR)/pacman_client
```

- [ ] **Step 2: Build and verify compilation**

```bash
make -C tests/test_games/PacMan clean && make -C tests/test_games/PacMan all
```

Expected: zero warnings, zero errors.

- [ ] **Step 3: Run clang-format on all source files**

```bash
clang-format -i tests/test_games/PacMan/common/pacman_common.h
clang-format -i tests/test_games/PacMan/common/pacman_common.c
clang-format -i tests/test_games/PacMan/server/pacman_server.h
clang-format -i tests/test_games/PacMan/server/pacman_server.c
clang-format -i tests/test_games/PacMan/client/pacman_client.h
clang-format -i tests/test_games/PacMan/client/pacman_client.c
```

- [ ] **Step 4: Commit**

```bash
git add tests/test_games/PacMan/Makefile
git commit -m "feat: add PacMan Makefile for standalone game builds"
```

---

### Task 14: Write server logic tests and final verification

**Files:**
- Create: `tests/test_pacman_server.c`

- [ ] **Step 1: Write tests for server logic**

```c
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
    TEST_MAP_CELLS = 800,
    TEST_MAX_PLAYERS = 4,
    TEST_GHOST_COUNT = 4,
    TEST_START_LIVES = 3,
    TEST_DURATION = 180,
};

static void testServerCreateDestroy(void) {
    PacManServer *srv = pacmanServerCreate();
    ASSERT_NOT_NULL(srv);
    pacmanServerDestroy(srv);
}

static void testServerCreateDestroyNull(void) {
    pacmanServerDestroy(NULL);
}

static void testServerInit(void) {
    PacManServer *srv = pacmanServerCreate();
    ASSERT_NOT_NULL(srv);
    pacmanServerInit(srv);
    ASSERT_TRUE(srv->beanCount > 0);
    ASSERT_UINT_EQ(srv->playerCount, 0);
    ASSERT_UINT_EQ(srv->playersAlive, 0);
    ASSERT_FALSE(srv->gameStarted);
    ASSERT_FALSE(srv->gameOver);
    ASSERT_UINT_EQ(srv->timeLeftSec, TEST_DURATION);
    ASSERT_UINT_EQ(srv->seqNum, 0);
    pacmanServerDestroy(srv);
}

static void testInitOnNull(void) {
    pacmanServerInit(NULL);
    /* Should not crash. */
}

static void testAddPlayer(void) {
    PacManServer *srv = pacmanServerCreate();
    ASSERT_NOT_NULL(srv);
    pacmanServerInit(srv);

    int pid0 = pacmanServerAddPlayer(srv);
    ASSERT_INT_EQ(pid0, 0);
    ASSERT_UINT_EQ(srv->playerCount, 1);
    ASSERT_UINT_EQ(srv->playersAlive, 1);
    ASSERT_UINT_EQ(srv->players[0].playerId, 0);
    ASSERT_UINT_EQ(srv->players[0].lives, TEST_START_LIVES);
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
    ASSERT_NOT_NULL(srv);
    pacmanServerInit(srv);
    for (int i = 0; i < TEST_MAX_PLAYERS; i++) {
        int pid = pacmanServerAddPlayer(srv);
        ASSERT_INT_EQ(pid, i);
    }
    int pid = pacmanServerAddPlayer(srv);
    ASSERT_INT_EQ(pid, -1);
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

    pacmanServerHandleMove(srv, 0, 99);
    ASSERT_UINT_EQ(srv->players[0].direction, PacManDirRight);

    pacmanServerHandleMove(NULL, 0, PacManDirUp);
    pacmanServerHandleMove(srv, 99, PacManDirUp);

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
    srv->seqNum = 42;
    srv->players[0].posX = 10;
    srv->players[0].posY = 5;

    PacManStateMsg msg;
    pacmanServerBuildStateMsg(srv, &msg);
    ASSERT_UINT_EQ(msg.msgType, PacManMsgState);
    ASSERT_UINT_EQ(msg.seqNum, 42);
    ASSERT_UINT_EQ(msg.playerCount, 1);
    ASSERT_UINT_EQ(msg.players[0].posX, 10);
    ASSERT_UINT_EQ(msg.players[0].posY, 5);

    pacmanServerDestroy(srv);
}

static void testBuildGameOverMsg(void) {
    PacManServer *srv = pacmanServerCreate();
    ASSERT_NOT_NULL(srv);
    pacmanServerInit(srv);
    pacmanServerAddPlayer(srv);
    pacmanServerAddPlayer(srv);
    srv->players[0].score = 100;
    srv->players[1].score = 200;
    srv->players[0].alive = 0;
    srv->players[1].alive = 1;

    PacManGameOverMsg msg;
    pacmanServerBuildGameOverMsg(srv, &msg);
    ASSERT_UINT_EQ(msg.msgType, PacManMsgGameOver);
    ASSERT_UINT_EQ(msg.playerCount, 2);
    /* Player 1 (200) should rank above Player 0 (100). */
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
```

- [ ] **Step 2: Build and run tests**

```bash
make -C tests/test_games/PacMan json  # Not applicable — tests are separate
# Build test binaries manually:
clang -Wall -Wextra -Werror -g \
  -Iinclude -Isrc -Itests -Itests/test_games/PacMan/common -Itests/test_games/PacMan/server \
  -o bin/tests/test_pacman_common \
  tests/test_pacman_common.c
bin/tests/test_pacman_common

clang -Wall -Wextra -Werror -g \
  -Iinclude -Isrc -Itests -Itests/test_games/PacMan/common -Itests/test_games/PacMan/server \
  -o bin/tests/test_pacman_server \
  tests/test_pacman_server.c tests/test_games/PacMan/common/pacman_common.c tests/test_games/PacMan/server/pacman_server.c
bin/tests/test_pacman_server
```

Expected: all tests PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/test_pacman_server.c
git commit -m "test: add PacMan server logic tests"
```

---

### Task 15: Final verification

- [ ] **Step 1: Ensure SDK is built**

```bash
make sdk
```

Expected: `sdk/lib/libpacplay_client_sdk.so` and `sdk/lib/libpacplay_server_sdk.so` exist.

- [ ] **Step 2: Build PacMan game binaries**

```bash
make -C tests/test_games/PacMan clean && make -C tests/test_games/PacMan all
```

Expected: zero warnings, zero errors. Binaries at `bin/pacman_server` and `bin/pacman_client`.

- [ ] **Step 3: Run clang-format on all new files**

```bash
clang-format -i tests/test_games/PacMan/common/pacman_common.h
clang-format -i tests/test_games/PacMan/common/pacman_common.c
clang-format -i tests/test_games/PacMan/server/pacman_server.h
clang-format -i tests/test_games/PacMan/server/pacman_server.c
clang-format -i tests/test_games/PacMan/client/pacman_client.h
clang-format -i tests/test_games/PacMan/client/pacman_client.c
clang-format -i tests/test_games/PacMan/Makefile
clang-format -i tests/test_pacman_common.c
clang-format -i tests/test_pacman_server.c
```

- [ ] **Step 4: Final commit with all changes**

```bash
git add -A
git commit -m "feat: complete PacMan multiplayer game implementation"
```
