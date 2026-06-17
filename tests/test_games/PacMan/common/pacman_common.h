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

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Map constants ─────────────────────────────────────────────────── */

#define PACMAN_MAP_WIDTH 40
#define PACMAN_MAP_HEIGHT 20
#define PACMAN_MAP_CELLS (PACMAN_MAP_WIDTH * PACMAN_MAP_HEIGHT)

/* ── Gameplay constants ─────────────────────────────────────────────── */

#define PACMAN_GAME_DURATION_SEC 180
#define PACMAN_TICK_MS 100
#define PACMAN_TICKS_PER_SEC (1000 / PACMAN_TICK_MS)
#define PACMAN_MAX_PLAYERS 4
#define PACMAN_GHOST_COUNT 4
#define PACMAN_STARTING_LIVES 3
#define PACMAN_FRIGHTENED_SEC 5
#define PACMAN_FRIGHTENED_TICKS (PACMAN_FRIGHTENED_SEC * PACMAN_TICKS_PER_SEC)
#define PACMAN_INVULN_TICKS (3 * PACMAN_TICKS_PER_SEC)
#define PACMAN_CHASE_INTERVAL_TICKS (7 * PACMAN_TICKS_PER_SEC)

/* ── Scoring constants ──────────────────────────────────────────────── */

#define PACMAN_BEAN_SCORE 10
#define PACMAN_POWER_BEAN_SCORE 50
#define PACMAN_GHOST_EAT_SCORE 200
#define PACMAN_PLAYER_NAME_LEN 16

/* ── Enums ──────────────────────────────────────────────────────────── */

enum PacManMsgType {
    PacManMsgJoin = 1,
    PacManMsgMove = 2,
    PacManMsgStart = 3,
    PacManMsgState = 4,
    PacManMsgGameOver = 5,
};

enum PacManDir {
    PacManDirUp = 0,
    PacManDirDown = 1,
    PacManDirLeft = 2,
    PacManDirRight = 3,
};

enum PacManCell {
    PacManCellWall = 0,
    PacManCellPath = 1,
    PacManCellBean = 2,
    PacManCellPowerBean = 3,
};

enum PacManGhostMode {
    PacManGhostScatter = 0,
    PacManGhostChase = 1,
    PacManGhostFrightened = 2,
    PacManGhostEaten = 3,
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
    char playerName[PACMAN_PLAYER_NAME_LEN];
} PacManJoinMsg;

/** Per-player state snapshot (used in PacManStateMsg). */
typedef struct {
    uint8_t playerId;
    uint16_t posX;
    uint16_t posY;
    uint8_t direction;
    uint8_t lives;
    uint32_t score;
    uint8_t alive;
} PacManPlayerInfo;

/** Per-ghost state snapshot (used in PacManStateMsg). */
typedef struct {
    uint8_t ghostId;
    uint16_t posX;
    uint16_t posY;
    uint8_t direction;
    uint8_t mode;
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
    uint8_t msgType;
    uint32_t seqNum;
    uint32_t timeLeftSec;
    uint8_t playerCount;
    uint8_t beanCount;
    PacManPlayerInfo players[PACMAN_MAX_PLAYERS];
    PacManGhostInfo ghosts[PACMAN_GHOST_COUNT];
} PacManStateMsg;

/** Server→Client: game over with final ranking. */
typedef struct {
    uint8_t msgType;
    uint8_t playerCount;
    uint8_t rankings[PACMAN_MAX_PLAYERS];
    uint32_t scores[PACMAN_MAX_PLAYERS];
} PacManGameOverMsg;

#pragma pack(pop)

/* ── Shared utility functions ───────────────────────────────────────── */

int pacmanDirDx(int dir);
int pacmanDirDy(int dir);
int pacmanDirOpposite(int dir);
bool pacmanIsWall(const uint8_t *map, uint16_t x, uint16_t y);
bool pacmanCanMove(const uint8_t *map, uint16_t x, uint16_t y, int dir);
int pacmanBfsFindDir(const uint8_t *map, uint16_t startX, uint16_t startY,
                     uint16_t endX, uint16_t endY, bool canPassWalls);

#ifdef __cplusplus
}
#endif

#endif /* PACMAN_COMMON_H */
