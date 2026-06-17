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
    uint8_t playerCount;
    uint8_t playersAlive;

    /* Invulnerability timers (in ticks). */
    int playerInvulnTimer[PACMAN_MAX_PLAYERS];

    /* Ghost state. */
    PacManGhostInfo ghosts[PACMAN_GHOST_COUNT];
    int frightenedTimer[PACMAN_GHOST_COUNT];
    int chaseToggleCounter;

    /* Timing. */
    uint32_t seqNum;
    uint32_t timeLeftSec;
    uint32_t tickCount;
    bool gameStarted;
    bool gameOver;
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
