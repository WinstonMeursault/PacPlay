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
