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
 * Legend: #=wall, .=path(bean), ' '=path(no bean)
 * 40 chars per line, 20 lines = 800 cells total.
 */

static const char mapTemplateChars[] =
    "########################################"
    "####..........................####......"
    "####.####.######.######.######.####....."
    "####.####.######.######.######.####....."
    "####..........................####......"
    "####.####.##.##############.##.####....."
    "####.####.##.##############.##.####....."
    "####......##....##....##....##.........#"
    "######.######.##.##.##.##.###.######.##."
    "######.######.##.##.##.##.###.######.##."
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

static const uint16_t nestX[PACMAN_GHOST_COUNT] = {18, 19, 20, 21};
static const uint16_t nestY[PACMAN_GHOST_COUNT] = {9, 9, 10, 10};

static const uint16_t spawnX[PACMAN_MAX_PLAYERS] = {4, 38, 6, 38};
static const uint16_t spawnY[PACMAN_MAX_PLAYERS] = {1, 1, 18, 13};

static const uint16_t ghostHomeX = 19;
static const uint16_t ghostHomeY = 9;

static void initMapTemplate(uint8_t *map, uint8_t *beanCount) {
    int beanPositions[PACMAN_GHOST_COUNT] = {45, 75, 525, 555};
    size_t i;
    int p;
    *beanCount = 0;

    for (i = 0; i < PACMAN_MAP_CELLS; i++) {
        switch (mapTemplateChars[i]) {
        case '#':
            map[i] = PacManCellWall;
            break;
        case '.':
            map[i] = PacManCellBean;
            (*beanCount)++;
            break;
        default:
            map[i] = PacManCellPath;
            break;
        }
    }

    for (p = 0; p < PACMAN_GHOST_COUNT; p++) {
        map[beanPositions[p]] = PacManCellPowerBean;
        (*beanCount)++;
    }

    for (p = 0; p < PACMAN_GHOST_COUNT; p++) {
        map[nestY[p] * PACMAN_MAP_WIDTH + nestX[p]] = PacManCellPath;
    }
}

/* ── Lifecycle ─────────────────────────────────────────────────────── */

PacManServer *pacmanServerCreate(void) {
    PacManServer *srv = calloc(1, sizeof(PacManServer));
    if (srv == NULL)
        return NULL;
    return srv;
}

void pacmanServerDestroy(PacManServer *srv) { free(srv); }

void pacmanServerInit(PacManServer *srv) {
    int i;
    if (srv == NULL)
        return;

    srand((unsigned int)time(NULL));

    srv->beanCount = 0;
    initMapTemplate(srv->mapTemplate, &srv->beanCount);
    memcpy(srv->map, srv->mapTemplate, PACMAN_MAP_CELLS);

    srv->playerCount = 0;
    srv->playersAlive = 0;
    memset(srv->players, 0, sizeof(srv->players));
    memset(srv->playerInvulnTimer, 0, sizeof(srv->playerInvulnTimer));

    for (i = 0; i < PACMAN_GHOST_COUNT; i++) {
        srv->ghosts[i].ghostId = (uint8_t)i;
        srv->ghosts[i].posX = ghostHomeX;
        srv->ghosts[i].posY = ghostHomeY;
        srv->ghosts[i].direction = PacManDirUp;
        srv->ghosts[i].mode = PacManGhostScatter;
        srv->frightenedTimer[i] = 0;
    }
    srv->chaseToggleCounter = 0;

    srv->seqNum = 0;
    srv->timeLeftSec = PACMAN_GAME_DURATION_SEC;
    srv->tickCount = 0;
    srv->gameStarted = false;
    srv->gameOver = false;
}

/* ── Player management ──────────────────────────────────────────────── */

int pacmanServerAddPlayer(PacManServer *srv) {
    uint8_t pid;
    if (srv == NULL || srv->playerCount >= PACMAN_MAX_PLAYERS)
        return -1;
    pid = srv->playerCount;
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
    return (int)pid;
}

/* ── Ghost movement helpers ─────────────────────────────────────────── */

static void moveGhost(PacManServer *srv, int gi, int dir) {
    srv->ghosts[gi].direction = (uint8_t)dir;
    srv->ghosts[gi].posX =
        (uint16_t)((int)srv->ghosts[gi].posX + pacmanDirDx(dir));
    srv->ghosts[gi].posY =
        (uint16_t)((int)srv->ghosts[gi].posY + pacmanDirDy(dir));
}

static int chooseGhostScatterDir(const PacManServer *srv, int gi) {
    int opposite = pacmanDirOpposite((int)srv->ghosts[gi].direction);
    int valid[4];
    int validCount = 0;
    int d;
    for (d = 0; d < 4; d++) {
        uint16_t nx;
        uint16_t ny;
        if (d == opposite)
            continue;
        nx = (uint16_t)((int)srv->ghosts[gi].posX + pacmanDirDx(d));
        ny = (uint16_t)((int)srv->ghosts[gi].posY + pacmanDirDy(d));
        if (!pacmanIsWall(srv->map, nx, ny)) {
            valid[validCount++] = d;
        }
    }
    if (validCount == 0)
        return opposite;
    return valid[rand() % validCount];
}

static int chooseGhostChaseDir(const PacManServer *srv, int gi) {
    uint16_t tx = 0;
    uint16_t ty = 0;
    int found = 0;
    uint32_t bestDist = UINT32_MAX;
    uint8_t i;
    int dir;
    for (i = 0; i < srv->playerCount; i++) {
        uint32_t dx;
        uint32_t dy;
        uint32_t dist;
        if (!srv->players[i].alive)
            continue;
        dx = (uint32_t)abs((int)srv->players[i].posX -
                           (int)srv->ghosts[gi].posX);
        dy = (uint32_t)abs((int)srv->players[i].posY -
                           (int)srv->ghosts[gi].posY);
        dist = dx + dy;
        if (dist < bestDist) {
            bestDist = dist;
            tx = srv->players[i].posX;
            ty = srv->players[i].posY;
            found = 1;
        }
    }
    if (!found)
        return chooseGhostScatterDir(srv, gi);
    dir = pacmanBfsFindDir(srv->map, srv->ghosts[gi].posX, srv->ghosts[gi].posY,
                           tx, ty, false);
    if (dir < 0)
        return chooseGhostScatterDir(srv, gi);
    return dir;
}

static int chooseGhostFrightenedDir(const PacManServer *srv, int gi) {
    int opposite = pacmanDirOpposite((int)srv->ghosts[gi].direction);
    int valid[4];
    int validCount = 0;
    int d;
    for (d = 0; d < 4; d++) {
        uint16_t nx = (uint16_t)((int)srv->ghosts[gi].posX + pacmanDirDx(d));
        uint16_t ny = (uint16_t)((int)srv->ghosts[gi].posY + pacmanDirDy(d));
        if (nx < PACMAN_MAP_WIDTH && ny < PACMAN_MAP_HEIGHT &&
            srv->map[ny * PACMAN_MAP_WIDTH + nx] != PacManCellWall) {
            valid[validCount++] = d;
        }
    }
    if (validCount == 0)
        return opposite;
    return valid[rand() % validCount];
}

static int chooseGhostEatenDir(const PacManServer *srv, int gi) {
    int dir =
        pacmanBfsFindDir(srv->map, srv->ghosts[gi].posX, srv->ghosts[gi].posY,
                         ghostHomeX, ghostHomeY, true);
    if (dir < 0) {
        dir = chooseGhostScatterDir(srv, gi);
    }
    return dir;
}

static void updateGhost(PacManServer *srv, int gi) {
    int dir;
    bool moveSlow = false;
    int opposite;

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

    if (moveSlow && (srv->tickCount % 2 != 0))
        return;

    opposite = pacmanDirOpposite((int)srv->ghosts[gi].direction);
    if (dir == opposite) {
        dir = chooseGhostScatterDir(srv, gi);
    }

    moveGhost(srv, gi, dir);

    if (srv->ghosts[gi].mode == PacManGhostEaten) {
        if (srv->ghosts[gi].posX == ghostHomeX &&
            srv->ghosts[gi].posY == ghostHomeY) {
            srv->ghosts[gi].mode = PacManGhostScatter;
        }
    }
}

static void updateGhostModeSwitch(PacManServer *srv) {
    int i;
    srv->chaseToggleCounter++;
    for (i = 0; i < PACMAN_GHOST_COUNT; i++) {
        if (srv->frightenedTimer[i] > 0) {
            srv->frightenedTimer[i]--;
            if (srv->frightenedTimer[i] == 0 &&
                srv->ghosts[i].mode == PacManGhostFrightened) {
                srv->ghosts[i].mode = PacManGhostScatter;
            }
        }
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
    int i;
    for (i = 0; i < PACMAN_GHOST_COUNT; i++) {
        if (srv->ghosts[i].mode != PacManGhostEaten) {
            srv->ghosts[i].mode = PacManGhostFrightened;
        }
        srv->frightenedTimer[i] = PACMAN_FRIGHTENED_TICKS;
    }
}

/* ── Collision & eating ─────────────────────────────────────────────── */

static void handlePlayerEating(PacManServer *srv, uint8_t pid) {
    uint16_t idx = (uint16_t)(srv->players[pid].posY * PACMAN_MAP_WIDTH +
                              srv->players[pid].posX);
    if (idx >= PACMAN_MAP_CELLS)
        return;
    if (srv->map[idx] == PacManCellBean) {
        srv->players[pid].score += PACMAN_BEAN_SCORE;
        srv->map[idx] = PacManCellPath;
        srv->beanCount--;
    } else if (srv->map[idx] == PacManCellPowerBean) {
        srv->players[pid].score += PACMAN_POWER_BEAN_SCORE;
        srv->map[idx] = PacManCellPath;
        srv->beanCount--;
        activateFrightened(srv);
    }
}

static void handlePlayerGhostCollision(PacManServer *srv) {
    int gi;
    uint8_t pid;
    for (pid = 0; pid < srv->playerCount; pid++) {
        if (!srv->players[pid].alive)
            continue;
        if (srv->playerInvulnTimer[pid] > 0)
            continue;
        for (gi = 0; gi < PACMAN_GHOST_COUNT; gi++) {
            if (srv->ghosts[gi].posX != srv->players[pid].posX)
                continue;
            if (srv->ghosts[gi].posY != srv->players[pid].posY)
                continue;
            if (srv->ghosts[gi].mode == PacManGhostFrightened) {
                srv->players[pid].score += PACMAN_GHOST_EAT_SCORE;
                srv->ghosts[gi].mode = PacManGhostEaten;
            } else if (srv->ghosts[gi].mode != PacManGhostEaten) {
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
    if (srv == NULL || playerId >= srv->playerCount)
        return;
    if (!srv->players[playerId].alive)
        return;
    if (dir > PacManDirRight)
        return;
    srv->players[playerId].direction = dir;
}

/* ── Game tick ──────────────────────────────────────────────────────── */

bool pacmanServerTick(PacManServer *srv) {
    uint8_t i;
    int gi;
    if (srv == NULL || srv->gameOver)
        return false;
    srv->tickCount++;
    srv->seqNum++;

    if (!srv->gameStarted) {
        srv->gameStarted = true;
        return true;
    }

    if (srv->tickCount % PACMAN_TICKS_PER_SEC == 0 && srv->timeLeftSec > 0) {
        srv->timeLeftSec--;
    }

    for (i = 0; i < srv->playerCount; i++) {
        if (srv->playerInvulnTimer[i] > 0) {
            srv->playerInvulnTimer[i]--;
        }
    }

    for (i = 0; i < srv->playerCount; i++) {
        int d;
        uint16_t nx;
        uint16_t ny;
        if (!srv->players[i].alive)
            continue;
        d = (int)srv->players[i].direction;
        nx = (uint16_t)((int)srv->players[i].posX + pacmanDirDx(d));
        ny = (uint16_t)((int)srv->players[i].posY + pacmanDirDy(d));
        if (!pacmanIsWall(srv->map, nx, ny)) {
            srv->players[i].posX = nx;
            srv->players[i].posY = ny;
        }
    }

    updateGhostModeSwitch(srv);

    for (gi = 0; gi < PACMAN_GHOST_COUNT; gi++) {
        updateGhost(srv, gi);
    }

    for (i = 0; i < srv->playerCount; i++) {
        if (srv->players[i].alive) {
            handlePlayerEating(srv, i);
        }
    }

    handlePlayerGhostCollision(srv);

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
    if (srv == NULL || msg == NULL)
        return;
    memset(msg, 0, sizeof(*msg));
    msg->msgType = PacManMsgStart;
    msg->playerId = playerId;
    msg->playerCount = srv->playerCount;
    memcpy(msg->mapData, srv->mapTemplate, PACMAN_MAP_CELLS);
}

void pacmanServerBuildStateMsg(const PacManServer *srv, PacManStateMsg *msg) {
    if (srv == NULL || msg == NULL)
        return;
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
    uint8_t order[PACMAN_MAX_PLAYERS];
    uint8_t i;
    uint8_t j;
    uint8_t tmp;
    if (srv == NULL || msg == NULL)
        return;
    memset(msg, 0, sizeof(*msg));
    msg->msgType = PacManMsgGameOver;
    msg->playerCount = srv->playerCount;

    for (i = 0; i < srv->playerCount; i++)
        order[i] = i;

    for (i = 0; i < srv->playerCount; i++) {
        for (j = (uint8_t)(i + 1); j < srv->playerCount; j++) {
            uint32_t si = srv->players[order[i]].score;
            uint32_t sj = srv->players[order[j]].score;
            if (sj > si || (sj == si && srv->players[order[j]].alive &&
                            !srv->players[order[i]].alive)) {
                tmp = order[i];
                order[i] = order[j];
                order[j] = tmp;
            }
        }
    }
    memcpy(msg->rankings, order, srv->playerCount);
    for (i = 0; i < srv->playerCount; i++) {
        msg->scores[i] = srv->players[i].score;
    }
}

/* ── Server entry point ─────────────────────────────────────────────── */

#include "pacplay_sdk.h"
#include <stdio.h>
#include <unistd.h>

static PacManServer *gServer = NULL;

static void onServerReceive(const void *payload, size_t len, void *userData) {
    (void)userData;
    const uint8_t *data;
    uint8_t msgType;
    if (payload == NULL || len < 1)
        return;

    data = (const uint8_t *)payload;
    msgType = data[0];

    if (msgType == PacManMsgJoin) {
        int pid = pacmanServerAddPlayer(gServer);
        if (pid >= 0) {
            PacManStartMsg startMsg;
            PacManServer *srv = gServer;
            PacPlaySDK *sdk = (PacPlaySDK *)userData;
            pacmanServerBuildStartMsg(srv, (uint8_t)pid, &startMsg);
            pacplay_srv_send(sdk, &startMsg, sizeof(startMsg));
            printf("[PacMan Server] Player %d joined (total: %d)\n", pid,
                   gServer->playerCount);
        }
    } else if (msgType == PacManMsgMove) {
        if (len >= sizeof(PacManMoveMsg)) {
            const PacManMoveMsg *move = (const PacManMoveMsg *)payload;
            pacmanServerHandleMove(gServer, 0, move->direction);
        }
    }
}

void pacplayMain(void) {
    PacPlaySDK *sdk;
    printf("PacMan Server starting...\n");

    gServer = pacmanServerCreate();
    if (gServer == NULL) {
        fprintf(stderr, "Failed to create PacMan server\n");
        return;
    }
    pacmanServerInit(gServer);

    sdk = pacplay_srv_create();
    if (sdk == NULL) {
        fprintf(stderr, "Failed to create Server SDK\n");
        pacmanServerDestroy(gServer);
        return;
    }

    pacplay_srv_on_receive(sdk, onServerReceive, sdk);

    printf("PacMan Server ready. Waiting for players...\n");

    while (true) {
        pacplay_srv_poll(sdk);

        if (gServer->gameStarted) {
            bool running = pacmanServerTick(gServer);
            if (!running)
                break;

            PacManStateMsg stateMsg;
            pacmanServerBuildStateMsg(gServer, &stateMsg);
            pacplay_srv_send(sdk, &stateMsg, sizeof(stateMsg));
        }

        usleep(PACMAN_TICK_MS * 1000);
    }

    {
        PacManGameOverMsg overMsg;
        uint8_t i;
        pacmanServerBuildGameOverMsg(gServer, &overMsg);
        pacplay_srv_send(sdk, &overMsg, sizeof(overMsg));
        printf("[PacMan Server] Game over!\n");
        for (i = 0; i < gServer->playerCount; i++) {
            printf("  Player %d: %u points\n", i, gServer->players[i].score);
        }
    }

    pacplay_srv_destroy(sdk);
    pacmanServerDestroy(gServer);
}
