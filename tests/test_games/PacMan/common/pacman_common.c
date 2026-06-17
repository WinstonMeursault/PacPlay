/**
 * @file pacman_common.c
 * @brief Shared utility functions for PacMan (BFS pathfinding, direction
 * helpers).
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
#include <errno.h>
#include <string.h>

/* Stub logLog for container.h LOG_ERROR (avoids linking project log.c). */
void logLog(LogLevel level, const char *file, int line, const char *fmt, ...) {
    (void)level;
    (void)file;
    (void)line;
    (void)fmt;
}

/* ── Direction helpers ──────────────────────────────────────────────── */

static const int dirDx[4] = {0, 0, -1, 1};
static const int dirDy[4] = {-1, 1, 0, 0};

int pacmanDirDx(int dir) {
    if (dir < 0 || dir > PacManDirRight)
        return 0;
    return dirDx[dir];
}

int pacmanDirDy(int dir) {
    if (dir < 0 || dir > PacManDirRight)
        return 0;
    return dirDy[dir];
}

int pacmanDirOpposite(int dir) {
    switch (dir) {
    case PacManDirUp:
        return PacManDirDown;
    case PacManDirDown:
        return PacManDirUp;
    case PacManDirLeft:
        return PacManDirRight;
    case PacManDirRight:
        return PacManDirLeft;
    default:
        return PacManDirUp;
    }
}

/* ── Map helpers ────────────────────────────────────────────────────── */

bool pacmanIsWall(const uint8_t *map, uint16_t x, uint16_t y) {
    if (x >= PACMAN_MAP_WIDTH || y >= PACMAN_MAP_HEIGHT)
        return true;
    return map[y * PACMAN_MAP_WIDTH + x] == PacManCellWall;
}

bool pacmanCanMove(const uint8_t *map, uint16_t x, uint16_t y, int dir) {
    uint16_t nx = (uint16_t)((int)x + pacmanDirDx(dir));
    uint16_t ny = (uint16_t)((int)y + pacmanDirDy(dir));
    return !pacmanIsWall(map, nx, ny);
}

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
    if (startX == endX && startY == endY)
        return PacManDirUp;

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
        if (queuePacManBfsNodeFront(&q, &cur) != ContainerSucc)
            break;
        queuePacManBfsNodePop(&q);

        if (cur.x == endX && cur.y == endY) {
            found = 1;
            break;
        }

        int d;
        for (d = 0; d < 4; d++) {
            uint16_t nx = (uint16_t)((int)cur.x + dirDx[d]);
            uint16_t ny = (uint16_t)((int)cur.y + dirDy[d]);
            if (nx >= PACMAN_MAP_WIDTH || ny >= PACMAN_MAP_HEIGHT)
                continue;
            if (visited[ny][nx])
                continue;
            if (!canPassWalls && pacmanIsWall(map, nx, ny))
                continue;
            visited[ny][nx] = 1;
            parentDir[ny][nx] = d;
            PacManBfsNode next = {nx, ny};
            queuePacManBfsNodePush(&q, next);
        }
    }

    queuePacManBfsNodeDeinit(&q);

    if (!found)
        return -1;

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
