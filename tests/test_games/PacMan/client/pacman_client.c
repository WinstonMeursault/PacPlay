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
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

static struct termios savedTermios;
static int termSaved = 0;

/* ── Cell display character ───────────────────────────────────────────*/

static char cellChar(uint8_t cell, uint16_t pos, const PacManClient *cli) {
    uint8_t i;
    uint16_t px, py;
    int gi;
    px = (uint16_t)(pos % PACMAN_MAP_WIDTH);
    py = (uint16_t)(pos / PACMAN_MAP_WIDTH);
    for (i = 0; i < cli->playerCount; i++) {
        if (cli->players[i].posX == px && cli->players[i].posY == py) {
            return cli->players[i].alive ? (char)('1' + i) : 'x';
        }
    }
    for (gi = 0; gi < PACMAN_GHOST_COUNT; gi++) {
        if (cli->ghosts[gi].posX == px && cli->ghosts[gi].posY == py) {
            switch (cli->ghosts[gi].mode) {
            case PacManGhostFrightened:
                return 'f';
            case PacManGhostEaten:
                return 'e';
            default:
                return (char)('A' + gi);
            }
        }
    }
    switch (cell) {
    case PacManCellWall:
        return '#';
    case PacManCellBean:
        return '.';
    case PacManCellPowerBean:
        return 'O';
    default:
        return ' ';
    }
}

/* ── ANSI color helpers ────────────────────────────────────────────────*/

static const char *ghostColor(int gi, uint8_t mode) {
    (void)gi;
    if (mode == PacManGhostFrightened)
        return "\033[34m";
    if (mode == PacManGhostEaten)
        return "\033[37m";
    {
        const char *colors[] = {"\033[31m", "\033[35m", "\033[36m", "\033[33m"};
        return colors[gi % PACMAN_GHOST_COUNT];
    }
}

/* ── State management ─────────────────────────────────────────────────*/

void pacmanClientInit(PacManClient *cli) {
    if (cli == NULL)
        return;
    memset(cli, 0, sizeof(*cli));
}

void pacmanClientApplyStart(PacManClient *cli, const PacManStartMsg *msg) {
    if (cli == NULL || msg == NULL)
        return;
    cli->myPlayerId = msg->playerId;
    cli->playerCount = msg->playerCount;
    memcpy(cli->map, msg->mapData, PACMAN_MAP_CELLS);
}

void pacmanClientApplyState(PacManClient *cli, const PacManStateMsg *msg) {
    size_t i;
    if (cli == NULL || msg == NULL)
        return;
    cli->playerCount = msg->playerCount;
    cli->timeLeftSec = msg->timeLeftSec;
    cli->beanCount = msg->beanCount;
    memcpy(cli->players, msg->players,
           PACMAN_MAX_PLAYERS * sizeof(PacManPlayerInfo));
    memcpy(cli->ghosts, msg->ghosts, sizeof(cli->ghosts));
    for (i = 0; i < PACMAN_MAP_CELLS; i++) {
        if (cli->map[i] == PacManCellBean ||
            cli->map[i] == PacManCellPowerBean) {
            cli->map[i] = PacManCellPath;
        }
    }
}

void pacmanClientApplyGameOver(PacManClient *cli,
                               const PacManGameOverMsg *msg) {
    if (cli == NULL || msg == NULL)
        return;
    cli->gameOver = true;
    (void)msg;
}

/* ── Rendering ────────────────────────────────────────────────────────*/

void pacmanClientRender(const PacManClient *cli) {
    uint16_t y, x;
    if (cli == NULL)
        return;

    printf("\033[H\033[2J");

    for (y = 0; y < PACMAN_MAP_HEIGHT; y++) {
        for (x = 0; x < PACMAN_MAP_WIDTH; x++) {
            uint16_t pos = (uint16_t)(y * PACMAN_MAP_WIDTH + x);
            uint8_t cell = cli->map[pos];
            char ch = cellChar(cell, pos, cli);
            int entityHere = 0;
            int gi;
            uint8_t pi;

            for (gi = 0; gi < PACMAN_GHOST_COUNT; gi++) {
                if (cli->ghosts[gi].posX == x && cli->ghosts[gi].posY == y) {
                    printf("%s%c\033[0m", ghostColor(gi, cli->ghosts[gi].mode),
                           ch);
                    entityHere = 1;
                    break;
                }
            }
            if (entityHere)
                continue;

            for (pi = 0; pi < cli->playerCount; pi++) {
                if (cli->players[pi].posX == x && cli->players[pi].posY == y) {
                    printf("\033[1;33m%c\033[0m",
                           cli->players[pi].alive ? (char)('1' + pi) : 'x');
                    entityHere = 1;
                    break;
                }
            }
            if (entityHere)
                continue;

            switch (cell) {
            case PacManCellWall:
                printf("\033[34m#\033[0m");
                break;
            case PacManCellBean:
                printf("\033[37m.\033[0m");
                break;
            case PacManCellPowerBean:
                printf("\033[1;37mO\033[0m");
                break;
            default:
                putchar(' ');
                break;
            }
        }
        putchar('\n');
    }

    printf("\n  Time: %us  |  Beans: %u", cli->timeLeftSec, cli->beanCount);
    {
        uint8_t i;
        for (i = 0; i < cli->playerCount; i++) {
            printf("  P%d: %u%s", i, cli->players[i].score,
                   cli->players[i].playerId == cli->myPlayerId ? " (YOU)" : "");
        }
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
    if (n <= 0)
        return -1;
    if (n >= 3 && buf[0] == '\033' && buf[1] == '[') {
        switch (buf[2]) {
        case 'A':
            return PacManDirUp;
        case 'B':
            return PacManDirDown;
        case 'C':
            return PacManDirRight;
        case 'D':
            return PacManDirLeft;
        }
    }
    switch (buf[0]) {
    case 'w':
    case 'W':
        return PacManDirUp;
    case 's':
    case 'S':
        return PacManDirDown;
    case 'a':
    case 'A':
        return PacManDirLeft;
    case 'd':
    case 'D':
        return PacManDirRight;
    case 'q':
    case 'Q':
        return -2;
    }
    return -1;
}

/* ── Client entry point ─────────────────────────────────────────────── */

#include "pacplay_sdk.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

enum { PacManStrtoulBase = 10 };

static PacManClient gClient;
static int gQuit = 0;

static void onClientReceive(const void *payload, size_t len, void *userData) {
    (void)userData;
    const uint8_t *data;
    uint8_t msgType;
    if (payload == NULL || len < 1)
        return;

    data = (const uint8_t *)payload;
    msgType = data[0];

    switch (msgType) {
    case PacManMsgStart:
        if (len >= sizeof(PacManStartMsg)) {
            pacmanClientApplyStart(&gClient, (const PacManStartMsg *)payload);
            printf("Game started! You are Player %u of %u\n",
                   (unsigned int)(gClient.myPlayerId + 1),
                   (unsigned int)gClient.playerCount);
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

void pacplayMain(void) {
    PacPlaySDK *sdk;
    PacManJoinMsg joinMsg;
    int lastDir = -1;
    const char *gameIdStr;
    const char *platform;
    uint32_t gameId;

    printf("PacMan Client starting...\n");
    pacmanClientInit(&gClient);

    sdk = pacplay_cli_create();
    if (sdk == NULL) {
        fprintf(stderr, "Failed to create Client SDK\n");
        return;
    }

    pacplay_cli_on_receive(sdk, onClientReceive, sdk);

    gameIdStr = getenv("PACPLAY_GAME_ID");
    platform = getenv("PACPLAY_SERVER_PLATFORM");
    if (gameIdStr != NULL && platform != NULL) {
        gameId = (uint32_t)strtoul(gameIdStr, NULL, PacManStrtoulBase);
        printf("Requesting server start: gameId=%" PRIu32 " platform=%s\n",
               gameId, platform);
        pacplay_cli_request_start_server(sdk, gameId, platform);
    }

    pacmanClientTermInit();

    memset(&joinMsg, 0, sizeof(joinMsg));
    joinMsg.msgType = PacManMsgJoin;
    snprintf(joinMsg.playerName, sizeof(joinMsg.playerName), "Player");
    pacplay_cli_send(sdk, &joinMsg, sizeof(joinMsg));

    printf("Waiting for game start...\n");

    while (!gQuit) {
        int dir;
        pacplay_cli_poll(sdk);

        if (gClient.playerCount > 0) {
            pacmanClientRender(&gClient);
        }

        dir = pacmanClientReadInput();
        if (dir == -2) {
            gQuit = 1;
            break;
        }
        if (dir >= 0 && dir != lastDir) {
            PacManMoveMsg move;
            lastDir = dir;
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
}
