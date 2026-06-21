/**
 * @file mainPage.c
 * @brief Client TUI home page and game page.
 *
 * @date 2026-06-13
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

#include "mainPage.h"
#include "client/connection.h"
#include "client/database.h"
#include "client/gameDownload.h"
#include "client/gameLoad.h"
#include "client/gameRoom.h"
#include "client/room.h"
#include "clientTUI.h"
#include "controlGameView.h"
#include "pacplay_sdk.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define TUI_HOME_STATUSGRID_HEIGHT 9
#define TUI_HOME_STATUSGRID_WIDTH 40
#define TUI_HOME_OPERGRID_WIDTH TUI_HOME_STATUSGRID_WIDTH

#if defined(__linux__)
#define CLIENT_DEFAULT_PLATFORM "linux"
#elif defined(_WIN32) || defined(_WIN64)
#define CLIENT_DEFAULT_PLATFORM "windows"
#elif defined(__APPLE__)
#define CLIENT_DEFAULT_PLATFORM "macos"
#else
#define CLIENT_DEFAULT_PLATFORM "unknown"
#endif

struct {
    GameRecord **record;
    size_t cnt;
} gameList;

static DownloadManager *downloadMgr = NULL;
static GameInfoEntry *serverGameEntries = NULL;
static size_t serverGameCount = 0;
static bool downloadWasActive = false;

static uint32_t gameRoomLobbyGameId = 0;
static char gameRoomLobbyGameName[GAME_NAME_LEN] = {0};
static char gameRoomLobbyGamePath[512] = {0};
static GameRoomListEntry *gameRoomEntries = NULL;
static size_t gameRoomEntryCount = 0;
static bool gameRoomIsHost = false;
static uint32_t gameRoomJoinedId = 0;

enum { DescMaxLines = 3, EntryFormatBufLen = 2048 };

static void formatServerGameEntry(const GameInfoEntry *entry, int availWidth,
                                  char *out, size_t outSize) {
    const char *desc = entry->description;
    size_t descLen = strlen(desc);
    int descMaxChars = availWidth * DescMaxLines;
    bool truncated = (descLen > (size_t)descMaxChars);

    if (truncated) {
        snprintf(out, outSize, "%s\n%.*s...", entry->name, descMaxChars, desc);
    } else {
        snprintf(out, outSize, "%s\n%s", entry->name, desc);
    }
}

// Home page
ControlPage homePage;
ControlGrid homePageGrid;
ControlGrid homeStatusGrid;
ControlListBox homeGameList;
ControlGrid homeOperGrid;

ControlLabel homeStatusUsername;
ControlLabel homeStatusNickname;
ControlButton homeStatusExit;

ControlLabel homeOperGameName;
ControlLabel homeOperGamePath;
ControlLabel homeOperGameTime;
ControlButton homeOperPlay;
ControlButton homeOperRemoveGame;
ControlLabel homeOperEmpty1;
ControlLabel homeOperEmpty2;
ControlListBox homeOperServerGames;
ControlLabel homeOperDownloadStatus;
ControlButton homeOperDownloadGame;
ControlButton homeOperRefreshDownloadableGames;

// Game page
ControlPage gamePage;
ControlGrid gameGrid;
ControlButton backBtn;
ControlGameView gameView;

// Game room lobby page
ControlPage gameRoomLobbyPage;
ControlGrid gameRoomLobbyGrid;
ControlListBox gameRoomLobbyRoomList;
ControlButton gameRoomLobbyRefreshBtn;
ControlButton gameRoomLobbyJoinBtn;
ControlButton gameRoomLobbyCreateBtn;
ControlLabel gameRoomLobbyStatus;
ControlButton gameRoomLobbyStartBtn;
ControlButton gameRoomLobbyBackBtn;
ControlScrollTextBox gameRoomLobbyMemberBox;


static void updateUserData(char *nickname, char *username) {
    if (nickname != NULL) {
        sprintf(homeStatusNickname.text, "User: %s", nickname);
    }
    if (username != NULL) {
        sprintf(homeStatusUsername.text, "     (%s)", username);
    }
}

static void freeGameListRecords(void) {
    if (gameList.record != NULL) {
        for (size_t i = 0; i < gameList.cnt; ++i) {
            free(gameList.record[i]->gameName);
            free(gameList.record[i]->gamePath);
            free(gameList.record[i]->gameVersion);
            free(gameList.record[i]->platform);
            free(gameList.record[i]->fileHash);
            free(gameList.record[i]);
        }
        free(gameList.record);
        gameList.record = NULL;
        gameList.cnt = 0;
    }
}

static void fetchGames() {
    listGames(client, &gameList.record, &gameList.cnt);
    for (size_t i = 0; i < gameList.cnt; ++i) {
        controlListBoxAppend(&homeGameList, gameList.record[i]->gameName,
                             gameList.record[i]->gameId);
    }
}

void homePageInitUpdate(char *nickname, char *username) {
    updateUserData(nickname, username);
    fetchGames();
    if (downloadMgr == NULL) {
        downloadManagerInit(&downloadMgr, client);
    }
    if (serverGameEntries != NULL) {
        clientFreeGameList(serverGameEntries);
        serverGameEntries = NULL;
    }
    serverGameCount = 0;
    downloadWasActive = false;
}

static void homePageGridResize(ControlGrid *self) {
    self->base.height = pViewArea->height;
    self->base.width = pViewArea->width;
}

static void homePageGridDraw(ControlGrid *self) {
    werase(self->base.windowHandler);

    DOUBLE_BOX(self->base.windowHandler);
    int x = 3, y = 2;
    wattron(self->base.windowHandler, A_BOLD);
    mvwprintw(self->base.windowHandler, y + 0, x,
              "    ____             ____  __");
    mvwprintw(self->base.windowHandler, y + 1, x,
              "   / __ \\____ ______/ __ \\/ /___ ___  __");
    mvwprintw(self->base.windowHandler, y + 2, x,
              "  / /_/ / __ `/ ___/ /_/ / / __ `/ / / /");
    mvwprintw(self->base.windowHandler, y + 3, x,
              " / ____/ /_/ / /__/ ____/ / /_/ / /_/ /");
    mvwprintw(self->base.windowHandler, y + 4, x,
              "/_/    \\__,_/\\___/_/   /_/\\__,_/\\__, /");
    mvwprintw(self->base.windowHandler, y + 5, x,
              "                               /____/");
    wattroff(self->base.windowHandler, A_BOLD);

    int descriptionBegin = 3;
    mvwprintw(self->base.windowHandler, descriptionBegin + 0, 45, "v0.1");
    mvwprintw(self->base.windowHandler, descriptionBegin + 1, 45,
              "GPLv3 License");
    mvwprintw(self->base.windowHandler, descriptionBegin + 2, 45,
              "Copyright (C) 2026");
    mvwprintw(self->base.windowHandler, descriptionBegin + 3, 45,
              "Winston Meursault & Kiraterin");
    wattron(self->base.windowHandler, A_UNDERLINE);
    mvwprintw(self->base.windowHandler, descriptionBegin + 4, 45,
              "https://github.com/WinstonMeursault/PacPlay");
    wattroff(self->base.windowHandler, A_UNDERLINE);

    wnoutrefresh(self->base.windowHandler);
}

static void homeStatusGridResize(ControlGrid *self) {
    self->base.x = pViewArea->width - 1 - TUI_HOME_STATUSGRID_WIDTH;
}

static void homeStatusExitOnClick(ControlButton *self) {
    (void)self;
    tuiAppStop();
    if (downloadMgr != NULL) {
        downloadManagerDestroy(downloadMgr);
        downloadMgr = NULL;
    }
    if (serverGameEntries != NULL) {
        clientFreeGameList(serverGameEntries);
        serverGameEntries = NULL;
    }
    clientDisconnect(client);
}

static void homeGameListResize(ControlListBox *self) {
    self->base.height = pViewArea->height - 2 - TUI_HOME_STATUSGRID_HEIGHT;
    self->base.width = pViewArea->width - 2 - TUI_HOME_OPERGRID_WIDTH;
    self->base.y = 1 + TUI_HOME_STATUSGRID_HEIGHT;
}

static void homeOperGridResize(ControlGrid *self) {
    self->base.height = pViewArea->height - 2 - TUI_HOME_STATUSGRID_HEIGHT;
    self->base.y = 1 + TUI_HOME_STATUSGRID_HEIGHT;
    self->base.x = pViewArea->width - 1 - TUI_HOME_OPERGRID_WIDTH;
}

static void homeOperGridUpdate(ControlGrid *self) {
    (void)self;
    ControlListBoxEntry selected;
    if (arrayControlListBoxEntryGet(&homeGameList.list, homeGameList.curLine,
                                    &selected) == ContainerSucc) {
        GameRecord *cur = NULL;
        for (size_t i = 0; i < gameList.cnt; ++i) {
            if (gameList.record[i]->gameId == selected.id) {
                cur = gameList.record[i];
            }
        }
        if (cur != NULL) {
            strcpy(homeOperGameName.text, cur->gameName);
            strcpy(homeOperGamePath.text, cur->gamePath);

            uint64_t time = cur->playTime;
            if (time < 60) {
                sprintf(homeOperGameTime.text, "Play time: %lds", time);
            } else if (time % 60 == 0) {
                sprintf(homeOperGameTime.text, "Play time: %ldm", time / 60);
            } else {
                sprintf(homeOperGameTime.text, "Play time: %ldm%lds", time / 60,
                        time % 60);
            }
        }
    }

    if (downloadMgr != NULL) {
        DownloadProgress progress[MAX_CLIENT_DOWNLOADS];
        size_t count = 0;
        if (downloadManagerGetProgress(downloadMgr, progress, &count) ==
            CLIENT_SUCC) {
            if (count > 0) {
                downloadWasActive = true;
                DownloadProgress *dl = &progress[0];
                switch (dl->status) {
                case DlPending:
                    sprintf(homeOperDownloadStatus.text,
                            "Download: pending...");
                    break;
                case DlDownloading:
                    sprintf(homeOperDownloadStatus.text,
                            "Download: %u/%u chunks", dl->receivedChunks,
                            dl->totalChunks);
                    break;
                case DlVerifying:
                    sprintf(homeOperDownloadStatus.text,
                            "Download: verifying...");
                    break;
                case DlDone:
                    sprintf(homeOperDownloadStatus.text, "Download: complete!");
                    break;
                case DlFailed:
                    sprintf(homeOperDownloadStatus.text, "Download: failed");
                    break;
                case DlCancelled:
                    sprintf(homeOperDownloadStatus.text, "Download: cancelled");
                    break;
                }
            } else if (downloadWasActive) {
                downloadWasActive = false;
                sprintf(homeOperDownloadStatus.text,
                        "Download: complete, refreshing...");
                freeGameListRecords();
                controlListBoxClear(&homeGameList);
                fetchGames();
            }
        }
    }
}

static void homeOperPlayOnClick(ControlButton *self) {
    (void)self;
    ControlListBoxEntry selected;
    if (arrayControlListBoxEntryGet(&homeGameList.list, homeGameList.curLine,
                                    &selected) != ContainerSucc) {
        return;
    }
    GameRecord *cur = NULL;
    for (size_t i = 0; i < gameList.cnt; ++i) {
        if (gameList.record[i]->gameId == selected.id) {
            cur = gameList.record[i];
        }
    }
    if (cur == NULL) {
        return;
    }
    gameRoomLobbyGameId = (uint32_t)selected.id;
    strncpy(gameRoomLobbyGameName, cur->gameName,
            sizeof(gameRoomLobbyGameName) - 1);
    strncpy(gameRoomLobbyGamePath, cur->gamePath,
            sizeof(gameRoomLobbyGamePath) - 1);
    gameRoomIsHost = false;
    gameRoomJoinedId = 0;
    if (gameRoomEntries != NULL) {
        free(gameRoomEntries);
        gameRoomEntries = NULL;
    }
    gameRoomEntryCount = 0;
    strcpy(gameRoomLobbyStatus.text, "Loading rooms...");
    tuiAppChangePage(&gameRoomLobbyPage);
    clientGameRoomList(client, gameRoomLobbyGameId, &gameRoomEntries,
                       &gameRoomEntryCount);
    controlListBoxClear(&gameRoomLobbyRoomList);
    for (size_t i = 0; i < gameRoomEntryCount; i++) {
        char entryBuf[512];
        const char *stateStr =
            gameRoomEntries[i].state == 0 ? "Lobby" : "Playing";
        snprintf(entryBuf, sizeof(entryBuf), "#%u | Host: %s(%s) | %u/10 | %s",
                 gameRoomEntries[i].gameRoomId, gameRoomEntries[i].hostNickname,
                 gameRoomEntries[i].hostUsername,
                 gameRoomEntries[i].memberCount, stateStr);
        controlListBoxAppend(&gameRoomLobbyRoomList, entryBuf,
                             gameRoomEntries[i].gameRoomId);
    }
    if (gameRoomEntryCount == 0) {
        strcpy(gameRoomLobbyStatus.text,
               "No rooms found. Create one or refresh.");
    } else {
        sprintf(gameRoomLobbyStatus.text, "%zu room(s) found",
                gameRoomEntryCount);
    }
}

static void gameGridDraw(ControlGrid *self) {
    werase(self->base.windowHandler);

    DOUBLE_BOX(self->base.windowHandler);

    wnoutrefresh(self->base.windowHandler);
}

static void gameGridResize(ControlGrid *self) {
    self->base.height = pViewArea->height;
    self->base.width = pViewArea->width;

    gameView.base.width = pViewArea->width - 2;
    gameView.base.height = pViewArea->height - 2 - TUI_BTN_HEIGHT;

    backBtn.base.x = gameGrid.base.width - backBtn.base.width - 1;
}

static void backBtnOnClick(ControlButton *self) {
    (void)self;
    if (client->currentRoomId != 0) {
        clientQuitRoom(client);
    }
    if (gameView.running) {
        controlGameViewStop(&gameView);
    }
    tuiAppChangePage(&homePage);
}

static void homeOperDownloadOnClick(ControlButton *self) {
    (void)self;
    ControlListBoxEntry selected;
    if (arrayControlListBoxEntryGet(&homeOperServerGames.list,
                                    homeOperServerGames.curLine,
                                    &selected) != ContainerSucc) {
        strcpy(homeOperDownloadStatus.text, "Download: no game selected");
        return;
    }

    if (downloadMgr == NULL) {
        downloadManagerInit(&downloadMgr, client);
        if (downloadMgr == NULL) {
            strcpy(homeOperDownloadStatus.text,
                   "Download: failed to init manager");
            return;
        }
    }

    const char *platform = CLIENT_DEFAULT_PLATFORM;
    downloadWasActive = true;
    int ret = downloadManagerStartDownload(downloadMgr, (uint32_t)selected.id,
                                           platform);
    if (ret != CLIENT_SUCC) {
        downloadWasActive = false;
        sprintf(homeOperDownloadStatus.text,
                "Download: failed to start (game %u)", (uint32_t)selected.id);
    } else {
        sprintf(homeOperDownloadStatus.text, "Download: starting game %u...",
                (uint32_t)selected.id);
    }
}

static void homeOperRefreshOnClick(ControlButton *self) {
    (void)self;
    if (serverGameEntries != NULL) {
        clientFreeGameList(serverGameEntries);
        serverGameEntries = NULL;
    }
    serverGameCount = 0;

    int ret = clientRequestGameList(client, 0, 0, CLIENT_DEFAULT_PLATFORM,
                                    &serverGameEntries, &serverGameCount);
    if (ret != CLIENT_SUCC || serverGameCount == 0) {
        strcpy(homeOperDownloadStatus.text, "Refresh: no games available");
        return;
    }

    controlListBoxClear(&homeOperServerGames);
    int entryWidth = homeOperServerGames.base.width - 2;
    for (size_t i = 0; i < serverGameCount; i++) {
        char entryBuf[EntryFormatBufLen];
        formatServerGameEntry(&serverGameEntries[i], entryWidth, entryBuf,
                              sizeof(entryBuf));
        controlListBoxAppendMulti(&homeOperServerGames, entryBuf,
                                  serverGameEntries[i].gameId, 2);
    }
    sprintf(homeOperDownloadStatus.text, "Loaded %zu games", serverGameCount);
}

static void homeOperRemoveOnClick(ControlButton *self) {
    (void)self;
    ControlListBoxEntry selected;
    if (arrayControlListBoxEntryGet(&homeGameList.list, homeGameList.curLine,
                                    &selected) != ContainerSucc) {
        return;
    }
    deleteGame(client, (uint32_t)selected.id);
    freeGameListRecords();
    controlListBoxClear(&homeGameList);
    fetchGames();
    strcpy(homeOperDownloadStatus.text, "Game removed");
}

static void gameRoomLobbyGridDraw(ControlGrid *self) {
    werase(self->base.windowHandler);
    DOUBLE_BOX(self->base.windowHandler);
    int x = 3;
    int y = 1;
    wattron(self->base.windowHandler, A_BOLD);
    mvwprintw(self->base.windowHandler, y, x, "Game Room Lobby — %s",
              gameRoomLobbyGameName);
    wattroff(self->base.windowHandler, A_BOLD);
    wnoutrefresh(self->base.windowHandler);
}

static void gameRoomLobbyGridResize(ControlGrid *self) {
    self->base.height = pViewArea->height;
    self->base.width = pViewArea->width;
    gameRoomLobbyBackBtn.base.x =
        self->base.width - gameRoomLobbyBackBtn.base.width - 1;
}

static void gameRoomLobbyRefreshOnClick(ControlButton *self) {
    (void)self;
    if (gameRoomEntries != NULL) {
        free(gameRoomEntries);
        gameRoomEntries = NULL;
    }
    gameRoomEntryCount = 0;
    strcpy(gameRoomLobbyStatus.text, "Refreshing...");
    clientGameRoomList(client, gameRoomLobbyGameId, &gameRoomEntries,
                       &gameRoomEntryCount);
    controlListBoxClear(&gameRoomLobbyRoomList);
    for (size_t i = 0; i < gameRoomEntryCount; i++) {
        char entryBuf[512];
        const char *stateStr =
            gameRoomEntries[i].state == 0 ? "Lobby" : "Playing";
        snprintf(entryBuf, sizeof(entryBuf), "#%u | Host: %s(%s) | %u/10 | %s",
                 gameRoomEntries[i].gameRoomId, gameRoomEntries[i].hostNickname,
                 gameRoomEntries[i].hostUsername,
                 gameRoomEntries[i].memberCount, stateStr);
        controlListBoxAppend(&gameRoomLobbyRoomList, entryBuf,
                             gameRoomEntries[i].gameRoomId);
    }
    if (gameRoomEntryCount == 0) {
        strcpy(gameRoomLobbyStatus.text,
               "No rooms found. Create one or refresh.");
    } else {
        sprintf(gameRoomLobbyStatus.text, "%zu room(s) found",
                gameRoomEntryCount);
    }
}

static void gameRoomLobbyJoinOnClick(ControlButton *self) {
    (void)self;
    ControlListBoxEntry selected;
    if (arrayControlListBoxEntryGet(&gameRoomLobbyRoomList.list,
                                    gameRoomLobbyRoomList.curLine,
                                    &selected) != ContainerSucc) {
        strcpy(gameRoomLobbyStatus.text, "No room selected");
        return;
    }
    if ((uint32_t)selected.id == gameRoomJoinedId) {
        strcpy(gameRoomLobbyStatus.text, "You are already in this room");
        return;
    }
    if (clientGameRoomJoin(client, (uint32_t)selected.id) != CLIENT_SUCC) {
        if ((uint32_t)selected.id == gameRoomJoinedId) {
            gameRoomJoinedId = 0;
            gameRoomIsHost = false;
            gameRoomLobbyStartBtn.base.visible = false;
        }
        sprintf(gameRoomLobbyStatus.text, "Failed to join room %zu",
                selected.id);
        gameRoomLobbyRefreshOnClick(NULL);
        return;
    }
    gameRoomJoinedId = (uint32_t)selected.id;
    gameRoomIsHost = false;
    sprintf(gameRoomLobbyStatus.text, "Joined room #%u. Waiting for host...",
            gameRoomJoinedId);
    gameRoomLobbyStartBtn.base.visible = false;
}

static void gameRoomLobbyCreateOnClick(ControlButton *self) {
    (void)self;
    uint32_t roomId = 0;
    if (clientGameRoomCreate(client, gameRoomLobbyGameId, &roomId) !=
        CLIENT_SUCC) {
        strcpy(gameRoomLobbyStatus.text, "Failed to create room");
        gameRoomLobbyRefreshOnClick(NULL);
        return;
    }
    gameRoomJoinedId = roomId;
    gameRoomIsHost = true;
    sprintf(gameRoomLobbyStatus.text,
            "Created room #%u. You are the host. Invite others!",
            gameRoomJoinedId);
    gameRoomLobbyStartBtn.base.visible = true;
    gameRoomLobbyRefreshOnClick(NULL);
}

static void gameRoomLobbyStartOnClick(ControlButton *self) {
    (void)self;
    if (!gameRoomIsHost || gameRoomJoinedId == 0) {
        strcpy(gameRoomLobbyStatus.text, "Only the host can start the game");
        return;
    }
    if (clientGameRoomStart(client, gameRoomJoinedId) != CLIENT_SUCC) {
        strcpy(gameRoomLobbyStatus.text, "Failed to start game");
        return;
    }
    strcpy(gameRoomLobbyStatus.text, "Starting game...");
    PacPlaySDK *sdk = pacplay_cli_create();
    if (sdk != NULL) {
        clientLaunch(client, sdk);
    }
    tuiAppChangePage(&gamePage);
    controlGameViewRun(&gameView, gameRoomLobbyGamePath);
}

static void gameRoomLobbyBackOnClick(ControlButton *self) {
    (void)self;
    if (gameRoomJoinedId != 0) {
        clientGameRoomQuit(client);
        gameRoomJoinedId = 0;
        gameRoomIsHost = false;
    }
    if (gameRoomEntries != NULL) {
        free(gameRoomEntries);
        gameRoomEntries = NULL;
    }
    gameRoomEntryCount = 0;
    tuiAppChangePage(&homePage);
}

static void gameRoomLobbyGridUpdate(ControlGrid *self) {
    (void)self;
    static int lastMemberCount = -1;

    clientPollNotifications(client);

    if (client->gameStarted) {
        client->gameStarted = false;
        PacPlaySDK *sdk = pacplay_cli_create();
        if (sdk != NULL) {
            clientLaunch(client, sdk);
        }
        tuiAppChangePage(&gamePage);
        controlGameViewRun(&gameView, gameRoomLobbyGamePath);
        return;
    }

    if (client->roomMemberCount == lastMemberCount) {
        return;
    }
    lastMemberCount = client->roomMemberCount;

    gameRoomLobbyMemberBox.base.text[0] = '\0';
    gameRoomLobbyMemberBox.base.textLen = 0;

    if (client->roomMembers != NULL && client->roomMemberCount > 0) {
        char memberBuf[128];
        for (int i = 0; i < client->roomMemberCount; i++) {
            const char *hostPrefix = (i == 0) ? "(*)" : "";
            snprintf(memberBuf, sizeof(memberBuf), "%s%s(%s)", hostPrefix,
                     client->roomMembers[i].nickname,
                     client->roomMembers[i].username);
            controlScrollTextBoxAppend(&gameRoomLobbyMemberBox, memberBuf);
        }
    }
}

void tuiClientGameRoomLobbyInit(void) {
    controlPageConstruct(&gameRoomLobbyPage);
    controlGridConstruct(&gameRoomLobbyGrid, 0, 0, 0, 0, LayoutNone, 0, 0,
                         gameRoomLobbyGridDraw, gameRoomLobbyGridResize, NULL,
                         gameRoomLobbyGridUpdate, NULL);
    controlListBoxConstruct(&gameRoomLobbyRoomList, 15, 70, 3, 3, NULL, NULL,
                            NULL, NULL);
    controlButtonConstruct(&gameRoomLobbyRefreshBtn, TUI_BTN_HEIGHT,
                           TUI_BTN_WIDTH, 19, 3, "Refresh", NULL,
                           gameRoomLobbyRefreshOnClick, NULL, NULL, NULL);
    controlButtonConstruct(&gameRoomLobbyJoinBtn, TUI_BTN_HEIGHT, TUI_BTN_WIDTH,
                           19, 18, "Join", NULL, gameRoomLobbyJoinOnClick, NULL,
                           NULL, NULL);
    controlButtonConstruct(&gameRoomLobbyCreateBtn, TUI_BTN_HEIGHT,
                           TUI_BTN_WIDTH, 19, 33, "Create", NULL,
                           gameRoomLobbyCreateOnClick, NULL, NULL, NULL);
    controlLabelConstruct(&gameRoomLobbyStatus, "", 70, 22, 3, NULL, NULL, NULL,
                          NULL);
    controlButtonConstruct(&gameRoomLobbyStartBtn, TUI_BTN_HEIGHT,
                           TUI_BTN_WIDTH, 25, 3, "Start Game", NULL,
                           gameRoomLobbyStartOnClick, NULL, NULL, NULL);
    controlButtonConstruct(&gameRoomLobbyBackBtn, TUI_BTN_HEIGHT, TUI_BTN_WIDTH,
                           1, 70, "Back", NULL, gameRoomLobbyBackOnClick, NULL,
                           NULL, NULL);
    controlScrollTextBoxConstruct(&gameRoomLobbyMemberBox, 15, 30, 3, 74, 100,
                                  NULL, NULL, NULL, NULL);

    gameRoomLobbyStartBtn.base.visible = false;

    tuiAppControlRegister((Control *)&gameRoomLobbyPage, NULL);
    tuiAppControlRegister((Control *)&gameRoomLobbyGrid,
                          (Control *)&gameRoomLobbyPage);
    tuiAppControlRegister((Control *)&gameRoomLobbyRoomList,
                          (Control *)&gameRoomLobbyGrid);
    tuiAppControlRegister((Control *)&gameRoomLobbyRefreshBtn,
                          (Control *)&gameRoomLobbyGrid);
    tuiAppControlRegister((Control *)&gameRoomLobbyJoinBtn,
                          (Control *)&gameRoomLobbyGrid);
    tuiAppControlRegister((Control *)&gameRoomLobbyCreateBtn,
                          (Control *)&gameRoomLobbyGrid);
    tuiAppControlRegister((Control *)&gameRoomLobbyStatus,
                          (Control *)&gameRoomLobbyGrid);
    tuiAppControlRegister((Control *)&gameRoomLobbyStartBtn,
                          (Control *)&gameRoomLobbyGrid);
    tuiAppControlRegister((Control *)&gameRoomLobbyBackBtn,
                          (Control *)&gameRoomLobbyGrid);
    tuiAppControlRegister((Control *)&gameRoomLobbyMemberBox,
                          (Control *)&gameRoomLobbyGrid);
}

void tuiClientMainPageInit() {
    controlPageConstruct(&homePage);
    controlGridConstruct(&homePageGrid, 0, 0, 0, 0, LayoutNone, 0, 0,
                         homePageGridDraw, homePageGridResize, NULL, NULL,
                         NULL);
    controlGridConstruct(&homeStatusGrid, TUI_HOME_STATUSGRID_HEIGHT,
                         TUI_HOME_STATUSGRID_WIDTH, 1, 0, LayoutNone, 0, 0,
                         NULL, homeStatusGridResize, NULL, NULL, NULL);
    controlListBoxConstruct(&homeGameList, 0, 0, 0, 1, NULL, homeGameListResize,
                            NULL, NULL);
    controlGridConstruct(&homeOperGrid, 0, TUI_HOME_OPERGRID_WIDTH, 0, 0,
                         LayoutVertical, 2, 2, NULL, homeOperGridResize, NULL,
                         homeOperGridUpdate, NULL);
    controlLabelConstruct(&homeStatusNickname, "",
                          TUI_HOME_STATUSGRID_WIDTH - 2 - 6, 2, 2, NULL, NULL,
                          NULL, NULL);
    controlLabelConstruct(&homeStatusUsername, "",
                          TUI_HOME_STATUSGRID_WIDTH - 2 - 6, 3, 2, NULL, NULL,
                          NULL, NULL);
    controlButtonConstruct(&homeStatusExit, TUI_BTN_HEIGHT, 6, 1,
                           TUI_HOME_STATUSGRID_WIDTH - 1 - 6, "Exit", NULL,
                           homeStatusExitOnClick, NULL, NULL, NULL);
    controlLabelConstruct(&homeOperGameName, "", TUI_HOME_OPERGRID_WIDTH - 4, 0,
                          0, NULL, NULL, NULL, NULL);
    controlLabelConstruct(&homeOperGamePath, "", TUI_HOME_OPERGRID_WIDTH - 4, 0,
                          0, NULL, NULL, NULL, NULL);
    controlLabelConstruct(&homeOperGameTime, "", TUI_HOME_OPERGRID_WIDTH - 4, 0,
                          0, NULL, NULL, NULL, NULL);
    controlButtonConstruct(&homeOperPlay, TUI_BTN_HEIGHT, TUI_BTN_WIDTH, 0, 0,
                           "Play...", NULL, homeOperPlayOnClick, NULL, NULL,
                           NULL);
    controlButtonConstruct(&homeOperRemoveGame, TUI_BTN_HEIGHT,
                           TUI_BTN_WIDTH + 6, 0, 0, "Remove selected", NULL,
                           homeOperRemoveOnClick, NULL, NULL, NULL);
    controlLabelConstruct(&homeOperEmpty1, "", 1, 0, 0, NULL, NULL, NULL, NULL);
    controlLabelConstruct(&homeOperEmpty2, "", 1, 0, 0, NULL, NULL, NULL, NULL);
    controlListBoxConstruct(&homeOperServerGames, 10,
                            TUI_HOME_OPERGRID_WIDTH - 4, 0, 1, NULL, NULL, NULL,
                            NULL);
    controlLabelConstruct(&homeOperDownloadStatus, "",
                          TUI_HOME_OPERGRID_WIDTH - 4, 0, 0, NULL, NULL, NULL,
                          NULL);
    controlButtonConstruct(&homeOperDownloadGame, TUI_BTN_HEIGHT,
                           TUI_BTN_WIDTH + 8, 0, 0, "Download selected", NULL,
                           homeOperDownloadOnClick, NULL, NULL, NULL);
    controlButtonConstruct(&homeOperRefreshDownloadableGames, TUI_BTN_HEIGHT,
                           TUI_BTN_WIDTH + 8, 0, 0, "Refresh games", NULL,
                           homeOperRefreshOnClick, NULL, NULL, NULL);

    tuiAppControlRegister(&homePage, NULL);
    tuiAppControlRegister((Control *)&homePageGrid, (Control *)&homePage);
    tuiAppControlRegister((Control *)&homeStatusGrid, (Control *)&homePage);
    tuiAppControlRegister((Control *)&homeGameList, (Control *)&homePage);
    tuiAppControlRegister((Control *)&homeOperGrid, (Control *)&homePage);
    tuiAppControlRegister((Control *)&homeStatusNickname,
                          (Control *)&homeStatusGrid);
    tuiAppControlRegister((Control *)&homeStatusUsername,
                          (Control *)&homeStatusGrid);
    tuiAppControlRegister((Control *)&homeStatusExit,
                          (Control *)&homeStatusGrid);
    tuiAppControlRegister((Control *)&homeOperGameName,
                          (Control *)&homeOperGrid);
    tuiAppControlRegister((Control *)&homeOperGamePath,
                          (Control *)&homeOperGrid);
    tuiAppControlRegister((Control *)&homeOperGameTime,
                          (Control *)&homeOperGrid);
    tuiAppControlRegister((Control *)&homeOperPlay, (Control *)&homeOperGrid);
    tuiAppControlRegister((Control *)&homeOperRemoveGame,
                          (Control *)&homeOperGrid);
    tuiAppControlRegister((Control *)&homeOperEmpty1, (Control *)&homeOperGrid);
    tuiAppControlRegister((Control *)&homeOperEmpty2, (Control *)&homeOperGrid);
    tuiAppControlRegister((Control *)&homeOperServerGames,
                          (Control *)&homeOperGrid);
    tuiAppControlRegister((Control *)&homeOperDownloadStatus,
                          (Control *)&homeOperGrid);
    tuiAppControlRegister((Control *)&homeOperDownloadGame,
                          (Control *)&homeOperGrid);
    tuiAppControlRegister((Control *)&homeOperRefreshDownloadableGames,
                          (Control *)&homeOperGrid);

    // Game page
    controlPageConstruct(&gamePage);
    controlGridConstruct(&gameGrid, 0, 0, 0, 0, LayoutNone, 0, 0, gameGridDraw,
                         gameGridResize, NULL, NULL, NULL);
    controlButtonConstruct(&backBtn, TUI_BTN_HEIGHT, TUI_BTN_WIDTH, 1, 1,
                           "Back", NULL, backBtnOnClick, NULL, NULL, NULL);
    controlGameViewConstruct(&gameView, 3, 3, TUI_BTN_HEIGHT + 1, 1);

    tuiAppControlRegister((Control *)&gamePage, NULL);
    tuiAppControlRegister((Control *)&gameGrid, (Control *)&gamePage);
    tuiAppControlRegister((Control *)&backBtn, (Control *)&gameGrid);
    tuiAppControlRegister((Control *)&gameView, (Control *)&gameGrid);
}
