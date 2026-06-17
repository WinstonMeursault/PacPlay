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
#include "clientTUI.h"
#include <stdlib.h>
#include <string.h>
#include "client/room.h"
#include "clientTUI.h"
#include "controlGameView.h"
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

bool onlyChat = false;

static DownloadManager *downloadMgr = NULL;
static GameInfoEntry *serverGameEntries = NULL;
static size_t serverGameCount = 0;
static bool downloadWasActive = false;

enum {
    DescMaxLines = 3,
    EntryFormatBufLen = 2048
};

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
ControlButton homeStatusChat;
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
ControlButton toGameBtn;
ControlButton toChatBtn;
ControlButton backBtn;
ControlGameView gameView;
ControlGrid chatGrid;
ControlListBox chatRoomList;
ControlButton chatEnterRoomBtn;
ControlButton chatRefreshRoomBtn;
ControlButton chatCreateRoomBtn;
ControlScrollTextBox chatHistoryBox;
ControlInputBox chatInputBox;

typedef enum { GameTag = 1, ChatTag = 2 } TagEnum;
static void switchTag(TagEnum tag) {
    switch (tag) {
    case GameTag:
        tuiAppVisibilityChange((Control *)&chatGrid, false);
        tuiAppVisibilityChange((Control *)&gameView, true);
        break;
    case ChatTag:
        tuiAppVisibilityChange((Control *)&gameView, false);
        tuiAppVisibilityChange((Control *)&chatGrid, true);
        break;
    default:
        break;
    }
    tuiAppRefresh();
}

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
    switchTag(GameTag);
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

static void homeStatusChatOnClick(ControlButton *self) {
    (void)self;
    switchTag(ChatTag);
    tuiAppChangePage(&gamePage);
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
                    sprintf(homeOperDownloadStatus.text, "Download: pending...");
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
    switchTag(GameTag);
    tuiAppChangePage(&gamePage);
    controlGameViewRun(&gameView, cur->gamePath);
}

static void gameGridDraw(ControlGrid *self) {
    werase(self->base.windowHandler);

    DOUBLE_BOX(self->base.windowHandler);

    wnoutrefresh(self->base.windowHandler);
}

static void gameGridResize(ControlGrid *self) {
    self->base.height = pViewArea->height;
    self->base.width = pViewArea->width;

    gameView.base.width = chatGrid.base.width = pViewArea->width - 2;
    gameView.base.height = chatGrid.base.height =
        pViewArea->height - 2 - TUI_BTN_HEIGHT;

    backBtn.base.x = gameGrid.base.width - backBtn.base.width - 1;

    chatRoomList.base.x = self->base.width / 2 - chatRoomList.base.width / 2;
    chatRoomList.base.y = self->base.height / 2 - chatRoomList.base.height / 2;

    chatEnterRoomBtn.base.x =
        self->base.width / 2 - chatEnterRoomBtn.base.width / 2;
    chatEnterRoomBtn.base.y =
        chatRoomList.base.y + chatRoomList.base.height + 1;

    chatHistoryBox.base.base.width = self->base.width - 2;
    chatHistoryBox.base.base.height = self->base.height - 5;

    chatInputBox.base.width = self->base.width - 2;
    chatInputBox.base.y = self->base.height - 4;
}

static void toGameBtnOnClick(ControlButton *self) {
    (void)self;
    switchTag(GameTag);
}
static void toChatBtnOnClick(ControlButton *self) {
    (void)self;
    switchTag(ChatTag);
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
    controlButtonConstruct(&homeStatusChat, TUI_BTN_HEIGHT, TUI_BTN_WIDTH,
                           TUI_HOME_STATUSGRID_HEIGHT - 1 - TUI_BTN_HEIGHT, 2,
                           "Chat...", NULL, homeStatusChatOnClick, NULL, NULL,
                           NULL);
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
    tuiAppControlRegister((Control *)&homeStatusChat,
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
    controlButtonConstruct(&toGameBtn, TUI_BTN_HEIGHT, TUI_BTN_WIDTH, 1, 1,
                           "Game", NULL, toGameBtnOnClick, NULL, NULL, NULL);
    controlButtonConstruct(&toChatBtn, TUI_BTN_HEIGHT, TUI_BTN_WIDTH, 1,
                           1 + TUI_BTN_WIDTH + 1, "Chat", NULL,
                           toChatBtnOnClick, NULL, NULL, NULL);
    controlButtonConstruct(&backBtn, TUI_BTN_HEIGHT, TUI_BTN_WIDTH, 1,
                           1 + TUI_BTN_WIDTH + 1, "Back", NULL, backBtnOnClick,
                           NULL, NULL, NULL);
    controlGameViewConstruct(&gameView, 3, 3, TUI_BTN_HEIGHT + 1, 1);
    controlGridConstruct(&chatGrid, 0, 0, TUI_BTN_HEIGHT + 1, 1, LayoutNone, 0,
                          0, NULL, NULL, NULL, NULL, NULL);
    controlListBoxConstruct(&chatRoomList, 20, 20, 0, 0, NULL, NULL, NULL,
                            NULL);
    controlButtonConstruct(&chatEnterRoomBtn, TUI_BTN_HEIGHT, TUI_BTN_WIDTH, 0,
                           0, "Enter", NULL, NULL, NULL, NULL, NULL);
    controlButtonConstruct(&chatRefreshRoomBtn, TUI_BTN_HEIGHT, TUI_BTN_WIDTH,
                           0, 0, "Refresh", NULL, NULL, NULL, NULL, NULL);
    controlButtonConstruct(&chatCreateRoomBtn, TUI_BTN_HEIGHT, TUI_BTN_WIDTH, 0,
                           0, "Create", NULL, NULL, NULL, NULL, NULL);
    controlScrollTextBoxConstruct(&chatHistoryBox, 0, 0, 1, 1, 1000, NULL, NULL,
                                  NULL, NULL);
    controlInputBoxConstruct(&chatInputBox, 10, 0, 1, false, NULL, NULL, NULL,
                             NULL, NULL);

    tuiAppControlRegister((Control *)&gamePage, NULL);
    tuiAppControlRegister((Control *)&gameGrid, (Control *)&gamePage);
    tuiAppControlRegister((Control *)&toGameBtn, (Control *)&gameGrid);
    tuiAppControlRegister((Control *)&toChatBtn, (Control *)&gameGrid);
    tuiAppControlRegister((Control *)&backBtn, (Control *)&gameGrid);
    tuiAppControlRegister((Control *)&gameView, (Control *)&gameGrid);
    tuiAppControlRegister((Control *)&chatGrid, (Control *)&gameGrid);
    tuiAppControlRegister((Control *)&chatRoomList, (Control *)&chatGrid);
    tuiAppControlRegister((Control *)&chatEnterRoomBtn, (Control *)&chatGrid);
    tuiAppControlRegister((Control *)&chatHistoryBox, (Control *)&chatGrid);
    tuiAppControlRegister((Control *)&chatInputBox, (Control *)&chatGrid);
}
