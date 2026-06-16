/**
 * @file mainPage.c
 * @brief
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
#include "client/gameLoad.h"
#include "clientTUI.h"
#include <string.h>
#include "client/room.h"
#include "clientTUI.h"
#include "controlGameView.h"
#include <time.h>

#define TUI_HOME_STATUSGRID_HEIGHT 9
#define TUI_HOME_STATUSGRID_WIDTH 40
#define TUI_HOME_OPERGRID_WIDTH TUI_HOME_STATUSGRID_WIDTH

struct {
    GameRecord **record;
    size_t cnt;
} gameList;

bool onlyChat = false;

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
                                    &selected) != ContainerSucc) {
        return;
    }
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

static void homeOperPlayOnClick(ControlButton *self) {
    (void)self;
    switchTag(GameTag);
    tuiAppChangePage(&gamePage);
    controlGameViewRun(&gameView, "123");
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
    strcpy(homeOperDownloadStatus.text, "Download: not yet implemented");
}

static void homeOperRefreshOnClick(ControlButton *self) {
    (void)self;
    strcpy(homeOperDownloadStatus.text, "Refresh: not yet implemented");
}

static void homeOperRemoveOnClick(ControlButton *self) {
    (void)self;
    // TODO: implement game removal
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