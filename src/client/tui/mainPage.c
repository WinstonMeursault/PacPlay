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
#include "../database.h"
#include "clientTUI.h"

#define TUI_HOME_STATUSGRID_HEIGHT 9
#define TUI_HOME_STATUSGRID_WIDTH 40
#define TUI_HOME_OPERGRID_WIDTH TUI_HOME_STATUSGRID_WIDTH

// Home page
ControlPage homePage;
ControlGrid homePageGrid;
ControlGrid homeStatusGrid;
ControlListBox homeGameList;
ControlGrid homeOperGrid;
ControlButton homeStatusExit;
ControlLabel homeStatusUsername;
ControlLabel homeStatusNickname;

// Game page
ControlPage gamePage;

static void homePageUpdateUserData(char *nickname, char *username) {
    if (nickname != NULL) {
        sprintf(homeStatusNickname.text, "User: %s", nickname);
    }
    if (username != NULL) {
        sprintf(homeStatusUsername.text, "     (%s)", username);
    }
}

void homePageInitUpdate(char *nickname, char *username) {
    homePageUpdateUserData(nickname, username);
}

static void homePageGridResize(ControlGrid *self) {
    self->base.height = pViewArea->height;
    self->base.width = pViewArea->width;
}

static void homePageGridDraw(ControlGrid *self) {
    werase(self->base.windowHandler);

    DOUBLE_BOX(self->base.windowHandler);
    int x = 3, y = 2;
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

    mvwprintw(self->base.windowHandler, 4, 45, "v0.1");
    mvwprintw(self->base.windowHandler, 5, 45, "GPLv3 License");
    mvwprintw(self->base.windowHandler, 6, 45, "Copyright (C) 2026");
    mvwprintw(self->base.windowHandler, 7, 45, "Winston Meursault & Kiraterin");

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

void tuiClientMainPageInit() {
    controlPageConstruct(&homePage);
    controlGridConstruct(&homePageGrid, 0, 0, 0, 0, LayoutNone, 0, 0,
                         homePageGridDraw, homePageGridResize, NULL, NULL);
    controlGridConstruct(&homeStatusGrid, TUI_HOME_STATUSGRID_HEIGHT,
                         TUI_HOME_STATUSGRID_WIDTH, 1, 0, LayoutNone, 0, 0,
                         NULL, homeStatusGridResize, NULL, NULL);
    controlListBoxConstruct(&homeGameList, 0, 0, 0, 1, NULL, homeGameListResize,
                            NULL);
    controlGridConstruct(&homeOperGrid, 0, TUI_HOME_OPERGRID_WIDTH, 0, 0,
                         LayoutNone, 0, 0, NULL, homeOperGridResize, NULL,
                         NULL);
    controlLabelConstruct(&homeStatusNickname, "",
                          TUI_HOME_STATUSGRID_WIDTH - 2 - 6, 2, 2, NULL, NULL,
                          NULL);
    controlLabelConstruct(&homeStatusUsername, "",
                          TUI_HOME_STATUSGRID_WIDTH - 2 - 6, 3, 2, NULL, NULL,
                          NULL);
    controlButtonConstruct(&homeStatusExit, TUI_BTN_HEIGHT, 6, 1,
                           TUI_HOME_STATUSGRID_WIDTH - 1 - 6, "Exit", NULL,
                           homeStatusExitOnClick, NULL, NULL);
    controlListBoxAppend(&homeGameList, "123");

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
}