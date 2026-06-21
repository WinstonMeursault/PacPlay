/**
 * @file clientTUI.c
 * @brief
 *
 * @date 2026-06-09
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

#include "clientTUI.h"
#include "client/client.h"
#include "connectPage.h"
#include "log.h"
#include "loginReg.h"
#include "mainPage.h"
#include "socialPage.h"
#include "tui/tuiapp.h"

// Client pointer
Client *client;

static void tuiClientColorInit() {
    init_color(ColorRed, 973, 318, 286);
    init_color(ColorGreen, 298, 686, 314);
    init_pair(ColorAttrRed, ColorRed, -1);
    init_pair(ColorAttrGreen, ColorGreen, -1);
    init_pair(ColorAttrStableBlack, COLOR_BLACK, COLOR_BLACK);
    init_pair(ColorAttrStableWhite, COLOR_WHITE, COLOR_WHITE);
}

void tuiClientEntry(Client *clientInstance) {
    client = clientInstance;
    logSetQuiet(true);
    tuiAppInit();
    tuiClientColorInit();
    tuiClientConnectPageInit();
    tuiClientLoginRegInit();
    tuiClientMainPageInit();
    tuiClientGameRoomLobbyInit();
    tuiClientSocialPageInit();
    tuiAppStart(&connectPage);
}