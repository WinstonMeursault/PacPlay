/**
 * @file client_tui.h
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

#ifndef CLIENTTUI_H
#define CLIENTTUI_H

#include "client/client.h"
#include "tui/tuiapp.h"

#define TUI_BTN_HEIGHT 3
#define TUI_BTN_WIDTH 13

// Client pointer
extern Client *client;

extern ControlPage connectPage;
extern ControlPage loginPage;
extern ControlPage homePage;

typedef enum TuiClientColor {
    ColorRed = 1,
    ColorGreen,
    ColorStableBlack,
    ColorStableWhite
} TuiClientColor;

typedef enum TuiClientColorAttr {
    ColorAttrDefault = 0,
    ColorAttrRed = 1,
    ColorAttrGreen,
    ColorAttrStableBlack,
    ColorAttrStableWhite
} TuiClientColorAttr;

void tuiClientEntry(Client *clientInstance);

#endif // CLIENTTUI_H