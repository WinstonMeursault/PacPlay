/**
 * @file tuiapp.h
 * @brief
 *
 * @date 2026-05-31
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

#ifndef TUIAPP_H
#define TUIAPP_H

#include "control.h"
#include "ncurses_wrapper.h"
#include "tuimsg.h"

typedef struct {
    WINDOW *windowHandler;
    int width;
    int height;
    int x;
    int y;
} ViewArea;

extern ViewArea *pViewArea;

void tuiAppInit();
void tuiAppControlRegister(Control *entry, Control *parent);
void tuiAppStart(ControlPage *orgPage);
void tuiAppStop();

// entry == NULL means stdscr
void tuiAppChangePage(ControlPage *entry);
void tuiAppPushMessage(TuiMsg msg);
void tuiAppRefresh();
void tuiAppVisibilityChange(Control *dest, bool visible);

#endif // TUIAPP_H