/**
 * @file controlGameView.h
 * @brief
 *
 * @date 2026-06-15
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

#ifndef CONTROLGAMEVIEW_H
#define CONTROLGAMEVIEW_H

#include "client/gameLoad.h"
#include "tui/control.h"
#include "poll.h"

typedef struct {
    Control base;
    bool running;
    VTerm *vterm;
    VTermScreen *vscreen;
    int vtHeight;
    int vtWidth;
    pid_t pid;
    int ptyFD;
} ControlGameView;

void controlGameViewConstruct(ControlGameView *self, int height, int width,
                              int y, int x);
void controlGameViewRun(ControlGameView *self, const char *gamePath);
void controlGameViewStop(ControlGameView *self);

#endif // CONTROLGAMEVIEW_H