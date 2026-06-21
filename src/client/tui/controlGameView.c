/**
 * @file controlGameView.c
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

#include "controlGameView.h"
#include "client/client.h"
#include "utils.h"
#include <errno.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define MAX_BUF_SIZE 4096

static void controlGameViewDraw(ControlGameView *self);
static void controlGameViewUpdate(ControlGameView *self);
static void controlGameViewMsgHandler(ControlGameView *self, TuiMsg msg);

const ControlVTable defaultControlGameViewVTable = {
    .destruct = NULL,
    .draw = (void (*)(Control *))controlGameViewDraw,
    .msgHandler = (void (*)(Control *, TuiMsg))controlGameViewMsgHandler,
    .update = (void (*)(Control *))controlGameViewUpdate,
    .coordToByteOffset = NULL,
    .getSelectableText = NULL};

void controlGameViewConstruct(ControlGameView *self, int height, int width,
                              int y, int x) {
    controlConstruct((Control *)self, height, width, y, x, true, false);
    self->base.vtable = defaultControlGameViewVTable;
    self->base.takeOverInput = true;
    self->running = false;
    self->vtHeight = height - 2;
    self->vtWidth = width - 2;
}

static void controlGameViewDraw(ControlGameView *self) {
    werase(self->base.windowHandler);

    if (self->base.focused) {
        if (self->base.takeOverInput) {
            DOUBLE_BOX(self->base.windowHandler);
        } else {
            customBox(self->base.windowHandler, L"┊", L"┊", L"╌", L"╌", L"┌",
                      L"┐", L"└", L"┘");
        }
    } else {
        box(self->base.windowHandler, 0, 0);
    }

    if (self->running) {
        self->vscreen = vterm_obtain_screen(self->vterm);
        VTermScreenCell vtscell;
        for (int y = 0; y < self->base.height - 2; ++y) {
            for (int x = 0; x < self->base.width - 2; ++x) {
                vterm_screen_get_cell(self->vscreen,
                                      (VTermPos){.row = y, .col = x}, &vtscell);
                if (vtscell.width == -1) {
                    continue;
                }
                mvwaddwstr(self->base.windowHandler, y + 1, x + 1,
                           (wchar_t *)vtscell.chars);
            }
        }
    } else {
        mvwprintw(self->base.windowHandler, self->base.height / 2,
                  self->base.width / 2 - 16 / 2, "No game running");
    }

    wnoutrefresh(self->base.windowHandler);
}

static void controlGameViewUpdate(ControlGameView *self) {
    if (self->running) {
        char buf[MAX_BUF_SIZE];
        ssize_t n;
        // int readQuota = 4;
        // while (readQuota > 0 && (n = read(self->ptyFD, buf, sizeof(buf))) >
        // 0) {
        //     vterm_input_write(self->vterm, buf, n);
        //     --readQuota;
        // }

        // if (readQuota > 0) {
        //     if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK))
        //     {
        //         controlGameViewStop(self);
        //     }
        // }
        while ((n = read(self->ptyFD, buf, sizeof(buf))) > 0) {
            vterm_input_write(self->vterm, buf, n);
        }

        if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
            controlGameViewStop(self);
        }
    }
}

void controlGameViewRun(ControlGameView *self, const char *gamePath) {
    self->running =
        clientRunGame(&self->vterm, &self->vscreen, gamePath, self->vtHeight,
                      self->vtWidth, &self->pid, &self->ptyFD) == CLIENT_SUCC;
}

void controlGameViewStop(ControlGameView *self) {
    self->running = false;
    clientStopGame(&self->vterm, &self->pid, &self->ptyFD);
}

static void controlGameViewMsgHandler(ControlGameView *self, TuiMsg msg) {
    if (self->running) {
        switch (msg.type) {
        case MsgInput: {
            switch (msg.arg1.input) {
            case '\e':
                self->base.takeOverInput = false;
                break;
            default: {
                self->base.takeOverInput = true;
                VTermKey vtk = ncursesKeyToVTerm(msg.arg1.input);
                if (vtk != VTERM_KEY_NONE) {
                    vterm_keyboard_key(self->vterm, vtk, 0);
                } else {
                    vterm_keyboard_unichar(self->vterm,
                                           (uint32_t)msg.arg1.input, 0);
                }
                char buf[MAX_BUF_SIZE];
                size_t len = vterm_output_read(self->vterm, buf, sizeof(buf));
                if (len > 0) {
                    write(self->ptyFD, buf, len);
                }
                break;
            }
            }
            break;
        }
        case MsgFocusEnter:
            self->base.takeOverInput = true;
            break;
        case MsgResize: {
            self->vtHeight = self->base.height - 2;
            self->vtWidth = self->base.width - 2;
            vterm_set_size(self->vterm, self->vtHeight, self->vtWidth);
            struct winsize ws = {.ws_row = self->vtHeight,
                                 .ws_col = self->vtWidth};
            ioctl(self->ptyFD, TIOCSWINSZ, &ws);
            kill(self->pid, SIGWINCH);
            break;
        }
        default:
            break;
        }
    } else {
        switch (msg.type) {
        case MsgInput: {
            switch (msg.arg1.input) {
            case '\e':
                self->base.takeOverInput = false;
                break;
            default:
                self->base.takeOverInput = true;
            }
            break;
        }
        case MsgFocusEnter:
            self->base.takeOverInput = true;
            break;
        default:
            break;
        }
    }
}