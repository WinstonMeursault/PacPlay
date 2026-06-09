/**
 * @file control.c
 * @brief
 *
 * @date 2026-05-30
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

#include "tui/control.h"
#include "log.h"
#include "tui/tuiapp.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

static void customBox(WINDOW *handler, const wchar_t *lsRaw,
                      const wchar_t *rsRaw, const wchar_t *tsRaw,
                      const wchar_t *bsRaw, const wchar_t *tlRaw,
                      const wchar_t *trRaw, const wchar_t *blRaw,
                      const wchar_t *brRaw);
#define DOUBLE_BOX(handler)                                                    \
    customBox((handler), L"║", L"║", L"═", L"═", L"╔", L"╗", L"╚", L"╝")

static void controlConstruct(Control *self, int height, int width, int y, int x,
                             bool focusable, bool isContainer);

static void controlPageMsgHandler(void *self, TuiMsg msg);
static void controlPageRefreshChild(void *self, void *child);

static void controlButtonDestruct(void *self);
static void controlButtonMsgHandler(void *self, TuiMsg msg);

static void controlGridMsgHandler(void *self, TuiMsg msg);
static void controlGridLayout(void *self, void *child);

static void controlLabelDestruct(void *self);
static void controlLabelMsgHandler(void *self, TuiMsg msg);

static void controlInputBoxDestruct(void *self);
static void controlInputBoxMsgHandler(void *self, TuiMsg msg);

const static ControlVTable defaultCtrlVtable = {
    .destruct = NULL, .draw = NULL, .msgHandler = NULL};
const static ControlVTable defaultBtnVtable = {
    .destruct = controlButtonDestruct,
    .draw = controlButtonDraw,
    .msgHandler = controlButtonMsgHandler};
const static ControlVTable defaultGridVtable = {.destruct = NULL,
                                                .draw = controlGridDraw,
                                                .msgHandler =
                                                    controlGridMsgHandler};
const static ControlVTable defaultLabelVtable = {
    .destruct = controlLabelDestruct,
    .draw = controlLabelDraw,
    .msgHandler = controlLabelMsgHandler};
const static ControlVTable defaultInputBoxVtable = {
    .destruct = controlInputBoxDestruct,
    .draw = controlInputBoxDraw,
    .msgHandler = controlInputBoxMsgHandler};

static void customBox(WINDOW *handler, const wchar_t *lsRaw,
                      const wchar_t *rsRaw, const wchar_t *tsRaw,
                      const wchar_t *bsRaw, const wchar_t *tlRaw,
                      const wchar_t *trRaw, const wchar_t *blRaw,
                      const wchar_t *brRaw) {
    cchar_t ls, rs, ts, bs, tl, tr, bl, br;
    setcchar(&ls, lsRaw, A_NORMAL, 0, NULL);
    setcchar(&rs, rsRaw, A_NORMAL, 0, NULL);
    setcchar(&ts, tsRaw, A_NORMAL, 0, NULL);
    setcchar(&bs, bsRaw, A_NORMAL, 0, NULL);
    setcchar(&tl, tlRaw, A_NORMAL, 0, NULL);
    setcchar(&tr, trRaw, A_NORMAL, 0, NULL);
    setcchar(&bl, blRaw, A_NORMAL, 0, NULL);
    setcchar(&br, brRaw, A_NORMAL, 0, NULL);
    wborder_set(handler, &ls, &rs, &ts, &bs, &tl, &tr, &bl, &br);
}

// parent == NULL to use stdscr
void controlInstantiate(Control *self, Control *parent) {
    if (parent == NULL) {
        self->windowHandler =
            subwin(stdscr, self->height, self->width, self->y, self->x);
    } else {
        // If parent is a derived structure, it also works. Because the base
        // member is always at the first in derived structure.
        self->windowHandler =
            subwin(((Control *)parent)->windowHandler, self->height,
                   self->width, self->y, self->x);
    }
    if (self->windowHandler == NULL) {
        LOG_ERROR("subwin failed for control at index %zu", self->index);
    }
}

void controlDeinstantiate(Control *self) {
    delwin(self->windowHandler);
    self->windowHandler = NULL;
}

// parent == NULL means stdscr
static void controlConstruct(Control *self, int height, int width, int y, int x,
                             bool focusable, bool isContainer) {
    self->vtable = defaultCtrlVtable;
    self->windowHandler = NULL;
    self->isPage = false;
    self->index = 0;
    self->height = height;
    self->width = width;
    self->y = y;
    self->x = x;
    self->focusable = focusable;
    self->focused = false;
    self->isContainer = isContainer;
    self->childCount = 0;
    self->takeOverInput = false;
    self->visible = true;
    self->commonMsgHandlers.resize = NULL;
    self->commonMsgHandlers.refresh = NULL;
}

void controlPageConstruct(ControlPage *self) {
    controlConstruct(self, 0, 0, 0, 0, false, true);
    self->isPage = true;
    self->vtable.msgHandler = controlPageMsgHandler;
}

static void controlPageMsgHandler(void *self, TuiMsg msg) {
    ControlPage *page = (ControlPage *)self;
    switch (msg.type) {
    case MsgResize:
    case MsgRefresh:
        tuiAppPushMessage(
            (TuiMsg){.type = MsgFetch,
                     .arg1 = {.index = page->index},
                     .arg2 = {.fetchRecv = controlPageRefreshChild}});
        break;
    default:
        break;
    }
}

static void controlPageRefreshChild(void *self, void *child) {
    ControlPage *page = (ControlPage *)self;
    controlDeinstantiate((Control *)child);
    controlInstantiate((Control *)child, (Control *)page);
}

// funcptrs == NULL to use default
void controlButtonConstruct(ControlButton *self, int height, int width, int y,
                            int x, const char *text,
                            void (*draw)(ControlButton *),
                            void (*onClick)(ControlButton *self),
                            void (*resize)(ControlButton *self),
                            void (*refresh)(ControlButton *self)) {
    controlConstruct((Control *)self, height, width, y, x, true, false);
    self->base.vtable = defaultBtnVtable;
    if (draw != NULL) {
        self->base.vtable.draw = (void (*)(void *))draw;
    }
    self->onClick = onClick;
    self->base.commonMsgHandlers.resize = (void (*)(void *))resize;
    self->base.commonMsgHandlers.refresh = (void (*)(void *))refresh;
    self->text = malloc(sizeof(char) * BTN_LABEL_MAXLEN);
    if (self->text == NULL) {
        LOG_ERROR("malloc failed for button text");
        return;
    }
    strncpy(self->text, text, BTN_LABEL_MAXLEN);
    self->text[BTN_LABEL_MAXLEN - 1] = '\0';
}

static void controlButtonDestruct(void *self) {
    ControlButton *btn = (ControlButton *)self;
    free(btn->text);
}

void controlButtonDraw(void *self) {
    ControlButton *btn = (ControlButton *)self;
    werase(btn->base.windowHandler);

    if (btn->base.focused) {
        DOUBLE_BOX(btn->base.windowHandler);
    } else {
        box(btn->base.windowHandler, 0, 0);
    }

    if (btn->text != NULL) {
        size_t textLen = strlen(btn->text);
        mvwprintw(btn->base.windowHandler, btn->base.height / 2,
                  btn->base.width / 2 - textLen / 2, "%s", btn->text);
    }

    wnoutrefresh(btn->base.windowHandler);
}

static void controlButtonMsgHandler(void *self, TuiMsg msg) {
    ControlButton *btn = (ControlButton *)self;
    switch (msg.type) {
    case MsgInput: {
        if ((msg.arg1.input == '\n' || msg.arg1.input == '\r' ||
             msg.arg1.input == KEY_ENTER) &&
            btn->onClick != NULL) {
            btn->onClick(btn);
        }
        break;
    }
    case MsgRefresh:
        if (btn->base.commonMsgHandlers.refresh != NULL) {
            btn->base.commonMsgHandlers.refresh(btn);
        }
        break;
    case MsgResize:
        if (btn->base.commonMsgHandlers.resize != NULL) {
            btn->base.commonMsgHandlers.resize(btn);
        }
        break;
    default:
        break;
    }
}

void controlGridConstruct(ControlGrid *self, int height, int width, int y,
                          int x, GridLayoutMethod layoutMethod, size_t hmargin,
                          size_t vmargin, void (*draw)(ControlGrid *),
                          void (*resize)(ControlGrid *self),
                          void (*refresh)(ControlGrid *self),
                          void (*layout)(void *, void *)) {
    controlConstruct((Control *)self, height, width, y, x, false, true);
    self->base.vtable = defaultGridVtable;
    self->layoutMethod = layoutMethod;
    self->margin.horizontal = hmargin;
    self->margin.vertical = vmargin;
    self->layoutCounter = 0;
    self->layoutAccCol = 0;
    self->layoutAccRow = 0;
    if (draw != NULL) {
        self->base.vtable.draw = (void (*)(void *))draw;
    }
    self->base.commonMsgHandlers.resize = (void (*)(void *))resize;
    self->base.commonMsgHandlers.refresh = (void (*)(void *))refresh;
    if (layout != NULL) {
        self->layout = layout;
    } else {
        self->layout = controlGridLayout;
    }
}

void controlGridDraw(void *self) {
    ControlGrid *grid = (ControlGrid *)self;
    werase(grid->base.windowHandler);

    box(grid->base.windowHandler, 0, 0);

    wnoutrefresh(grid->base.windowHandler);
}

static void controlGridMsgHandler(void *self, TuiMsg msg) {
    ControlGrid *grid = (ControlGrid *)self;
    switch (msg.type) {
    case MsgRefresh:
        if (grid->base.commonMsgHandlers.refresh != NULL) {
            grid->base.commonMsgHandlers.refresh(grid);
        }
        break;
    case MsgResize:
        if (grid->base.commonMsgHandlers.resize != NULL) {
            grid->base.commonMsgHandlers.resize(grid);
        }
        tuiAppPushMessage(
            (TuiMsg){.type = MsgFetch,
                     .arg1 = {.index = grid->base.index},
                     .arg2 = {.fetchRecv = ((ControlGrid *)self)->layout}});
        break;
    default:
        break;
    }
}

static void controlGridLayout(void *self, void *child) {
    ControlGrid *grid = (ControlGrid *)self;
    Control *ch = (Control *)child;
    if (grid->layoutCounter == 0) {
        grid->layoutAccCol = grid->margin.horizontal;
        grid->layoutAccRow = grid->margin.vertical;
    }
    switch (grid->layoutMethod) {
    case LayoutHorizontal: {
        if (grid->layoutAccCol + ch->width >
            (size_t)grid->base.width - grid->margin.horizontal) {
            grid->layoutAccCol = grid->margin.horizontal;
            grid->layoutAccRow += grid->margin.vertical + ch->height;
        }
        ch->x = (int)grid->layoutAccCol;
        ch->y = (int)grid->layoutAccRow;
        grid->layoutAccCol += (size_t)ch->width;
        break;
    }
    case LayoutVertical: {
        if (grid->layoutAccRow + ch->height >
            (size_t)grid->base.height - grid->margin.vertical) {
            grid->layoutAccRow = grid->margin.vertical;
            grid->layoutAccCol += grid->margin.horizontal + ch->width;
        }
        ch->x = (int)grid->layoutAccCol;
        ch->y = (int)grid->layoutAccRow;
        grid->layoutAccRow += (size_t)ch->height;
        break;
    }
    default:
        break;
    }
    controlDeinstantiate(ch);
    controlInstantiate(ch, (Control *)grid);
    if (grid->base.childCount > 0) {
        grid->layoutCounter = (grid->layoutCounter + 1) % grid->base.childCount;
    }
}

void controlLabelConstruct(ControlLabel *self, const char *text, int y, int x,
                           void (*draw)(ControlLabel *),
                           void (*resize)(ControlLabel *self),
                           void (*refresh)(ControlLabel *self)) {
    size_t len = strlen(text);
    controlConstruct((Control *)self, 1, len, y, x, false, false);
    self->base.vtable = defaultLabelVtable;
    if (draw != NULL) {
        self->base.vtable.draw = (void (*)(void *))draw;
    }
    self->base.commonMsgHandlers.resize = (void (*)(void *))resize;
    self->base.commonMsgHandlers.refresh = (void (*)(void *))refresh;
    self->text = malloc(sizeof(char) * LABEL_TEXT_MAXLEN);
    if (self->text == NULL) {
        LOG_ERROR("malloc failed for label text");
        return;
    }
    strncpy(self->text, text, LABEL_TEXT_MAXLEN);
    self->text[LABEL_TEXT_MAXLEN - 1] = '\0';
}

void controlLabelDraw(void *self) {
    ControlLabel *label = (ControlLabel *)self;
    werase(label->base.windowHandler);

    if (label->text != NULL) {
        mvwprintw(label->base.windowHandler, 0, 0, "%s", label->text);
    }

    wnoutrefresh(label->base.windowHandler);
}

static void controlLabelDestruct(void *self) {
    ControlLabel *label = (ControlLabel *)self;
    free(label->text);
}

static void controlLabelMsgHandler(void *self, TuiMsg msg) {
    ControlLabel *label = (ControlLabel *)self;
    switch (msg.type) {
    case MsgResize:
        if (label->base.commonMsgHandlers.resize != NULL) {
            label->base.commonMsgHandlers.resize(label);
        }
        break;
    case MsgRefresh:
        if (label->base.commonMsgHandlers.refresh != NULL) {
            label->base.commonMsgHandlers.refresh(label);
        }
        break;
    default:
        break;
    }
}

void controlInputBoxConstruct(ControlInputBox *self, int width, int y, int x,
                              void (*draw)(ControlInputBox *),
                              void (*resize)(ControlInputBox *self),
                              void (*submit)(ControlInputBox *self),
                              void (*refresh)(ControlInputBox *self)) {
    enum { InputBoxMinWidth = 3 };
    if (width < InputBoxMinWidth) {
        LOG_ERROR("InputBox width %d is less than minimum %d, clamping", width,
                  InputBoxMinWidth);
        width = InputBoxMinWidth;
    }
    controlConstruct((Control *)self, InputBoxMinWidth, width, y, x, true,
                     false);
    self->base.vtable = defaultInputBoxVtable;
    if (draw != NULL) {
        self->base.vtable.draw = (void (*)(void *))draw;
    }
    self->base.commonMsgHandlers.resize = (void (*)(void *))resize;
    self->base.commonMsgHandlers.refresh = (void (*)(void *))refresh;
    self->buf = malloc(sizeof(char) * INPUTBOX_BUF_MAX_LEN);
    if (self->buf == NULL) {
        LOG_ERROR("malloc failed for input box buffer");
        return;
    }
    self->curLen = 0;
    self->viewBegin = 0;
    self->curLoc = 0;
    self->submit = submit;
}

void controlInputBoxDraw(void *self) {
    ControlInputBox *box = (ControlInputBox *)self;
    werase(box->base.windowHandler);

    if (box->base.focused) {
        if (box->base.takeOverInput) {
            DOUBLE_BOX(box->base.windowHandler);
        } else {
            customBox(box->base.windowHandler, L"┊", L"┊", L"╌", L"╌", L"┌",
                      L"┐", L"└", L"┘");
        }
    } else {
        box(box->base.windowHandler, 0, 0);
    }

    if (box->buf != NULL) {
        for (size_t i = box->viewBegin;
             i <= box->viewBegin + (size_t)box->base.width - 3 &&
             i <= box->curLen;
             ++i) {
            int curX = 1 + (int)i - (int)box->viewBegin;
            if (i == box->curLoc) {
                mvwaddch(box->base.windowHandler, 1, curX,
                         (i == box->curLen ? ' ' : box->buf[i]) |
                             (box->base.focused ? A_REVERSE : 0));
            } else if (i < box->curLen) {
                mvwaddch(box->base.windowHandler, 1, curX, box->buf[i]);
            }
        }
    }

    wnoutrefresh(box->base.windowHandler);
}

static void controlInputBoxDestruct(void *self) {
    ControlInputBox *box = (ControlInputBox *)self;
    free(box->buf);
}

static void controlInputBoxMsgHandler(void *self, TuiMsg msg) {
    ControlInputBox *box = (ControlInputBox *)self;
    switch (msg.type) {
    case MsgResize:
        if (box->base.commonMsgHandlers.resize != NULL) {
            box->base.commonMsgHandlers.resize(box);
        }
        break;
    case MsgRefresh:
        if (box->base.commonMsgHandlers.refresh != NULL) {
            box->base.commonMsgHandlers.refresh(box);
        }
        break;
    case MsgFocusEnter:
        box->base.takeOverInput = true;
        break;
    case MsgInput: {
        switch (msg.arg1.input) {
        case '\n':
        case '\r':
        case KEY_ENTER:
            if (box->submit != NULL) {
                box->submit(box);
            }
            box->base.takeOverInput = false;
            break;
        case '\e':
            box->base.takeOverInput = false;
            break;
        case KEY_LEFT:
            if (box->curLoc > 0) {
                --box->curLoc;
            }
            break;
        case KEY_RIGHT:
            if (box->curLoc < box->curLen) {
                ++box->curLoc;
            }
            break;
        case KEY_UP:
        case KEY_HOME:
            box->curLoc = 0;
            break;
        case KEY_DOWN:
        case KEY_END:
            box->curLoc = box->curLen;
            break;
        default: {
            box->base.takeOverInput = true;
            if (msg.arg1.input == KEY_BACKSPACE) {
                if (box->curLoc > 0) {
                    if (box->curLoc < box->curLen) {
                        memmove(box->buf + box->curLoc - 1,
                                box->buf + box->curLoc,
                                box->curLen - box->curLoc);
                    }
                    --box->curLoc;
                    --box->curLen;
                }
            } else if (msg.arg1.input == KEY_DC) {
                if (box->curLoc < box->curLen) {
                    memmove(box->buf + box->curLoc, box->buf + box->curLoc + 1,
                            box->curLen - box->curLoc - 1);
                    --box->curLen;
                }
            } else {
                if (msg.arg1.input < ' ' || msg.arg1.input > '~') {
                    break;
                }
                if (box->curLen < INPUTBOX_BUF_MAX_LEN) {
                    if (box->curLoc == box->curLen) {
                        box->buf[box->curLoc] = (char)msg.arg1.input;
                        ++box->curLoc;
                    } else {
                        memmove(box->buf + box->curLoc + 1,
                                box->buf + box->curLoc,
                                box->curLen - box->curLoc);
                        box->buf[box->curLoc] = (char)msg.arg1.input;
                        ++box->curLoc;
                    }
                    ++box->curLen;
                }
            }
            break;
        }
        }
        break;
    }
    default:
        break;
    }
    if (box->curLoc >= ((size_t)box->base.width - 2) + box->viewBegin) {
        box->viewBegin = box->curLoc - ((size_t)box->base.width - 2) + 1;
    } else if (box->viewBegin > 0 && box->curLoc <= box->viewBegin) {
        box->viewBegin = box->curLoc > 0 ? box->curLoc - 1 : 0;
    }
}
