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
#include "clipboard.h"
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

static void controlTextBoxDestruct(void *self);
static void controlTextBoxMsgHandler(void *self, TuiMsg msg);
static size_t textBoxAdvanceVisualLine(const char *text, size_t textLen,
                                       size_t start, int availWidth,
                                       bool *isBreakOut);
static size_t textBoxCountVisualLines(const char *text, size_t textLen,
                                       int availWidth);

static const char *labelGetSelectableText(void *self, size_t *outLen);
static size_t labelCoordToByteOffset(void *self, int localY, int localX);

static const char *inputBoxGetSelectableText(void *self, size_t *outLen);
static size_t inputBoxCoordToByteOffset(void *self, int localY, int localX);

static const char *textBoxGetSelectableText(void *self, size_t *outLen);
static size_t textBoxCoordToByteOffset(void *self, int localY, int localX);

const static ControlVTable defaultCtrlVtable = {
    .destruct = NULL,
    .draw = NULL,
    .msgHandler = NULL,
    .getSelectableText = NULL,
    .coordToByteOffset = NULL};
const static ControlVTable defaultBtnVtable = {
    .destruct = controlButtonDestruct,
    .draw = controlButtonDraw,
    .msgHandler = controlButtonMsgHandler,
    .getSelectableText = NULL,
    .coordToByteOffset = NULL};
const static ControlVTable defaultGridVtable = {
    .destruct = NULL,
    .draw = controlGridDraw,
    .msgHandler = controlGridMsgHandler,
    .getSelectableText = NULL,
    .coordToByteOffset = NULL};
const static ControlVTable defaultLabelVtable = {
    .destruct = controlLabelDestruct,
    .draw = controlLabelDraw,
    .msgHandler = controlLabelMsgHandler,
    .getSelectableText = labelGetSelectableText,
    .coordToByteOffset = labelCoordToByteOffset};
const static ControlVTable defaultInputBoxVtable = {
    .destruct = controlInputBoxDestruct,
    .draw = controlInputBoxDraw,
    .msgHandler = controlInputBoxMsgHandler,
    .getSelectableText = inputBoxGetSelectableText,
    .coordToByteOffset = inputBoxCoordToByteOffset};
const static ControlVTable defaultTextBoxVtable = {
    .destruct = controlTextBoxDestruct,
    .draw = controlTextBoxDraw,
    .msgHandler = controlTextBoxMsgHandler,
    .getSelectableText = textBoxGetSelectableText,
    .coordToByteOffset = textBoxCoordToByteOffset};
const static ControlVTable defaultScrollTextBoxVtable = {
    .destruct = controlTextBoxDestruct,
    .draw = controlTextBoxDraw,
    .msgHandler = controlTextBoxMsgHandler,
    .getSelectableText = textBoxGetSelectableText,
    .coordToByteOffset = textBoxCoordToByteOffset};

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
            derwin(((Control *)parent)->windowHandler, self->height,
                   self->width, self->y, self->x);
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
    self->selection.active = false;
    self->selection.startByte = 0;
    self->selection.endByte = 0;
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

bool controlSelectionHandleMouse(Control *self, TuiMsg msg) {
    int input;
    size_t textLen;
    const char *text;

    if (self->vtable.getSelectableText == NULL ||
        self->vtable.coordToByteOffset == NULL) {
        return false;
    }

    text = self->vtable.getSelectableText(self, &textLen);
    if (text == NULL || textLen == 0) {
        return false;
    }

    if (self->windowHandler != NULL) {
        wmouse_trafo(self->windowHandler, &msg.mouseY, &msg.mouseX, FALSE);
    }

    input = msg.arg2.input;

    if ((input & BUTTON1_PRESSED) != 0) {
        self->selection.active = true;
        self->selection.startByte =
            self->vtable.coordToByteOffset(self, msg.mouseY, msg.mouseX);
        self->selection.endByte = self->selection.startByte;
        return true;
    }

    if (input == REPORT_MOUSE_POSITION && self->selection.active) {
        self->selection.endByte =
            self->vtable.coordToByteOffset(self, msg.mouseY, msg.mouseX);
        return true;
    }

    if ((input & BUTTON1_RELEASED) != 0 && self->selection.active) {
        size_t selStart;
        size_t selEnd;

        self->selection.endByte =
            self->vtable.coordToByteOffset(self, msg.mouseY, msg.mouseX);

        selStart = self->selection.startByte;
        selEnd = self->selection.endByte;
        if (selStart > selEnd) {
            size_t tmp = selStart;
            selStart = selEnd;
            selEnd = tmp;
        }

        if (selEnd > selStart && selEnd <= textLen) {
            char *selected = malloc(selEnd - selStart + 1);
            if (selected != NULL) {
                memcpy(selected, text + selStart, selEnd - selStart);
                selected[selEnd - selStart] = '\0';
                clipboardCopy(selected);
                free(selected);
            }
        }

        self->selection.active = false;
        return true;
    }

    return false;
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
    case MsgMouse:
        if ((msg.arg2.input & BUTTON1_CLICKED) != 0 &&
            btn->onClick != NULL) {
            btn->onClick(btn);
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

// maxWidth == 0 to use inital text length
void controlLabelConstruct(ControlLabel *self, const char *text,
                           size_t maxWidth, int y, int x,
                           void (*draw)(ControlLabel *),
                           void (*resize)(ControlLabel *self),
                           void (*refresh)(ControlLabel *self)) {
    size_t len = strlen(text);
    controlConstruct((Control *)self, 1, (maxWidth == 0 ? len : maxWidth), y, x,
                     false, false);
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
        size_t textLen = strlen(label->text);
        if (label->base.selection.active && textLen > 0) {
            size_t selStart = label->base.selection.startByte;
            size_t selEnd = label->base.selection.endByte;

            if (selStart > selEnd) {
                size_t tmp = selStart;
                selStart = selEnd;
                selEnd = tmp;
            }
            if (selEnd > textLen) {
                selEnd = textLen;
            }
            if (selStart > textLen) {
                selStart = textLen;
            }

            if (selStart > 0) {
                mvwprintw(label->base.windowHandler, 0, 0, "%.*s",
                          (int)selStart, label->text);
            }
            if (selEnd > selStart) {
                wattron(label->base.windowHandler, A_REVERSE);
                mvwprintw(label->base.windowHandler, 0, (int)selStart, "%.*s",
                          (int)(selEnd - selStart), label->text + selStart);
                wattroff(label->base.windowHandler, A_REVERSE);
            }
            if (selEnd < textLen) {
                mvwprintw(label->base.windowHandler, 0, (int)selEnd, "%.*s",
                          (int)(textLen - selEnd), label->text + selEnd);
            }
        } else {
            mvwprintw(label->base.windowHandler, 0, 0, "%s", label->text);
        }
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
    case MsgMouse:
        controlSelectionHandleMouse((Control *)label, msg);
        break;
    default:
        break;
    }
}

static const char *labelGetSelectableText(void *self, size_t *outLen) {
    ControlLabel *label = (ControlLabel *)self;
    if (label->text == NULL) {
        *outLen = 0;
        return NULL;
    }
    *outLen = strlen(label->text);
    return label->text;
}

static size_t labelCoordToByteOffset(void *self, int localY, int localX) {
    ControlLabel *label = (ControlLabel *)self;
    size_t textLen;
    size_t offset;
    (void)localY;

    if (label->text == NULL) {
        return 0;
    }
    textLen = strlen(label->text);
    if (localX < 0) {
        return 0;
    }
    offset = (size_t)localX;
    return (offset > textLen) ? textLen : offset;
}

void controlInputBoxConstruct(ControlInputBox *self, int width, int y, int x,
                              bool hideContent, void (*draw)(ControlInputBox *),
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
    self->hideContent = hideContent;
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
        size_t selStart = box->base.selection.startByte;
        size_t selEnd = box->base.selection.endByte;
        if (selStart > selEnd) {
            size_t tmp = selStart;
            selStart = selEnd;
            selEnd = tmp;
        }

        for (size_t i = box->viewBegin;
             i <= box->viewBegin + (size_t)box->base.width - 3 &&
             i <= box->curLen;
             ++i) {
            int curX = 1 + (int)i - (int)box->viewBegin;
            char dest = box->hideContent ? '*' : box->buf[i];
            attr_t attr = 0;

            if (i == box->curLoc && box->base.focused) {
                attr |= A_REVERSE;
            }
            if (box->base.selection.active && i >= selStart && i < selEnd) {
                attr |= A_REVERSE;
            }

            if (i == box->curLoc) {
                mvwaddch(box->base.windowHandler, 1, curX,
                         (chtype)(i == box->curLen ? ' ' : dest) | attr);
            } else if (i < box->curLen) {
                mvwaddch(box->base.windowHandler, 1, curX, (chtype)dest | attr);
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
    case MsgMouse:
        controlSelectionHandleMouse((Control *)box, msg);
        break;
    default:
        break;
    }
    if (box->curLoc >= ((size_t)box->base.width - 2) + box->viewBegin) {
        box->viewBegin = box->curLoc - ((size_t)box->base.width - 2) + 1;
    } else if (box->viewBegin > 0 && box->curLoc <= box->viewBegin) {
        box->viewBegin = box->curLoc > 0 ? box->curLoc - 1 : 0;
    }
}

static const char *inputBoxGetSelectableText(void *self, size_t *outLen) {
    ControlInputBox *box = (ControlInputBox *)self;
    if (box->buf == NULL || box->hideContent) {
        *outLen = 0;
        return NULL;
    }
    *outLen = box->curLen;
    return box->buf;
}

static size_t inputBoxCoordToByteOffset(void *self, int localY, int localX) {
    ControlInputBox *box = (ControlInputBox *)self;
    size_t offset;
    (void)localY;

    if (localX <= 1) {
        return box->viewBegin;
    }
    offset = box->viewBegin + (size_t)(localX - 1);
    return (offset > box->curLen) ? box->curLen : offset;
}

void controlTextBoxConstruct(ControlTextBox *self, int height, int width,
                             int y, int x, const char *text,
                             void (*draw)(ControlTextBox *),
                             void (*resize)(ControlTextBox *self),
                             void (*refresh)(ControlTextBox *self)) {
    enum { TextBoxMinHeight = 3, TextBoxMinWidth = 3 };
    if (height < TextBoxMinHeight) {
        height = TextBoxMinHeight;
    }
    if (width < TextBoxMinWidth) {
        width = TextBoxMinWidth;
    }
    controlConstruct((Control *)self, height, width, y, x, true, false);
    self->base.vtable = defaultTextBoxVtable;
    if (draw != NULL) {
        self->base.vtable.draw = (void (*)(void *))draw;
    }
    self->base.commonMsgHandlers.resize = (void (*)(void *))resize;
    self->base.commonMsgHandlers.refresh = (void (*)(void *))refresh;
    self->text = malloc(sizeof(char) * TEXTBOX_TEXT_MAXLEN);
    if (self->text == NULL) {
        LOG_ERROR("malloc failed for text box text");
        return;
    }
    strncpy(self->text, text, TEXTBOX_TEXT_MAXLEN);
    self->text[TEXTBOX_TEXT_MAXLEN - 1] = '\0';
    self->textLen = strlen(self->text);
    self->viewBegin = 0;
}

static const char *textBoxGetSelectableText(void *self, size_t *outLen) {
    ControlTextBox *box = (ControlTextBox *)self;
    if (box->text == NULL) {
        *outLen = 0;
        return NULL;
    }
    *outLen = box->textLen;
    return box->text;
}

static size_t textBoxAdvanceVisualLine(const char *text, size_t textLen,
                                       size_t start, int availWidth,
                                       bool *isBreakOut) {
    *isBreakOut = false;
    if (start >= textLen) {
        return textLen;
    }
    if (text[start] == '\n') {
        return start + 1;
    }

    size_t logicalEnd = start;
    while (logicalEnd < textLen && text[logicalEnd] != '\n') {
        logicalEnd++;
    }
    size_t logicalLen = logicalEnd - start;

    if (logicalLen <= (size_t)availWidth) {
        return (logicalEnd < textLen) ? logicalEnd + 1 : logicalEnd;
    }

    size_t maxPos = start + (size_t)availWidth;
    if (maxPos > logicalEnd) {
        maxPos = logicalEnd;
    }
    size_t bp = maxPos;
    while (bp > start && text[bp - 1] != ' ') {
        bp--;
    }

    if (bp > start) {
        *isBreakOut = true;
        return bp;
    }
    return start + (size_t)availWidth;
}

static size_t textBoxCountVisualLines(const char *text, size_t textLen,
                                      int availWidth) {
    size_t offset = 0;
    size_t count = 0;
    bool unused;
    while (offset < textLen) {
        offset = textBoxAdvanceVisualLine(text, textLen, offset, availWidth,
                                          &unused);
        count++;
    }
    return count;
}

static bool textBoxGetVisualLineRange(const ControlTextBox *box,
                                      size_t visualLineIdx, size_t *outStart,
                                      size_t *outEnd) {
    int availWidth = box->base.width - 2;
    size_t offset;
    bool isContinuation;
    size_t curLine;
    size_t renderStart;

    if (availWidth < 1 || box->text == NULL) {
        return false;
    }

    offset = 0;
    isContinuation = false;
    curLine = 0;

    while (curLine < visualLineIdx && offset < box->textLen) {
        offset = textBoxAdvanceVisualLine(box->text, box->textLen, offset,
                                          availWidth, &isContinuation);
        curLine++;
    }

    if (offset >= box->textLen) {
        return false;
    }

    renderStart = offset;
    if (isContinuation) {
        while (renderStart < box->textLen && box->text[renderStart] == ' ') {
            renderStart++;
        }
    }

    offset = textBoxAdvanceVisualLine(box->text, box->textLen, offset,
                                      availWidth, &isContinuation);

    *outEnd = offset;
    if (*outEnd > renderStart && box->text[*outEnd - 1] == '\n') {
        (*outEnd)--;
    }
    while (*outEnd > renderStart && box->text[*outEnd - 1] == ' ') {
        (*outEnd)--;
    }

    *outStart = renderStart;
    return true;
}

static size_t textBoxCoordToByteOffset(void *self, int localY, int localX) {
    ControlTextBox *box = (ControlTextBox *)self;
    int availWidth;
    int visibleLines;
    size_t visualLineIdx;
    size_t lineStart;
    size_t lineEnd;
    size_t charOff;
    size_t result;

    availWidth = box->base.width - 2;
    visibleLines = box->base.height - 2;
    if (availWidth < 1 || visibleLines < 1 || box->text == NULL ||
        box->textLen == 0) {
        return 0;
    }

    if (localY < 1) {
        localY = 1;
    }

    visualLineIdx = box->viewBegin + (size_t)(localY - 1);

    if (!textBoxGetVisualLineRange(box, visualLineIdx, &lineStart, &lineEnd)) {
        return box->textLen;
    }

    if (localX < 1) {
        return lineStart;
    }

    charOff = (size_t)(localX - 1);
    result = lineStart + charOff;
    if (result > lineEnd) {
        result = lineEnd;
    }
    return result;
}

void controlTextBoxDraw(void *self) {
    ControlTextBox *box = (ControlTextBox *)self;
    werase(box->base.windowHandler);

    if (box->base.focused) {
        DOUBLE_BOX(box->base.windowHandler);
    } else {
        box(box->base.windowHandler, 0, 0);
    }

    int availWidth = box->base.width - 2;
    int visibleLines = box->base.height - 2;
    if (availWidth < 1 || visibleLines < 1 || box->text == NULL) {
        wnoutrefresh(box->base.windowHandler);
        return;
    }

    size_t offset = 0;
    bool isContinuation = false;
    size_t visualLine = 0;

    while (visualLine < box->viewBegin && offset < box->textLen) {
        offset = textBoxAdvanceVisualLine(box->text, box->textLen, offset,
                                          availWidth, &isContinuation);
        visualLine++;
    }

    int curY = 1;
    while (curY <= visibleLines && offset < box->textLen) {
        size_t renderStart = offset;
        if (isContinuation) {
            while (renderStart < box->textLen &&
                   box->text[renderStart] == ' ') {
                renderStart++;
            }
        }

        offset = textBoxAdvanceVisualLine(box->text, box->textLen, offset,
                                          availWidth, &isContinuation);

        size_t end = offset;
        if (end > renderStart && box->text[end - 1] == '\n') {
            end--;
        }
        while (end > renderStart && box->text[end - 1] == ' ') {
            end--;
        }

        if (end <= renderStart) {
            curY++;
            continue;
        }

        if (box->base.selection.active) {
            size_t selStart = box->base.selection.startByte;
            size_t selEnd = box->base.selection.endByte;

            if (selStart > selEnd) {
                size_t tmp = selStart;
                selStart = selEnd;
                selEnd = tmp;
            }

            if (selEnd > renderStart && selStart < end) {
                size_t hlStart;
                size_t hlEnd;

                hlStart = (selStart > renderStart) ? selStart : renderStart;
                hlEnd = (selEnd < end) ? selEnd : end;

                if (hlStart > renderStart) {
                    mvwprintw(box->base.windowHandler, curY, 1, "%.*s",
                              (int)(hlStart - renderStart),
                              box->text + renderStart);
                }
                wattron(box->base.windowHandler, A_REVERSE);
                mvwprintw(box->base.windowHandler,
                          curY, 1 + (int)(hlStart - renderStart), "%.*s",
                          (int)(hlEnd - hlStart), box->text + hlStart);
                wattroff(box->base.windowHandler, A_REVERSE);
                if (hlEnd < end) {
                    mvwprintw(box->base.windowHandler,
                              curY, 1 + (int)(hlEnd - renderStart), "%.*s",
                              (int)(end - hlEnd), box->text + hlEnd);
                }
            } else {
                mvwprintw(box->base.windowHandler, curY, 1, "%.*s",
                          (int)(end - renderStart), box->text + renderStart);
            }
        } else {
            mvwprintw(box->base.windowHandler, curY, 1, "%.*s",
                      (int)(end - renderStart), box->text + renderStart);
        }
        curY++;
    }

    wnoutrefresh(box->base.windowHandler);
}

static void controlTextBoxDestruct(void *self) {
    ControlTextBox *box = (ControlTextBox *)self;
    free(box->text);
}

static void controlTextBoxMsgHandler(void *self, TuiMsg msg) {
    ControlTextBox *box = (ControlTextBox *)self;
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
        box->base.focused = true;
        break;
    case MsgFocusLeave:
        box->base.focused = false;
        break;
    case MsgInput: {
        int availWidth = box->base.width - 2;
        int visibleLines = box->base.height - 2;
        if (availWidth < 1 || visibleLines < 1 || box->text == NULL) {
            break;
        }
        size_t totalLines = textBoxCountVisualLines(box->text, box->textLen,
                                                     availWidth);
        size_t maxView = (totalLines > (size_t)visibleLines)
                             ? totalLines - (size_t)visibleLines
                             : 0;
        switch (msg.arg1.input) {
        case KEY_UP:
            if (box->viewBegin > 0) {
                box->viewBegin--;
            }
            break;
        case KEY_DOWN:
            if (box->viewBegin < maxView) {
                box->viewBegin++;
            }
            break;
        case KEY_PPAGE:
            if (box->viewBegin > (size_t)visibleLines) {
                box->viewBegin -= (size_t)visibleLines;
            } else {
                box->viewBegin = 0;
            }
            break;
        case KEY_NPAGE:
            if (box->viewBegin + (size_t)visibleLines < maxView) {
                box->viewBegin += (size_t)visibleLines;
            } else {
                box->viewBegin = maxView;
            }
            break;
        case KEY_HOME:
            box->viewBegin = 0;
            break;
        case KEY_END:
            box->viewBegin = maxView;
            break;
        }
        break;
    }
    case MsgMouse: {
        int availWidth = box->base.width - 2;
        int visibleLines = box->base.height - 2;
        int input;

        if (availWidth < 1 || visibleLines < 1 || box->text == NULL) {
            break;
        }

        if (controlSelectionHandleMouse((Control *)box, msg)) {
            break;
        }

        input = msg.arg2.input;
        if (input == BUTTON4_PRESSED || input == BUTTON5_PRESSED) {
            size_t totalLines = textBoxCountVisualLines(box->text, box->textLen,
                                                         availWidth);
            size_t maxView = (totalLines > (size_t)visibleLines)
                                 ? totalLines - (size_t)visibleLines
                                 : 0;
            if (input == BUTTON4_PRESSED) {
                if (box->viewBegin > 0) {
                    box->viewBegin--;
                }
            } else {
                if (box->viewBegin < maxView) {
                    box->viewBegin++;
                }
            }
        }
        break;
    }
    default:
        break;
    }
}

void controlScrollTextBoxConstruct(ControlScrollTextBox *self, int height,
                                   int width, int y, int x, size_t maxLines,
                                   void (*draw)(ControlScrollTextBox *),
                                   void (*resize)(ControlScrollTextBox *self),
                                   void (*refresh)(ControlScrollTextBox *self)) {
    enum {
        ScrollTextBoxMinHeight = 3,
        ScrollTextBoxMinWidth = 3
    };
    if (height < ScrollTextBoxMinHeight) {
        height = ScrollTextBoxMinHeight;
    }
    if (width < ScrollTextBoxMinWidth) {
        width = ScrollTextBoxMinWidth;
    }
    controlConstruct((Control *)self, height, width, y, x, true, false);
    self->base.base.vtable = defaultScrollTextBoxVtable;
    if (draw != NULL) {
        self->base.base.vtable.draw = (void (*)(void *))draw;
    }
    self->base.base.commonMsgHandlers.resize = (void (*)(void *))resize;
    self->base.base.commonMsgHandlers.refresh = (void (*)(void *))refresh;
    self->base.text = malloc(sizeof(char) * SCROLLTEXTBOX_TEXT_MAXLEN);
    if (self->base.text == NULL) {
        LOG_ERROR("malloc failed for scroll text box text");
        return;
    }
    self->base.text[0] = '\0';
    self->base.textLen = 0;
    self->base.viewBegin = 0;
    self->maxLines =
        (maxLines > 0) ? maxLines : SCROLLTEXTBOX_DEFAULT_MAX_LINES;
}

void controlScrollTextBoxAppend(ControlScrollTextBox *self, const char *text) {
    ControlTextBox *box = &self->base;
    size_t appendLen;

    if (text == NULL || text[0] == '\0') {
        return;
    }

    appendLen = strlen(text);

    while (box->textLen + appendLen >= SCROLLTEXTBOX_TEXT_MAXLEN &&
           box->textLen > 0) {
        const char *nl = memchr(box->text, '\n', box->textLen);
        if (nl != NULL) {
            size_t trimLen = (size_t)(nl - box->text) + 1;
            size_t remaining = box->textLen - trimLen;
            memmove(box->text, box->text + trimLen, remaining);
            box->textLen = remaining;
            box->text[box->textLen] = '\0';
        } else {
            box->textLen = 0;
            box->text[0] = '\0';
            break;
        }
    }

    {
        size_t spaceLeft = SCROLLTEXTBOX_TEXT_MAXLEN - box->textLen - 1;
        if (spaceLeft == 0) {
            return;
        }
        if (appendLen > spaceLeft) {
            appendLen = spaceLeft;
        }
    }

    memcpy(box->text + box->textLen, text, appendLen);
    box->textLen += appendLen;
    box->text[box->textLen] = '\0';

    {
        size_t lineCount = 0;
        const char *p = box->text;
        const char *end = box->text + box->textLen;
        while (p < end) {
            if (*p == '\n') {
                lineCount++;
            }
            p++;
        }
        if (box->textLen > 0 && box->text[box->textLen - 1] != '\n') {
            lineCount++;
        }

        while (lineCount > self->maxLines && box->textLen > 0) {
            const char *nl = memchr(box->text, '\n', box->textLen);
            if (nl != NULL) {
                size_t trimLen = (size_t)(nl - box->text) + 1;
                size_t remaining = box->textLen - trimLen;
                memmove(box->text, box->text + trimLen, remaining);
                box->textLen = remaining;
                box->text[box->textLen] = '\0';
            } else {
                box->textLen = 0;
                box->text[0] = '\0';
                break;
            }
            lineCount--;
        }
    }

    if (box->base.windowHandler != NULL) {
        int availWidth = box->base.width - 2;
        int visibleLines = box->base.height - 2;
        if (availWidth >= 1 && visibleLines >= 1) {
            size_t totalLines =
                textBoxCountVisualLines(box->text, box->textLen, availWidth);
            size_t maxView = (totalLines > (size_t)visibleLines)
                                 ? totalLines - (size_t)visibleLines
                                 : 0;
            box->viewBegin = maxView;
        }
        controlTextBoxDraw(box);
    }
}
