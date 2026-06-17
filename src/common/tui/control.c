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
#include "utils.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

static void controlPageMsgHandler(ControlPage *self, TuiMsg msg);
static void controlPageRefreshChild(ControlPage *self, Control *child);

static void controlButtonDestruct(ControlButton *self);
static void controlButtonMsgHandler(ControlButton *self, TuiMsg msg);

static void controlGridMsgHandler(ControlGrid *self, TuiMsg msg);
static void controlGridLayout(ControlGrid *self, Control *child);

static void controlLabelDestruct(ControlLabel *self);
static void controlLabelMsgHandler(ControlLabel *self, TuiMsg msg);

static void controlInputBoxDestruct(ControlInputBox *self);
static void controlInputBoxMsgHandler(ControlInputBox *self, TuiMsg msg);

static void controlTextBoxDestruct(ControlTextBox *self);
static void controlTextBoxMsgHandler(ControlTextBox *self, TuiMsg msg);
static size_t textBoxAdvanceVisualLine(const char *text, size_t textLen,
                                       size_t start, int availWidth,
                                       bool *isBreakOut);
static size_t textBoxCountVisualLines(const char *text, size_t textLen,
                                      int availWidth);

static const char *labelGetSelectableText(ControlLabel *self, size_t *outLen);
static size_t labelCoordToByteOffset(ControlLabel *self, int localY,
                                     int localX);

static const char *inputBoxGetSelectableText(ControlInputBox *self,
                                             size_t *outLen);
static size_t inputBoxCoordToByteOffset(ControlInputBox *self, int localY,
                                        int localX);

static const char *textBoxGetSelectableText(ControlTextBox *self,
                                            size_t *outLen);
static size_t textBoxCoordToByteOffset(ControlTextBox *self, int localY,
                                       int localX);

static void controlListBoxDestruct(ControlListBox *self);
static void controlListBoxMsgHandler(ControlListBox *self, TuiMsg msg);

const static ControlVTable defaultCtrlVtable = {.destruct = NULL,
                                                .draw = NULL,
                                                .msgHandler = NULL,
                                                .getSelectableText = NULL,
                                                .coordToByteOffset = NULL};
const static ControlVTable defaultBtnVtable = {
    .destruct = (void (*)(Control *))controlButtonDestruct,
    .draw = (void (*)(Control *))controlButtonDraw,
    .update = NULL,
    .msgHandler = (void (*)(Control *, TuiMsg))controlButtonMsgHandler,
    .getSelectableText = NULL,
    .coordToByteOffset = NULL};
const static ControlVTable defaultGridVtable = {
    .destruct = NULL,
    .draw = (void (*)(Control *))controlGridDraw,
    .update = NULL,
    .msgHandler = (void (*)(Control *, TuiMsg))controlGridMsgHandler,
    .getSelectableText = NULL,
    .coordToByteOffset = NULL};
const static ControlVTable defaultLabelVtable = {
    .destruct = (void (*)(Control *))controlLabelDestruct,
    .draw = (void (*)(Control *))controlLabelDraw,
    .update = NULL,
    .msgHandler = (void (*)(Control *, TuiMsg))controlLabelMsgHandler,
    .getSelectableText =
        (const char *(*)(Control *, size_t *))labelGetSelectableText,
    .coordToByteOffset =
        (size_t (*)(Control *, int, int))labelCoordToByteOffset};
const static ControlVTable defaultInputBoxVtable = {
    .destruct = (void (*)(Control *))controlInputBoxDestruct,
    .draw = (void (*)(Control *))controlInputBoxDraw,
    .update = NULL,
    .msgHandler = (void (*)(Control *, TuiMsg))controlInputBoxMsgHandler,
    .getSelectableText =
        (const char *(*)(Control *, size_t *))inputBoxGetSelectableText,
    .coordToByteOffset =
        (size_t (*)(Control *, int, int))inputBoxCoordToByteOffset};
const static ControlVTable defaultTextBoxVtable = {
    .destruct = (void (*)(Control *))controlTextBoxDestruct,
    .draw = (void (*)(Control *))controlTextBoxDraw,
    .update = NULL,
    .msgHandler = (void (*)(Control *, TuiMsg))controlTextBoxMsgHandler,
    .getSelectableText =
        (const char *(*)(Control *, size_t *))textBoxGetSelectableText,
    .coordToByteOffset =
        (size_t (*)(Control *, int, int))textBoxCoordToByteOffset};
const static ControlVTable defaultScrollTextBoxVtable = {
    .destruct = (void (*)(Control *))controlTextBoxDestruct,
    .draw = (void (*)(Control *))controlTextBoxDraw,
    .update = NULL,
    .msgHandler = (void (*)(Control *, TuiMsg))controlTextBoxMsgHandler,
    .getSelectableText =
        (const char *(*)(Control *, size_t *))textBoxGetSelectableText,
    .coordToByteOffset =
        (size_t (*)(Control *, int, int))textBoxCoordToByteOffset};

const static ControlVTable defaultListBoxVtable = {
    .destruct = (void (*)(Control *))controlListBoxDestruct,
    .draw = (void (*)(Control *))controlListBoxDraw,
    .update = NULL,
    .msgHandler = (void (*)(Control *, TuiMsg))controlListBoxMsgHandler,
    .getSelectableText = NULL,
    .coordToByteOffset = NULL};

void customBox(WINDOW *handler, const wchar_t *lsRaw, const wchar_t *rsRaw,
               const wchar_t *tsRaw, const wchar_t *bsRaw, const wchar_t *tlRaw,
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
        self->windowHandler = derwin(pViewArea->windowHandler, self->height,
                                     self->width, self->y, self->x);
    } else {
        // If parent is a derived structure, it also works. Because the base
        // member is always at the first in derived structure.
        // Failed to fetch handler when the control exceeds the bound of parent
        self->windowHandler =
            derwin(((Control *)parent)->windowHandler, self->height,
                   self->width, self->y, self->x);
    }
}

void controlDeinstantiate(Control *self) {
    delwin(self->windowHandler);
    self->windowHandler = NULL;
}

void controlConstruct(Control *self, int height, int width, int y, int x,
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

static void controlPageMsgHandler(Control *self, TuiMsg msg) {
    ControlPage *page = (ControlPage *)self;
    switch (msg.type) {
    case MsgResize:
    case MsgRefresh:
        controlDeinstantiate(self);
        controlInstantiate(self, NULL);
        tuiAppPushMessage((TuiMsg){
            .type = MsgFetch,
            .arg1 = {.index = page->index},
            .arg2 = {.fetchRecv = (void (*)(
                         Control *, Control *))controlPageRefreshChild}});
        break;
    default:
        break;
    }
}

static void controlPageRefreshChild(ControlPage *self, Control *child) {
    controlDeinstantiate((Control *)child);
    controlInstantiate((Control *)child, (Control *)self);
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
                            void (*draw)(ControlButton *self),
                            void (*onClick)(ControlButton *self),
                            void (*resize)(ControlButton *self),
                            void (*refresh)(ControlButton *self),
                            void (*update)(ControlButton *self)) {
    controlConstruct((Control *)self, height, width, y, x, true, false);
    self->base.vtable = defaultBtnVtable;
    if (draw != NULL) {
        self->base.vtable.draw = (void (*)(Control *))draw;
    }
    if (update != NULL) {
        self->base.vtable.update = (void (*)(Control *))update;
    }
    self->onClick = onClick;
    self->base.commonMsgHandlers.resize = (void (*)(Control *))resize;
    self->base.commonMsgHandlers.refresh = (void (*)(Control *))refresh;
    self->text = malloc(sizeof(char) * BTN_LABEL_MAXLEN);
    if (self->text == NULL) {
        LOG_ERROR("malloc failed for button text");
        return;
    }
    strncpy(self->text, text, BTN_LABEL_MAXLEN);
    self->text[BTN_LABEL_MAXLEN - 1] = '\0';
}

static void controlButtonDestruct(ControlButton *self) { free(self->text); }

void controlButtonDraw(ControlButton *self) {
    werase(self->base.windowHandler);

    if (self->base.focused) {
        DOUBLE_BOX(self->base.windowHandler);
    } else {
        box(self->base.windowHandler, 0, 0);
    }

    if (self->text != NULL) {
        size_t textLen = strlen(self->text);
        mvwprintw(self->base.windowHandler, self->base.height / 2,
                  self->base.width / 2 - textLen / 2, "%s", self->text);
    }

    wnoutrefresh(self->base.windowHandler);
}

static void controlButtonMsgHandler(ControlButton *self, TuiMsg msg) {
    switch (msg.type) {
    case MsgInput: {
        if ((msg.arg1.input == '\n' || msg.arg1.input == '\r' ||
             msg.arg1.input == KEY_ENTER) &&
            self->onClick != NULL) {
            self->onClick(self);
        }
        break;
    }
    case MsgRefresh:
        if (self->base.commonMsgHandlers.refresh != NULL) {
            self->base.commonMsgHandlers.refresh((Control *)self);
        }
        break;
    case MsgResize:
        if (self->base.commonMsgHandlers.resize != NULL) {
            self->base.commonMsgHandlers.resize((Control *)self);
        }
        break;
    case MsgMouse:
        if ((msg.arg2.input & BUTTON1_CLICKED) != 0 && self->onClick != NULL) {
            self->onClick(self);
        }
        break;
    default:
        break;
    }
}

void controlGridConstruct(ControlGrid *self, int height, int width, int y,
                          int x, GridLayoutMethod layoutMethod, size_t hmargin,
                          size_t vmargin, void (*draw)(ControlGrid *self),
                          void (*resize)(ControlGrid *self),
                          void (*refresh)(ControlGrid *self),
                          void (*update)(ControlGrid *self),
                          void (*layout)(ControlGrid *self, Control *child)) {
    controlConstruct((Control *)self, height, width, y, x, false, true);
    self->base.vtable = defaultGridVtable;
    self->layoutMethod = layoutMethod;
    self->margin.horizontal = hmargin;
    self->margin.vertical = vmargin;
    self->layoutCounter = 0;
    self->layoutAccCol = 0;
    self->layoutAccRow = 0;
    if (draw != NULL) {
        self->base.vtable.draw = (void (*)(Control *))draw;
    }
    if (update != NULL) {
        self->base.vtable.update = (void (*)(Control *))update;
    }
    self->base.commonMsgHandlers.resize = (void (*)(Control *))resize;
    self->base.commonMsgHandlers.refresh = (void (*)(Control *))refresh;
    if (layout != NULL) {
        self->layout = layout;
    } else {
        self->layout = controlGridLayout;
    }
}

void controlGridDraw(ControlGrid *self) {
    werase(self->base.windowHandler);

    box(self->base.windowHandler, 0, 0);

    wnoutrefresh(self->base.windowHandler);
}

static void controlGridMsgHandler(ControlGrid *self, TuiMsg msg) {
    switch (msg.type) {
    case MsgRefresh:
        if (self->base.commonMsgHandlers.refresh != NULL) {
            self->base.commonMsgHandlers.refresh((Control *)self);
        }
        break;
    case MsgResize:
        if (self->base.commonMsgHandlers.resize != NULL) {
            self->base.commonMsgHandlers.resize((Control *)self);
        }
        tuiAppPushMessage((TuiMsg){
            .type = MsgFetch,
            .arg1 = {.index = self->base.index},
            .arg2 = {.fetchRecv =
                         (void (*)(Control *, Control *))self->layout}});
        break;
    default:
        break;
    }
}

static void controlGridLayout(ControlGrid *self, Control *child) {
    Control *ch = (Control *)child;
    if (self->layoutCounter == 0) {
        self->layoutAccCol = self->margin.horizontal;
        self->layoutAccRow = self->margin.vertical;
    }
    switch (self->layoutMethod) {
    case LayoutHorizontal: {
        if (self->layoutAccCol + ch->width >
            (size_t)self->base.width - self->margin.horizontal) {
            self->layoutAccCol = self->margin.horizontal;
            self->layoutAccRow += self->margin.vertical + ch->height;
        }
        ch->x = (int)self->layoutAccCol;
        ch->y = (int)self->layoutAccRow;
        self->layoutAccCol += (size_t)ch->width;
        break;
    }
    case LayoutVertical: {
        if (self->layoutAccRow + ch->height >
            (size_t)self->base.height - self->margin.vertical) {
            self->layoutAccRow = self->margin.vertical;
            self->layoutAccCol += self->margin.horizontal + ch->width;
        }
        ch->x = (int)self->layoutAccCol;
        ch->y = (int)self->layoutAccRow;
        self->layoutAccRow += (size_t)ch->height;
        break;
    }
    default:
        break;
    }
    controlDeinstantiate(ch);
    controlInstantiate(ch, (Control *)self);
    if (self->base.childCount > 0) {
        self->layoutCounter = (self->layoutCounter + 1) % self->base.childCount;
    }
}

// maxWidth == 0 to use inital text length
void controlLabelConstruct(ControlLabel *self, const char *text,
                           size_t maxWidth, int y, int x,
                           void (*draw)(ControlLabel *self),
                           void (*resize)(ControlLabel *self),
                           void (*refresh)(ControlLabel *self),
                           void (*update)(ControlLabel *self)) {
    size_t len = strlen(text);
    controlConstruct((Control *)self, 1, (maxWidth == 0 ? len : maxWidth), y, x,
                     false, false);
    self->base.vtable = defaultLabelVtable;
    if (draw != NULL) {
        self->base.vtable.draw = (void (*)(Control *))draw;
    }
    if (update != NULL) {
        self->base.vtable.update = (void (*)(Control *))update;
    }
    self->base.commonMsgHandlers.resize = (void (*)(Control *))resize;
    self->base.commonMsgHandlers.refresh = (void (*)(Control *))refresh;
    self->text = malloc(sizeof(char) * LABEL_TEXT_MAXLEN);
    if (self->text == NULL) {
        LOG_ERROR("malloc failed for self text");
        return;
    }
    strncpy(self->text, text, LABEL_TEXT_MAXLEN);
    self->text[LABEL_TEXT_MAXLEN - 1] = '\0';
}

void controlLabelDraw(ControlLabel *self) {
    werase(self->base.windowHandler);

    if (self->text != NULL) {
        size_t textLen = strlen(self->text);
        if (self->base.selection.active && textLen > 0) {
            size_t selStart = self->base.selection.startByte;
            size_t selEnd = self->base.selection.endByte;

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
                mvwprintw(self->base.windowHandler, 0, 0, "%.*s", (int)selStart,
                          self->text);
            }
            if (selEnd > selStart) {
                wattron(self->base.windowHandler, A_REVERSE);
                mvwprintw(self->base.windowHandler, 0, (int)selStart, "%.*s",
                          (int)(selEnd - selStart), self->text + selStart);
                wattroff(self->base.windowHandler, A_REVERSE);
            }
            if (selEnd < textLen) {
                mvwprintw(self->base.windowHandler, 0, (int)selEnd, "%.*s",
                          (int)(textLen - selEnd), self->text + selEnd);
            }
        } else {
            mvwprintw(self->base.windowHandler, 0, 0, "%s", self->text);
        }
    }

    wnoutrefresh(self->base.windowHandler);
}

static void controlLabelDestruct(ControlLabel *self) { free(self->text); }

static void controlLabelMsgHandler(ControlLabel *self, TuiMsg msg) {
    switch (msg.type) {
    case MsgResize:
        if (self->base.commonMsgHandlers.resize != NULL) {
            self->base.commonMsgHandlers.resize((Control *)self);
        }
        break;
    case MsgRefresh:
        if (self->base.commonMsgHandlers.refresh != NULL) {
            self->base.commonMsgHandlers.refresh((Control *)self);
        }
        break;
    case MsgMouse:
        controlSelectionHandleMouse((Control *)self, msg);
        break;
    default:
        break;
    }
}

static const char *labelGetSelectableText(ControlLabel *self, size_t *outLen) {
    if (self->text == NULL) {
        *outLen = 0;
        return NULL;
    }
    *outLen = strlen(self->text);
    return self->text;
}

static size_t labelCoordToByteOffset(ControlLabel *self, int localY,
                                     int localX) {
    size_t textLen;
    size_t offset;
    (void)localY;

    if (self->text == NULL) {
        return 0;
    }
    textLen = strlen(self->text);
    if (localX < 0) {
        return 0;
    }
    offset = (size_t)localX;
    return (offset > textLen) ? textLen : offset;
}

void controlInputBoxConstruct(ControlInputBox *self, int width, int y, int x,
                              bool hideContent,
                              void (*draw)(ControlInputBox *self),
                              void (*resize)(ControlInputBox *self),
                              void (*submit)(ControlInputBox *self),
                              void (*refresh)(ControlInputBox *self),
                              void (*update)(ControlInputBox *self)) {
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
        self->base.vtable.draw = (void (*)(Control *))draw;
    }
    if (update != NULL) {
        self->base.vtable.update = (void (*)(Control *))update;
    }
    self->base.commonMsgHandlers.resize = (void (*)(Control *))resize;
    self->base.commonMsgHandlers.refresh = (void (*)(Control *))refresh;
    self->buf = malloc(sizeof(char) * INPUTBOX_BUF_MAX_LEN);
    if (self->buf == NULL) {
        LOG_ERROR("malloc failed for input self buffer");
        return;
    }
    self->curLen = 0;
    self->viewBegin = 0;
    self->curLoc = 0;
    self->hideContent = hideContent;
    self->submit = submit;
}

void controlInputBoxDraw(ControlInputBox *self) {
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

    if (self->buf != NULL) {
        size_t selStart = self->base.selection.startByte;
        size_t selEnd = self->base.selection.endByte;
        if (selStart > selEnd) {
            size_t tmp = selStart;
            selStart = selEnd;
            selEnd = tmp;
        }

        for (size_t i = self->viewBegin;
             i <= self->viewBegin + (size_t)self->base.width - 3 &&
             i <= self->curLen;
             ++i) {
            int curX = 1 + (int)i - (int)self->viewBegin;
            char dest = self->hideContent ? '*' : self->buf[i];
            attr_t attr = 0;

            if (i == self->curLoc && self->base.focused) {
                attr |= A_REVERSE;
            }
            if (self->base.selection.active && i >= selStart && i < selEnd) {
                attr |= A_REVERSE;
            }

            if (i == self->curLoc) {
                mvwaddch(self->base.windowHandler, 1, curX,
                         (chtype)(i == self->curLen ? ' ' : dest) | attr);
            } else if (i < self->curLen) {
                mvwaddch(self->base.windowHandler, 1, curX,
                         (chtype)dest | attr);
            }
        }
    }

    wnoutrefresh(self->base.windowHandler);
}

static void controlInputBoxDestruct(ControlInputBox *self) { free(self->buf); }

static void controlInputBoxMsgHandler(ControlInputBox *self, TuiMsg msg) {
    switch (msg.type) {
    case MsgResize:
        if (self->base.commonMsgHandlers.resize != NULL) {
            self->base.commonMsgHandlers.resize((Control *)self);
        }
        break;
    case MsgRefresh:
        if (self->base.commonMsgHandlers.refresh != NULL) {
            self->base.commonMsgHandlers.refresh((Control *)self);
        }
        break;
    case MsgFocusEnter:
        self->base.takeOverInput = true;
        break;
    case MsgInput: {
        switch (msg.arg1.input) {
        case '\n':
        case '\r':
        case KEY_ENTER:
            if (self->submit != NULL) {
                self->submit(self);
            } else {
                tuiAppPushMessage((TuiMsg){.type = MsgCursorNext});
            }
            self->base.takeOverInput = false;
            break;
        case '\e':
            self->base.takeOverInput = false;
            break;
        case '\t':
            tuiAppPushMessage((TuiMsg){.type = MsgCursorNext});
            break;
        case KEY_BTAB:
            tuiAppPushMessage((TuiMsg){.type = MsgCursorPrev});
            break;
        case KEY_LEFT:
            if (self->curLoc > 0) {
                --self->curLoc;
            }
            break;
        case KEY_RIGHT:
            if (self->curLoc < self->curLen) {
                ++self->curLoc;
            }
            break;
        case KEY_UP:
        case KEY_HOME:
            self->curLoc = 0;
            break;
        case KEY_DOWN:
        case KEY_END:
            self->curLoc = self->curLen;
            break;
        default: {
            self->base.takeOverInput = true;
            if (msg.arg1.input == KEY_BACKSPACE) {
                if (self->curLoc > 0) {
                    if (self->curLoc < self->curLen) {
                        memmove(self->buf + self->curLoc - 1,
                                self->buf + self->curLoc,
                                self->curLen - self->curLoc);
                    }
                    --self->curLoc;
                    --self->curLen;
                }
            } else if (msg.arg1.input == KEY_DC) {
                if (self->curLoc < self->curLen) {
                    memmove(self->buf + self->curLoc,
                            self->buf + self->curLoc + 1,
                            self->curLen - self->curLoc - 1);
                    --self->curLen;
                }
            } else {
                if (msg.arg1.input < ' ' || msg.arg1.input > '~') {
                    break;
                }
                if (self->curLen < INPUTBOX_BUF_MAX_LEN) {
                    if (self->curLoc == self->curLen) {
                        self->buf[self->curLoc] = (char)msg.arg1.input;
                        ++self->curLoc;
                    } else {
                        memmove(self->buf + self->curLoc + 1,
                                self->buf + self->curLoc,
                                self->curLen - self->curLoc);
                        self->buf[self->curLoc] = (char)msg.arg1.input;
                        ++self->curLoc;
                    }
                    ++self->curLen;
                }
            }
            break;
        }
        }
        break;
    }
    case MsgMouse:
        controlSelectionHandleMouse((Control *)self, msg);
        break;
    default:
        break;
    }
    if (self->curLoc >= ((size_t)self->base.width - 2) + self->viewBegin) {
        self->viewBegin = self->curLoc - ((size_t)self->base.width - 2) + 1;
    } else if (self->viewBegin > 0 && self->curLoc <= self->viewBegin) {
        self->viewBegin = self->curLoc > 0 ? self->curLoc - 1 : 0;
    }
}

static const char *inputBoxGetSelectableText(ControlInputBox *self,
                                             size_t *outLen) {
    if (self->buf == NULL || self->hideContent) {
        *outLen = 0;
        return NULL;
    }
    *outLen = self->curLen;
    return self->buf;
}

static size_t inputBoxCoordToByteOffset(ControlInputBox *self, int localY,
                                        int localX) {
    size_t offset;
    (void)localY;

    if (localX <= 1) {
        return self->viewBegin;
    }
    offset = self->viewBegin + (size_t)(localX - 1);
    return (offset > self->curLen) ? self->curLen : offset;
}

void controlTextBoxConstruct(ControlTextBox *self, int height, int width, int y,
                             int x, const char *text,
                             void (*draw)(ControlTextBox *self),
                             void (*resize)(ControlTextBox *self),
                             void (*refresh)(ControlTextBox *self),
                             void (*update)(ControlTextBox *self)) {
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
        self->base.vtable.draw = (void (*)(Control *))draw;
    }
    if (update != NULL) {
        self->base.vtable.update = (void (*)(Control *))update;
    }
    self->base.commonMsgHandlers.resize = (void (*)(Control *))resize;
    self->base.commonMsgHandlers.refresh = (void (*)(Control *))refresh;
    self->text = malloc(sizeof(char) * TEXTBOX_TEXT_MAXLEN);
    if (self->text == NULL) {
        LOG_ERROR("malloc failed for text self text");
        return;
    }
    strncpy(self->text, text, TEXTBOX_TEXT_MAXLEN);
    self->text[TEXTBOX_TEXT_MAXLEN - 1] = '\0';
    self->textLen = strlen(self->text);
    self->viewBegin = 0;
}

static const char *textBoxGetSelectableText(ControlTextBox *self,
                                            size_t *outLen) {
    if (self->text == NULL) {
        *outLen = 0;
        return NULL;
    }
    *outLen = self->textLen;
    return self->text;
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

static bool textBoxGetVisualLineRange(const ControlTextBox *self,
                                      size_t visualLineIdx, size_t *outStart,
                                      size_t *outEnd) {
    int availWidth = self->base.width - 2;
    size_t offset;
    bool isContinuation;
    size_t curLine;
    size_t renderStart;

    if (availWidth < 1 || self->text == NULL) {
        return false;
    }

    offset = 0;
    isContinuation = false;
    curLine = 0;

    while (curLine < visualLineIdx && offset < self->textLen) {
        offset = textBoxAdvanceVisualLine(self->text, self->textLen, offset,
                                          availWidth, &isContinuation);
        curLine++;
    }

    if (offset >= self->textLen) {
        return false;
    }

    renderStart = offset;
    if (isContinuation) {
        while (renderStart < self->textLen && self->text[renderStart] == ' ') {
            renderStart++;
        }
    }

    offset = textBoxAdvanceVisualLine(self->text, self->textLen, offset,
                                      availWidth, &isContinuation);

    *outEnd = offset;
    if (*outEnd > renderStart && self->text[*outEnd - 1] == '\n') {
        (*outEnd)--;
    }
    while (*outEnd > renderStart && self->text[*outEnd - 1] == ' ') {
        (*outEnd)--;
    }

    *outStart = renderStart;
    return true;
}

static size_t textBoxCoordToByteOffset(ControlTextBox *self, int localY,
                                       int localX) {
    int availWidth;
    int visibleLines;
    size_t visualLineIdx;
    size_t lineStart;
    size_t lineEnd;
    size_t charOff;
    size_t result;

    availWidth = self->base.width - 2;
    visibleLines = self->base.height - 2;
    if (availWidth < 1 || visibleLines < 1 || self->text == NULL ||
        self->textLen == 0) {
        return 0;
    }

    if (localY < 1) {
        localY = 1;
    }

    visualLineIdx = self->viewBegin + (size_t)(localY - 1);

    if (!textBoxGetVisualLineRange(self, visualLineIdx, &lineStart, &lineEnd)) {
        return self->textLen;
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

void controlTextBoxDraw(ControlTextBox *self) {
    werase(self->base.windowHandler);

    if (self->base.focused) {
        DOUBLE_BOX(self->base.windowHandler);
    } else {
        box(self->base.windowHandler, 0, 0);
    }

    int availWidth = self->base.width - 2;
    int visibleLines = self->base.height - 2;
    if (availWidth < 1 || visibleLines < 1 || self->text == NULL) {
        wnoutrefresh(self->base.windowHandler);
        return;
    }

    size_t offset = 0;
    bool isContinuation = false;
    size_t visualLine = 0;

    while (visualLine < self->viewBegin && offset < self->textLen) {
        offset = textBoxAdvanceVisualLine(self->text, self->textLen, offset,
                                          availWidth, &isContinuation);
        visualLine++;
    }

    int curY = 1;
    while (curY <= visibleLines && offset < self->textLen) {
        size_t renderStart = offset;
        if (isContinuation) {
            while (renderStart < self->textLen &&
                   self->text[renderStart] == ' ') {
                renderStart++;
            }
        }

        offset = textBoxAdvanceVisualLine(self->text, self->textLen, offset,
                                          availWidth, &isContinuation);

        size_t end = offset;
        if (end > renderStart && self->text[end - 1] == '\n') {
            end--;
        }
        while (end > renderStart && self->text[end - 1] == ' ') {
            end--;
        }

        if (end <= renderStart) {
            curY++;
            continue;
        }

        if (self->base.selection.active) {
            size_t selStart = self->base.selection.startByte;
            size_t selEnd = self->base.selection.endByte;

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
                    mvwprintw(self->base.windowHandler, curY, 1, "%.*s",
                              (int)(hlStart - renderStart),
                              self->text + renderStart);
                }
                wattron(self->base.windowHandler, A_REVERSE);
                mvwprintw(self->base.windowHandler, curY,
                          1 + (int)(hlStart - renderStart), "%.*s",
                          (int)(hlEnd - hlStart), self->text + hlStart);
                wattroff(self->base.windowHandler, A_REVERSE);
                if (hlEnd < end) {
                    mvwprintw(self->base.windowHandler, curY,
                              1 + (int)(hlEnd - renderStart), "%.*s",
                              (int)(end - hlEnd), self->text + hlEnd);
                }
            } else {
                mvwprintw(self->base.windowHandler, curY, 1, "%.*s",
                          (int)(end - renderStart), self->text + renderStart);
            }
        } else {
            mvwprintw(self->base.windowHandler, curY, 1, "%.*s",
                      (int)(end - renderStart), self->text + renderStart);
        }
        curY++;
    }

    wnoutrefresh(self->base.windowHandler);
}

static void controlTextBoxDestruct(ControlTextBox *self) { free(self->text); }

static void controlTextBoxMsgHandler(ControlTextBox *self, TuiMsg msg) {
    switch (msg.type) {
    case MsgResize:
        if (self->base.commonMsgHandlers.resize != NULL) {
            self->base.commonMsgHandlers.resize((Control *)self);
        }
        break;
    case MsgRefresh:
        if (self->base.commonMsgHandlers.refresh != NULL) {
            self->base.commonMsgHandlers.refresh((Control *)self);
        }
        break;
    case MsgFocusEnter:
        self->base.focused = true;
        break;
    case MsgFocusLeave:
        self->base.focused = false;
        break;
    case MsgInput: {
        int availWidth = self->base.width - 2;
        int visibleLines = self->base.height - 2;
        if (availWidth < 1 || visibleLines < 1 || self->text == NULL) {
            break;
        }
        size_t totalLines =
            textBoxCountVisualLines(self->text, self->textLen, availWidth);
        size_t maxView = (totalLines > (size_t)visibleLines)
                             ? totalLines - (size_t)visibleLines
                             : 0;
        switch (msg.arg1.input) {
        case KEY_UP:
            if (self->viewBegin > 0) {
                self->viewBegin--;
            }
            break;
        case KEY_DOWN:
            if (self->viewBegin < maxView) {
                self->viewBegin++;
            }
            break;
        case KEY_PPAGE:
            if (self->viewBegin > (size_t)visibleLines) {
                self->viewBegin -= (size_t)visibleLines;
            } else {
                self->viewBegin = 0;
            }
            break;
        case KEY_NPAGE:
            if (self->viewBegin + (size_t)visibleLines < maxView) {
                self->viewBegin += (size_t)visibleLines;
            } else {
                self->viewBegin = maxView;
            }
            break;
        case KEY_HOME:
            self->viewBegin = 0;
            break;
        case KEY_END:
            self->viewBegin = maxView;
            break;
        }
        break;
    }
    case MsgMouse: {
        int availWidth = self->base.width - 2;
        int visibleLines = self->base.height - 2;
        int input;

        if (availWidth < 1 || visibleLines < 1 || self->text == NULL) {
            break;
        }

        if (controlSelectionHandleMouse((Control *)self, msg)) {
            break;
        }

        input = msg.arg2.input;
        if (input == BUTTON4_PRESSED || input == BUTTON5_PRESSED) {
            size_t totalLines =
                textBoxCountVisualLines(self->text, self->textLen, availWidth);
            size_t maxView = (totalLines > (size_t)visibleLines)
                                 ? totalLines - (size_t)visibleLines
                                 : 0;
            if (input == BUTTON4_PRESSED) {
                if (self->viewBegin > 0) {
                    self->viewBegin--;
                }
            } else {
                if (self->viewBegin < maxView) {
                    self->viewBegin++;
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
                                   void (*draw)(ControlScrollTextBox *self),
                                   void (*resize)(ControlScrollTextBox *self),
                                   void (*refresh)(ControlScrollTextBox *self),
                                   void (*update)(ControlScrollTextBox *self)) {
    enum { ScrollTextBoxMinHeight = 3, ScrollTextBoxMinWidth = 3 };
    if (height < ScrollTextBoxMinHeight) {
        height = ScrollTextBoxMinHeight;
    }
    if (width < ScrollTextBoxMinWidth) {
        width = ScrollTextBoxMinWidth;
    }
    controlConstruct((Control *)self, height, width, y, x, true, false);
    self->base.base.vtable = defaultScrollTextBoxVtable;
    if (draw != NULL) {
        self->base.base.vtable.draw = (void (*)(Control *))draw;
    }
    if (update != NULL) {
        self->base.base.vtable.update = (void (*)(Control *))update;
    }
    self->base.base.commonMsgHandlers.resize = (void (*)(Control *))resize;
    self->base.base.commonMsgHandlers.refresh = (void (*)(Control *))refresh;
    self->base.text = malloc(sizeof(char) * SCROLLTEXTBOX_TEXT_MAXLEN);
    if (self->base.text == NULL) {
        LOG_ERROR("malloc failed for scroll text self text");
        return;
    }
    self->base.text[0] = '\0';
    self->base.textLen = 0;
    self->base.viewBegin = 0;
    self->maxLines =
        (maxLines > 0) ? maxLines : SCROLLTEXTBOX_DEFAULT_MAX_LINES;
}

void controlScrollTextBoxAppend(ControlScrollTextBox *self, const char *text) {
    ControlTextBox *textBox = &self->base;
    size_t appendLen;

    if (text == NULL || text[0] == '\0') {
        return;
    }

    appendLen = strlen(text);

    while (textBox->textLen + appendLen >= SCROLLTEXTBOX_TEXT_MAXLEN &&
           textBox->textLen > 0) {
        const char *nl = memchr(textBox->text, '\n', textBox->textLen);
        if (nl != NULL) {
            size_t trimLen = (size_t)(nl - textBox->text) + 1;
            size_t remaining = textBox->textLen - trimLen;
            memmove(textBox->text, textBox->text + trimLen, remaining);
            textBox->textLen = remaining;
            textBox->text[textBox->textLen] = '\0';
        } else {
            textBox->textLen = 0;
            textBox->text[0] = '\0';
            break;
        }
    }

    {
        size_t spaceLeft = SCROLLTEXTBOX_TEXT_MAXLEN - textBox->textLen - 1;
        if (spaceLeft == 0) {
            return;
        }
        if (appendLen > spaceLeft) {
            appendLen = spaceLeft;
        }
    }

    memcpy(textBox->text + textBox->textLen, text, appendLen);
    textBox->textLen += appendLen;
    textBox->text[textBox->textLen] = '\0';

    {
        size_t lineCount = 0;
        const char *p = textBox->text;
        const char *end = textBox->text + textBox->textLen;
        while (p < end) {
            if (*p == '\n') {
                lineCount++;
            }
            p++;
        }
        if (textBox->textLen > 0 &&
            textBox->text[textBox->textLen - 1] != '\n') {
            lineCount++;
        }

        while (lineCount > self->maxLines && textBox->textLen > 0) {
            const char *nl = memchr(textBox->text, '\n', textBox->textLen);
            if (nl != NULL) {
                size_t trimLen = (size_t)(nl - textBox->text) + 1;
                size_t remaining = textBox->textLen - trimLen;
                memmove(textBox->text, textBox->text + trimLen, remaining);
                textBox->textLen = remaining;
                textBox->text[textBox->textLen] = '\0';
            } else {
                textBox->textLen = 0;
                textBox->text[0] = '\0';
                break;
            }
            lineCount--;
        }
    }

    if (textBox->base.windowHandler != NULL) {
        int availWidth = textBox->base.width - 2;
        int visibleLines = textBox->base.height - 2;
        if (availWidth >= 1 && visibleLines >= 1) {
            size_t totalLines = textBoxCountVisualLines(
                textBox->text, textBox->textLen, availWidth);
            size_t maxView = (totalLines > (size_t)visibleLines)
                                 ? totalLines - (size_t)visibleLines
                                 : 0;
            textBox->viewBegin = maxView;
        }
        controlTextBoxDraw(textBox);
    }
}

void controlListBoxConstruct(ControlListBox *self, int height, int width, int y,
                             int x, void (*draw)(ControlListBox *self),
                             void (*resize)(ControlListBox *self),
                             void (*refresh)(ControlListBox *self),
                             void (*update)(ControlListBox *self)) {
    controlConstruct((Control *)self, height, width, y, x, true, false);
    self->base.vtable = defaultListBoxVtable;
    arrayControlListBoxEntryInit(&self->list, ARRAY_DEFAULT_CAPACITY);
    self->viewBegin = 0;
    self->curLine = 0;
    self->entryCnt = 0;
    if (draw != NULL) {
        self->base.vtable.draw = (void (*)(Control *))draw;
    }
    if (update != NULL) {
        self->base.vtable.update = (void (*)(Control *))update;
    }
    self->base.commonMsgHandlers.resize = (void (*)(Control *))resize;
    self->base.commonMsgHandlers.refresh = (void (*)(Control *))refresh;
}

static void listBoxDrawEntryLine(WINDOW *win, int y, int x, int width,
                                    const char *text, int lineIdx) {
    const char *start = text;
    int i;
    for (i = 0; i < lineIdx; i++) {
        const char *nl = strchr(start, '\n');
        if (nl == NULL) {
            return;
        }
        start = nl + 1;
    }
    {
        const char *nl = strchr(start, '\n');
        int len = (nl != NULL) ? (int)(nl - start) : (int)strlen(start);
        mvwprintw(win, y, x, "%-*.*s", width, len, start);
    }
}

static size_t listBoxCountVisibleEntries(ControlListBox *self) {
    enum { BorderLines = 2 };
    size_t visible = 0;
    size_t cumulativeHeight = 0;
    size_t i;
    for (i = self->viewBegin; i < self->entryCnt; i++) {
        ControlListBoxEntry entry;
        ContainerRes res =
            arrayControlListBoxEntryGet(&self->list, i, &entry);
        if (res != ContainerSucc) {
            continue;
        }
        if (cumulativeHeight + entry.height >
            (size_t)(self->base.height - BorderLines)) {
            break;
        }
        cumulativeHeight += entry.height;
        visible++;
    }
    enum { MinVisible = 1 };
    return visible > 0 ? visible : MinVisible;
}

static void listBoxAdjustViewBegin(ControlListBox *self) {
    enum { BorderLines = 2 };
    size_t i;

    if (self->curLine < self->viewBegin) {
        self->viewBegin = self->curLine;
        return;
    }

    {
        size_t cumH = 0;
        size_t lastVisible = self->viewBegin;
        for (i = self->viewBegin; i < self->entryCnt; i++) {
            ControlListBoxEntry e;
            ContainerRes res =
                arrayControlListBoxEntryGet(&self->list, i, &e);
            if (res != ContainerSucc) {
                continue;
            }
            if (cumH + e.height >
                (size_t)(self->base.height - BorderLines)) {
                break;
            }
            cumH += e.height;
            lastVisible = i;
        }
        if (self->curLine > lastVisible) {
            cumH = 0;
            for (i = self->curLine; i > 0; i--) {
                ControlListBoxEntry e;
                ContainerRes res =
                    arrayControlListBoxEntryGet(&self->list, i, &e);
                if (res != ContainerSucc) {
                    continue;
                }
                if (cumH + e.height >
                    (size_t)(self->base.height - BorderLines)) {
                    self->viewBegin = i + 1;
                    return;
                }
                cumH += e.height;
            }
            self->viewBegin = 0;
        }
    }
}

void controlListBoxDraw(ControlListBox *self) {
    enum { BorderLines = 2, ContentStartX = 1, ContentStartY = 1 };
    int visibleHeight;
    int innerWidth;
    int curY;
    size_t i;

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

    visibleHeight = self->base.height - BorderLines;
    innerWidth = self->base.width - BorderLines;
    curY = ContentStartY;

    for (i = self->viewBegin; i < self->entryCnt && curY <= visibleHeight;
         i++) {
        ControlListBoxEntry entry;
        ContainerRes res =
            arrayControlListBoxEntryGet(&self->list, i, &entry);
        int entryHeight;
        int linesToShow;
        int line;

        if (res != ContainerSucc) {
            continue;
        }

        entryHeight = (int)entry.height;
        linesToShow = entryHeight;
        if (curY + entryHeight - 1 > visibleHeight) {
            linesToShow = visibleHeight - curY + 1;
        }
        if (linesToShow <= 0) {
            break;
        }

        if (i == self->curLine) {
            wattron(self->base.windowHandler, A_REVERSE);
        }

        for (line = 0; line < linesToShow; line++) {
            listBoxDrawEntryLine(self->base.windowHandler, curY, ContentStartX,
                                 innerWidth, entry.disp, line);
            curY++;
        }

        if (i == self->curLine) {
            wattroff(self->base.windowHandler, A_REVERSE);
        }
    }

    wnoutrefresh(self->base.windowHandler);
}

void controlListBoxAppend(ControlListBox *self, const char *disp, size_t id) {
    enum { DefaultHeight = 1 };
    char *cur = malloc(strlen(disp) + 1);
    strcpy(cur, disp);
    arrayControlListBoxEntryPushBack(
        &self->list,
        (ControlListBoxEntry){.disp = cur, .id = id, .height = DefaultHeight});
    ++self->entryCnt;
}

void controlListBoxAppendMulti(ControlListBox *self, const char *disp,
                               size_t id, uint8_t height) {
    char *cur = malloc(strlen(disp) + 1);
    strcpy(cur, disp);
    arrayControlListBoxEntryPushBack(
        &self->list,
        (ControlListBoxEntry){.disp = cur, .id = id, .height = height});
    ++self->entryCnt;
}

void controlListBoxClear(ControlListBox *self) {
    size_t sz = 0;
    while ((sz = arrayControlListBoxEntrySize(&self->list)) > 0) {
        ControlListBoxEntry cur = {0};
        arrayControlListBoxEntryGet(&self->list, sz - 1, &cur);
        free(cur.disp);
        arrayControlListBoxEntryPopBack(&self->list);
        --self->entryCnt;
    }
}

static void controlListBoxDestruct(ControlListBox *self) {
    controlListBoxClear(self);
    arrayControlListBoxEntryDeinit(&self->list);
}

static void controlListBoxMsgHandler(ControlListBox *self, TuiMsg msg) {
    switch (msg.type) {
    case MsgFocusEnter:
        self->base.takeOverInput = true;
        break;
    case MsgInput: {
        switch (msg.arg1.input) {
        case '\e':
            self->base.takeOverInput = false;
            break;
        case KEY_BTAB:
        case KEY_LEFT:
        case KEY_UP:
            if (self->curLine > 0) {
                --self->curLine;
            } else {
                self->curLine = self->entryCnt - 1;
            }
            break;
        case '\t':
        case KEY_RIGHT:
        case KEY_DOWN:
            if (self->curLine < self->entryCnt - 1) {
                ++self->curLine;
            } else {
                self->curLine = 0;
            }
            break;
        case KEY_PPAGE: {
            size_t visible = listBoxCountVisibleEntries(self);
            if (self->curLine > visible) {
                self->curLine -= visible;
            } else {
                self->curLine = 0;
            }
            break;
        }
        case KEY_HOME:
            self->curLine = 0;
            break;
        case KEY_NPAGE: {
            size_t visible = listBoxCountVisibleEntries(self);
            if (self->curLine + visible < self->entryCnt) {
                self->curLine += visible;
            } else if (self->entryCnt > 0) {
                self->curLine = self->entryCnt - 1;
            }
            break;
        }
        case KEY_END:
            if (self->entryCnt > 0) {
                self->curLine = self->entryCnt - 1;
            }
            break;
        default:
            break;
        }
        break;
    }
    case MsgRefresh:
        if (self->base.commonMsgHandlers.refresh != NULL) {
            self->base.commonMsgHandlers.refresh((Control *)self);
        }
        break;
    case MsgResize:
        if (self->base.commonMsgHandlers.resize != NULL) {
            self->base.commonMsgHandlers.resize((Control *)self);
        }
        break;
    case MsgMouse:
        if ((msg.arg2.input & BUTTON1_CLICKED) != 0) {
            int x = msg.mouseX, y = msg.mouseY;
            size_t cumulativeY = 0;
            size_t i;
            wmouse_trafo(self->base.windowHandler, &y, &x, false);
            for (i = self->viewBegin; i < self->entryCnt; i++) {
                ControlListBoxEntry entry;
                ContainerRes res =
                    arrayControlListBoxEntryGet(&self->list, i, &entry);
                if (res != ContainerSucc) {
                    continue;
                }
                cumulativeY += entry.height;
                if ((size_t)(y - 1) < cumulativeY) {
                    self->curLine = i;
                    break;
                }
            }
        }
        break;
    default:
        break;
    }
    listBoxAdjustViewBegin(self);
}