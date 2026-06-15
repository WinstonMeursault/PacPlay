/**
 * @file control.h
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

#ifndef CONTROL_H
#define CONTROL_H

#define BTN_LABEL_MAXLEN 20
#define INPUTBOX_BUF_MAX_LEN 128
#define LABEL_TEXT_MAXLEN 128
#define TEXTBOX_TEXT_MAXLEN 4096
#define SCROLLTEXTBOX_TEXT_MAXLEN 65536
#define SCROLLTEXTBOX_DEFAULT_MAX_LINES 100

#include "container.h"
#include "ncurses_wrapper.h"
#include "tuimsg.h"
#include <errno.h>
#include <stdbool.h>
#include <string.h>

// typedef char *Str;
typedef struct {
    char *disp;
    size_t id;
} ControlListBoxEntry;
ARRAY_DEFINE(ControlListBoxEntry);

typedef struct ControlVTable ControlVTable;
typedef struct ControlCommonMsgHandlers ControlCommonHandlers;
typedef struct Control Control;
typedef struct Control ControlPage;
typedef struct ControlButton ControlButton;
typedef struct ControlGrid ControlGrid;
typedef struct ControlLabel ControlLabel;
typedef struct ControlInputBox ControlInputBox;
typedef struct ControlTextBox ControlTextBox;
typedef struct ControlScrollTextBox ControlScrollTextBox;
typedef struct ControlListBox ControlListBox;

struct ControlVTable {
    void (*destruct)(Control *self);
    void (*draw)(Control *self);
    void (*update)(Control *self);
    void (*msgHandler)(Control *self, TuiMsg msg);
    const char *(*getSelectableText)(Control *self, size_t *outLen);
    size_t (*coordToByteOffset)(Control *self, int localY, int localX);
};

struct ControlCommonMsgHandlers {
    void (*resize)(Control *self);
    void (*refresh)(Control *self);
};

struct Control {
    ControlVTable vtable;
    WINDOW *windowHandler;
    ControlCommonHandlers commonMsgHandlers;
    // begin from 1
    size_t index;
    bool isPage;
    int x;
    int y;
    int width;
    int height;
    bool focusable;
    bool focused;
    bool isContainer;
    size_t childCount;
    bool takeOverInput;
    bool visible;
    struct {
        bool active;
        size_t startByte;
        size_t endByte;
    } selection;
};

struct ControlButton {
    Control base;
    char *text;
    void (*onClick)(ControlButton *self);
};

typedef enum {
    LayoutVertical = 1,
    LayoutHorizontal,
    LayoutNone
} GridLayoutMethod;

struct ControlGrid {
    Control base;
    GridLayoutMethod layoutMethod;
    struct {
        size_t vertical;
        size_t horizontal;
    } margin;
    size_t layoutCounter;
    size_t layoutAccCol;
    size_t layoutAccRow;
    void (*layout)(ControlGrid *self, Control *child);
};

struct ControlLabel {
    Control base;
    char *text;
};

struct ControlInputBox {
    Control base;
    char *buf;
    size_t curLen;
    size_t viewBegin;
    size_t curLoc;
    bool hideContent;
    void (*submit)(ControlInputBox *self);
};

struct ControlTextBox {
    Control base;
    char *text;
    size_t textLen;
    size_t viewBegin;
};

struct ControlScrollTextBox {
    ControlTextBox base;
    size_t maxLines;
};

struct ControlListBox {
    Control base;
    ArrayControlListBoxEntry list;
    size_t entryCnt;
    size_t viewBegin;
    size_t curLine;
};

void customBox(WINDOW *handler, const wchar_t *lsRaw, const wchar_t *rsRaw,
               const wchar_t *tsRaw, const wchar_t *bsRaw, const wchar_t *tlRaw,
               const wchar_t *trRaw, const wchar_t *blRaw,
               const wchar_t *brRaw);
#define DOUBLE_BOX(handler)                                                    \
    customBox((handler), L"║", L"║", L"═", L"═", L"╔", L"╗", L"╚", L"╝")

void controlInstantiate(Control *self, Control *parent);
void controlDeinstantiate(Control *self);

void controlPageConstruct(ControlPage *self);

void controlButtonConstruct(ControlButton *self, int height, int width, int y,
                            int x, const char *text,
                            void (*draw)(ControlButton *self),
                            void (*onClick)(ControlButton *self),
                            void (*resize)(ControlButton *self),
                            void (*refresh)(ControlButton *self),
                            void (*update)(ControlButton *self));
void controlButtonDraw(ControlButton *self);

void controlGridConstruct(ControlGrid *self, int height, int width, int y,
                          int x, GridLayoutMethod layoutMethod, size_t hmargin,
                          size_t vmargin, void (*draw)(ControlGrid *self),
                          void (*resize)(ControlGrid *self),
                          void (*refresh)(ControlGrid *self),
                          void (*update)(ControlGrid *self),
                          void (*layout)(ControlGrid *self, Control *child));
void controlGridDraw(ControlGrid *self);

void controlLabelConstruct(ControlLabel *self, const char *text,
                           size_t maxWidth, int y, int x,
                           void (*draw)(ControlLabel *self),
                           void (*resize)(ControlLabel *self),
                           void (*refresh)(ControlLabel *self),
                           void (*update)(ControlLabel *self));
void controlLabelDraw(ControlLabel *self);

void controlInputBoxConstruct(ControlInputBox *self, int width, int y, int x,
                              bool hideContent,
                              void (*draw)(ControlInputBox *self),
                              void (*resize)(ControlInputBox *self),
                              void (*submit)(ControlInputBox *self),
                              void (*refresh)(ControlInputBox *self),
                              void (*update)(ControlInputBox *self));
void controlInputBoxDraw(ControlInputBox *self);

void controlTextBoxConstruct(ControlTextBox *self, int height, int width, int y,
                             int x, const char *text,
                             void (*draw)(ControlTextBox *self),
                             void (*resize)(ControlTextBox *self),
                             void (*refresh)(ControlTextBox *self),
                             void (*update)(ControlTextBox *self));
void controlTextBoxDraw(ControlTextBox *self);

void controlScrollTextBoxConstruct(ControlScrollTextBox *self, int height,
                                   int width, int y, int x, size_t maxLines,
                                   void (*draw)(ControlScrollTextBox *self),
                                   void (*resize)(ControlScrollTextBox *self),
                                   void (*refresh)(ControlScrollTextBox *self),
                                   void (*update)(ControlScrollTextBox *self));
void controlScrollTextBoxAppend(ControlScrollTextBox *self, const char *text);

bool controlSelectionHandleMouse(Control *self, TuiMsg msg);

void controlListBoxConstruct(ControlListBox *self, int height, int width, int y,
                             int x, void (*draw)(ControlListBox *self),
                             void (*resize)(ControlListBox *self),
                             void (*refresh)(ControlListBox *self),
                             void (*update)(ControlListBox *self));

void controlListBoxDraw(ControlListBox *self);

void controlListBoxAppend(ControlListBox *self, const char *disp, size_t id);

void controlListBoxClear(ControlListBox *self);

#endif // CONTROL_H