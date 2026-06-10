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

#include "ncurses_wrapper.h"
#include "tuimsg.h"
#include <stdbool.h>

typedef struct ControlVTable ControlVTable;
typedef struct ControlCommonMsgHandlers ControlCommonHandlers;
typedef struct Control Control;
typedef struct Control ControlPage;
typedef struct ControlButton ControlButton;
typedef struct ControlGrid ControlGrid;
typedef struct ControlLabel ControlLabel;
typedef struct ControlInputBox ControlInputBox;
typedef struct ControlTextBox ControlTextBox;

struct ControlVTable {
    void (*destruct)(void *self);
    void (*draw)(void *self);
    void (*msgHandler)(void *self, TuiMsg msg);
};

struct ControlCommonMsgHandlers {
    void (*resize)(void *self);
    void (*refresh)(void *self);
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
    void (*layout)(void *self, void *child);
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

void controlInstantiate(Control *self, Control *parent);
void controlDeinstantiate(Control *self);

void controlPageConstruct(ControlPage *self);

void controlButtonConstruct(ControlButton *self, int height, int width, int y,
                            int x, const char *text,
                            void (*draw)(ControlButton *),
                            void (*onClick)(ControlButton *self),
                            void (*resize)(ControlButton *self),
                            void (*refresh)(ControlButton *self));
void controlButtonDraw(void *self);

void controlGridConstruct(ControlGrid *self, int height, int width, int y,
                          int x, GridLayoutMethod layoutMethod, size_t hmargin,
                          size_t vmargin, void (*draw)(ControlGrid *),
                          void (*resize)(ControlGrid *self),
                          void (*refresh)(ControlGrid *self),
                          void (*layout)(void *self, void *child));
void controlGridDraw(void *self);

void controlLabelConstruct(ControlLabel *self, const char *text, size_t maxWidth,
                           int y, int x, void (*draw)(ControlLabel *),
                           void (*resize)(ControlLabel *self),
                           void (*refresh)(ControlLabel *self));
void controlLabelDraw(void *self);

void controlInputBoxConstruct(ControlInputBox *self, int width, int y, int x,
                              bool hideContent, void (*draw)(ControlInputBox *),
                              void (*resize)(ControlInputBox *self),
                              void (*submit)(ControlInputBox *self),
                              void (*refresh)(ControlInputBox *self));
void controlInputBoxDraw(void *self);

void controlTextBoxConstruct(ControlTextBox *self, int height, int width,
                             int y, int x, const char *text,
                             void (*draw)(ControlTextBox *),
                             void (*resize)(ControlTextBox *self),
                             void (*refresh)(ControlTextBox *self));
void controlTextBoxDraw(void *self);

#endif // CONTROL_H