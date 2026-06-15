/**
 * @file tuiapp.c
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

#include "tui/tuiapp.h"
#include "clipboard.h"
#include "log.h"
#include "tui/tuimsg.h"
#include <errno.h>
#include <locale.h>
#include <pthread.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include "container.h"

#define A_SEC 1000000

#define CHECKED_REGENTRY_INDEX(arr, idx, ptr)                                  \
    do {                                                                       \
        if (arrayControlRegEntryIndex((arr), (idx), (ptr)) != ContainerSucc) { \
            LOG_FATAL("BUG: control registry index out of bounds");            \
            abort();                                                           \
        }                                                                      \
    } while (0)

#define CHECKED_ARRAY_INDEX_GET(arr, idx, ptr)                                 \
    do {                                                                       \
        if (arrayIndexGet((arr), (idx), (ptr)) != ContainerSucc) {             \
            LOG_FATAL("BUG: array index out of bounds");                       \
            abort();                                                           \
        }                                                                      \
    } while (0)

#define CHECKED_QUEUE_TUI_MSG_FRONT(q, ptr)                                    \
    do {                                                                       \
        if (queueTuiMsgFront((q), (ptr)) != ContainerSucc) {                   \
            LOG_FATAL("BUG: message queue front out of bounds");               \
            abort();                                                           \
        }                                                                      \
    } while (0)

#define CHECKED_QUEUE_INDEX_FRONT(q, ptr)                                      \
    do {                                                                       \
        if (queueIndexFront((q), (ptr)) != ContainerSucc) {                    \
            LOG_FATAL("BUG: index queue front out of bounds");                 \
            abort();                                                           \
        }                                                                      \
    } while (0)

typedef size_t Index;
// left child right sibling
typedef struct {
    Control *ptr;
    Index child;
    Index sibling;
} ControlRegEntry;

// NOLINTNEXTLINE(clang-analyzer-core.uninitialized.ArraySubscript)
QUEUE_DEFINE(Index);
QUEUE_DEFINE(TuiMsg)
ARRAY_DEFINE(Index);
ARRAY_DEFINE(ControlRegEntry);

static ArrayIndex gRenderStk = {0};

static void ensureRenderStkCap(size_t need) {
    if (gRenderStk.buf == NULL) {
        arrayIndexInit(&gRenderStk, need == 0 ? USE_DEFAULT_CAPACITY : need);
    } else if (gRenderStk.capacity < need) {
        arrayIndexDeinit(&gRenderStk);
        arrayIndexInit(&gRenderStk, need);
    }
}

static void tuiAppUpdateViewArea();
static void tuiAppDeinit();
static void tuiAppMainLoop();
static void tuiAppInput();
static void tuiAppMsgHandle();
static void tuiAppControlUpdate();
static void tuiAppRender();
static void tuiAppChangeRoot(Index root);
static void tuiAppRefreshNavChain();
static void tuiAppNavigate(bool isBack);
static bool findFocusableInNavChain(Index widgetIdx, Index *outPos);
static Index findWidgetAtMouse(int screenY, int screenX);

struct {
    bool isRunning;

    struct {
        const int escDelay;
    } constants;

    struct {
        int fps;
    } options;

    struct {
        Index index;
        Index indexOfCache;
    } userCursor;

    Index curRoot;
    Index selectingWidget;

    ArrayControlRegEntry controlRegistry;
    ArrayIndex navChainCache;
    QueueTuiMsg msgQueue;
    pthread_mutex_t msgQueueLock;

    ViewArea viewArea;

    bool fastRefresh;
} tuiApp = {.options = {.fps = 60},        // NOLINT(readability-magic-numbers)
            .constants = {.escDelay = 25}, // NOLINT(readability-magic-numbers)
            .selectingWidget = 0,
            .viewArea = {.x = 0, .y = 0}};

ViewArea *pViewArea;

void tuiAppChangePage(ControlPage *entry) {
    if (!entry->isPage) {
        LOG_ERROR("Cannot change page: Dest control is not a page");
        return;
    }
    tuiAppUpdateViewArea();
    tuiAppChangeRoot(entry->index);
    tuiAppPushMessage((TuiMsg){.type = MsgResize});
    clear();
}

void tuiAppPushMessage(TuiMsg msg) {
    pthread_mutex_lock(&tuiApp.msgQueueLock);
    queueTuiMsgPush(&tuiApp.msgQueue, msg);
    pthread_mutex_unlock(&tuiApp.msgQueueLock);
}

static void tuiAppUpdateViewArea() {
    int destHeight = COLS * 9 / 32; // NOLINT
    int destWidth = LINES * 32 / 9; // NOLINT
    if (destHeight < LINES) {
        pViewArea->height = destHeight;
        pViewArea->width = COLS;
        pViewArea->y = LINES / 2 - pViewArea->height / 2;
        pViewArea->x = 0;
    } else {
        pViewArea->height = LINES;
        pViewArea->width = destWidth;
        pViewArea->y = 0;
        pViewArea->x = COLS / 2 - pViewArea->width / 2;
    }
    delwin(pViewArea->windowHandler);
    pViewArea->windowHandler =
        newwin(pViewArea->height, pViewArea->width, pViewArea->y, pViewArea->x);
    clear();
}

void tuiAppInit() {
    tuiApp.userCursor.index = 0;
    tuiApp.userCursor.indexOfCache = 0;
    tuiApp.curRoot = 0;
    tuiApp.selectingWidget = 0;
    tuiApp.isRunning = false;

    if (arrayControlRegEntryInit(&tuiApp.controlRegistry,
                                 USE_DEFAULT_CAPACITY) != ContainerSucc ||
        arrayIndexInit(&tuiApp.navChainCache, USE_DEFAULT_CAPACITY) !=
            ContainerSucc ||
        queueTuiMsgInit(&tuiApp.msgQueue, USE_DEFAULT_CAPACITY) !=
            ContainerSucc) {
        LOG_FATAL("TUI initialization failed: out of memory");
    }
    // root index
    arrayControlRegEntryPushBack(
        &tuiApp.controlRegistry,
        (ControlRegEntry){.ptr = NULL, .child = 0, .sibling = 0});

    setlocale(LC_ALL, "");
    if (initscr() == NULL) {
        LOG_FATAL("TUI initialization failed: terminal not supported");
    }
    raw();
    keypad(stdscr, true);
    mousemask(BUTTON1_PRESSED | BUTTON1_RELEASED | BUTTON1_CLICKED |
                  BUTTON4_PRESSED | BUTTON5_PRESSED | REPORT_MOUSE_POSITION,
              NULL);
    mouseinterval(0);
    curs_set(0);
    noecho();
    nodelay(stdscr, true);
    set_escdelay(tuiApp.constants.escDelay);
    start_color();
    use_default_colors();
    intrflush(stdscr, FALSE);
    qiflush();
    {
        pthread_mutexattr_t attr;
        pthread_mutexattr_init(&attr);
        pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
        if (pthread_mutex_init(&tuiApp.msgQueueLock, &attr) != 0) {
            pthread_mutexattr_destroy(&attr);
            LOG_FATAL("TUI initialization failed: mutex init error");
            abort();
        }
        pthread_mutexattr_destroy(&attr);
    }
    clipboardInit();
    clipboardWriteRaw("\033[?1002h");

    pViewArea = &tuiApp.viewArea;
    tuiAppUpdateViewArea();
    tuiApp.viewArea.windowHandler =
        newwin(pViewArea->height, pViewArea->width, pViewArea->x, pViewArea->y);

    tuiApp.fastRefresh = false;
}

// parent must be already registered and it must be a container or a page.
// only page control can make the parent be NULL
void tuiAppControlRegister(Control *entry, Control *parent) {
    if (tuiApp.isRunning) {
        LOG_ERROR("Cannot register control: TUI is running");
        return;
    }
    if (parent != NULL) {
        if (parent->index == 0) {
            LOG_ERROR("Cannot register control: Parent control haven't been "
                      "registered");
            return;
        } else if (!parent->isContainer) {
            LOG_ERROR("Cannot register control: Parent control must be a "
                      "container or a page, or NULL if the control is a page");
            return;
        }
    }
    if (entry->isPage && parent != NULL) {
        LOG_ERROR("Cannot register control: Parent can only be NULL if the "
                  "control to be registered is a page");
        return;
    }
    if (!entry->isPage && parent == NULL) {
        LOG_ERROR("Cannot register control: Only page can have no "
                  "parent control");
        return;
    }

    arrayControlRegEntryPushBack(&tuiApp.controlRegistry,
                                 (ControlRegEntry){entry, 0, 0});
    entry->index = arrayControlRegEntrySize(&tuiApp.controlRegistry) - 1;
    Index parentIndex = 0;
    if (parent != NULL) {
        parentIndex = parent->index;
        ++parent->childCount;
    }
    ControlRegEntry *cursor;
    CHECKED_REGENTRY_INDEX(&tuiApp.controlRegistry, parentIndex, &cursor);
    if (cursor->child == 0) {
        cursor->child = entry->index;
    } else {
        CHECKED_REGENTRY_INDEX(&tuiApp.controlRegistry, cursor->child, &cursor);
        while (cursor->sibling != 0) {
            CHECKED_REGENTRY_INDEX(&tuiApp.controlRegistry, cursor->sibling,
                                   &cursor);
        }
        cursor->sibling = entry->index;
    }
}

void tuiAppStart(ControlPage *orgPage) {
    tuiAppChangePage(orgPage);
    tuiApp.isRunning = true;
    tuiAppMainLoop();
    tuiAppDeinit();
}

void tuiAppStop() { tuiApp.isRunning = false; }

static void tuiAppDeinit() {
    size_t max = arrayControlRegEntrySize(&tuiApp.controlRegistry);
    // Index 0 is the dummy root entry (ptr == NULL)
    for (Index i = 1; i < max; ++i) {
        ControlRegEntry *cur;
        CHECKED_REGENTRY_INDEX(&tuiApp.controlRegistry, i, &cur);
        if (cur->ptr->vtable.destruct != NULL) {
            cur->ptr->vtable.destruct(cur->ptr);
        }
        if (cur->ptr->windowHandler != NULL) {
            controlDeinstantiate(cur->ptr);
        }
    }
    arrayControlRegEntryDeinit(&tuiApp.controlRegistry);
    arrayIndexDeinit(&tuiApp.navChainCache);
    pthread_mutex_destroy(&tuiApp.msgQueueLock);
    queueTuiMsgDeinit(&tuiApp.msgQueue);
    clipboardWriteRaw("\033[?1002l");
    clipboardDeinit();
    delwin(tuiApp.viewArea.windowHandler);
    endwin();
}

static void tuiAppMainLoop() {
    tuiAppPushMessage((TuiMsg){.type = MsgResize});
    while (tuiApp.isRunning) {
        tuiAppInput();
        tuiAppMsgHandle();
        tuiAppControlUpdate();
        tuiAppRender();
        if (!tuiApp.fastRefresh) {
            usleep(A_SEC / tuiApp.options.fps);
        }
    }
}

static void tuiAppInput() {
    int ch;
    ch = getch();
    if (ch == -1) {
        return;
    }

    ControlRegEntry *cur;
    CHECKED_REGENTRY_INDEX(&tuiApp.controlRegistry, tuiApp.userCursor.index,
                           &cur);
    if (ch != KEY_MOUSE &&
        (cur->ptr != NULL && cur->ptr->takeOverInput && ch != KEY_RESIZE)) {
        tuiAppPushMessage((TuiMsg){.type = MsgInput, .arg1 = {.input = ch}});
        return;
    }

    switch (ch) {
    case '\t':
        tuiAppPushMessage((TuiMsg){.type = MsgCursorNext});
        break;
    case KEY_BTAB:
        tuiAppPushMessage((TuiMsg){.type = MsgCursorPrev});
        break;
    case KEY_RESIZE:
        tuiAppPushMessage((TuiMsg){.type = MsgResize});
        break;
    case KEY_MOUSE: {
        MEVENT event;
        if (getmouse(&event) == OK) {
            int bstate = event.bstate;
            Index target;

            if ((bstate & BUTTON1_PRESSED) != 0) {
                target = findWidgetAtMouse(event.y, event.x);
                if (target != 0) {
                    Index navPos;
                    if (findFocusableInNavChain(target, &navPos) &&
                        target != tuiApp.userCursor.index) {
                        ControlRegEntry *cur;
                        if (tuiApp.userCursor.index != 0) {
                            CHECKED_REGENTRY_INDEX(&tuiApp.controlRegistry,
                                                   tuiApp.userCursor.index,
                                                   &cur);
                            cur->ptr->focused = false;
                            tuiAppPushMessage((TuiMsg){
                                .type = MsgFocusLeave,
                                .arg1 = {.index = tuiApp.userCursor.index}});
                        }
                        tuiApp.userCursor.indexOfCache = navPos;
                        tuiApp.userCursor.index = target;
                        CHECKED_REGENTRY_INDEX(&tuiApp.controlRegistry, target,
                                               &cur);
                        cur->ptr->focused = true;
                        tuiAppPushMessage((TuiMsg){.type = MsgFocusEnter,
                                                   .arg1 = {.index = target}});
                    }
                    tuiApp.selectingWidget = target;
                    tuiAppPushMessage(
                        (TuiMsg){.type = MsgMouse,
                                 .arg1 = {.index = target},
                                 .arg2 = {.input = BUTTON1_PRESSED},
                                 .mouseY = event.y,
                                 .mouseX = event.x});
                }
            } else if ((bstate & BUTTON1_RELEASED) != 0) {
                if (tuiApp.selectingWidget != 0) {
                    target = tuiApp.selectingWidget;
                    tuiApp.selectingWidget = 0;
                    /* Synthesize BUTTON1_CLICKED when the release lands on
                       the same widget that received the press.  Most
                       terminal emulators never report BUTTON1_CLICKED
                       natively, so we compose it here to guarantee button
                       onClick fires. */
                    Index releaseTarget = findWidgetAtMouse(event.y, event.x);
                    if (releaseTarget == target) {
                        bstate |= BUTTON1_CLICKED;
                    }
                    tuiAppPushMessage((TuiMsg){.type = MsgMouse,
                                               .arg1 = {.index = target},
                                               .arg2 = {.input = bstate},
                                               .mouseY = event.y,
                                               .mouseX = event.x});
                }
            } else if ((bstate & BUTTON1_CLICKED) != 0) {
                target = findWidgetAtMouse(event.y, event.x);
                if (target != 0) {
                    Index navPos;
                    if (findFocusableInNavChain(target, &navPos) &&
                        target != tuiApp.userCursor.index) {
                        ControlRegEntry *cur;
                        if (tuiApp.userCursor.index != 0) {
                            CHECKED_REGENTRY_INDEX(&tuiApp.controlRegistry,
                                                   tuiApp.userCursor.index,
                                                   &cur);
                            cur->ptr->focused = false;
                            tuiAppPushMessage((TuiMsg){
                                .type = MsgFocusLeave,
                                .arg1 = {.index = tuiApp.userCursor.index}});
                        }
                        tuiApp.userCursor.indexOfCache = navPos;
                        tuiApp.userCursor.index = target;
                        CHECKED_REGENTRY_INDEX(&tuiApp.controlRegistry, target,
                                               &cur);
                        cur->ptr->focused = true;
                        tuiAppPushMessage((TuiMsg){.type = MsgFocusEnter,
                                                   .arg1 = {.index = target}});
                    }
                    tuiAppPushMessage(
                        (TuiMsg){.type = MsgMouse,
                                 .arg1 = {.index = target},
                                 .arg2 = {.input = BUTTON1_CLICKED},
                                 .mouseY = event.y,
                                 .mouseX = event.x});
                }
            } else if ((bstate & REPORT_MOUSE_POSITION) != 0 &&
                       tuiApp.selectingWidget != 0) {
                tuiAppPushMessage(
                    (TuiMsg){.type = MsgMouse,
                             .arg1 = {.index = tuiApp.selectingWidget},
                             .arg2 = {.input = REPORT_MOUSE_POSITION},
                             .mouseY = event.y,
                             .mouseX = event.x});
            } else if ((bstate & (BUTTON4_PRESSED | BUTTON5_PRESSED)) != 0) {
                target = findWidgetAtMouse(event.y, event.x);
                if (target != 0) {
                    tuiAppPushMessage(
                        (TuiMsg){.type = MsgMouse,
                                 .arg1 = {.index = target},
                                 .arg2 = {.input = (bstate & BUTTON4_PRESSED)
                                                       ? BUTTON4_PRESSED
                                                       : BUTTON5_PRESSED}});
                }
            }
        }
        return;
    }
    default:
        tuiAppPushMessage((TuiMsg){.type = MsgInput, .arg1 = {.input = ch}});
        break;
    }
}

static void tuiAppMsgHandle() {
    TuiMsg msg;
    pthread_mutex_lock(&tuiApp.msgQueueLock);

    while (!queueTuiMsgIsEmpty(&tuiApp.msgQueue)) {
        CHECKED_QUEUE_TUI_MSG_FRONT(&tuiApp.msgQueue, &msg);
        queueTuiMsgPop(&tuiApp.msgQueue);
        switch (msg.type) {
        case MsgCursorNext:
            tuiAppNavigate(false);
            break;
        case MsgCursorPrev:
            tuiAppNavigate(true);
            break;
        case MsgFocusEnter:
        case MsgFocusLeave: {
            ControlRegEntry *cur;
            CHECKED_REGENTRY_INDEX(&tuiApp.controlRegistry, msg.arg1.index,
                                   &cur);
            if (cur->ptr != NULL && cur->ptr->vtable.msgHandler != NULL) {
                cur->ptr->vtable.msgHandler(cur->ptr, msg);
            }
            break;
        }
        case MsgMouse: {
            ControlRegEntry *cur;
            CHECKED_REGENTRY_INDEX(&tuiApp.controlRegistry, msg.arg1.index,
                                   &cur);
            if (cur->ptr != NULL && cur->ptr->vtable.msgHandler != NULL) {
                cur->ptr->vtable.msgHandler(cur->ptr, msg);
            }
            break;
        }
        case MsgInput: {
            ControlRegEntry *cur;
            CHECKED_REGENTRY_INDEX(&tuiApp.controlRegistry,
                                   tuiApp.userCursor.index, &cur);
            if (cur->ptr != NULL && cur->ptr->vtable.msgHandler != NULL) {
                cur->ptr->vtable.msgHandler(cur->ptr, msg);
            }
            break;
        }
        case MsgRefresh:
        case MsgResize: {
            tuiAppUpdateViewArea();

            ControlRegEntry *curEntry;
            ensureRenderStkCap(
                arrayControlRegEntrySize(&tuiApp.controlRegistry));
            gRenderStk.size = 0;
            arrayIndexPushBack(&gRenderStk, tuiApp.curRoot);
            while (arrayIndexSize(&gRenderStk) > 0) {
                Index curIndex;
                CHECKED_ARRAY_INDEX_GET(
                    &gRenderStk, arrayIndexSize(&gRenderStk) - 1, &curIndex);
                arrayIndexPopBack(&gRenderStk);
                CHECKED_REGENTRY_INDEX(&tuiApp.controlRegistry, curIndex,
                                       &curEntry);
                if (curEntry->ptr != NULL &&
                    curEntry->ptr->vtable.msgHandler != NULL) {
                    curEntry->ptr->vtable.msgHandler(curEntry->ptr, msg);
                }
                if (curIndex != tuiApp.curRoot && curEntry->sibling != 0) {
                    arrayIndexPushBack(&gRenderStk, curEntry->sibling);
                }
                if (curEntry->child != 0) {
                    arrayIndexPushBack(&gRenderStk, curEntry->child);
                }
            }
            break;
        }
        case MsgFetch: {
            ControlRegEntry *container;
            CHECKED_REGENTRY_INDEX(&tuiApp.controlRegistry, msg.arg1.index,
                                   &container);
            Index curIdx = container->child;
            ControlRegEntry *cur;
            while (curIdx != 0) {
                CHECKED_REGENTRY_INDEX(&tuiApp.controlRegistry, curIdx, &cur);
                msg.arg2.fetchRecv(container->ptr, cur->ptr);
                curIdx = cur->sibling;
            }
            break;
        }
        default:
            break;
        }
        if (msg.type == MsgRefresh || msg.type == MsgResize) {
            tuiApp.fastRefresh = true;
        } else {
            tuiApp.fastRefresh = false;
        }
    }
    pthread_mutex_unlock(&tuiApp.msgQueueLock);
}

static void tuiAppControlUpdate() {
    ControlRegEntry *curEntry;
    ensureRenderStkCap(0);
    gRenderStk.size = 0;
    arrayIndexPushBack(&gRenderStk, tuiApp.curRoot);
    while (arrayIndexSize(&gRenderStk) > 0) {
        Index curIndex;
        CHECKED_ARRAY_INDEX_GET(&gRenderStk, arrayIndexSize(&gRenderStk) - 1,
                                &curIndex);
        arrayIndexPopBack(&gRenderStk);
        CHECKED_REGENTRY_INDEX(&tuiApp.controlRegistry, curIndex, &curEntry);
        if (curIndex != 0 && curEntry->ptr->windowHandler != NULL &&
            curEntry->ptr->vtable.update != NULL) {
            curEntry->ptr->vtable.update(curEntry->ptr);
        }
        if (curIndex != tuiApp.curRoot && curEntry->sibling != 0) {
            arrayIndexPushBack(&gRenderStk, curEntry->sibling);
        }
        if (curEntry->child != 0 && curEntry->ptr != NULL) {
            arrayIndexPushBack(&gRenderStk, curEntry->child);
        }
    }
}

static void tuiAppRender() {

    // DEBUG:
    // werase(pViewArea->windowHandler);
    // box(pViewArea->windowHandler, 0, 0);
    // wnoutrefresh(pViewArea->windowHandler);

    ControlRegEntry *curEntry;
    ensureRenderStkCap(0);
    gRenderStk.size = 0;
    arrayIndexPushBack(&gRenderStk, tuiApp.curRoot);
    while (arrayIndexSize(&gRenderStk) > 0) {
        Index curIndex;
        CHECKED_ARRAY_INDEX_GET(&gRenderStk, arrayIndexSize(&gRenderStk) - 1,
                                &curIndex);
        arrayIndexPopBack(&gRenderStk);
        CHECKED_REGENTRY_INDEX(&tuiApp.controlRegistry, curIndex, &curEntry);
        if (curIndex != 0 && curEntry->ptr->windowHandler != NULL &&
            curEntry->ptr->vtable.draw != NULL && curEntry->ptr->visible) {
            curEntry->ptr->vtable.draw(curEntry->ptr);
        }
        if (curIndex != tuiApp.curRoot && curEntry->sibling != 0) {
            arrayIndexPushBack(&gRenderStk, curEntry->sibling);
        }
        if (curEntry->child != 0 && curEntry->ptr != NULL &&
            curEntry->ptr->visible) {
            arrayIndexPushBack(&gRenderStk, curEntry->child);
        }
    }

    doupdate();
}

static void tuiAppChangeRoot(Index root) {
    ControlRegEntry *curEntry;
    QueueIndex q;
    queueIndexInit(&q, USE_DEFAULT_CAPACITY);
    if (tuiApp.isRunning) {
        queueIndexPush(&q, tuiApp.curRoot);
        while (!queueIndexIsEmpty(&q)) {
            Index curIndex;
            CHECKED_QUEUE_INDEX_FRONT(&q, &curIndex);
            queueIndexPop(&q);
            CHECKED_REGENTRY_INDEX(&tuiApp.controlRegistry, curIndex,
                                   &curEntry);
            if (curIndex != 0) {
                controlDeinstantiate(curEntry->ptr);
            }
            if (curEntry->child != 0) {
                queueIndexPush(&q, curEntry->child);
            }
            if (curEntry->sibling != 0) {
                queueIndexPush(&q, curEntry->sibling);
                CHECKED_REGENTRY_INDEX(&tuiApp.controlRegistry,
                                       curEntry->sibling, &curEntry);
            }
        }
    }
    tuiApp.curRoot = root;
    queueIndexPush(&q, tuiApp.curRoot);
    if (tuiApp.curRoot != 0) {
        CHECKED_REGENTRY_INDEX(&tuiApp.controlRegistry, tuiApp.curRoot,
                               &curEntry);
        controlInstantiate(curEntry->ptr, NULL);
    }
    while (!queueIndexIsEmpty(&q)) {
        Index curIndex;
        CHECKED_QUEUE_INDEX_FRONT(&q, &curIndex);
        queueIndexPop(&q);
        CHECKED_REGENTRY_INDEX(&tuiApp.controlRegistry, curIndex, &curEntry);
        if (curEntry->child != 0) {
            ControlRegEntry *parent = curEntry;
            Index childIdx = parent->child;
            while (childIdx != 0) {
                ControlRegEntry *child;
                queueIndexPush(&q, childIdx);
                CHECKED_REGENTRY_INDEX(&tuiApp.controlRegistry, childIdx,
                                       &child);
                controlInstantiate(child->ptr, parent->ptr);
                childIdx = child->sibling;
            }
        }
    }
    tuiAppRefreshNavChain();
    queueIndexDeinit(&q);
}

static void tuiAppRefreshNavChain() {
    tuiApp.navChainCache.size = 0;
    ControlRegEntry *curEntry;
    ensureRenderStkCap(0);
    gRenderStk.size = 0;
    arrayIndexPushBack(&gRenderStk, tuiApp.curRoot);
    while (arrayIndexSize(&gRenderStk) > 0) {
        Index curIndex;
        CHECKED_ARRAY_INDEX_GET(&gRenderStk, arrayIndexSize(&gRenderStk) - 1,
                                &curIndex);
        arrayIndexPopBack(&gRenderStk);
        CHECKED_REGENTRY_INDEX(&tuiApp.controlRegistry, curIndex, &curEntry);
        if (curIndex != 0 && curEntry->ptr->focusable &&
            curEntry->ptr->visible) {
            arrayIndexPushBack(&tuiApp.navChainCache, curIndex);
        }
        if (curIndex != tuiApp.curRoot && curEntry->sibling != 0) {
            arrayIndexPushBack(&gRenderStk, curEntry->sibling);
        }
        if (curEntry->child != 0 && curEntry->ptr->visible) {
            arrayIndexPushBack(&gRenderStk, curEntry->child);
        }
    }

    if (arrayIndexSize(&tuiApp.navChainCache) == 0) {
        return;
    }

    // correct the real index to registry
    Index tmp;
    bool found = false;
    if (tuiApp.userCursor.indexOfCache <
        arrayIndexSize(&tuiApp.navChainCache)) {
        CHECKED_ARRAY_INDEX_GET(&tuiApp.navChainCache,
                                tuiApp.userCursor.indexOfCache, &tmp);
    } else {
        tmp = 0;
    }
    if (tmp != tuiApp.userCursor.index) {
        ControlRegEntry *cur;
        // The root is the only entry who has NULL ptr
        if (tuiApp.userCursor.index != 0) {
            CHECKED_REGENTRY_INDEX(&tuiApp.controlRegistry,
                                   tuiApp.userCursor.index, &cur);
            cur->ptr->focused = false;
            tuiAppPushMessage(
                (TuiMsg){.type = MsgFocusLeave,
                         .arg1 = {.index = tuiApp.userCursor.index}});
        }
        size_t size = arrayIndexSize(&tuiApp.navChainCache);
        for (Index i = 0; i < size; ++i) {
            CHECKED_ARRAY_INDEX_GET(&tuiApp.navChainCache, i, &tmp);
            if (tmp == tuiApp.userCursor.index) {
                tuiApp.userCursor.indexOfCache = i;
                found = true;
                break;
            }
        }
        if (!found) {
            tuiApp.userCursor.indexOfCache = 0;
            CHECKED_ARRAY_INDEX_GET(&tuiApp.navChainCache,
                                    tuiApp.userCursor.indexOfCache,
                                    &tuiApp.userCursor.index);
        }
        CHECKED_REGENTRY_INDEX(&tuiApp.controlRegistry, tuiApp.userCursor.index,
                               &cur);
        cur->ptr->focused = true;
        tuiAppPushMessage((TuiMsg){.type = MsgFocusEnter,
                                   .arg1 = {.index = tuiApp.userCursor.index}});
    }
}

static void tuiAppNavigate(bool isBack) {
    ControlRegEntry *cur;
    Index nextIdx = tuiApp.userCursor.indexOfCache;

    CHECKED_REGENTRY_INDEX(&tuiApp.controlRegistry, tuiApp.userCursor.index,
                           &cur);
    cur->ptr->focused = false;
    tuiAppPushMessage((TuiMsg){.type = MsgFocusLeave,
                               .arg1 = {.index = tuiApp.userCursor.index}});

    size_t startIdx = nextIdx;
    do {
        if (!isBack) {
            if (nextIdx < arrayIndexSize(&tuiApp.navChainCache) - 1) {
                ++nextIdx;
            } else {
                nextIdx = 0;
            }
        } else {
            if (nextIdx > 0) {
                --nextIdx;
            } else {
                nextIdx = arrayIndexSize(&tuiApp.navChainCache) - 1;
            }
        }

        Index tmp;
        CHECKED_ARRAY_INDEX_GET(&tuiApp.navChainCache, nextIdx, &tmp);
        CHECKED_REGENTRY_INDEX(&tuiApp.controlRegistry, tmp, &cur);

        if (nextIdx == startIdx) {
            nextIdx = tuiApp.userCursor.indexOfCache;
            CHECKED_ARRAY_INDEX_GET(&tuiApp.navChainCache, nextIdx, &tmp);
            CHECKED_REGENTRY_INDEX(&tuiApp.controlRegistry, tmp, &cur);
            break;
        }
    } while (!cur->ptr->visible);

    tuiApp.userCursor.indexOfCache = nextIdx;
    CHECKED_ARRAY_INDEX_GET(&tuiApp.navChainCache,
                            tuiApp.userCursor.indexOfCache,
                            &tuiApp.userCursor.index);
    CHECKED_REGENTRY_INDEX(&tuiApp.controlRegistry, tuiApp.userCursor.index,
                           &cur);
    cur->ptr->focused = true;
    tuiAppPushMessage((TuiMsg){.type = MsgFocusEnter,
                               .arg1 = {.index = tuiApp.userCursor.index}});
}

static bool findFocusableInNavChain(Index widgetIdx, Index *outPos) {
    size_t size = arrayIndexSize(&tuiApp.navChainCache);
    Index i;
    for (i = 0; i < size; ++i) {
        Index cur;
        CHECKED_ARRAY_INDEX_GET(&tuiApp.navChainCache, i, &cur);
        if (cur == widgetIdx) {
            *outPos = i;
            return true;
        }
    }
    return false;
}

static Index findWidgetAtMouse(int screenY, int screenX) {
    Index deepest = 0;
    ControlRegEntry *curEntry;
    ensureRenderStkCap(0);
    gRenderStk.size = 0;
    arrayIndexPushBack(&gRenderStk, tuiApp.curRoot);
    while (arrayIndexSize(&gRenderStk) > 0) {
        Index curIndex;
        CHECKED_ARRAY_INDEX_GET(&gRenderStk, arrayIndexSize(&gRenderStk) - 1,
                                &curIndex);
        arrayIndexPopBack(&gRenderStk);
        CHECKED_REGENTRY_INDEX(&tuiApp.controlRegistry, curIndex, &curEntry);
        if (curIndex != 0 && curEntry->ptr->visible &&
            curEntry->ptr->windowHandler != NULL) {
            int localY = screenY;
            int localX = screenX;
            if (wmouse_trafo(curEntry->ptr->windowHandler, &localY, &localX,
                             FALSE)) {
                deepest = curIndex;
            }
        }
        if (curIndex != tuiApp.curRoot && curEntry->sibling != 0) {
            arrayIndexPushBack(&gRenderStk, curEntry->sibling);
        }
        if (curEntry->child != 0) {
            arrayIndexPushBack(&gRenderStk, curEntry->child);
        }
    }
    return deepest;
}

void tuiAppRefresh() {
    tuiAppRefreshNavChain();
    
    tuiAppPushMessage((TuiMsg){.type = MsgRefresh});
}

void tuiAppVisibilityChange(Control *dest, bool visible) {
    dest->visible = visible;
    tuiAppUpdateViewArea();
    if (dest->focusable) {
        tuiAppRefresh();
    }
}