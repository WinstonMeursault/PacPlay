/**
 * @file serverTUI.c
 * @brief Server TUI — key display, unlock, and main control pages.
 *
 * @date 2026-06-10
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

#include "serverTUI.h"
#include "server/gameControl.h"
#include "server/keyManager.h"
#include "server/serverLog.h"
#include "utils.h"

#include <openssl/crypto.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define TUI_BTN_HEIGHT 3
#define TUI_INIT_BTN_WIDTH 17
#define TUI_UNLOCK_BTN_WIDTH 10
#define TUI_INIT_GRID_WIDTH 72
#define TUI_INIT_GRID_HEIGHT 10
#define TUI_START_GRID_WIDTH 72
#define TUI_START_GRID_HEIGHT 12
#define TUI_MAIN_PANEL_X 2
#define TUI_MK_INPUT_WIDTH 68
#define TUI_CENTER_X(objW) ((TUI_START_GRID_WIDTH - (objW)) / 2)
#define TUI_LOG_MAX_LINES 1000
#define TUI_CMD_LINE_BUF_SIZE (INPUTBOX_BUF_MAX_LEN + 32)

/* Main page — tab bar */
#define TUI_TAB_BTN_HEIGHT 3
#define TUI_TAB_BTN_WIDTH 11
#define TUI_TAB_BAR_Y 1
#define TUI_TAB_LOG_X TUI_MAIN_PANEL_X
#define TUI_TAB_CMD_X (TUI_TAB_LOG_X + TUI_TAB_BTN_WIDTH)

/* Main page — content area (left panel, below tab bar) */
#define TUI_CONTENT_Y (TUI_TAB_BAR_Y + TUI_TAB_BTN_HEIGHT)
#define TUI_CONTENT_HEIGHT 16
#define TUI_CONTENT_WIDTH 52
#define TUI_CONTENT_X TUI_MAIN_PANEL_X

/* Main page — server status (right panel, full height) */
#define TUI_STATUS_BOX_WIDTH 20
#define TUI_STATUS_BOX_HEIGHT 22
#define TUI_STATUS_BOX_X (TUI_CONTENT_X + TUI_CONTENT_WIDTH + 1)
#define TUI_STATUS_BOX_Y 1

/* Main page — shared command input (bottom of left panel) */
#define TUI_CMD_INPUT_WIDTH TUI_CONTENT_WIDTH
#define TUI_CMD_INPUT_X TUI_MAIN_PANEL_X
#define TUI_CMD_INPUT_Y 19

static Server *server;
static bool isFirstRun;
static const char *masterKeyDisplay;
static bool cmdPromptCleared;

/* Forward declarations — pages used across callback boundaries */
static ControlPage startPage;
static ControlPage mainPage;

/* ─────────────────────────────── Init Page ──────────────────────────────── */

static ControlPage initPage;
static ControlGrid initGrid;
static ControlLabel initPrompt;
static ControlLabel initMasterKeyLabel;
static ControlButton initConfirmBtn;

static void initGridResize(ControlGrid *self) {
    self->base.width = MIN(TUI_INIT_GRID_WIDTH, pViewArea->width);
    self->base.height = MIN(TUI_INIT_GRID_HEIGHT, pViewArea->height);
    self->base.x = (pViewArea->width - self->base.width) / 2;
    self->base.y = (pViewArea->height - self->base.height) / 2;
}

static void initConfirmBtnOnClick(ControlButton *self) {
    (void)self;
    if (masterKeyDisplay != NULL) {
        OPENSSL_cleanse((void *)masterKeyDisplay, strlen(masterKeyDisplay));
    }
    tuiAppChangePage(&startPage);
}

/* ─────────────────────────────── Start Page ─────────────────────────────── */

static ControlPage startPage;
static ControlGrid startGrid;
static ControlLabel startPrompt;
static ControlInputBox startMasterKeyInput;
static ControlLabel startStatus;
static ControlButton startUnlockBtn;

static void startGridResize(ControlGrid *self) {
    self->base.width = MIN(TUI_START_GRID_WIDTH, pViewArea->width);
    self->base.height = MIN(TUI_START_GRID_HEIGHT, pViewArea->height);
    self->base.x = (pViewArea->width - self->base.width) / 2;
    self->base.y = (pViewArea->height - self->base.height) / 2;
}

static void tryUnlock(void) {
    startStatus.base.visible = false;
    char key[INPUTBOX_BUF_MAX_LEN] = {0};
    strncpy(key, startMasterKeyInput.buf, startMasterKeyInput.curLen);
    OPENSSL_cleanse(startMasterKeyInput.buf, INPUTBOX_BUF_MAX_LEN);
    if (serverUnlockWithMK(server, key) == SERVER_SUCC) {
        OPENSSL_cleanse(key, INPUTBOX_BUF_MAX_LEN);
        startMasterKeyInput.curLen = 0;
        startMasterKeyInput.curLoc = 0;
        if (serverLaunch(server) != SERVER_SUCC) {
            tuiAppStop();
            return;
        }
        tuiAppChangePage(&mainPage);
        return;
    }
    strncpy(startStatus.text, "Invalid Master Key. Please try again.",
            LABEL_TEXT_MAXLEN);
    startStatus.text[LABEL_TEXT_MAXLEN - 1] = '\0';
    startStatus.base.visible = true;
    tuiAppRefresh();
}

static void startUnlockBtnOnClick(ControlButton *self) {
    (void)self;
    tryUnlock();
}

static void startInputSubmit(ControlInputBox *self) {
    (void)self;
    tryUnlock();
}

/* ─────────────────────────────── Main Page ──────────────────────────────── */

static ControlPage mainPage;
static ControlGrid mainGrid;
static ControlButton tabLogBtn;
static ControlButton tabCmdBtn;
static ControlScrollTextBox logScrollBox;
static ControlScrollTextBox cmdScrollBox;
static ControlTextBox serverStatusBox;
static ControlInputBox commandInput;

/* Tab switching callbacks */
static void tabLogBtnOnClick(ControlButton *self) {
    (void)self;
    logScrollBox.base.base.visible = true;
    cmdScrollBox.base.base.visible = false;
    // tuiAppRefresh();
}

static void tabCmdBtnOnClick(ControlButton *self) {
    (void)self;
    logScrollBox.base.base.visible = false;
    cmdScrollBox.base.base.visible = true;
    // tuiAppRefresh();
}

static void mainGridResize(ControlGrid *self) {
    self->base.width = pViewArea->width;
    self->base.height = pViewArea->height;
    self->base.x = 0;
    self->base.y = 0;
}

static void mainGridUpdate(ControlGrid *self) {
    (void)self;

    /* Update log scroll box */
    char **lines;
    int count;
    if (serverLogFetch(LogLevelTrace, &lines, &count) == 0) {
        for (int i = 0; i < count; i++) {
            controlScrollTextBoxAppend(&logScrollBox, lines[i]);
        }
        serverLogFetchFree(lines, count);
    }

    /* Update server status panel */
    time_t uptime = getCurrentTimestamp() - server->startTime;
    int hours = (int)(uptime / 3600);
    int minutes = (int)((uptime % 3600) / 60);
    int seconds = (int)(uptime % 60);
    (void)snprintf(serverStatusBox.text, TEXTBOX_TEXT_MAXLEN,
                   "Server Status\n\n"
                   "Connections: %d\n"
                   "Active Rooms: %d\n"
                   "Uptime: %02d:%02d:%02d",
                   server->clientCount, server->activeRoomCount, hours, minutes,
                   seconds);
    serverStatusBox.textLen = strlen(serverStatusBox.text);
}

static void cmdScrollBoxClear(void) {
    if (cmdScrollBox.base.text != NULL) {
        cmdScrollBox.base.text[0] = '\0';
        cmdScrollBox.base.textLen = 0;
        cmdScrollBox.base.viewBegin = 0;
    }
}

static void commandInputSubmit(ControlInputBox *self) {
    (void)self;
    commandInput.buf[commandInput.curLen] = '\0';

    if (commandInput.curLen == 0) {
        return;
    }

    /* Clear initial prompt on first command */
    if (!cmdPromptCleared) {
        cmdScrollBoxClear();
        cmdPromptCleared = true;
    }

    /* Echo the input command */
    char line[TUI_CMD_LINE_BUF_SIZE];
    (void)snprintf(line, sizeof(line), "> %s\n", commandInput.buf);
    controlScrollTextBoxAppend(&cmdScrollBox, line);

    if (strcmp(commandInput.buf, "exit") == 0) {
        controlScrollTextBoxAppend(&cmdScrollBox, "Server shutting down...\n");
        serverShutdown(server);
        tuiAppStop();
        return;
    }

    if (strncmp(commandInput.buf, "gamectl ", 8) == 0) {
        char *sub = commandInput.buf + 8;
        if (strncmp(sub, "list", 4) == 0 &&
            (sub[4] == '\0' || sub[4] == ' ')) {
            gameCtlList(server, &cmdScrollBox);
        } else if (strncmp(sub, "update ", 7) == 0) {
            gameCtlUpdate(server, sub + 7, &cmdScrollBox);
        } else if (strncmp(sub, "delete ", 7) == 0) {
            uint32_t gid = (uint32_t)strtoul(sub + 7, NULL, 10);
            gameCtlDelete(server, gid, &cmdScrollBox);
        } else if (strncmp(sub, "scan", 4) == 0 &&
                   (sub[4] == '\0' || sub[4] == ' ')) {
            gameCtlScan(server, &cmdScrollBox);
        } else if (strncmp(sub, "info ", 5) == 0) {
            uint32_t gid = (uint32_t)strtoul(sub + 5, NULL, 10);
            gameCtlInfo(server, gid, &cmdScrollBox);
        } else {
            controlScrollTextBoxAppend(
                &cmdScrollBox,
                "Usage: gamectl <list|update|delete|scan|info>\n");
        }
        commandInput.curLen = 0;
        commandInput.curLoc = 0;
        commandInput.buf[0] = '\0';
        return;
    }

    /* Unrecognised command */
    (void)snprintf(line, sizeof(line), "Error: unknown command '%s'\n",
                   commandInput.buf);
    controlScrollTextBoxAppend(&cmdScrollBox, line);

    commandInput.curLen = 0;
    commandInput.curLoc = 0;
    commandInput.buf[0] = '\0';
}

static void logScrollBoxResize(ControlScrollTextBox *self) {
    self->base.base.width = pViewArea->width - TUI_STATUS_BOX_WIDTH - 3;
    self->base.base.height = pViewArea->height - 2 - 3 - TUI_TAB_BTN_HEIGHT;
}

static void serverStatusBoxResize(ControlTextBox *self) {
    self->base.height = pViewArea->height - 2;
    self->base.x = pViewArea->width - TUI_STATUS_BOX_WIDTH - 1;
}

static void commandInputResize(ControlInputBox *self) {
    self->base.y = pViewArea->height - 3 - 1;
    self->base.width = pViewArea->width - 3 - TUI_STATUS_BOX_WIDTH;
}

/* ─────────────────────────────── Init & Entry ───────────────────────────── */

static void tuiServerInit(void) {
    /* Init Page */
    controlPageConstruct(&initPage);
    controlGridConstruct(&initGrid, TUI_INIT_GRID_HEIGHT, TUI_INIT_GRID_WIDTH,
                         0, 0, LayoutNone, 0, 0, NULL, initGridResize, NULL,
                         NULL, NULL);
    controlLabelConstruct(&initPrompt,
                          "Server initialized. Save this Master Key "
                          "(shown only once):",
                          0, 1, 2, NULL, NULL, NULL, NULL);
    controlLabelConstruct(&initMasterKeyLabel,
                          masterKeyDisplay != NULL ? masterKeyDisplay : "", 0,
                          3, 2, NULL, NULL, NULL, NULL);
    controlButtonConstruct(&initConfirmBtn, TUI_BTN_HEIGHT, TUI_INIT_BTN_WIDTH,
                           6, TUI_CENTER_X(TUI_INIT_BTN_WIDTH),
                           "I Have Saved It", NULL, initConfirmBtnOnClick, NULL,
                           NULL, NULL);

    tuiAppControlRegister((Control *)&initPage, NULL);
    tuiAppControlRegister((Control *)&initGrid, (Control *)&initPage);
    tuiAppControlRegister((Control *)&initPrompt, (Control *)&initGrid);
    tuiAppControlRegister((Control *)&initMasterKeyLabel, (Control *)&initGrid);
    tuiAppControlRegister((Control *)&initConfirmBtn, (Control *)&initGrid);

    /* Start Page */
    controlPageConstruct(&startPage);
    controlGridConstruct(&startGrid, TUI_START_GRID_HEIGHT,
                         TUI_START_GRID_WIDTH, 0, 0, LayoutNone, 0, 0, NULL,
                         startGridResize, NULL, NULL, NULL);
    controlLabelConstruct(&startPrompt, "Enter Master Key to unlock:", 0, 1, 2,
                          NULL, NULL, NULL, NULL);
    controlInputBoxConstruct(&startMasterKeyInput, TUI_MK_INPUT_WIDTH, 3, 2,
                             true, NULL, NULL, startInputSubmit, NULL, NULL);
    controlLabelConstruct(&startStatus, "", TUI_START_GRID_WIDTH - 4, 6, 2,
                          NULL, NULL, NULL, NULL);
    startStatus.base.visible = false;
    controlButtonConstruct(&startUnlockBtn, TUI_BTN_HEIGHT,
                           TUI_UNLOCK_BTN_WIDTH, 7,
                           TUI_CENTER_X(TUI_UNLOCK_BTN_WIDTH), "Unlock", NULL,
                           startUnlockBtnOnClick, NULL, NULL, NULL);

    tuiAppControlRegister((Control *)&startPage, NULL);
    tuiAppControlRegister((Control *)&startGrid, (Control *)&startPage);
    tuiAppControlRegister((Control *)&startPrompt, (Control *)&startGrid);
    tuiAppControlRegister((Control *)&startMasterKeyInput,
                          (Control *)&startGrid);
    tuiAppControlRegister((Control *)&startStatus, (Control *)&startGrid);
    tuiAppControlRegister((Control *)&startUnlockBtn, (Control *)&startGrid);

    /* Main Page */
    controlPageConstruct(&mainPage);
    controlGridConstruct(&mainGrid, 0, 0, 0, 0, LayoutNone, 0, 0, NULL,
                         mainGridResize, NULL, mainGridUpdate, NULL);

    /* Tab bar */
    controlButtonConstruct(&tabLogBtn, TUI_TAB_BTN_HEIGHT, TUI_TAB_BTN_WIDTH,
                           TUI_TAB_BAR_Y, TUI_TAB_LOG_X, "Log", NULL,
                           tabLogBtnOnClick, NULL, NULL, NULL);
    controlButtonConstruct(&tabCmdBtn, TUI_TAB_BTN_HEIGHT, TUI_TAB_BTN_WIDTH,
                           TUI_TAB_BAR_Y, TUI_TAB_CMD_X, "Command", NULL,
                           tabCmdBtnOnClick, NULL, NULL, NULL);

    /* Tab content — Log (visible by default) */
    controlScrollTextBoxConstruct(
        &logScrollBox, TUI_CONTENT_HEIGHT, TUI_CONTENT_WIDTH, TUI_CONTENT_Y,
        TUI_CONTENT_X, TUI_LOG_MAX_LINES, NULL, logScrollBoxResize, NULL, NULL);

    /* Tab content — Command (hidden by default) */
    controlScrollTextBoxConstruct(
        &cmdScrollBox, TUI_CONTENT_HEIGHT, TUI_CONTENT_WIDTH, TUI_CONTENT_Y,
        TUI_CONTENT_X, TUI_LOG_MAX_LINES, NULL, logScrollBoxResize, NULL, NULL);
    cmdScrollBox.base.base.visible = false;
    controlScrollTextBoxAppend(&cmdScrollBox, "Type a command below...\n");

    /* Right panel — server status (full height, always visible) */
    controlTextBoxConstruct(&serverStatusBox, TUI_STATUS_BOX_HEIGHT,
                            TUI_STATUS_BOX_WIDTH, TUI_STATUS_BOX_Y,
                            TUI_STATUS_BOX_X, "Server Status", NULL,
                            serverStatusBoxResize, NULL, NULL);

    /* Shared command input (bottom of left panel) */
    controlInputBoxConstruct(
        &commandInput, TUI_CMD_INPUT_WIDTH, TUI_CMD_INPUT_Y, TUI_CMD_INPUT_X,
        false, NULL, commandInputResize, commandInputSubmit, NULL, NULL);

    tuiAppControlRegister((Control *)&mainPage, NULL);
    tuiAppControlRegister((Control *)&mainGrid, (Control *)&mainPage);
    tuiAppControlRegister((Control *)&tabLogBtn, (Control *)&mainGrid);
    tuiAppControlRegister((Control *)&tabCmdBtn, (Control *)&mainGrid);
    tuiAppControlRegister((Control *)&logScrollBox, (Control *)&mainGrid);
    tuiAppControlRegister((Control *)&cmdScrollBox, (Control *)&mainGrid);
    tuiAppControlRegister((Control *)&serverStatusBox, (Control *)&mainGrid);
    tuiAppControlRegister((Control *)&commandInput, (Control *)&mainGrid);
}

void tuiServerEntry(Server *serverInstance, bool firstRun,
                    const char *masterKeyHex) {
    server = serverInstance;
    isFirstRun = firstRun;
    masterKeyDisplay = masterKeyHex;
    logSetQuiet(true);
    tuiAppInit();
    tuiServerInit();
    if (isFirstRun) {
        tuiAppStart(&initPage);
    } else {
        tuiAppStart(&startPage);
    }
}
