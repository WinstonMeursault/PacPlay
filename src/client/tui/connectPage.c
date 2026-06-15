/**
 * @file connectPage.c
 * @brief
 *
 * @date 2026-06-13
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

#include "connectPage.h"
#include "clientTUI.h"
#include "utils.h"
#include <ctype.h>
#include <pthread.h>
#include <stdlib.h>

#define TUI_CONNECT_HEIGHT 16
#define TUI_CONNECT_WIDTH 42

struct {
    uint8_t addr[4];
    char addrStr[3 * 4 + 3 + 2];
    uint16_t port;
} serverAddr;

// Connect page
ControlPage connectPage;
ControlGrid connectGrid;
ControlLabel connectPrompt;
ControlLabel connectAddressLabel;
ControlInputBox connectAddressBox;
ControlLabel connectPortLabel;
ControlInputBox connectPortBox;
ControlLabel connectStatusLabel;
TuiClientColorAttr statusColor = ColorAttrRed;
ControlButton connectButton;
ControlButton connectExitButton;

static void connectGridResize(ControlGrid *self) {
    self->base.width = MIN(TUI_CONNECT_WIDTH, pViewArea->width);
    self->base.height = MIN(TUI_CONNECT_HEIGHT, pViewArea->height);
    self->base.x = MAX(0, pViewArea->width / 2 - TUI_CONNECT_WIDTH / 2);
    self->base.y = MAX(0, pViewArea->height / 2 - TUI_CONNECT_HEIGHT / 2);
}

static void connectStatusDraw(ControlLabel *self) {
    (void)self;
    werase(self->base.windowHandler);
    if (self->text != NULL) {
        wattron(self->base.windowHandler, COLOR_PAIR(statusColor));
        mvwprintw(self->base.windowHandler, 0, 0, "%s", self->text);
        wattroff(self->base.windowHandler, COLOR_PAIR(statusColor));
    }
    wnoutrefresh(self->base.windowHandler);
}

static bool checkInput() {
    char portStr[INPUTBOX_BUF_MAX_LEN];
    strncpy(portStr, connectPortBox.buf, connectPortBox.curLen);
    long port = strtol(portStr, NULL, 10);
    if (!(0 <= port && port <= 65535)) {
        return false;
    } else {
        serverAddr.port = port;
    }

    if (strncmp(connectAddressBox.buf, "localhost",
                MIN(connectAddressBox.curLen, 9)) == 0) {
        serverAddr.addr[0] = 127;
        serverAddr.addr[1] = 0;
        serverAddr.addr[2] = 0;
        serverAddr.addr[3] = 1;
        return true;
    }

    int idx = 0;
    int curNum = 0;
    int digitCnt = 0;
    for (size_t i = 0; i < connectAddressBox.curLen; ++i) {
        char cur = connectAddressBox.buf[i];
        if (!isdigit(cur) && cur != '.') {
            return false;
        }
        if (isdigit(cur)) {
            if (curNum == 0 && digitCnt != 0) {
                return false;
            }
            curNum = curNum * 10 + cur - '0';
            ++digitCnt;
            if (curNum > 255) {
                return false;
            }
        } else if (cur == '.') {
            if (digitCnt == 0 || idx >= 4) {
                return false;
            }
            serverAddr.addr[idx] = curNum;
            ++idx;
            curNum = 0;
            digitCnt = 0;
        }
    }
    if (digitCnt == 0 || idx != 3) {
        return false;
    }
    serverAddr.addr[idx] = curNum;
    return true;
}

static void *setupRunner(void *arg) {
    (void)arg;
    int connectRes = clientConnect(client, serverAddr.addrStr, serverAddr.port);
    if (connectRes != CLIENT_SUCC) {
        strcpy(connectStatusLabel.text, "Cannot connect to the address");
        statusColor = ColorAttrRed;
        tuiAppVisibilityChange((Control *)&connectStatusLabel, true);
    } else {
        tuiAppChangePage(&loginPage);
    }
    return NULL;
}

static void connectButtonOnClick(ControlButton *self) {
    (void)self;
    bool res = checkInput();
    if (res) {
        sprintf(serverAddr.addrStr, "%d.%d.%d.%d", serverAddr.addr[0],
                serverAddr.addr[1], serverAddr.addr[2], serverAddr.addr[3]);
        strcpy(connectStatusLabel.text, "Connecting...");
        statusColor = ColorAttrDefault;
        tuiAppVisibilityChange((Control *)&connectStatusLabel, true);
        pthread_t tid;
        pthread_create(&tid, NULL, setupRunner, NULL);
        pthread_detach(tid);
    } else {
        statusColor = ColorAttrRed;
        strcpy(connectStatusLabel.text, "Invalid address or port");
        tuiAppVisibilityChange((Control *)&connectStatusLabel, true);
    }
}

static void exitBtn(ControlButton *self) {
    (void)*self;
    tuiAppStop();
}

void tuiClientConnectPageInit() {
    controlPageConstruct(&connectPage);
    controlGridConstruct(&connectGrid, 0, 0, 0, 0, LayoutNone, 0, 0, NULL,
                         connectGridResize, NULL, NULL);
    controlLabelConstruct(&connectPrompt, "Connect to server", 0, 1,
                          TUI_CONNECT_WIDTH / 2 - 9, NULL, NULL, NULL);
    controlLabelConstruct(&connectAddressLabel, "Server address: ", 0, 4, 2,
                          NULL, NULL, NULL);
    controlInputBoxConstruct(&connectAddressBox, 20, 3, 19, false, NULL, NULL,
                             NULL, NULL);
    controlLabelConstruct(&connectPortLabel, "Port: ", 0, 7, 2, NULL, NULL,
                          NULL);
    controlInputBoxConstruct(&connectPortBox, 20, 6, 19, false, NULL, NULL,
                             NULL, NULL);
    controlLabelConstruct(&connectStatusLabel, "", TUI_CONNECT_WIDTH - 3,
                          TUI_CONNECT_HEIGHT - TUI_BTN_HEIGHT - 3, 2,
                          connectStatusDraw, NULL, NULL);
    tuiAppVisibilityChange((Control *)&connectStatusLabel, false);
    controlButtonConstruct(&connectButton, TUI_BTN_HEIGHT, TUI_BTN_WIDTH,
                           TUI_CONNECT_HEIGHT - TUI_BTN_HEIGHT - 1,
                           TUI_CONNECT_WIDTH - 2 * TUI_BTN_WIDTH - 3, "Connect",
                           NULL, connectButtonOnClick, NULL, NULL);
    controlButtonConstruct(&connectExitButton, TUI_BTN_HEIGHT, TUI_BTN_WIDTH,
                           TUI_CONNECT_HEIGHT - TUI_BTN_HEIGHT - 1,
                           TUI_CONNECT_WIDTH - TUI_BTN_WIDTH - 2, "Exit", NULL,
                           exitBtn, NULL, NULL);

    tuiAppControlRegister((Control *)&connectPage, NULL);
    tuiAppControlRegister((Control *)&connectGrid, (Control *)&connectPage);
    tuiAppControlRegister((Control *)&connectPrompt, (Control *)&connectGrid);
    tuiAppControlRegister((Control *)&connectAddressLabel,
                          (Control *)&connectGrid);
    tuiAppControlRegister((Control *)&connectAddressBox,
                          (Control *)&connectGrid);
    tuiAppControlRegister((Control *)&connectPortLabel,
                          (Control *)&connectGrid);
    tuiAppControlRegister((Control *)&connectPortBox, (Control *)&connectGrid);
    tuiAppControlRegister((Control *)&connectStatusLabel,
                          (Control *)&connectGrid);
    tuiAppControlRegister((Control *)&connectButton, (Control *)&connectGrid);
    tuiAppControlRegister((Control *)&connectExitButton,
                          (Control *)&connectGrid);

    strcpy(connectAddressBox.buf, "localhost");
    connectAddressBox.curLen = 9;
    connectAddressBox.curLoc = 9;
    strcpy(connectPortBox.buf, "12345");
    connectPortBox.curLen = 5;
    connectPortBox.curLoc = 5;
}