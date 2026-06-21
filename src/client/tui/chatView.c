/**
 * @file chatView.c
 * @brief Generic chat view TUI page for private and group chat.
 *
 * @date 2026-06-21
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

#include "chatView.h"
#include "client/social.h"
#include "clientTUI.h"
#include <stdlib.h>
#include <string.h>

enum {
    ChatTitleMax = 128,
    ChatMsgMaxLines = 200,
    ChatMsgAreaHeightOff = 7,
    ChatInputWidthMin = 20
};

static Client *gChatClient;
static uint32_t gChatTarget;
static uint8_t gChatIsGroup;

enum { ChatInputBoxWidth = 40 };

static ControlPage chatPage;
static ControlGrid chatGrid;
static ControlButton chatBackBtn;
static ControlLabel chatTitleLabel;
static ControlScrollTextBox chatMessages;
static ControlInputBox chatInput;
static ControlButton chatSendBtn;

static void chatDoSend(void);

static void chatGridDraw(ControlGrid *self) {
    (void)self;
    werase(self->base.windowHandler);
    DOUBLE_BOX(self->base.windowHandler);

    int titleX = chatBackBtn.base.width + 2;
    wattron(self->base.windowHandler, A_BOLD);
    mvwprintw(self->base.windowHandler, 1, titleX, "%s", chatTitleLabel.text);
    wattroff(self->base.windowHandler, A_BOLD);

    wnoutrefresh(self->base.windowHandler);
}

static void chatGridResize(ControlGrid *self) {
    self->base.height = pViewArea->height;
    self->base.width = pViewArea->width;

    chatBackBtn.base.x = 1;
    chatBackBtn.base.y = 1;

    int msgAreaY = chatBackBtn.base.y + chatBackBtn.base.height;
    chatMessages.base.base.y = msgAreaY;
    chatMessages.base.base.x = 1;
    chatMessages.base.base.width = self->base.width - 2;
    chatMessages.base.base.height =
        self->base.height - msgAreaY - ChatMsgAreaHeightOff;
    if (chatMessages.base.base.height < 3) {
        chatMessages.base.base.height = 3;
    }

    int inputY = chatMessages.base.base.y + chatMessages.base.base.height;
    chatInput.base.y = inputY;
    chatInput.base.x = 1;
    int inputWidth = self->base.width - chatSendBtn.base.width - 4;
    if (inputWidth < ChatInputWidthMin) {
        inputWidth = ChatInputWidthMin;
    }
    chatInput.base.width = inputWidth;

    chatSendBtn.base.y = inputY;
    chatSendBtn.base.x = chatInput.base.x + chatInput.base.width + 1;
}

static void chatGridUpdate(ControlGrid *self) {
    (void)self;
    if (gChatClient == NULL) {
        return;
    }

    char lineBuf[ChatTitleMax + INPUTBOX_BUF_MAX_LEN];

    for (int i = 0; i < gChatClient->pendingChatMsgCount; i++) {
        const uint8_t *buf = gChatClient->pendingChatMessages[i];
        size_t bufLen = gChatClient->pendingChatMsgLens[i];
        uint32_t msgType = gChatClient->pendingChatMsgTypes[i];

        if (buf == NULL || bufLen < sizeof(PacketHeader)) {
            continue;
        }

        const uint8_t *payload = buf + sizeof(PacketHeader);
        size_t payloadLen = bufLen - sizeof(PacketHeader);

        if ((MessageType)msgType == MsgPrivateChatBroadcast) {
            const PrivateChatPayload *pm =
                (const PrivateChatPayload *)payload;
            if (payloadLen < sizeof(PrivateChatPayload)) {
                continue;
            }
            if (pm->fromUid == gChatClient->uid) {
                snprintf(lineBuf, sizeof(lineBuf), "You: %s\n", pm->message);
            } else {
                snprintf(lineBuf, sizeof(lineBuf), "User#%u: %s\n",
                         pm->fromUid, pm->message);
            }
            controlScrollTextBoxAppend(&chatMessages, lineBuf);
        } else if ((MessageType)msgType == MsgGroupChatBroadcast) {
            const GroupChatBroadcastPayload *gm =
                (const GroupChatBroadcastPayload *)payload;
            if (payloadLen < sizeof(GroupChatBroadcastPayload)) {
                continue;
            }
            if (gm->groupId != gChatTarget) {
                continue;
            }
            if (gm->uid == gChatClient->uid) {
                snprintf(lineBuf, sizeof(lineBuf), "You: %s\n", gm->message);
            } else {
                snprintf(lineBuf, sizeof(lineBuf), "User#%u: %s\n", gm->uid,
                         gm->message);
            }
            controlScrollTextBoxAppend(&chatMessages, lineBuf);
        }
    }

    for (int i = 0; i < gChatClient->pendingChatMsgCount; i++) {
        free(gChatClient->pendingChatMessages[i]);
    }
    free(gChatClient->pendingChatMessages);
    free(gChatClient->pendingChatMsgLens);
    free(gChatClient->pendingChatMsgTypes);
    gChatClient->pendingChatMessages = NULL;
    gChatClient->pendingChatMsgLens = NULL;
    gChatClient->pendingChatMsgTypes = NULL;
    gChatClient->pendingChatMsgCount = 0;
}

static void chatSendBtnOnClick(ControlButton *self) {
    (void)self;
    chatDoSend();
}

static void chatInputSubmit(ControlInputBox *self) {
    (void)self;
    chatDoSend();
}

static void chatDoSend(void) {
    if (chatInput.curLen == 0) {
        return;
    }

    const char *msg = chatInput.buf;
    int ret;

    if (gChatIsGroup) {
        ret = clientGroupChatSend(gChatClient, gChatTarget, msg);
    } else {
        ret = clientPrivateChatSend(gChatClient, gChatTarget, msg);
    }

    if (ret == PROTOCOL_SUCC) {
        char lineBuf[ChatTitleMax + INPUTBOX_BUF_MAX_LEN];
        snprintf(lineBuf, sizeof(lineBuf), "You: %s\n", msg);
        controlScrollTextBoxAppend(&chatMessages, lineBuf);
    }

    chatInput.buf[0] = '\0';
    chatInput.curLen = 0;
    chatInput.curLoc = 0;
    chatInput.viewBegin = 0;
}

static void chatBackBtnOnClick(ControlButton *self) {
    (void)self;
    tuiAppChangePage(&homePage);
}

static void tuiClientChatViewInit(void) {
    controlPageConstruct(&chatPage);
    controlGridConstruct(&chatGrid, 0, 0, 0, 0, LayoutNone, 0, 0, chatGridDraw,
                         chatGridResize, NULL, chatGridUpdate, NULL);
    controlButtonConstruct(&chatBackBtn, TUI_BTN_HEIGHT, TUI_BTN_WIDTH, 1, 1,
                           "Back", NULL, chatBackBtnOnClick, NULL, NULL, NULL);
    controlLabelConstruct(&chatTitleLabel, "", ChatTitleMax, 1,
                          TUI_BTN_WIDTH + 2, NULL, NULL, NULL, NULL);
    controlScrollTextBoxConstruct(&chatMessages, 10, 40, 3, 1, ChatMsgMaxLines,
                                  NULL, NULL, NULL, NULL);
    controlInputBoxConstruct(&chatInput, ChatInputBoxWidth, 0, 0, false, NULL,
                             NULL, chatInputSubmit, NULL, NULL);
    controlButtonConstruct(&chatSendBtn, TUI_BTN_HEIGHT, ChatInputBoxWidth, 0,
                           0, "Send", NULL, chatSendBtnOnClick, NULL, NULL,
                           NULL);

    tuiAppControlRegister((Control *)&chatPage, NULL);
    tuiAppControlRegister((Control *)&chatGrid, (Control *)&chatPage);
    tuiAppControlRegister((Control *)&chatBackBtn, (Control *)&chatGrid);
    tuiAppControlRegister((Control *)&chatTitleLabel, (Control *)&chatGrid);
    tuiAppControlRegister((Control *)&chatMessages, (Control *)&chatGrid);
    tuiAppControlRegister((Control *)&chatInput, (Control *)&chatGrid);
    tuiAppControlRegister((Control *)&chatSendBtn, (Control *)&chatGrid);
}

void chatViewEnter(Client *client, uint32_t target, uint8_t isGroup) {
    static bool initialized = false;

    gChatClient = client;
    gChatTarget = target;
    gChatIsGroup = isGroup;

    if (!initialized) {
        tuiClientChatViewInit();
        initialized = true;
    }

    if (isGroup) {
        snprintf(chatTitleLabel.text, LABEL_TEXT_MAXLEN, "Group Chat #%u",
                 target);
    } else {
        snprintf(chatTitleLabel.text, LABEL_TEXT_MAXLEN, "Chat with User#%u",
                 target);
    }

    chatMessages.base.text[0] = '\0';
    chatMessages.base.textLen = 0;

    chatInput.buf[0] = '\0';
    chatInput.curLen = 0;
    chatInput.curLoc = 0;
    chatInput.viewBegin = 0;
}
