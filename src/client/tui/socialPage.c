/**
 * @file socialPage.c
 * @brief Client TUI social hub page — friends, groups, and friend requests.
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

#include "socialPage.h"

#include "chatView.h"
#include "client/communication.h"
#include "client/social.h"
#include "clientTUI.h"
#include "mainPage.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ──────────────────────── constants ────────────────────────────────────────
 */

#define SOCIAL_OVERLAY_WIDTH 46
#define SOCIAL_OVERLAY_HEIGHT 10
#define SOCIAL_REQ_OVERLAY_WIDTH 50
#define SOCIAL_REQ_OVERLAY_HEIGHT 18
#define CONTACT_ENTRY_BUF_LEN 256
#define BTN_ACTION1_WIDTH (TUI_BTN_WIDTH + 4)
#define BTN_ACTION2_WIDTH (TUI_BTN_WIDTH + 2)

enum {
    MaxContacts = 1024,
    MaxPendingReqs = 64,
};

/* ──────────────────────── types ────────────────────────────────────────────
 */

typedef enum {
    ContactFriend = 0,
    ContactGroup = 1,
} ContactType;

typedef struct {
    ContactType type;
    uint32_t id;
    char name[LOGIN_NICKNAME_LEN];
    uint8_t online;
    uint32_t memberCount;
} ContactEntry;

typedef enum {
    OverlayNone = 0,
    OverlayAddFriend,
    OverlayNewGroup,
} OverlayMode;

/* ──────────────────────── static state ─────────────────────────────────────
 */

static ContactEntry contacts[MaxContacts];
static size_t contactCnt;

static FriendInfo pendingReqs[MaxPendingReqs];
static size_t pendingReqCnt;

static OverlayMode overlayMode = OverlayNone;

static bool refetchScheduled = false;

/* ──────────────────────── widget declarations ──────────────────────────────
 */

static ControlPage socialPage;
static ControlGrid socialGrid;
static ControlGrid topBarGrid;
static ControlButton friendReqBtn;
static ControlButton addFriendBtn;
static ControlButton newGroupBtn;
static ControlListBox contactListBox;
static ControlGrid botBarGrid;
static ControlButton actionBtn1;
static ControlButton actionBtn2;
static ControlButton backBtn;
static ControlLabel statusLabel;

static ControlGrid overlayGrid;
static ControlLabel overlayPrompt;
static ControlInputBox overlayInputBox;
static ControlButton overlayCancelBtn;

static ControlGrid reqOverlayGrid;
static ControlLabel reqOverlayPrompt;
static ControlListBox reqOverlayListBox;
static ControlButton reqAcceptBtn;
static ControlButton reqRejectBtn;
static ControlButton reqCloseBtn;

/* ──────────────────────── helpers ──────────────────────────────────────────
 */

static void clearContacts(void) {
    controlListBoxClear(&contactListBox);
    contactCnt = 0;
}

static void freeFriendList(void) {
    if (client->friendList != NULL) {
        free(client->friendList);
        client->friendList = NULL;
    }
    client->friendCount = 0;
}

static void freeGroupList(void) {
    if (client->groupList != NULL) {
        free(client->groupList);
        client->groupList = NULL;
    }
    client->groupCount = 0;
}

static void rebuildContactList(void) {
    clearContacts();

    for (uint32_t i = 0; i < client->friendCount && contactCnt < MaxContacts;
         i++) {
        const FriendInfo *fi = &client->friendList[i];
        contacts[contactCnt].type = ContactFriend;
        contacts[contactCnt].id = fi->uid;
        snprintf(contacts[contactCnt].name, sizeof(contacts[contactCnt].name),
                 "%s", fi->nickname);
        contacts[contactCnt].online = fi->online;
        contacts[contactCnt].memberCount = 0;
        contactCnt++;
    }

    for (uint32_t i = 0; i < client->groupCount && contactCnt < MaxContacts;
         i++) {
        const GroupInfo *gi = &client->groupList[i];
        contacts[contactCnt].type = ContactGroup;
        contacts[contactCnt].id = gi->groupId;
        snprintf(contacts[contactCnt].name, sizeof(contacts[contactCnt].name),
                 "%s", gi->groupName);
        contacts[contactCnt].online = 0;
        contacts[contactCnt].memberCount = gi->memberCount;
        contactCnt++;
    }

    for (size_t i = 0; i < contactCnt; i++) {
        char buf[CONTACT_ENTRY_BUF_LEN];
        const ContactEntry *e = &contacts[i];
        if (e->type == ContactFriend) {
            snprintf(buf, sizeof(buf), "[Friend] %s %s", e->name,
                     e->online ? "(online)" : "(offline)");
        } else {
            snprintf(buf, sizeof(buf), "[Group]  %s (%u members)", e->name,
                     e->memberCount);
        }
        controlListBoxAppend(&contactListBox, buf, i);
    }
}

static void updateFriendReqBtnLabel(void) {
    char label[BTN_LABEL_MAXLEN];
    snprintf(label, sizeof(label), "Friend Req(%zu)", pendingReqCnt);
    strncpy(friendReqBtn.text, label, BTN_LABEL_MAXLEN);
    friendReqBtn.text[BTN_LABEL_MAXLEN - 1] = '\0';
}

static void fetchFriendAndGroupLists(void) {
    clientFriendListRequest(client);
    clientGroupListRequest(client);
}

static void showMainWidgets(bool visible) {
    tuiAppVisibilityChange((Control *)&topBarGrid, visible);
    tuiAppVisibilityChange((Control *)&contactListBox, visible);
    tuiAppVisibilityChange((Control *)&botBarGrid, visible);
    tuiAppVisibilityChange((Control *)&backBtn, visible);
    tuiAppVisibilityChange((Control *)&statusLabel, visible);
}

static void hideOverlay(void) {
    tuiAppVisibilityChange((Control *)&overlayGrid, false);
    tuiAppVisibilityChange((Control *)&reqOverlayGrid, false);
    showMainWidgets(true);
    overlayMode = OverlayNone;
}

static void showInputOverlay(const char *prompt, OverlayMode mode) {
    overlayMode = mode;
    showMainWidgets(false);
    tuiAppVisibilityChange((Control *)&reqOverlayGrid, false);
    strncpy(overlayPrompt.text, prompt, LABEL_TEXT_MAXLEN - 1);
    overlayInputBox.curLen = 0;
    overlayInputBox.curLoc = 0;
    overlayInputBox.viewBegin = 0;
    memset(overlayInputBox.buf, 0, INPUTBOX_BUF_MAX_LEN);
    tuiAppVisibilityChange((Control *)&overlayGrid, true);
}

static ContactEntry *getSelectedContact(void) {
    if (contactListBox.entryCnt == 0) {
        return NULL;
    }
    ControlListBoxEntry sel;
    if (arrayControlListBoxEntryGet(&contactListBox.list,
                                    contactListBox.curLine,
                                    &sel) != ContainerSucc) {
        return NULL;
    }
    if (sel.id >= contactCnt) {
        return NULL;
    }
    return &contacts[sel.id];
}

/* ──────────────────────── social poll ──────────────────────────────────────
 */

static void socialPoll(void) {
    if (client == NULL || client->fd == NULL_SOCKETFD) {
        return;
    }

    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    int pollRet = clientPollAndDispatch(client, &pkt);
    if (pollRet <= 0) {
        return;
    }

    switch ((MessageType)pkt.header.messageType) {
    case MsgFriendListResp: {
        if (pkt.header.payloadLength < sizeof(uint32_t)) {
            break;
        }
        freeFriendList();
        uint32_t count;
        memcpy(&count, pkt.payload, sizeof(uint32_t));
        if (count == 0) {
            break;
        }
        size_t expected = sizeof(uint32_t) + count * sizeof(FriendInfo);
        if (pkt.header.payloadLength < expected) {
            break;
        }
        client->friendList = malloc(count * sizeof(FriendInfo));
        if (client->friendList == NULL) {
            break;
        }
        memcpy(client->friendList, pkt.payload + sizeof(uint32_t),
               count * sizeof(FriendInfo));
        client->friendCount = count;
        rebuildContactList();
        break;
    }
    case MsgGroupListResp: {
        if (pkt.header.payloadLength < sizeof(uint32_t)) {
            break;
        }
        freeGroupList();
        uint32_t count;
        memcpy(&count, pkt.payload, sizeof(uint32_t));
        if (count == 0) {
            break;
        }
        size_t expected = sizeof(uint32_t) + count * sizeof(GroupInfo);
        if (pkt.header.payloadLength < expected) {
            break;
        }
        client->groupList = malloc(count * sizeof(GroupInfo));
        if (client->groupList == NULL) {
            break;
        }
        memcpy(client->groupList, pkt.payload + sizeof(uint32_t),
               count * sizeof(GroupInfo));
        client->groupCount = count;
        rebuildContactList();
        break;
    }
    case MsgFriendNotify: {
        if (pkt.header.payloadLength < sizeof(FriendNotifyPayload)) {
            break;
        }
        const FriendNotifyPayload *fn =
            (const FriendNotifyPayload *)pkt.payload;
        for (uint32_t i = 0; i < client->friendCount; i++) {
            if (client->friendList[i].uid == fn->uid) {
                client->friendList[i].online = fn->online;
                break;
            }
        }
        rebuildContactList();
        break;
    }
    case MsgFriendRequestResp:
    case MsgFriendAcceptResp:
    case MsgFriendDeleteResp:
    case MsgGroupCreateResp:
    case MsgGroupJoinResp:
    case MsgGroupQuitResp:
    case MsgGroupKickResp:
    case MsgGroupDisbandResp:
    case MsgGroupDisbandNotify:
    case MsgGroupMemberJoin:
    case MsgGroupMemberQuit:
        refetchScheduled = true;
        break;
    case MsgPrivateChatBroadcast:
    case MsgGroupChatBroadcast:
        if (client->activeChatTarget != 0) {
            size_t bufSize = sizeof(PacketHeader) + pkt.header.payloadLength;
            uint8_t *buf = malloc(bufSize);
            if (buf != NULL) {
                memcpy(buf, &pkt.header, sizeof(PacketHeader));
                memcpy(buf + sizeof(PacketHeader), pkt.payload,
                       pkt.header.payloadLength);
                int idx = client->pendingChatMsgCount;
                size_t newCount = (size_t)(idx + 1);
                uint8_t **tmpMsgs = realloc(client->pendingChatMessages,
                                            newCount * sizeof(uint8_t *));
                size_t *tmpLens = realloc(client->pendingChatMsgLens,
                                          newCount * sizeof(size_t));
                uint32_t *tmpTypes = realloc(client->pendingChatMsgTypes,
                                             newCount * sizeof(uint32_t));
                if (tmpMsgs != NULL && tmpLens != NULL && tmpTypes != NULL) {
                    client->pendingChatMessages = tmpMsgs;
                    client->pendingChatMsgLens = tmpLens;
                    client->pendingChatMsgTypes = tmpTypes;
                    client->pendingChatMessages[idx] = buf;
                    client->pendingChatMsgLens[idx] = bufSize;
                    client->pendingChatMsgTypes[idx] =
                        pkt.header.messageType;
                    client->pendingChatMsgCount = idx + 1;
                } else {
                    free(buf);
                }
            }
        }
        break;
    default:
        break;
    }

    packetClear(&pkt);
}

/* ──────────────────────── overlay submit ───────────────────────────────────
 */

static void overlayInputSubmit(ControlInputBox *self) {
    (void)self;

    if (overlayInputBox.curLen == 0) {
        hideOverlay();
        return;
    }

    switch (overlayMode) {
    case OverlayAddFriend: {
        char buf[INPUTBOX_BUF_MAX_LEN + 1];
        size_t copyLen = overlayInputBox.curLen < sizeof(buf) - 1
                             ? overlayInputBox.curLen
                             : sizeof(buf) - 1;
        memcpy(buf, overlayInputBox.buf, copyLen);
        buf[copyLen] = '\0';
        long uid = strtol(buf, NULL, 10);
        if (uid > 0 && uid <= UINT32_MAX) {
            clientFriendRequest(client, (uint32_t)uid);
            snprintf(statusLabel.text, LABEL_TEXT_MAXLEN,
                     "Friend request sent to UID %lu", uid);
        } else {
            snprintf(statusLabel.text, LABEL_TEXT_MAXLEN, "Invalid UID");
        }
        break;
    }
    case OverlayNewGroup: {
        char buf[GROUP_NAME_LEN];
        size_t copyLen = overlayInputBox.curLen < sizeof(buf) - 1
                             ? overlayInputBox.curLen
                             : sizeof(buf) - 1;
        memcpy(buf, overlayInputBox.buf, copyLen);
        buf[copyLen] = '\0';
        clientGroupCreate(client, buf);
        snprintf(statusLabel.text, LABEL_TEXT_MAXLEN,
                 "Creating group \"%s\"...", buf);
        refetchScheduled = true;
        break;
    }
    case OverlayNone:
    default:
        break;
    }

    hideOverlay();
}

/* ──────────────────────── button callbacks ─────────────────────────────────
 */

static void friendReqBtnOnClick(ControlButton *self) {
    (void)self;
    if (pendingReqCnt == 0) {
        strcpy(statusLabel.text, "No pending friend requests");
        return;
    }
    showMainWidgets(false);
    tuiAppVisibilityChange((Control *)&overlayGrid, false);
    controlListBoxClear(&reqOverlayListBox);
    for (size_t i = 0; i < pendingReqCnt; i++) {
        char buf[128];
        snprintf(buf, sizeof(buf), "%s (UID: %u)", pendingReqs[i].nickname,
                 pendingReqs[i].uid);
        controlListBoxAppend(&reqOverlayListBox, buf, i);
    }
    tuiAppVisibilityChange((Control *)&reqOverlayGrid, true);
}

static void addFriendBtnOnClick(ControlButton *self) {
    (void)self;
    showInputOverlay("Enter friend UID:", OverlayAddFriend);
}

static void newGroupBtnOnClick(ControlButton *self) {
    (void)self;
    showInputOverlay("Enter group name:", OverlayNewGroup);
}

static void actionBtn1OnClick(ControlButton *self) {
    (void)self;
    ContactEntry *sel = getSelectedContact();
    if (sel == NULL) {
        strcpy(statusLabel.text, "No contact selected");
        return;
    }
    if (sel->type == ContactFriend) {
        client->activeChatTarget = sel->id;
        client->activeChatIsGroup = 0;
        chatViewEnter(client, sel->id, 0);
    } else {
        client->activeChatTarget = sel->id;
        client->activeChatIsGroup = 1;
        chatViewEnter(client, sel->id, 1);
    }
}

static void actionBtn2OnClick(ControlButton *self) {
    (void)self;
    ContactEntry *sel = getSelectedContact();
    if (sel == NULL) {
        strcpy(statusLabel.text, "No contact selected");
        return;
    }
    if (sel->type == ContactFriend) {
        clientFriendDelete(client, sel->id);
        snprintf(statusLabel.text, LABEL_TEXT_MAXLEN, "Removed friend %s",
                 sel->name);
    } else {
        clientGroupQuit(client, sel->id);
        snprintf(statusLabel.text, LABEL_TEXT_MAXLEN, "Left group %s",
                 sel->name);
    }
    refetchScheduled = true;
}

static void backBtnOnClick(ControlButton *self) {
    (void)self;
    freeFriendList();
    freeGroupList();
    clearContacts();
    pendingReqCnt = 0;
    updateFriendReqBtnLabel();
    tuiAppChangePage(&homePage);
}

static void overlayCancelBtnOnClick(ControlButton *self) {
    (void)self;
    hideOverlay();
}

static void reqAcceptBtnOnClick(ControlButton *self) {
    (void)self;
    ControlListBoxEntry sel;
    if (arrayControlListBoxEntryGet(&reqOverlayListBox.list,
                                    reqOverlayListBox.curLine,
                                    &sel) != ContainerSucc) {
        return;
    }
    if (sel.id >= pendingReqCnt) {
        return;
    }
    clientFriendAccept(client, pendingReqs[sel.id].uid);
    snprintf(statusLabel.text, LABEL_TEXT_MAXLEN,
             "Accepted friend request from %s", pendingReqs[sel.id].nickname);
    pendingReqCnt = 0;
    updateFriendReqBtnLabel();
    refetchScheduled = true;
    hideOverlay();
}

static void reqRejectBtnOnClick(ControlButton *self) {
    (void)self;
    ControlListBoxEntry sel;
    if (arrayControlListBoxEntryGet(&reqOverlayListBox.list,
                                    reqOverlayListBox.curLine,
                                    &sel) != ContainerSucc) {
        return;
    }
    if (sel.id >= pendingReqCnt) {
        return;
    }
    clientFriendReject(client, pendingReqs[sel.id].uid);
    snprintf(statusLabel.text, LABEL_TEXT_MAXLEN,
             "Rejected friend request from %s", pendingReqs[sel.id].nickname);
    pendingReqCnt = 0;
    updateFriendReqBtnLabel();
    hideOverlay();
}

static void reqCloseBtnOnClick(ControlButton *self) {
    (void)self;
    pendingReqCnt = 0;
    updateFriendReqBtnLabel();
    hideOverlay();
}

/* ──────────────────────── resize / draw / update ───────────────────────────
 */

static void socialGridResize(ControlGrid *self) {
    self->base.width = pViewArea->width;
    self->base.height = pViewArea->height;
    backBtn.base.x = pViewArea->width - TUI_BTN_WIDTH - 2;
    backBtn.base.y = pViewArea->height - TUI_BTN_HEIGHT - 1;
}

static void socialGridDraw(ControlGrid *self) {
    werase(self->base.windowHandler);
    DOUBLE_BOX(self->base.windowHandler);
    wattron(self->base.windowHandler, A_BOLD);
    mvwprintw(self->base.windowHandler, 1, (int)(self->base.width / 2) - 5,
              "Social Hub");
    wattroff(self->base.windowHandler, A_BOLD);
    wnoutrefresh(self->base.windowHandler);
}

static void contactListResize(ControlListBox *self) {
    self->base.y = 2 + TUI_BTN_HEIGHT;
    self->base.width = pViewArea->width - 4;
    self->base.height = pViewArea->height - 5 - 2 * TUI_BTN_HEIGHT;
    self->base.x = 2;
}

static void botBarResize(ControlGrid *self) {
    self->base.y = pViewArea->height - TUI_BTN_HEIGHT - 2;
    self->base.width = pViewArea->width - 4;
    self->base.x = 2;
}

static void botBarUpdate(ControlGrid *self) {
    (void)self;
    ContactEntry *sel = getSelectedContact();
    if (sel == NULL) {
        tuiAppVisibilityChange((Control *)&actionBtn1, false);
        tuiAppVisibilityChange((Control *)&actionBtn2, false);
        return;
    }
    if (sel->type == ContactFriend) {
        strncpy(actionBtn1.text, "Chat", BTN_LABEL_MAXLEN);
        strncpy(actionBtn2.text, "Remove", BTN_LABEL_MAXLEN);
    } else {
        strncpy(actionBtn1.text, "Enter Group", BTN_LABEL_MAXLEN);
        strncpy(actionBtn2.text, "Leave", BTN_LABEL_MAXLEN);
    }
    tuiAppVisibilityChange((Control *)&actionBtn1, true);
    tuiAppVisibilityChange((Control *)&actionBtn2, true);
}

static void statusLabelResize(ControlLabel *self) {
    self->base.y = pViewArea->height - TUI_BTN_HEIGHT - 2;
    self->base.width = pViewArea->width - TUI_BTN_WIDTH - 6;
    self->base.x = 2;
}

static void socialGridUpdate(ControlGrid *self) {
    (void)self;
    socialPoll();
    if (refetchScheduled) {
        refetchScheduled = false;
        fetchFriendAndGroupLists();
    }
}

/* ──────────────────────── overlay resize / draw ────────────────────────────
 */

static void overlayGridResize(ControlGrid *self) {
    self->base.width = MIN(SOCIAL_OVERLAY_WIDTH, pViewArea->width);
    self->base.height = MIN(SOCIAL_OVERLAY_HEIGHT, pViewArea->height);
    self->base.x =
        MAX(0, (int)(pViewArea->width / 2) - (int)(self->base.width / 2));
    self->base.y =
        MAX(0, (int)(pViewArea->height / 2) - (int)(self->base.height / 2));
}

static void overlayGridDraw(ControlGrid *self) {
    werase(self->base.windowHandler);
    DOUBLE_BOX(self->base.windowHandler);
    wnoutrefresh(self->base.windowHandler);
}

static void reqOverlayGridResize(ControlGrid *self) {
    self->base.width = MIN(SOCIAL_REQ_OVERLAY_WIDTH, pViewArea->width);
    self->base.height = MIN(SOCIAL_REQ_OVERLAY_HEIGHT, pViewArea->height);
    self->base.x =
        MAX(0, (int)(pViewArea->width / 2) - (int)(self->base.width / 2));
    self->base.y =
        MAX(0, (int)(pViewArea->height / 2) - (int)(self->base.height / 2));
}

static void reqOverlayGridDraw(ControlGrid *self) {
    werase(self->base.windowHandler);
    DOUBLE_BOX(self->base.windowHandler);
    wnoutrefresh(self->base.windowHandler);
}

/* ──────────────────────── init ─────────────────────────────────────────────
 */

void tuiClientSocialPageInit(void) {
    controlPageConstruct(&socialPage);

    controlGridConstruct(&socialGrid, 0, 0, 0, 0, LayoutNone, 0, 0,
                         socialGridDraw, socialGridResize, NULL,
                         socialGridUpdate, NULL);

    /* Top action bar */
    controlGridConstruct(&topBarGrid, TUI_BTN_HEIGHT, 0, 2, 2, LayoutHorizontal,
                         1, 0, NULL, NULL, NULL, NULL, NULL);

    controlButtonConstruct(&friendReqBtn, TUI_BTN_HEIGHT, TUI_BTN_WIDTH + 8, 0,
                           0, "Friend Req(0)", NULL, friendReqBtnOnClick, NULL,
                           NULL, NULL);

    controlButtonConstruct(&addFriendBtn, TUI_BTN_HEIGHT, TUI_BTN_WIDTH + 2, 0,
                           0, "Add Friend", NULL, addFriendBtnOnClick, NULL,
                           NULL, NULL);

    controlButtonConstruct(&newGroupBtn, TUI_BTN_HEIGHT, TUI_BTN_WIDTH + 2, 0,
                           0, "New Group", NULL, newGroupBtnOnClick, NULL, NULL,
                           NULL);

    /* Contact list */
    controlListBoxConstruct(&contactListBox, 0, 0, 0, 0, NULL,
                            contactListResize, NULL, NULL);

    /* Bottom action bar */
    controlGridConstruct(&botBarGrid, TUI_BTN_HEIGHT, 0, 0, 0, LayoutHorizontal,
                         1, 0, NULL, botBarResize, NULL, botBarUpdate, NULL);

    controlButtonConstruct(&actionBtn1, TUI_BTN_HEIGHT, BTN_ACTION1_WIDTH, 0, 0,
                           "Chat", NULL, actionBtn1OnClick, NULL, NULL, NULL);
    tuiAppVisibilityChange((Control *)&actionBtn1, false);

    controlButtonConstruct(&actionBtn2, TUI_BTN_HEIGHT, BTN_ACTION2_WIDTH, 0, 0,
                           "Remove", NULL, actionBtn2OnClick, NULL, NULL, NULL);
    tuiAppVisibilityChange((Control *)&actionBtn2, false);

    /* Back button */
    controlButtonConstruct(&backBtn, TUI_BTN_HEIGHT, TUI_BTN_WIDTH,
                           pViewArea->height - TUI_BTN_HEIGHT - 1,
                           pViewArea->width - TUI_BTN_WIDTH - 2, "Back", NULL,
                           backBtnOnClick, NULL, NULL, NULL);

    /* Status label */
    controlLabelConstruct(&statusLabel, "",
                          pViewArea->width - TUI_BTN_WIDTH - 6,
                          pViewArea->height - TUI_BTN_HEIGHT - 2, 2, NULL,
                          statusLabelResize, NULL, NULL);

    /* Overlay: add friend / new group */
    controlGridConstruct(&overlayGrid, SOCIAL_OVERLAY_HEIGHT,
                         SOCIAL_OVERLAY_WIDTH, 0, 0, LayoutNone, 0, 0,
                         overlayGridDraw, overlayGridResize, NULL, NULL, NULL);
    tuiAppVisibilityChange((Control *)&overlayGrid, false);

    controlLabelConstruct(&overlayPrompt, "", SOCIAL_OVERLAY_WIDTH - 4, 2, 2,
                          NULL, NULL, NULL, NULL);

    controlInputBoxConstruct(&overlayInputBox, SOCIAL_OVERLAY_WIDTH - 6, 4,
                             SOCIAL_OVERLAY_WIDTH / 2 - 10, false, NULL, NULL,
                             overlayInputSubmit, NULL, NULL);

    controlButtonConstruct(&overlayCancelBtn, TUI_BTN_HEIGHT, TUI_BTN_WIDTH + 2,
                           SOCIAL_OVERLAY_HEIGHT - TUI_BTN_HEIGHT - 1,
                           SOCIAL_OVERLAY_WIDTH - TUI_BTN_WIDTH - 4, "Cancel",
                           NULL, overlayCancelBtnOnClick, NULL, NULL, NULL);

    /* Overlay: friend requests */
    controlGridConstruct(&reqOverlayGrid, SOCIAL_REQ_OVERLAY_HEIGHT,
                         SOCIAL_REQ_OVERLAY_WIDTH, 0, 0, LayoutNone, 0, 0,
                         reqOverlayGridDraw, reqOverlayGridResize, NULL, NULL,
                         NULL);
    tuiAppVisibilityChange((Control *)&reqOverlayGrid, false);

    controlLabelConstruct(&reqOverlayPrompt, "Pending Friend Requests",
                          SOCIAL_REQ_OVERLAY_WIDTH - 4, 1, 2, NULL, NULL, NULL,
                          NULL);

    controlListBoxConstruct(&reqOverlayListBox, SOCIAL_REQ_OVERLAY_HEIGHT - 6,
                            SOCIAL_REQ_OVERLAY_WIDTH - 4, 2, 2, NULL, NULL,
                            NULL, NULL);

    controlButtonConstruct(&reqAcceptBtn, TUI_BTN_HEIGHT, TUI_BTN_WIDTH + 2,
                           SOCIAL_REQ_OVERLAY_HEIGHT - TUI_BTN_HEIGHT - 1, 2,
                           "Accept", NULL, reqAcceptBtnOnClick, NULL, NULL,
                           NULL);

    controlButtonConstruct(&reqRejectBtn, TUI_BTN_HEIGHT, TUI_BTN_WIDTH + 2,
                           SOCIAL_REQ_OVERLAY_HEIGHT - TUI_BTN_HEIGHT - 1,
                           2 + TUI_BTN_WIDTH + 4, "Reject", NULL,
                           reqRejectBtnOnClick, NULL, NULL, NULL);

    controlButtonConstruct(&reqCloseBtn, TUI_BTN_HEIGHT, TUI_BTN_WIDTH + 2,
                           SOCIAL_REQ_OVERLAY_HEIGHT - TUI_BTN_HEIGHT - 1,
                           SOCIAL_REQ_OVERLAY_WIDTH - TUI_BTN_WIDTH - 4,
                           "Close", NULL, reqCloseBtnOnClick, NULL, NULL, NULL);

    /* ── Registration ── */
    tuiAppControlRegister((Control *)&socialPage, NULL);
    tuiAppControlRegister((Control *)&socialGrid, (Control *)&socialPage);
    tuiAppControlRegister((Control *)&topBarGrid, (Control *)&socialGrid);
    tuiAppControlRegister((Control *)&friendReqBtn, (Control *)&topBarGrid);
    tuiAppControlRegister((Control *)&addFriendBtn, (Control *)&topBarGrid);
    tuiAppControlRegister((Control *)&newGroupBtn, (Control *)&topBarGrid);
    tuiAppControlRegister((Control *)&contactListBox, (Control *)&socialGrid);
    tuiAppControlRegister((Control *)&botBarGrid, (Control *)&socialGrid);
    tuiAppControlRegister((Control *)&actionBtn1, (Control *)&botBarGrid);
    tuiAppControlRegister((Control *)&actionBtn2, (Control *)&botBarGrid);
    tuiAppControlRegister((Control *)&backBtn, (Control *)&socialGrid);
    tuiAppControlRegister((Control *)&statusLabel, (Control *)&socialGrid);

    /* Overlays — registered after main widgets to draw on top */
    tuiAppControlRegister((Control *)&overlayGrid, (Control *)&socialGrid);
    tuiAppControlRegister((Control *)&overlayPrompt, (Control *)&overlayGrid);
    tuiAppControlRegister((Control *)&overlayInputBox, (Control *)&overlayGrid);
    tuiAppControlRegister((Control *)&overlayCancelBtn,
                          (Control *)&overlayGrid);

    tuiAppControlRegister((Control *)&reqOverlayGrid, (Control *)&socialGrid);
    tuiAppControlRegister((Control *)&reqOverlayPrompt,
                          (Control *)&reqOverlayGrid);
    tuiAppControlRegister((Control *)&reqOverlayListBox,
                          (Control *)&reqOverlayGrid);
    tuiAppControlRegister((Control *)&reqAcceptBtn, (Control *)&reqOverlayGrid);
    tuiAppControlRegister((Control *)&reqRejectBtn, (Control *)&reqOverlayGrid);
    tuiAppControlRegister((Control *)&reqCloseBtn, (Control *)&reqOverlayGrid);
}

/* ──────────────────────── entry point ──────────────────────────────────────
 */

void socialPageEnter(Client *clientInstance) {
    client = clientInstance;
    freeFriendList();
    freeGroupList();
    clearContacts();
    pendingReqCnt = 0;
    overlayMode = OverlayNone;
    refetchScheduled = false;

    showMainWidgets(true);
    tuiAppVisibilityChange((Control *)&actionBtn1, false);
    tuiAppVisibilityChange((Control *)&actionBtn2, false);
    tuiAppVisibilityChange((Control *)&overlayGrid, false);
    tuiAppVisibilityChange((Control *)&reqOverlayGrid, false);

    updateFriendReqBtnLabel();
    strcpy(statusLabel.text, "Loading contacts...");

    tuiAppChangePage(&socialPage);
    fetchFriendAndGroupLists();
}
