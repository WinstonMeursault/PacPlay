/**
 * @file social.h
 * @brief Client-side social module — friend, private chat, and group requests.
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

#ifndef CLIENT_SOCIAL_H
#define CLIENT_SOCIAL_H

#include "client.h"
#include "protocol.h"

#include <stddef.h>
#include <stdint.h>

/* ─────────────────── socket polling (shared by TUI pages) ────────────────── */

/**
 * @brief Non-blocking poll + receive one encrypted packet from the server.
 *
 * Calls select() with a zero timeout on c->fd, then clientRecvEncryptedPacket
 * if data is available.  This is the canonical polling entry point used by
 * socialPage::socialPoll() on every frame.  chatView reads pending messages
 * from the Client::pendingChatMessages queue populated by socialPoll().
 *
 * @param c       Connected, authenticated client.
 * @param outPkt  Output packet (must be zero-initialised by caller).
 * @return 1 if a packet was received, 0 if no data was available, -1 on error.
 */
int clientPollAndDispatch(Client *c, Packet *outPkt);

/* ─────────────────────────── friend system ──────────────────────────────── */

/**
 * @brief Send a friend request to another user.
 * @param c          Connected, authenticated client.
 * @param targetUid  UID of the user to befriend.
 * @return @c PROTOCOL_SUCC on success, @c PROTOCOL_FAIL on failure.
 */
int clientFriendRequest(Client *c, uint32_t targetUid);

/**
 * @brief Accept a pending friend request.
 * @param c          Connected, authenticated client.
 * @param targetUid  UID of the requesting user.
 * @return @c PROTOCOL_SUCC on success, @c PROTOCOL_FAIL on failure.
 */
int clientFriendAccept(Client *c, uint32_t targetUid);

/**
 * @brief Reject a pending friend request.
 * @param c          Connected, authenticated client.
 * @param targetUid  UID of the requesting user.
 * @return @c PROTOCOL_SUCC on success, @c PROTOCOL_FAIL on failure.
 */
int clientFriendReject(Client *c, uint32_t targetUid);

/**
 * @brief Delete an existing friend.
 * @param c          Connected, authenticated client.
 * @param targetUid  UID of the friend to delete.
 * @return @c PROTOCOL_SUCC on success, @c PROTOCOL_FAIL on failure.
 */
int clientFriendDelete(Client *c, uint32_t targetUid);

/**
 * @brief Request the current user's friend list from the server.
 * @param c  Connected, authenticated client.
 * @return @c PROTOCOL_SUCC on success, @c PROTOCOL_FAIL on failure.
 */
int clientFriendListRequest(Client *c);

/* ─────────────────────────── private chat ───────────────────────────────── */

/**
 * @brief Send a private chat message to another user.
 * @param c        Connected, authenticated client.
 * @param toUid    Recipient UID.
 * @param message  NUL-terminated message text.
 * @return @c PROTOCOL_SUCC on success, @c CLIENT_FAIL/@c PROTOCOL_FAIL on
 *         failure.
 */
int clientPrivateChatSend(Client *c, uint32_t toUid, const char *message);

/**
 * @brief Request private chat history with a peer.
 * @param c            Connected, authenticated client.
 * @param peerUid      UID of the conversation peer.
 * @param beforeMsgId  Fetch messages with id smaller than this (0 = newest).
 * @param limit        Maximum number of messages to return.
 * @return @c PROTOCOL_SUCC on success, @c PROTOCOL_FAIL on failure.
 */
int clientPrivateChatHistoryRequest(Client *c, uint32_t peerUid,
                                    uint32_t beforeMsgId, uint32_t limit);

/* ────────────────────────────── group chat ──────────────────────────────── */

/**
 * @brief Create a new chat group.
 * @param c          Connected, authenticated client.
 * @param groupName  NUL-terminated group name.
 * @return @c PROTOCOL_SUCC on success, @c PROTOCOL_FAIL on failure.
 */
int clientGroupCreate(Client *c, const char *groupName);

/**
 * @brief Join an existing chat group.
 * @param c        Connected, authenticated client.
 * @param groupId  Target group identifier.
 * @return @c PROTOCOL_SUCC on success, @c PROTOCOL_FAIL on failure.
 */
int clientGroupJoin(Client *c, uint32_t groupId);

/**
 * @brief Quit a chat group.
 * @param c        Connected, authenticated client.
 * @param groupId  Target group identifier.
 * @return @c PROTOCOL_SUCC on success, @c PROTOCOL_FAIL on failure.
 */
int clientGroupQuit(Client *c, uint32_t groupId);

/**
 * @brief Request the current user's group list from the server.
 * @param c  Connected, authenticated client.
 * @return @c PROTOCOL_SUCC on success, @c PROTOCOL_FAIL on failure.
 */
int clientGroupListRequest(Client *c);

/**
 * @brief Send a message to a group.
 * @param c        Connected, authenticated client.
 * @param groupId  Target group identifier.
 * @param message  NUL-terminated message text.
 * @return @c PROTOCOL_SUCC on success, @c CLIENT_FAIL/@c PROTOCOL_FAIL on
 *         failure.
 */
int clientGroupChatSend(Client *c, uint32_t groupId, const char *message);

/**
 * @brief Kick a member from a group (owner only).
 * @param c          Connected, authenticated client.
 * @param groupId    Target group identifier.
 * @param targetUid  UID of the member to remove.
 * @return @c PROTOCOL_SUCC on success, @c PROTOCOL_FAIL on failure.
 */
int clientGroupKick(Client *c, uint32_t groupId, uint32_t targetUid);

/**
 * @brief Disband a group (owner only).
 * @param c        Connected, authenticated client.
 * @param groupId  Target group identifier.
 * @return @c PROTOCOL_SUCC on success, @c PROTOCOL_FAIL on failure.
 */
int clientGroupDisband(Client *c, uint32_t groupId);

/**
 * @brief Request group chat history.
 * @param c            Connected, authenticated client.
 * @param groupId      Target group identifier.
 * @param beforeMsgId  Fetch messages with id smaller than this (0 = newest).
 * @param limit        Maximum number of messages to return.
 * @return @c PROTOCOL_SUCC on success, @c PROTOCOL_FAIL on failure.
 */
int clientGroupChatHistoryRequest(Client *c, uint32_t groupId,
                                  uint32_t beforeMsgId, uint32_t limit);

#endif /* CLIENT_SOCIAL_H */
