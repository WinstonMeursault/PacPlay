/**
 * @file privateChat.h
 * @brief Server-side private chat message handing.
 *
 * Handles send, history, and offline delivery of private (1-to-1) messages
 * between two users.
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

#ifndef SERVER_PRIVATECHAT_H
#define SERVER_PRIVATECHAT_H

#include "protocol.h"
#include "server.h"

/**
 * @brief Handle a private chat send request from a client.
 *
 * Validates the payload, stores the message in PrivateChatDB, and
 * delivers it immediately to the receiver if online.
 *
 * @param s   Server instance.
 * @param cs  Sending client session.
 * @param pkt Decrypted incoming packet with MsgPrivateChat payload.
 * @return @c SERVER_SUCC on success, @c SERVER_FAIL on failure.
 */
int serverHandlePrivateChatSend(Server *s, ClientSession *cs,
                                const Packet *pkt);

/**
 * @brief Handle a private chat history request from a client.
 *
 * Retrieves paginated message history between the requesting user and
 * a peer, and sends the result back via @c MsgPrivateChatHistoryResp.
 *
 * @param s   Server instance.
 * @param cs  Requesting client session.
 * @param pkt Decrypted incoming packet with @c PrivateChatHistoryReqPayload.
 * @return @c SERVER_SUCC on success, @c SERVER_FAIL on failure.
 */
int serverHandlePrivateChatHistory(Server *s, ClientSession *cs,
                                   const Packet *pkt);

/**
 * @brief Deliver all pending offline private messages to a newly logged-in
 *        client.
 *
 * Fetches undelivered messages from PrivateChatDB, marks them as delivered,
 * and sends each one as @c MsgPrivateChatBroadcast.
 *
 * @param s   Server instance.
 * @param cs  Client session to deliver messages to.
 */
void serverDeliverOfflineMessages(Server *s, ClientSession *cs);

#endif /* SERVER_PRIVATECHAT_H */
