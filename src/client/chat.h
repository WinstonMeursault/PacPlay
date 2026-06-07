/**
 * @file chat.h
 * @brief Client-side chat payload construction and parsing.
 *
 * @date 2026-06-07
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

#ifndef CLIENT_CHAT_H
#define CLIENT_CHAT_H

#include "client.h"
#include "protocol.h"

/**
 * @brief Construct a ChatPacketPayload and send it as MsgChat.
 *
 * Allocates a heap buffer for the payload (timestamp + NUL-terminated
 * message), sends it via the client communication layer, and frees the
 * buffer.
 *
 * @param client     Connected client with completed key exchange.
 * @param message    NUL-terminated chat message text.
 * @param timestamp  UNIX timestamp (UTC seconds).
 * @return @c CLIENT_SUCC on success, @c CLIENT_FAIL on failure.
 */
int clientChatSend(Client *client, const char *message, int64_t timestamp);

/**
 * @brief Parse a ChatBroadcastPayload from a received server broadcast
 * packet.
 *
 * Validates minimum payload size, then copies the fixed header fields
 * and message body into @p out.  @p *outLen receives the message body
 * length (excluding NUL).
 *
 * @param pkt     Decrypted incoming MsgChat packet.
 * @param out     Output structure receiving uid, msgId, timestamp, message.
 * @param outLen  Output: length of the message body in bytes.
 * @return @c CLIENT_SUCC on success, @c CLIENT_FAIL on invalid payload.
 */
int clientChatParseBroadcast(const Packet *pkt, ChatBroadcastPayload *out,
                             size_t *outLen);

#endif /* CLIENT_CHAT_H */
