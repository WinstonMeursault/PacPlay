/**
 * @file protocol.h
 * @brief PacPlay network protocol definitions and packet operations.
 *
 * @date 2026-05-16
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

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "crypto.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#define PROTOCOL_SUCC (0)
#define PROTOCOL_FAIL (-1)
#define PROTOCOL_AUTH_FAIL (-2)

#define MAX_PAYLOAD_LEN 1024

/** @brief Extra bytes added by AES-256-GCM encryption: nonce + tag. */
#define AES_PACKET_EXTRA_LEN (AES_GCM_NONCE_LEN + AES_GCM_TAG_LEN)

#define BACKLOG 5

/* When the value of a socket fd is NULL_SOCKETFD, the exception should have
   been already handled if any error occurred. */
#define NULL_SOCKETFD (-1)

typedef int SocketFD;

#define PACKET_MAGIC 0x5050504Du // 'PPPM' in ASCII, PacPlay Packet Magic

typedef enum {
    PlaintextPacket = 1,

    AES256GCMPacket
} PacketType;

typedef enum {
    MsgLoginReq = 1,
    MsgLoginResp,

    MsgKeyExchangeReq,
    MsgKeyExchangeResp,

    MsgChat,

    MsgCreateRoom,
    MsgJoinRoom,

    MsgGameStart,
    MsgGameStop,

    MsgHeartbeat
} MessageType;

#pragma pack(push, 1)

typedef struct {
    uint32_t magic;
    PacketType packetType;
    MessageType messageType;
    size_t payloadLength;
    uint32_t sequenceID;
} PacketHeader;

#pragma pack(pop)

typedef struct {
    PacketHeader header;
    uint8_t *payload;
} Packet;

#pragma pack(push, 1)

typedef struct {
    uint8_t publicKey[ECDH_PUBLIC_KEY_SIZE];
} KeyExchangePacketPayload;

#pragma pack(pop)

/**
 * @brief Setup a server.
 *
 * @param port The port on which the server to be launched.
 * @return SocketFD The socket FD of the created server, and macro
 *         @c NULL_SOCKETFD when it fails to launch.
 *
 * Setup a server on a given port and return the socket FD and begin listening.
 * It will output error message when it failed to do that. Use function
 * @c socketClose to close the server FD.
 */
SocketFD serverSetup(uint16_t port);

/**
 * @brief Setup a client.
 *
 * @param serverAddress The server address.
 * @param serverPort The server port.
 * @return SocketFD The socket FD of the created client, and macro
 *         @c NULL_SOCKETFD when it fails.
 *
 * Setup a client connecting to a specific server and return the socket FD.
 * It will output error message when it failed to do that. Use function
 * @c socketClose to close the client FD.
 */
SocketFD clientSetup(const char *serverAddress, uint16_t serverPort);

/**
 * @brief Close a socket.
 *
 * @param socketFD A pointer to the socket FD to be closed.
 *
 * Close a socket FD. It will automatically reject to close an illegal
 * socketFD (e.g. @c *socketFD @c == @c -1), hence it's safe not to care about
 * whether the fd is valid.
 */
void socketClose(SocketFD *socketFD);

/**
 * @brief Initialise a packet with header fields and a copy of the payload.
 *
 * Allocates memory for @p data of @p dataLen bytes and copies it into
 * @c packet->payload.  All header fields are set according to the parameters.
 *
 * @param packet   The packet to initialise.  @c packet->payload MUST be NULL
 *                 on entry; otherwise the call returns @c PROTOCOL_FAIL.
 * @param msgType  Application-layer message type.
 * @param seqID    Sequence number for this packet.
 * @param pktType  Packet encryption type (e.g. @c PlaintextPacket).
 * @param data     Pointer to the payload data to copy, or @c NULL if
 *                 @p dataLen is zero.
 * @param dataLen  Length of @p data in bytes.  Must be &le; @c MAX_PAYLOAD_LEN.
 * @return @c PROTOCOL_SUCC on success, @c PROTOCOL_FAIL on failure.
 */
int packetInit(Packet *packet, MessageType msgType, uint32_t seqID,
               PacketType pktType, const void *data, size_t dataLen);

/**
 * @brief Clear a packet.
 *
 * @param packet The packet to clear.
 *
 * Free the dynamically allocated payload and set the pointer to NULL.
 */
void packetClear(Packet *packet);

/**
 * @brief Serialize a packet into a raw byte buffer.
 *
 * @param packet The packet to serialize.
 * @param buffer The buffer to store the serialized data.
 * @param bufferSize The capacity of @p buffer in bytes.
 * @param serializedSize Output: the number of bytes written to @p buffer.
 * @return @c PROTOCOL_SUCC on success, @c PROTOCOL_FAIL on failure.
 *
 * Writes the packet header followed by the payload into a contiguous byte
 * buffer. No encryption is performed; call @c packetAESEncrypt beforehand
 * if encryption is needed.
 */
int packetSerialize(const Packet *packet, uint8_t *buffer, size_t bufferSize,
                    size_t *serializedSize);

/**
 * @brief Deserialize a raw byte buffer into a packet.
 *
 * @param buffer The buffer containing the serialized packet.
 * @param bufferSize The size of @p buffer in bytes.
 * @param packet The packet to populate. @c packet->payload MUST be NULL.
 * @return @c PROTOCOL_SUCC on success, @c PROTOCOL_FAIL on failure.
 *
 * Reads the packet header from the buffer, validates the magic number, then
 * allocates and copies the payload. Call @c packetClear to free the payload
 * when done.
 */
int packetDeserialize(const uint8_t *buffer, size_t bufferSize, Packet *packet);

/**
 * @brief Encrypt a packet in-place using AES-256-GCM.
 *
 * @param packet The plaintext packet to encrypt. Must have
 *               @c packetType @c == @c PlaintextPacket.
 * @param key    The 32-byte AES-256-GCM key.
 * @return @c PROTOCOL_SUCC on success, @c PROTOCOL_FAIL on failure.
 *
 * Encrypts the payload, replacing it with the encrypted form:
 * @c nonce(12B) @c || @c ciphertext @c || @c tag(16B). The nonce is randomly
 * generated. AAD is a @c uint64_t formed by @c (payloadLength @c << @c 32)
 * @c | @c sequenceID. On success, @c packetType is set to @c AES256GCMPacket
 * and @c payloadLength is updated accordingly.
 */
int packetAESEncrypt(Packet *packet, uint8_t key[AES_GCM_KEY_LEN]);

/**
 * @brief Decrypt a packet in-place using AES-256-GCM.
 *
 * @param packet The encrypted packet to decrypt. Must have
 *               @c packetType @c == @c AES256GCMPacket.
 * @param key    The 32-byte AES-256-GCM key.
 * @return @c PROTOCOL_SUCC on success, @c PROTOCOL_FAIL on internal failure,
 *         @c PROTOCOL_AUTH_FAIL if authentication tag verification fails or
 *         the AAD does not match the decrypted content.
 *
 * Parses @c nonce, @c ciphertext, and @c tag from the payload, then decrypts.
 * On success, @c packetType is restored to @c PlaintextPacket and
 * @c payloadLength is updated to the original plaintext length.
 */
int packetAESDecrypt(Packet *packet, uint8_t key[AES_GCM_KEY_LEN]);

/**
 * @brief Send a packet over a socket.
 *
 * @param packet A pointer to the packet to send. @c packet->payload must not
 *               be NULL.
 * @param socketFD The socket FD through which the packet is sent.
 * @return @c PROTOCOL_SUCC on success, @c PROTOCOL_FAIL on failure.
 *
 * Sends the packet header followed by the payload. Handles partial writes
 * internally until the entire packet is transmitted.
 */
int packetSend(Packet *packet, SocketFD socketFD);

/**
 * @brief Receive a packet from a socket.
 *
 * @param dest A pointer to the packet to populate. @c dest->payload MUST be
 *             NULL.
 * @param socketFD The socket FD from which to receive.
 * @return @c PROTOCOL_SUCC on success, @c PROTOCOL_FAIL on failure.
 *
 * Receives the packet header first, validates magic and payload length, then
 * allocates and receives the payload. Call @c packetClear to free the payload
 * when done.
 */
int packetRecv(Packet *dest, SocketFD socketFD);

#endif /* PROTOCOL_H */
