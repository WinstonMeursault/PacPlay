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

/** @brief Fixed username length in login request payload (NUL-terminated). */
#define LOGIN_USERNAME_LEN 32

/** @brief Fixed nickname length in login request payload (NUL-terminated). */
#define LOGIN_NICKNAME_LEN 32

/** @brief Fixed length of Base32-encoded TOTP secret in setup response
 *         (32 chars + NUL). */
#define TOTP_SETUP_SECRET_LEN 33

/** @brief Length of a per-user client database encryption key (256-bit). */
#define CLIENT_DB_KEY_LEN 32

#define GAME_NAME_LEN 64
#define GAME_VERSION_LEN 32
#define GAME_HASH_LEN 65
#define GAME_DESC_LEN 1024
#define PLATFORM_NAME_LEN 16
#define GAME_CHUNK_SIZE 65536u
#define MAX_PAYLOAD_LEN (GAME_CHUNK_SIZE * 2)
#define DATA_AUTH_TOKEN_LEN 32
#define TOKEN_EXPIRE_SECS 30

/** @brief Extra bytes added by AES-256-GCM encryption: nonce + tag. */
#define AES_PACKET_EXTRA_LEN (AES_GCM_NONCE_LEN + AES_GCM_TAG_LEN)

#define BACKLOG 1024

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
    /* Key exchange (plaintext, happens before any encryption). */
    MsgKeyExchangeReq = 1,
    MsgKeyExchangeResp,

    /* Authentication. */
    MsgLoginReq,
    MsgLoginResp,
    MsgRegisterReq,
    MsgRegisterResp,

    MsgTOTPSetupReq,
    MsgTOTPSetupResp,
    MsgTOTPVerifyReq,
    MsgTOTPVerifyResp,

    MsgDBKeyReq,
    MsgDBKeyResp,

    /* Room management. */
    MsgRoomListReq,
    MsgRoomListResp,
    MsgCreateRoom,
    MsgCreateRoomResp,
    MsgJoinRoom,
    MsgJoinRoomResp,
    MsgQuitRoom,

    /* In-room chat. */
    MsgChat,

    /* Session lifecycle. */
    MsgLogout,
    MsgHeartbeat,

    /* Game distribution — control channel. */
    MsgGameListReq,
    MsgGameListResp,
    MsgGameDownloadReq,
    MsgGameDownloadResp,
    MsgGameDownloadCancel,

    /* Game distribution — data channel. */
    MsgDataAuth,
    MsgDataAuthResp,
    MsgGameMetadata,
    MsgGameChunk,
    MsgGameChunkAck,
    MsgGameDownloadDone,

    /* In-game payload. */
    MsgGamePayload,

    /* Game start request / response — client requests server-side game launch. */
    MsgGameStartReq,
    MsgGameStartResp
} MessageType;

#pragma pack(push, 1)

/* All fields use fixed-width types so the wire format is platform-independent.
 * Enums (PacketType, MessageType) are used only as named constants; the wire
 * stores uint32_t values for deterministic width. */
typedef struct {
    uint32_t magic;
    uint32_t packetType;
    uint32_t messageType;
    uint32_t payloadLength;
    uint32_t sequenceID;
} PacketHeader;

#pragma pack(pop)

/* Packet itself is never serialised directly — header and payload are sent
 * separately.  Therefore it does not need #pragma pack. */
typedef struct {
    PacketHeader header;
    uint8_t *payload;
} Packet;

#pragma pack(push, 1)

typedef struct {
    uint8_t publicKey[ECDH_PUBLIC_KEY_SIZE];
} KeyExchangePacketPayload;

#pragma pack(pop)

/** @brief TOTP setup response payload sent from server to client.
 *
 *  Used by @c MsgTOTPSetupResp.  Contains the Base32-encoded (RFC 4648,
 *  no padding) TOTP shared secret as a NUL-terminated string.  The secret
 *  is 160 bits (20 bytes) of raw entropy, encoded to 32 Base32 characters
 *  plus a NUL terminator. */
#pragma pack(push, 1)
typedef struct {
    char secret[TOTP_SETUP_SECRET_LEN];
} TOTPSetupRespPayload;
#pragma pack(pop)

/** @brief Login request payload sent from client to server.
 *
 *  Used by @c MsgLoginReq.  Contains only the username and password — UID is
 *  assigned by the server on registration and returned to the client in a
 *  @c LoginResponsePayload upon successful login.  username is a fixed-length
 *  NUL-terminated / NUL-padded array.  password is a flexible array member
 *  whose length is derived from PacketHeader::payloadLength minus
 *  @c LOGIN_USERNAME_LEN.  The caller is responsible for ensuring the password
 *  is NUL-terminated within the total payload. */
#pragma pack(push, 1)
typedef struct {
    char username[LOGIN_USERNAME_LEN];
    char password[];
} LoginRequestPayload;
#pragma pack(pop)

/** @brief Registration request payload sent from client to server.
 *
 *  Used by @c MsgRegisterReq.  username and nickname are fixed-length
 *  NUL-terminated / NUL-padded arrays.  password is a flexible array member
 *  whose length is derived from PacketHeader::payloadLength minus
 *  @c LOGIN_USERNAME_LEN minus @c LOGIN_NICKNAME_LEN.  The caller is
 *  responsible for ensuring the password is NUL-terminated within the total
 *  payload.  UID is server-assigned — the client does not send one. */
#pragma pack(push, 1)
typedef struct {
    char username[LOGIN_USERNAME_LEN];
    char nickname[LOGIN_NICKNAME_LEN];
    char password[];
} RegisterRequestPayload;
#pragma pack(pop)

/** @brief Login response payload sent from server to client.
 *
 *  Sent as the payload of @c MsgLoginResp.  On success, all fields are
 *  populated with the authenticated user's canonical record from the database;
 *  @c totpEnabled indicates whether TOTP is registered (1) or not (0). On
 *  failure, @c uid is 0 and all other fields are zero-filled.  The client
 *  must check @c uid @c != @c 0 to determine success. */
#pragma pack(push, 1)
typedef struct {
    uint32_t uid;
    char username[LOGIN_USERNAME_LEN];
    char nickname[LOGIN_NICKNAME_LEN];
    uint8_t totpEnabled;
} LoginResponsePayload;
#pragma pack(pop)

/** @brief TOTP verification code payload sent from client to server.
 *
 *  Used by @c MsgTOTPVerifyResp.  Contains the 6-digit TOTP code entered
 *  by the user.  Fixed size: 4 bytes. */
#pragma pack(push, 1)
typedef struct {
    uint32_t code;
} TOTPVerifyPayload;
#pragma pack(pop)

/** @brief DB key response payload sent from server to client.
 *
 *  Used by @c MsgDBKeyResp.  Contains the decrypted per-user CDBKey
 *  (256-bit / 32 bytes of raw key material).  Fixed size: CLIENT_DB_KEY_LEN. */
#pragma pack(push, 1)
typedef struct {
    uint8_t cdbkey[CLIENT_DB_KEY_LEN];
} DBKeyRespPayload;
#pragma pack(pop)

/** @brief Chat message payload sent from client to server.
 *
 *  message is a FAM whose length = payloadLength - sizeof(timestamp).
 *  The server infers the room from the sender's session state. */
#pragma pack(push, 1)
typedef struct {
    int64_t timestamp;
    uint8_t message[];
} ChatPacketPayload;
#pragma pack(pop)

/** @brief Chat broadcast payload forwarded from server to room members.
 *
 *  Includes the server-assigned msgId and originating uid so clients
 *  can display sender identity and track message ordering. */
#pragma pack(push, 1)
typedef struct {
    uint32_t uid;
    uint64_t msgId;
    int64_t timestamp;
    uint8_t message[];
} ChatBroadcastPayload;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    char platform[PLATFORM_NAME_LEN];
} PlatformInfoPayload;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    uint32_t gameId;
    uint64_t fileSize;
    char name[GAME_NAME_LEN];
    char version[GAME_VERSION_LEN];
    char hash[GAME_HASH_LEN];
} GameListEntry;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    uint32_t gameId;
    uint32_t resumeChunkIndex;
    char platform[PLATFORM_NAME_LEN];
} GameDownloadReqPayload;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    uint8_t status;
    uint32_t gameId;
    uint64_t fileSize;
    uint32_t totalChunks;
    uint16_t dataPort;
    uint8_t token[DATA_AUTH_TOKEN_LEN];
    char hash[GAME_HASH_LEN];
} GameDownloadRespPayload;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    uint8_t token[DATA_AUTH_TOKEN_LEN];
} DataAuthPayload;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    uint32_t gameId;
    uint64_t fileSize;
    char name[GAME_NAME_LEN];
    char version[GAME_VERSION_LEN];
    char hash[GAME_HASH_LEN];
    char platform[PLATFORM_NAME_LEN];
} GameMetadataPayload;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    uint32_t chunkIndex;
    uint32_t chunkSize;
    uint8_t data[];
} GameChunkPayload;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    uint32_t chunkIndex;
} GameChunkAckPayload;
#pragma pack(pop)

/** @brief Game server start request payload sent from client to server.
 *
 *  Used by @c MsgGameStartReq.  Requests the server to load and run the
 *  server-side game dynamic library for the specified game and platform. */
#pragma pack(push, 1)
typedef struct {
    uint32_t gameId;
    char platform[PLATFORM_NAME_LEN];
} GameStartReqPayload;
#pragma pack(pop)

/** @brief Game list request payload for range-based browsing with optional
 *         platform filter.
 *
 *  Used by @c MsgGameListReq.  Specifies a [rangeStart, rangeEnd] inclusive
 *  range of gameId values.  Both fields set to 0 means "return all games".
 *  When rangeStart > rangeEnd (both non-zero), the server returns an empty
 *  list without error.
 *
 *  @c platform is a NUL-terminated platform identifier (e.g. "linux-x86_64").
 *  When non-empty the server filters results to games that support the given
 *  platform.  An empty string disables platform filtering (backward
 *  compatible). */
#pragma pack(push, 1)
typedef struct {
    uint32_t rangeStart;
    uint32_t rangeEnd;
    char platform[PLATFORM_NAME_LEN];
} GameListReqPayload;
#pragma pack(pop)

/** @brief Full game metadata entry returned in @c MsgGameListResp.
 *
 *  The response payload is a contiguous array of @c GameInfoEntry structs.
 *  Element count = payloadLength / sizeof(GameInfoEntry).  Sent via
 *  @c packetSendEncrypted (MAX_PAYLOAD_LEN = 65536, fits ~57). */
#pragma pack(push, 1)
typedef struct {
    uint32_t gameId;
    char name[GAME_NAME_LEN];
    char version[GAME_VERSION_LEN];
    char description[GAME_DESC_LEN];
    int64_t createdAt;
    int64_t updatedAt;
} GameInfoEntry;
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

/**
 * @brief Build, encrypt, and send a packet in one call.
 *
 * Constructs a plaintext packet via @c packetInit, encrypts it in-place
 * via @c packetAESEncrypt, increments @p *seqID, sends it via
 * @c packetSend, then clears the packet.  The caller owns @p seqID; this
 * function only increments it on success.
 *
 * @param fd      Destination socket.
 * @param mt      Application-layer message type.
 * @param seqID   Pointer to the caller's monotonic sequence counter.
 * @param key     32-byte AES-256-GCM key.
 * @param data    Payload bytes to send (may be NULL if dataLen is 0).
 * @param dataLen Length of @p data in bytes.
 * @return @c PROTOCOL_SUCC on success, @c PROTOCOL_FAIL on failure.
 */
int packetSendEncrypted(SocketFD fd, MessageType mt, uint32_t *seqID,
                        uint8_t key[AES_GCM_KEY_LEN], const void *data,
                        size_t dataLen);

/**
 * @brief Receive and decrypt an AES-256-GCM packet.
 *
 * Receives a packet via @c packetRecv, verifies the packet type is
 * @c AES256GCMPacket, decrypts the payload in-place via
 * @c packetAESDecrypt, and restores @c PlaintextPacket on success.
 * On any failure the packet is cleared and its payload is freed.
 *
 * @param fd   Socket to read from.
 * @param out  Destination packet (must have NULL payload on entry).
 * @param key  32-byte AES-256-GCM key.
 * @return @c PROTOCOL_SUCC on success, @c PROTOCOL_FAIL or
 *         @c PROTOCOL_AUTH_FAIL on failure.
 */
int packetRecvEncrypted(SocketFD fd, Packet *out, uint8_t key[AES_GCM_KEY_LEN]);

#endif /* PROTOCOL_H */
