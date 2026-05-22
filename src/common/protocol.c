/**
 * @file protocol.c
 * @brief PacPlay network protocol implementation.
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

#include "protocol.h"
#include "log.h"
#include "utils.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ───────────────────────── internal constants ──────────────────────────── */

/** @brief Size of the AAD used for AES-GCM packet encryption. */
#define AAD_LEN (sizeof(uint64_t))

/** @brief Number of bits to shift payloadLength when building the AAD. */
#define AAD_PAYLOAD_SHIFT 32

/* ──────────────────── AAD helper ───────────────────────────────────────── */

/**
 * @brief Build the AAD value for AES-GCM packet encryption.
 *
 * The AAD is a single @c uint64_t: @c (payloadLength @c << @c 32) @c |
 * @c sequenceID.
 *
 * @param payloadLength The plaintext payload length (before encryption).
 * @param sequenceID    The packet sequence ID.
 * @return The AAD as a @c uint64_t.
 */
static uint64_t buildAAD(size_t payloadLength, uint32_t sequenceID) {
    return ((uint64_t)payloadLength << AAD_PAYLOAD_SHIFT) |
           (uint64_t)sequenceID;
}

/* ─────────────────── socket helpers ────────────────────────────────────── */

/**
 * @brief Open a TCP socket.
 *
 * @return SocketFD FD of the opened socket or @c NULL_SOCKETFD when failed.
 */
static SocketFD socketOpen(void) {
    SocketFD socketFD = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socketFD == -1) {
        LOG_ERROR("Failed to create socket file descriptor: %s (%d)",
                  strerror(errno), errno);
        socketClose(&socketFD);
        return NULL_SOCKETFD;
    }
    return socketFD;
}

/**
 * @brief Send exactly @p totalLen bytes from @p data over @p socketFD.
 *
 * @param socketFD The socket to write to.
 * @param data     Pointer to the data.
 * @param totalLen Number of bytes to send.
 * @return @c PROTOCOL_SUCC on success, @c PROTOCOL_FAIL on failure.
 */
static int sendAll(SocketFD socketFD, const void *data, size_t totalLen) {
    const uint8_t *ptr = (const uint8_t *)data;
    size_t remaining = totalLen;

    while (remaining > 0) {
        ssize_t sent = send(socketFD, ptr, remaining, MSG_NOSIGNAL);
        if (sent < 0) {
            if (errno == EINTR) {
                continue;
            }
            LOG_ERROR("Failed to send data: %s (%d)", strerror(errno), errno);
            return PROTOCOL_FAIL;
        }
        if (sent == 0) {
            LOG_ERROR("Failed to send data: connection closed");
            return PROTOCOL_FAIL;
        }
        ptr += sent;
        remaining -= (size_t)sent;
    }
    return PROTOCOL_SUCC;
}

/**
 * @brief Receive exactly @p totalLen bytes into @p data from @p socketFD.
 *
 * @param socketFD The socket to read from.
 * @param data     Pointer to the destination buffer.
 * @param totalLen Number of bytes to receive.
 * @return @c PROTOCOL_SUCC on success, @c PROTOCOL_FAIL on failure.
 */
static int recvAll(SocketFD socketFD, void *data, size_t totalLen) {
    uint8_t *ptr = (uint8_t *)data;
    size_t remaining = totalLen;

    while (remaining > 0) {
        ssize_t received = recv(socketFD, ptr, remaining, MSG_NOSIGNAL);
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            LOG_ERROR("Failed to receive data: %s (%d)", strerror(errno),
                      errno);
            return PROTOCOL_FAIL;
        }
        if (received == 0) {
            LOG_ERROR("Failed to receive data: connection closed by peer");
            return PROTOCOL_FAIL;
        }
        ptr += received;
        remaining -= (size_t)received;
    }
    return PROTOCOL_SUCC;
}

/* ────────────────────── public API: sockets ─────────────────────────────── */

SocketFD serverSetup(uint16_t port) {
    struct sockaddr_in sockAddr;

    SocketFD socketFD = socketOpen();
    if (socketFD == NULL_SOCKETFD) {
        goto cleanup;
    }

    memset(&sockAddr, 0, sizeof(sockAddr));
    sockAddr.sin_family = AF_INET;
    sockAddr.sin_port = htons(port);
    sockAddr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(socketFD, (struct sockaddr *)&sockAddr, sizeof(sockAddr)) < 0) {
        LOG_ERROR("Failed to bind socket file descriptor with address: %s (%d)",
                  strerror(errno), errno);
        goto cleanup;
    }

    if (listen(socketFD, BACKLOG) == -1) {
        LOG_ERROR("Failed to listen on port %d: %s (%d)", port, strerror(errno),
                  errno);
        goto cleanup;
    }

    return socketFD;

cleanup:
    socketClose(&socketFD);
    return NULL_SOCKETFD;
}

SocketFD clientSetup(const char *serverAddress, uint16_t serverPort) {
    if (serverAddress == NULL) {
        LOG_ERROR("clientSetup: NULL server address");
        return NULL_SOCKETFD;
    }

    struct sockaddr_in serverSockAddr;

    SocketFD socketFD = socketOpen();
    if (socketFD == NULL_SOCKETFD) {
        return NULL_SOCKETFD;
    }

    serverSockAddr.sin_family = AF_INET;
    serverSockAddr.sin_port = htons(serverPort);
    switch (inet_pton(AF_INET, serverAddress, &serverSockAddr.sin_addr)) {
    case 0:
        LOG_ERROR("Unknown address: %s", serverAddress);
        goto cleanup;
    case -1:
        LOG_ERROR("Unable to parse address: %s (%d)", strerror(errno), errno);
        goto cleanup;
    default:
        break;
    }

    if (connect(socketFD, (struct sockaddr *)&serverSockAddr,
                sizeof(struct sockaddr)) == -1) {
        LOG_ERROR("Cannot connect to the server %s:%d: %s (%d)", serverAddress,
                  serverPort, strerror(errno), errno);
        goto cleanup;
    }

    return socketFD;

cleanup:
    socketClose(&socketFD);
    return NULL_SOCKETFD;
}

void socketClose(SocketFD *socketFD) {
    if (socketFD == NULL) {
        return;
    }
    if (*socketFD >= 0) {
        int32_t result;
#ifdef _WIN32
        result = closesocket(*socketFD);
#else
        result = close(*socketFD);
#endif
        if (result < 0) {
            LOG_ERROR("Failed to close socket FD: %s (%d)", strerror(errno),
                      errno);
        }
    }
    *socketFD = NULL_SOCKETFD;
}

/* ──────────────────── public API: packet lifecycle ──────────────────────── */

/* payloadLength sits between MessageType/PacketType (enums) and
 * seqID/dataLen (unsigned integers); even with reordering, the remaining
 * adjacent integral parameters cannot be fully separated.  Suppress the
 * adjacent-parameters check for this constructor. */
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
int packetInit(Packet *packet, MessageType msgType, uint32_t seqID,
               PacketType pktType, const void *data, size_t dataLen) {
    if (packet == NULL) {
        return PROTOCOL_FAIL;
    }
    if (packet->payload != NULL) {
        LOG_ERROR("packetInit: payload is not NULL; must be cleared first");
        return PROTOCOL_FAIL;
    }
    if (dataLen > MAX_PAYLOAD_LEN) {
        LOG_ERROR("packetInit: dataLen %zu exceeds MAX_PAYLOAD_LEN %d", dataLen,
                  MAX_PAYLOAD_LEN);
        return PROTOCOL_FAIL;
    }
    if (dataLen > 0 && data == NULL) {
        LOG_ERROR("packetInit: dataLen %zu > 0 but data is NULL", dataLen);
        return PROTOCOL_FAIL;
    }

    packet->header.magic = PACKET_MAGIC;
    packet->header.packetType = pktType;
    packet->header.messageType = msgType;
    packet->header.payloadLength = dataLen;
    packet->header.sequenceID = seqID;

    if (dataLen > 0) {
        packet->payload = malloc(dataLen);
        if (packet->payload == NULL) {
            LOG_ERROR("packetInit: failed to allocate payload: %s (%d)",
                      strerror(errno), errno);
            return PROTOCOL_FAIL;
        }
        memcpy(packet->payload, data, dataLen);
    } else {
        packet->payload = NULL;
    }

    return PROTOCOL_SUCC;
}

void packetClear(Packet *packet) {
    if (packet == NULL) {
        return;
    }
    free(packet->payload);
    packet->payload = NULL;
}

/* ──────────────── public API: serialize / deserialize ───────────────────── */

int packetSerialize(const Packet *packet, uint8_t *buffer, size_t bufferSize,
                    size_t *serializedSize) {
    if (packet == NULL || buffer == NULL || serializedSize == NULL) {
        return PROTOCOL_FAIL;
    }

    /* Guard against integer overflow in size calculation. */
    if (packet->header.payloadLength > SIZE_MAX - sizeof(PacketHeader)) {
        LOG_ERROR("Payload length overflow in serialize");
        return PROTOCOL_FAIL;
    }

    size_t totalSize = sizeof(PacketHeader) + packet->header.payloadLength;
    if (bufferSize < totalSize) {
        LOG_ERROR("Serialize buffer too small (%zu < %zu)", bufferSize,
                  totalSize);
        return PROTOCOL_FAIL;
    }

    /* Copy header, then payload. */
    memcpy(buffer, &packet->header, sizeof(PacketHeader));
    if (packet->header.payloadLength > 0 && packet->payload != NULL) {
        memcpy(buffer + sizeof(PacketHeader), packet->payload,
               packet->header.payloadLength);
    }

    *serializedSize = totalSize;
    return PROTOCOL_SUCC;
}

int packetDeserialize(const uint8_t *buffer, size_t bufferSize,
                      Packet *packet) {
    if (buffer == NULL || packet == NULL || packet->payload != NULL) {
        return PROTOCOL_FAIL;
    }

    if (bufferSize < sizeof(PacketHeader)) {
        LOG_ERROR("Buffer too small for header (%zu < %zu)", bufferSize,
                  sizeof(PacketHeader));
        return PROTOCOL_FAIL;
    }

    /* Read header. */
    memcpy(&packet->header, buffer, sizeof(PacketHeader));

    if (packet->header.magic != PACKET_MAGIC) {
        LOG_ERROR("Invalid packet magic: 0x%08X", packet->header.magic);
        return PROTOCOL_FAIL;
    }

    /* Validate payload length against protocol limits. */
    size_t maxPayload = (packet->header.packetType == AES256GCMPacket)
                            ? MAX_PAYLOAD_LEN + AES_PACKET_EXTRA_LEN
                            : MAX_PAYLOAD_LEN;
    if (packet->header.payloadLength > maxPayload) {
        LOG_ERROR("Payload length exceeds protocol limit (%zu > %zu)",
                  packet->header.payloadLength, maxPayload);
        return PROTOCOL_FAIL;
    }

    /* Guard against integer overflow in size calculation. */
    if (packet->header.payloadLength > SIZE_MAX - sizeof(PacketHeader)) {
        LOG_ERROR("Payload length overflow in deserialize");
        return PROTOCOL_FAIL;
    }

    size_t totalSize = sizeof(PacketHeader) + packet->header.payloadLength;
    if (bufferSize < totalSize) {
        LOG_ERROR("Buffer too small for payload (%zu < %zu)", bufferSize,
                  totalSize);
        return PROTOCOL_FAIL;
    }

    /* Allocate and copy payload. */
    if (packet->header.payloadLength > 0) {
        packet->payload = malloc(packet->header.payloadLength);
        if (packet->payload == NULL) {
            LOG_ERROR("Failed to allocate payload: %s (%d)", strerror(errno),
                      errno);
            return PROTOCOL_FAIL;
        }
        memcpy(packet->payload, buffer + sizeof(PacketHeader),
               packet->header.payloadLength);
    }

    return PROTOCOL_SUCC;
}

/* ──────────────── public API: AES-256-GCM encrypt / decrypt ────────────── */

int packetAESEncrypt(Packet *packet, uint8_t key[AES_GCM_KEY_LEN]) {
    if (packet == NULL || packet->payload == NULL || key == NULL) {
        return PROTOCOL_FAIL;
    }

    if (packet->header.packetType != PlaintextPacket) {
        LOG_ERROR("Cannot encrypt: packet is not PlaintextPacket");
        return PROTOCOL_FAIL;
    }

    if (packet->header.payloadLength > MAX_PAYLOAD_LEN) {
        LOG_ERROR("Payload too large for encryption (%zu > %d)",
                  packet->header.payloadLength, MAX_PAYLOAD_LEN);
        return PROTOCOL_FAIL;
    }

    size_t plaintextLen = packet->header.payloadLength;

    /* 1. Generate random nonce and build key material. */
    AESGCMKey aesKey;
    memcpy(aesKey.key, key, AES_GCM_KEY_LEN);
    if (cryptoRandomBytes(aesKey.nonce, AES_GCM_NONCE_LEN) != CRYPTO_SUCC) {
        OPENSSL_cleanse(&aesKey, sizeof(aesKey));
        return PROTOCOL_FAIL;
    }

    /* 2. Build AAD: (payloadLength << 32) | sequenceID. */
    uint64_t aadValue = buildAAD(plaintextLen, packet->header.sequenceID);
    AESGCMBuffer aad = {
        .data = (uint8_t *)&aadValue, .capacity = AAD_LEN, .len = AAD_LEN};

    /* 3. Prepare plaintext buffer (references existing payload, no copy). */
    AESGCMBuffer plaintext = {
        .data = packet->payload, .capacity = plaintextLen, .len = plaintextLen};

    /* 4. Allocate ciphertext output buffer. */
    AESGCMCipher cipher;
    if (aesGCMBufferInit(&cipher.buffer, plaintextLen) != CRYPTO_SUCC) {
        OPENSSL_cleanse(&aesKey, sizeof(aesKey));
        return PROTOCOL_FAIL;
    }

    /* 5. Encrypt. */
    if (encryptAESGCM(&plaintext, &aad, &aesKey, &cipher) != CRYPTO_SUCC) {
        aesGCMBufferDeinit(&cipher.buffer);
        OPENSSL_cleanse(&aesKey, sizeof(aesKey));
        return PROTOCOL_FAIL;
    }

    /* 6. Build new flat payload: nonce(12) || ciphertext(N) || tag(16). */
    size_t newPayloadLen =
        AES_GCM_NONCE_LEN + cipher.buffer.len + AES_GCM_TAG_LEN;
    uint8_t *newPayload = malloc(newPayloadLen);
    if (newPayload == NULL) {
        LOG_ERROR("Failed to allocate encrypted payload: %s (%d)",
                  strerror(errno), errno);
        aesGCMBufferDeinit(&cipher.buffer);
        OPENSSL_cleanse(&aesKey, sizeof(aesKey));
        return PROTOCOL_FAIL;
    }

    uint8_t *cursor = newPayload;
    memcpy(cursor, aesKey.nonce, AES_GCM_NONCE_LEN);
    cursor += AES_GCM_NONCE_LEN;
    memcpy(cursor, cipher.buffer.data, cipher.buffer.len);
    cursor += cipher.buffer.len;
    memcpy(cursor, cipher.tag, AES_GCM_TAG_LEN);

    /* 7. Replace old payload with encrypted payload. */
    OPENSSL_cleanse(packet->payload, plaintextLen);
    free(packet->payload);
    packet->payload = newPayload;
    packet->header.payloadLength = newPayloadLen;
    packet->header.packetType = AES256GCMPacket;

    aesGCMBufferDeinit(&cipher.buffer);
    OPENSSL_cleanse(&aesKey, sizeof(aesKey));
    return PROTOCOL_SUCC;
}

int packetAESDecrypt(Packet *packet, uint8_t key[AES_GCM_KEY_LEN]) {
    if (packet == NULL || packet->payload == NULL || key == NULL) {
        return PROTOCOL_FAIL;
    }

    if (packet->header.packetType != AES256GCMPacket) {
        LOG_ERROR("Cannot decrypt: packet is not AES256GCMPacket");
        return PROTOCOL_FAIL;
    }

    if (packet->header.payloadLength < AES_PACKET_EXTRA_LEN) {
        LOG_ERROR("Encrypted payload too short (%zu < %d)",
                  packet->header.payloadLength, AES_PACKET_EXTRA_LEN);
        return PROTOCOL_FAIL;
    }

    /* 1. Parse flat payload: nonce(12) || ciphertext(N) || tag(16). */
    size_t ciphertextLen = packet->header.payloadLength - AES_PACKET_EXTRA_LEN;
    uint8_t *payloadPtr = packet->payload;

    uint8_t nonce[AES_GCM_NONCE_LEN];
    memcpy(nonce, payloadPtr, AES_GCM_NONCE_LEN);
    payloadPtr += AES_GCM_NONCE_LEN;

    /* Ciphertext starts at payloadPtr, length = ciphertextLen. */
    uint8_t *ciphertextPtr = payloadPtr;
    payloadPtr += ciphertextLen;

    uint8_t tag[AES_GCM_TAG_LEN];
    memcpy(tag, payloadPtr, AES_GCM_TAG_LEN);

    /* 2. Build key material from the provided key and extracted nonce. */
    AESGCMKey aesKey;
    memcpy(aesKey.key, key, AES_GCM_KEY_LEN);
    memcpy(aesKey.nonce, nonce, AES_GCM_NONCE_LEN);

    /* 3. Reconstruct AAD: original payloadLength == ciphertextLen. */
    uint64_t aadValue = buildAAD(ciphertextLen, packet->header.sequenceID);
    AESGCMBuffer aad = {
        .data = (uint8_t *)&aadValue, .capacity = AAD_LEN, .len = AAD_LEN};

    /* 4. Set up cipher input (references existing payload, no extra copy). */
    AESGCMCipher cipher;
    cipher.buffer.data = ciphertextPtr;
    cipher.buffer.capacity = ciphertextLen;
    cipher.buffer.len = ciphertextLen;
    memcpy(cipher.tag, tag, AES_GCM_TAG_LEN);

    /* 5. Allocate plaintext output buffer. */
    AESGCMBuffer plaintext;
    if (aesGCMBufferInit(&plaintext, ciphertextLen) != CRYPTO_SUCC) {
        OPENSSL_cleanse(&aesKey, sizeof(aesKey));
        return PROTOCOL_FAIL;
    }

    /* 6. Decrypt. If tag verification fails, return authentication error. */
    int decryptRet = decryptAESGCM(&cipher, &aad, &aesKey, &plaintext);
    if (decryptRet == CRYPTO_AUTH_FAIL) {
        LOG_ERROR("Decryption authentication failed: AAD or payload tampered");
        aesGCMBufferDeinit(&plaintext);
        OPENSSL_cleanse(&aesKey, sizeof(aesKey));
        return PROTOCOL_AUTH_FAIL;
    }
    if (decryptRet != CRYPTO_SUCC) {
        aesGCMBufferDeinit(&plaintext);
        OPENSSL_cleanse(&aesKey, sizeof(aesKey));
        return PROTOCOL_FAIL;
    }

    /* 7. Post-decryption AAD verification: ensure the decrypted length
     *    matches what was encoded in the AAD. */
    uint64_t verifyAAD = buildAAD(plaintext.len, packet->header.sequenceID);
    if (verifyAAD != aadValue) {
        LOG_ERROR("Post-decryption AAD mismatch");
        aesGCMBufferDeinit(&plaintext);
        OPENSSL_cleanse(&aesKey, sizeof(aesKey));
        return PROTOCOL_AUTH_FAIL;
    }

    /* 8. Replace encrypted payload with decrypted plaintext. */
    free(packet->payload);
    packet->payload = plaintext.data;
    packet->header.payloadLength = plaintext.len;
    packet->header.packetType = PlaintextPacket;

    /* Do NOT call aesGCMBufferDeinit here; ownership transferred to packet. */
    OPENSSL_cleanse(&aesKey, sizeof(aesKey));
    return PROTOCOL_SUCC;
}

/* ──────────────────── public API: send / recv ──────────────────────────── */

int packetSend(Packet *packet, SocketFD socketFD) {
    if (packet == NULL || packet->payload == NULL) {
        return PROTOCOL_FAIL;
    }

    /* Send header first, then payload — Packet is not contiguous in memory. */
    if (sendAll(socketFD, &packet->header, sizeof(PacketHeader)) !=
        PROTOCOL_SUCC) {
        return PROTOCOL_FAIL;
    }

    if (sendAll(socketFD, packet->payload, packet->header.payloadLength) !=
        PROTOCOL_SUCC) {
        return PROTOCOL_FAIL;
    }

    return PROTOCOL_SUCC;
}

int packetRecv(Packet *dest, SocketFD socketFD) {
    if (dest == NULL || dest->payload != NULL) {
        return PROTOCOL_FAIL;
    }

    /* Receive header. */
    if (recvAll(socketFD, &dest->header, sizeof(PacketHeader)) !=
        PROTOCOL_SUCC) {
        return PROTOCOL_FAIL;
    }

    /* Validate magic. */
    if (dest->header.magic != PACKET_MAGIC) {
        LOG_ERROR("Received invalid packet magic: 0x%08X", dest->header.magic);
        return PROTOCOL_FAIL;
    }

    /* Validate packet type. */
    if (dest->header.packetType != PlaintextPacket &&
        dest->header.packetType != AES256GCMPacket) {
        LOG_ERROR("Received unknown packet type: %d", dest->header.packetType);
        return PROTOCOL_FAIL;
    }

    /* Validate payload length based on packet type. */
    size_t maxLen = (dest->header.packetType == AES256GCMPacket)
                        ? MAX_PAYLOAD_LEN + AES_PACKET_EXTRA_LEN
                        : MAX_PAYLOAD_LEN;
    if (dest->header.payloadLength > maxLen) {
        LOG_ERROR("Payload length exceeds limit (%zu > %zu)",
                  dest->header.payloadLength, maxLen);
        return PROTOCOL_FAIL;
    }

    /* Allocate and receive payload. */
    dest->payload = malloc(dest->header.payloadLength);
    if (dest->payload == NULL) {
        LOG_ERROR("Failed to allocate payload: %s (%d)", strerror(errno),
                  errno);
        return PROTOCOL_FAIL;
    }

    if (recvAll(socketFD, dest->payload, dest->header.payloadLength) !=
        PROTOCOL_SUCC) {
        free(dest->payload);
        dest->payload = NULL;
        return PROTOCOL_FAIL;
    }

    return PROTOCOL_SUCC;
}
