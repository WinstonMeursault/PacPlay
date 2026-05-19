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
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ───────────────────────── internal constants ──────────────────────────── */

#define CIPHER_SUCC (0)
#define CIPHER_FAIL (-1)
#define CIPHER_AUTH_FAIL (-2)

/** @brief Size of the AAD used for AES-GCM packet encryption. */
#define AAD_LEN (sizeof(uint64_t))

/** @brief Number of bits to shift payloadLength when building the AAD. */
#define AAD_PAYLOAD_SHIFT 32

/* ───────────────────────── internal types ───────────────────────────────── */

/** @brief AES-256-GCM key material: symmetric key + per-message nonce. */
typedef struct {
    uint8_t key[AES_GCM_KEY_LEN];
    uint8_t nonce[AES_GCM_NONCE_LEN];
} AESGCMKey;

/** @brief General-purpose byte buffer with capacity tracking. */
typedef struct {
    uint8_t *data;
    size_t capacity;
    size_t len;
} AESGCMBuffer;

/** @brief Ciphertext buffer with appended authentication tag. */
typedef struct {
    AESGCMBuffer buffer;
    uint8_t tag[AES_GCM_TAG_LEN];
} AESGCMCipher;

/* ──────────── OpenSSL error-logging helper ──────────────────────────────── */

#define LOG_ERROR_SSL(msg)                                                     \
    do {                                                                       \
        unsigned long errCode = ERR_get_error();                               \
        LOG_ERROR(msg ": %s (SSLERR:%lu)", ERR_reason_error_string(errCode),   \
                  errCode);                                                    \
    } while (false)

/* ──────────────────────── AESGCMBuffer helpers ─────────────────────────── */

/**
 * @brief Allocate an AESGCMBuffer with the given capacity.
 *
 * @param buf      Buffer to initialise.
 * @param capacity Number of bytes to allocate.
 * @return @c CIPHER_SUCC on success, @c CIPHER_FAIL on allocation failure.
 */
static int aesGCMBufferInit(AESGCMBuffer *buf, size_t capacity) {
    buf->data = malloc(capacity);
    buf->capacity = capacity;
    buf->len = 0;
    if (buf->data == NULL) {
        LOG_ERROR("Failed to allocate memory for AESGCM buffer: %s (%d)",
                  strerror(errno), errno);
        return CIPHER_FAIL;
    }
    return CIPHER_SUCC;
}

/**
 * @brief Free the memory held by an AESGCMBuffer.
 *
 * @param buf Buffer to deinitialise.
 */
static void aesGCMBufferDeinit(AESGCMBuffer *buf) {
    free(buf->data);
    buf->data = NULL;
}

/* ───────────────────── AES-256-GCM encrypt / decrypt ───────────────────── */

/**
 * @brief Encrypt plaintext using AES-256-GCM.
 *
 * @param plaintext Input plaintext buffer.
 * @param aad       Additional authenticated data, or NULL if unused.
 * @param key       Encryption key and nonce.
 * @param output    Output ciphertext and authentication tag.
 *                  Caller must pre-allocate @c output->buffer.data with at
 *                  least @c plaintext->len bytes.
 * @return @c CIPHER_SUCC on success, @c CIPHER_FAIL on failure.
 */
static int encryptAESGCM(const AESGCMBuffer *plaintext, const AESGCMBuffer *aad,
                         const AESGCMKey *key, AESGCMCipher *output) {
    if (plaintext == NULL || key == NULL || output == NULL ||
        output->buffer.data == NULL) {
        return CIPHER_FAIL;
    }

    if (output->buffer.capacity < plaintext->len) {
        LOG_ERROR(
            "Output buffer capacity too small (%zu(capacity) < %zu(length))",
            output->buffer.capacity, plaintext->len);
        return CIPHER_FAIL;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        LOG_ERROR_SSL("Failed to create EVP_CIPHER_CTX");
        return CIPHER_FAIL;
    }

    int32_t len = 0;
    int ret = CIPHER_FAIL;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        LOG_ERROR_SSL("Failed to initialize AES-256-GCM encryption");
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_NONCE_LEN,
                            NULL) != 1) {
        LOG_ERROR_SSL("Failed to set GCM nonce length");
        goto cleanup;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key->key, key->nonce) != 1) {
        LOG_ERROR_SSL("Failed to set AES-GCM key and nonce");
        goto cleanup;
    }

    /* Feed AAD (authenticated but not encrypted). */
    if (aad != NULL && aad->len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad->data, (int32_t)aad->len) !=
            1) {
            LOG_ERROR_SSL("Failed to set AAD for AES-GCM encryption");
            goto cleanup;
        }
    }

    if (EVP_EncryptUpdate(ctx, output->buffer.data, &len, plaintext->data,
                          (int32_t)plaintext->len) != 1) {
        LOG_ERROR_SSL("Failed to encrypt plaintext");
        goto cleanup;
    }
    output->buffer.len = (size_t)len;

    if (EVP_EncryptFinal_ex(ctx, output->buffer.data + len, &len) != 1) {
        LOG_ERROR_SSL("Failed to finalize AES-GCM encryption");
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_LEN,
                            output->tag) != 1) {
        LOG_ERROR_SSL("Failed to get AES-GCM authentication tag");
        goto cleanup;
    }

    ret = CIPHER_SUCC;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/**
 * @brief Decrypt ciphertext using AES-256-GCM.
 *
 * @param cipher    Input ciphertext, length, and authentication tag.
 * @param aad       Additional authenticated data, or NULL if unused.
 *                  Must match the AAD used during encryption.
 * @param key       Decryption key and nonce.
 * @param plaintext Output plaintext buffer. Caller must pre-allocate
 *                  @c plaintext->data with at least @c cipher->buffer.len
 *                  bytes.
 * @return @c CIPHER_SUCC on success, @c CIPHER_FAIL on internal failure,
 *         @c CIPHER_AUTH_FAIL on authentication tag verification failure.
 */
static int decryptAESGCM(const AESGCMCipher *cipher, const AESGCMBuffer *aad,
                         const AESGCMKey *key, AESGCMBuffer *plaintext) {
    if (cipher == NULL || key == NULL || plaintext == NULL ||
        plaintext->data == NULL) {
        return CIPHER_FAIL;
    }

    if (plaintext->capacity < cipher->buffer.len) {
        LOG_ERROR(
            "Output buffer capacity too small (%zu(capacity) < %zu(length))",
            plaintext->capacity, cipher->buffer.len);
        return CIPHER_FAIL;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        LOG_ERROR_SSL("Failed to create EVP_CIPHER_CTX");
        return CIPHER_FAIL;
    }

    int32_t len = 0;
    int ret = CIPHER_FAIL;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        LOG_ERROR_SSL("Failed to initialize AES-256-GCM decryption");
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_NONCE_LEN,
                            NULL) != 1) {
        LOG_ERROR_SSL("Failed to set GCM nonce length");
        goto cleanup;
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key->key, key->nonce) != 1) {
        LOG_ERROR_SSL("Failed to set AES-GCM key and nonce");
        goto cleanup;
    }

    /* Feed AAD (must match what was used during encryption). */
    if (aad != NULL && aad->len > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad->data, (int32_t)aad->len) !=
            1) {
            LOG_ERROR_SSL("Failed to set AAD for AES-GCM decryption");
            goto cleanup;
        }
    }

    if (EVP_DecryptUpdate(ctx, plaintext->data, &len, cipher->buffer.data,
                          (int32_t)cipher->buffer.len) != 1) {
        LOG_ERROR_SSL("Failed to decrypt ciphertext");
        goto cleanup;
    }
    plaintext->len = (size_t)len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_LEN,
                            (void *)(uintptr_t)cipher->tag) != 1) {
        LOG_ERROR_SSL("Failed to set AES-GCM authentication tag");
        goto cleanup;
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext->data + len, &len) != 1) {
        LOG_ERROR_SSL("AES-GCM tag verification failed");
        EVP_CIPHER_CTX_free(ctx);
        return CIPHER_AUTH_FAIL;
    }

    ret = CIPHER_SUCC;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

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
        if (sent <= 0) {
            LOG_ERROR("Failed to send data: %s (%d)", strerror(errno), errno);
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
        if (received <= 0) {
            LOG_ERROR("Failed to receive data: %s (%d)", strerror(errno),
                      errno);
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

void packetClear(Packet *packet) {
    free(packet->payload);
    packet->payload = NULL;
}

/* ──────────────── public API: serialize / deserialize ───────────────────── */

int packetSerialize(const Packet *packet, uint8_t *buffer, size_t bufferSize,
                    size_t *serializedSize) {
    if (packet == NULL || buffer == NULL || serializedSize == NULL) {
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
    if (RAND_bytes(aesKey.nonce, AES_GCM_NONCE_LEN) != 1) {
        LOG_ERROR_SSL("Failed to generate random nonce");
        return PROTOCOL_FAIL;
    }

    /* 2. Build AAD: (payloadLength << 32) | sequenceID. */
    uint64_t aadValue = buildAAD(plaintextLen, packet->header.sequenceID);
    AESGCMBuffer aad = {.data = (uint8_t *)&aadValue,
                        .capacity = AAD_LEN,
                        .len = AAD_LEN};

    /* 3. Prepare plaintext buffer (references existing payload, no copy). */
    AESGCMBuffer plaintext = {.data = packet->payload,
                              .capacity = plaintextLen,
                              .len = plaintextLen};

    /* 4. Allocate ciphertext output buffer. */
    AESGCMCipher cipher;
    if (aesGCMBufferInit(&cipher.buffer, plaintextLen) != CIPHER_SUCC) {
        return PROTOCOL_FAIL;
    }

    /* 5. Encrypt. */
    if (encryptAESGCM(&plaintext, &aad, &aesKey, &cipher) != CIPHER_SUCC) {
        aesGCMBufferDeinit(&cipher.buffer);
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
        return PROTOCOL_FAIL;
    }

    uint8_t *cursor = newPayload;
    memcpy(cursor, aesKey.nonce, AES_GCM_NONCE_LEN);
    cursor += AES_GCM_NONCE_LEN;
    memcpy(cursor, cipher.buffer.data, cipher.buffer.len);
    cursor += cipher.buffer.len;
    memcpy(cursor, cipher.tag, AES_GCM_TAG_LEN);

    /* 7. Replace old payload with encrypted payload. */
    free(packet->payload);
    packet->payload = newPayload;
    packet->header.payloadLength = newPayloadLen;
    packet->header.packetType = AES256GCMPacket;

    aesGCMBufferDeinit(&cipher.buffer);
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
    size_t ciphertextLen =
        packet->header.payloadLength - AES_PACKET_EXTRA_LEN;
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
    AESGCMBuffer aad = {.data = (uint8_t *)&aadValue,
                        .capacity = AAD_LEN,
                        .len = AAD_LEN};

    /* 4. Set up cipher input (references existing payload, no extra copy). */
    AESGCMCipher cipher;
    cipher.buffer.data = ciphertextPtr;
    cipher.buffer.capacity = ciphertextLen;
    cipher.buffer.len = ciphertextLen;
    memcpy(cipher.tag, tag, AES_GCM_TAG_LEN);

    /* 5. Allocate plaintext output buffer. */
    AESGCMBuffer plaintext;
    if (aesGCMBufferInit(&plaintext, ciphertextLen) != CIPHER_SUCC) {
        return PROTOCOL_FAIL;
    }

    /* 6. Decrypt. If tag verification fails, return authentication error. */
    int decryptRet = decryptAESGCM(&cipher, &aad, &aesKey, &plaintext);
    if (decryptRet == CIPHER_AUTH_FAIL) {
        LOG_ERROR("Decryption authentication failed: AAD or payload tampered");
        aesGCMBufferDeinit(&plaintext);
        return PROTOCOL_AUTH_FAIL;
    }
    if (decryptRet != CIPHER_SUCC) {
        aesGCMBufferDeinit(&plaintext);
        return PROTOCOL_FAIL;
    }

    /* 7. Post-decryption AAD verification: ensure the decrypted length
     *    matches what was encoded in the AAD. */
    uint64_t verifyAAD = buildAAD(plaintext.len, packet->header.sequenceID);
    if (verifyAAD != aadValue) {
        LOG_ERROR("Post-decryption AAD mismatch");
        aesGCMBufferDeinit(&plaintext);
        return PROTOCOL_AUTH_FAIL;
    }

    /* 8. Replace encrypted payload with decrypted plaintext. */
    free(packet->payload);
    packet->payload = plaintext.data;
    packet->header.payloadLength = plaintext.len;
    packet->header.packetType = PlaintextPacket;

    /* Do NOT call aesGCMBufferDeinit here; ownership transferred to packet. */
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
