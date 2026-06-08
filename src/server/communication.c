/**
 * @file communication.c
 * @brief Server-side communication: ECDH+HKDF AES key exchange.
 *
 * @date 2026-05-20
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

#include "communication.h"
#include "log.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <string.h>

/* ─────────────────────────────── public API ─────────────────────────────── */

int serverExchangeAESKey(SocketFD clientFD, Packet *reqPacket,
                         AESGCMKey *outKey) {
    if (reqPacket == NULL || outKey == NULL) {
        LOG_ERROR("serverExchangeAESKey: NULL argument (reqPacket=%p, "
                  "outKey=%p)",
                  (void *)reqPacket, (void *)outKey);
        return PROTOCOL_FAIL;
    }

    /* ────────── zero-trust validation of the client's request packet
     * ────────── */

    if (reqPacket->payload == NULL) {
        LOG_ERROR("serverExchangeAESKey: reqPacket has NULL payload");
        return PROTOCOL_FAIL;
    }

    if (reqPacket->header.messageType != MsgKeyExchangeReq) {
        LOG_ERROR("serverExchangeAESKey: unexpected message type %d (expected "
                  "MsgKeyExchangeReq=%d)",
                  reqPacket->header.messageType, MsgKeyExchangeReq);
        return PROTOCOL_FAIL;
    }

    if (reqPacket->header.packetType != PlaintextPacket) {
        LOG_ERROR("serverExchangeAESKey: unexpected packet type %d (expected "
                  "PlaintextPacket=%d)",
                  reqPacket->header.packetType, PlaintextPacket);
        return PROTOCOL_FAIL;
    }

    if (reqPacket->header.payloadLength != ECDH_PUBLIC_KEY_SIZE) {
        LOG_ERROR("serverExchangeAESKey: unexpected payload length %zu "
                  "(expected %d)",
                  reqPacket->header.payloadLength, ECDH_PUBLIC_KEY_SIZE);
        return PROTOCOL_FAIL;
    }

    EVP_PKEY *myKeypair = NULL;
    EVP_PKEY *peerKey = NULL;
    uint8_t myPub[ECDH_PUBLIC_KEY_SIZE];
    uint8_t peerPub[ECDH_PUBLIC_KEY_SIZE];
    uint8_t sharedSecret[ECDH_SHARED_SECRET_SIZE];
    KeyExchangePacketPayload keyPayload;
    Packet respPacket;
    int ret = PROTOCOL_FAIL;

    /* packetInit requires payload == NULL on entry. */
    memset(&respPacket, 0, sizeof(respPacket));

    /* 1. Generate ephemeral X25519 key pair. */
    myKeypair = genECDHKeypair();
    if (myKeypair == NULL) {
        goto cleanup;
    }

    /* 2. Export our 32-byte raw public key. */
    if (exportECDHPublicKey(myKeypair, myPub) != CRYPTO_SUCC) {
        goto cleanup;
    }

    /* Reject client sending back our own public key (reflection attack). */
    if (memcmp(myPub, reqPacket->payload, ECDH_PUBLIC_KEY_SIZE) == 0) {
        LOG_ERROR("serverExchangeAESKey: client returned our own public key");
        goto cleanup;
    }

    /* 3. Extract client's public key, then cleanse the request payload. */
    memcpy(peerPub, reqPacket->payload, ECDH_PUBLIC_KEY_SIZE);
    OPENSSL_cleanse(reqPacket->payload, reqPacket->header.payloadLength);

    /* 4. Build key-exchange response packet and send it. */
    memcpy(keyPayload.publicKey, myPub, ECDH_PUBLIC_KEY_SIZE);
    if (packetInit(&respPacket, MsgKeyExchangeResp, 0, PlaintextPacket,
                   &keyPayload, sizeof(keyPayload)) != PROTOCOL_SUCC) {
        goto cleanup;
    }

    if (packetSend(&respPacket, clientFD) != PROTOCOL_SUCC) {
        goto cleanup;
    }

    /* 5. Import client's public key into an EVP_PKEY. */
    peerKey = importECDHPeerPublicKey(peerPub);
    if (peerKey == NULL) {
        goto cleanup;
    }

    /* 6. Derive ECDH shared secret (X25519). */
    if (deriveECDHSharedSecret(myKeypair, peerKey, sharedSecret) !=
        CRYPTO_SUCC) {
        goto cleanup;
    }

    /* 7. Derive AES-256 key via HKDF-SHA256. */
    if (deriveAESKey(sharedSecret, ECDH_SHARED_SECRET_SIZE, outKey) !=
        CRYPTO_SUCC) {
        goto cleanup;
    }

    ret = PROTOCOL_SUCC;

cleanup:
    /* Securely wipe all sensitive material. */
    OPENSSL_cleanse(myPub, sizeof(myPub));
    OPENSSL_cleanse(peerPub, sizeof(peerPub));
    OPENSSL_cleanse(sharedSecret, sizeof(sharedSecret));
    OPENSSL_cleanse(&keyPayload, sizeof(keyPayload));
    EVP_PKEY_free(myKeypair);
    EVP_PKEY_free(peerKey);
    packetClear(&respPacket);

    return ret;
}

int serverSendEncryptedPacket(ClientSession *cs, MessageType mt,
                              const void *data, size_t dataLen) {
    if (cs == NULL) {
        return SERVER_FAIL;
    }
    int ret = packetSendEncrypted(cs->fd, mt, &cs->seqID, cs->aesKey.key, data,
                                  dataLen);
    return (ret == PROTOCOL_SUCC) ? SERVER_SUCC : SERVER_FAIL;
}

int serverRecvEncryptedPacket(ClientSession *cs, Packet *out) {
    if (cs == NULL || out == NULL) {
        return SERVER_FAIL;
    }
    int ret = packetRecvEncrypted(cs->fd, out, cs->aesKey.key);
    return (ret == PROTOCOL_SUCC) ? SERVER_SUCC : SERVER_FAIL;
}

int serverSendStatusResponse(ClientSession *cs, MessageType mt,
                             uint8_t status) {
    return serverSendEncryptedPacket(cs, mt, &status, sizeof(status));
}
