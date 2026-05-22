/**
 * @file communication.c
 * @brief Client-side communication: ECDH+HKDF AES key exchange.
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

/* ─────────────────── public API ─────────────────────────────────────────── */

int clientExchangeAESKey(SocketFD socketFD, AESGCMKey *outKey) {
    if (outKey == NULL) {
        LOG_ERROR("clientExchangeAESKey: NULL outKey");
        return COMM_FAIL;
    }

    EVP_PKEY *myKeypair = NULL;
    EVP_PKEY *peerKey = NULL;
    uint8_t myPub[ECDH_PUBLIC_KEY_SIZE];
    uint8_t peerPub[ECDH_PUBLIC_KEY_SIZE];
    uint8_t sharedSecret[ECDH_SHARED_SECRET_SIZE];
    KeyExchangePacketPayload keyPayload;
    Packet txPacket;
    Packet rxPacket;
    int ret = COMM_FAIL;

    /* packetInit requires payload == NULL on entry. */
    memset(&txPacket, 0, sizeof(txPacket));
    /* rxPacket.payload must be NULL for packetRecv. */
    memset(&rxPacket, 0, sizeof(rxPacket));

    /* 1. Generate ephemeral X25519 key pair. */
    myKeypair = genECDHKeypair();
    if (myKeypair == NULL) {
        goto cleanup;
    }

    /* 2. Export our 32-byte raw public key. */
    if (exportECDHPublicKey(myKeypair, myPub) != CRYPTO_SUCC) {
        goto cleanup;
    }

    /* 3. Build key-exchange request packet and send it. */
    memcpy(keyPayload.publicKey, myPub, ECDH_PUBLIC_KEY_SIZE);
    if (packetInit(&txPacket, MsgKeyExchangeReq, 0, PlaintextPacket,
                   &keyPayload, sizeof(keyPayload)) != PROTOCOL_SUCC) {
        goto cleanup;
    }

    if (packetSend(&txPacket, socketFD) != PROTOCOL_SUCC) {
        goto cleanup;
    }

    /* 4. Receive server's key-exchange response packet. */
    if (packetRecv(&rxPacket, socketFD) != PROTOCOL_SUCC) {
        LOG_ERROR("clientExchangeAESKey: failed to receive server response");
        goto cleanup;
    }

    /* ──── zero-trust validation of network-received data ──────────────── */

    if (rxPacket.header.messageType != MsgKeyExchangeResp) {
        LOG_ERROR("clientExchangeAESKey: unexpected message type %d (expected "
                  "MsgKeyExchangeResp=%d)",
                  rxPacket.header.messageType, MsgKeyExchangeResp);
        goto cleanup;
    }

    if (rxPacket.header.packetType != PlaintextPacket) {
        LOG_ERROR("clientExchangeAESKey: unexpected packet type %d (expected "
                  "PlaintextPacket=%d)",
                  rxPacket.header.packetType, PlaintextPacket);
        goto cleanup;
    }

    if (rxPacket.header.payloadLength != ECDH_PUBLIC_KEY_SIZE) {
        LOG_ERROR("clientExchangeAESKey: unexpected payload length %zu "
                  "(expected %d)",
                  rxPacket.header.payloadLength, ECDH_PUBLIC_KEY_SIZE);
        goto cleanup;
    }

    if (rxPacket.payload == NULL) {
        LOG_ERROR("clientExchangeAESKey: received NULL payload");
        goto cleanup;
    }

    /* Reject peer sending back our own public key (self-loop / reflection). */
    if (memcmp(myPub, rxPacket.payload, ECDH_PUBLIC_KEY_SIZE) == 0) {
        LOG_ERROR("clientExchangeAESKey: server returned our own public key");
        goto cleanup;
    }

    /* 5. Copy peer public key out of the received payload, then cleanse. */
    memcpy(peerPub, rxPacket.payload, ECDH_PUBLIC_KEY_SIZE);
    OPENSSL_cleanse(rxPacket.payload, rxPacket.header.payloadLength);

    /* 6. Import server's public key into an EVP_PKEY. */
    peerKey = importECDHPeerPublicKey(peerPub);
    if (peerKey == NULL) {
        goto cleanup;
    }

    /* 7. Derive ECDH shared secret (X25519). */
    if (deriveECDHSharedSecret(myKeypair, peerKey, sharedSecret) !=
        CRYPTO_SUCC) {
        goto cleanup;
    }

    /* 8. Derive AES-256 key via HKDF-SHA256. */
    if (deriveAESKey(sharedSecret, ECDH_SHARED_SECRET_SIZE, outKey) !=
        CRYPTO_SUCC) {
        goto cleanup;
    }

    ret = COMM_SUCC;

cleanup:
    /* Securely wipe all sensitive material. */
    OPENSSL_cleanse(myPub, sizeof(myPub));
    OPENSSL_cleanse(peerPub, sizeof(peerPub));
    OPENSSL_cleanse(sharedSecret, sizeof(sharedSecret));
    OPENSSL_cleanse(&keyPayload, sizeof(keyPayload));
    EVP_PKEY_free(myKeypair);
    EVP_PKEY_free(peerKey);
    packetClear(&txPacket);
    packetClear(&rxPacket);

    return ret;
}
