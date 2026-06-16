/**
 * @file pacplay_sdk.h
 * @brief PacPlay SDK public C API — thread-safe ring buffer bridge between
 *        game threads and PacPlay IO threads.
 * 
 * The SDK does NOT handle protocol (no socket I/O, no encryption, no header
 * construction).  It provides mutex-protected FIFO queues so game code can
 * safely push/poll payloads across thread boundaries.
 * 
 * @date 2026-06-17
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

#ifndef PACPLAY_SDK_H
#define PACPLAY_SDK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ═══════════════════════════ common types ═════════════════════════════════ */

/** Opaque SDK handle.  Allocated by @c pacplay_cli_create or
 *  @c pacplay_srv_create and destroyed by the matching @c _destroy. */
typedef struct PacPlaySDK PacPlaySDK;

/** Callback signature for received game payloads.
 *  @param payload  Raw game payload (owned by SDK — do not free).
 *  @param len      Payload length in bytes.
 *  @param userData Opaque pointer registered with @c pacplay_*_on_receive. */
typedef void (*PacPlayOnReceive)(const void *payload, size_t len,
                                 void *userData);

/* ═════════════════════════ Client SDK API ═════════════════════════════════ */

/** Create a Client SDK instance (game → Client IO Thread bridge).
 *  @return New handle, or NULL on allocation failure. */
PacPlaySDK *pacplay_cli_create(void);

/** Destroy a Client SDK instance.  Safe to call with NULL. */
void pacplay_cli_destroy(PacPlaySDK *sdk);

/** Push a game payload into the send queue (non-blocking).
 *  The payload is copied internally; the caller may free/reuse @p data
 *  immediately.
 *  @param sdk  Client SDK handle.
 *  @param data Game payload bytes.
 *  @param len  Payload length (must be ≤ 65536).
 *  @return 0 on success, -1 on failure (OOM, queue full, or invalid args). */
int pacplay_cli_send(PacPlaySDK *sdk, const void *data, size_t len);

/** Register a callback for received game payloads.
 *  The callback is invoked from @c pacplay_cli_poll (game thread context).
 *  @param sdk      Client SDK handle.
 *  @param callback Function to call for each received payload.
 *  @param userData Opaque pointer forwarded to the callback. */
void pacplay_cli_on_receive(PacPlaySDK *sdk, PacPlayOnReceive callback,
                            void *userData);

/** Drain the receive queue and fire the registered callback for each payload.
 *  Call this once per game-loop tick from the game thread.
 *  @param sdk Client SDK handle. */
void pacplay_cli_poll(PacPlaySDK *sdk);

/* ── Client IO Thread API (called from Client IO Thread only) ─────────────── */

/** Poll the send queue for a pending game payload.
 *  @param sdk        Client SDK handle.
 *  @param outPayload Set to internal buffer (do not free — call
 *                    @c pacplay_cli_free_payload after use).
 *  @param outLen     Payload length in bytes.
 *  @return true if a payload was dequeued, false if the queue is empty. */
bool pacplay_cli_poll_send(PacPlaySDK *sdk, uint8_t **outPayload,
                           size_t *outLen);

/** Push a received game payload into the receive queue for the game callback.
 *  @param sdk     Client SDK handle.
 *  @param payload Raw game payload bytes (copied internally).
 *  @param len     Payload length. */
void pacplay_cli_push_received(PacPlaySDK *sdk, const uint8_t *payload,
                               size_t len);

/** Release a payload pointer returned by @c pacplay_cli_poll_send.
 *  @param sdk     Client SDK handle.
 *  @param payload Pointer previously returned by @c pacplay_cli_poll_send. */
void pacplay_cli_free_payload(PacPlaySDK *sdk, uint8_t *payload);

/* ═════════════════════════ Server SDK API ═════════════════════════════════ */

/** Create a Server SDK instance (game server → Server IO Thread bridge). */
PacPlaySDK *pacplay_srv_create(void);

/** Destroy a Server SDK instance.  Safe to call with NULL. */
void pacplay_srv_destroy(PacPlaySDK *sdk);

/** Push a game payload into the send queue (non-blocking). */
int pacplay_srv_send(PacPlaySDK *sdk, const void *data, size_t len);

/** Register a callback for received game payloads. */
void pacplay_srv_on_receive(PacPlaySDK *sdk, PacPlayOnReceive callback,
                            void *userData);

/** Drain the receive queue and fire callbacks. */
void pacplay_srv_poll(PacPlaySDK *sdk);

/* ── Server IO Thread API (called from Server IO Thread only) ─────────────── */

/** Poll the send queue for a pending game payload. */
bool pacplay_srv_poll_send(PacPlaySDK *sdk, uint8_t **outPayload,
                           size_t *outLen);

/** Push a received game payload into the receive queue. */
void pacplay_srv_push_received(PacPlaySDK *sdk, const uint8_t *payload,
                               size_t len);

/** Release a payload pointer returned by @c pacplay_srv_poll_send. */
void pacplay_srv_free_payload(PacPlaySDK *sdk, uint8_t *payload);

#ifdef __cplusplus
}
#endif

#endif /* PACPLAY_SDK_H */
