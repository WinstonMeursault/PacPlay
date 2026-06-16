/**
 * @file pacplay_client_sdk.c
 * @brief Client SDK thin wrapper — delegates to the shared implementation
 *        in pacplay_sdk.c.
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
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "pacplay_sdk.h"

PacPlaySDK *sdk_create(void);
void sdk_destroy(PacPlaySDK *sdk);
int sdk_send(PacPlaySDK *sdk, const void *data, size_t len);
bool sdk_poll_send(PacPlaySDK *sdk, uint8_t **outPayload, size_t *outLen);
void sdk_push_received(PacPlaySDK *sdk, const uint8_t *payload, size_t len);
void sdk_poll(PacPlaySDK *sdk);
void sdk_on_receive(PacPlaySDK *sdk, PacPlayOnReceive callback, void *userData);
void sdk_free_payload(PacPlaySDK *sdk, uint8_t *payload);

PacPlaySDK *pacplay_cli_create(void) { return sdk_create(); }

void pacplay_cli_destroy(PacPlaySDK *sdk) { sdk_destroy(sdk); }

int pacplay_cli_send(PacPlaySDK *sdk, const void *data, size_t len)
{
    return sdk_send(sdk, data, len);
}

bool pacplay_cli_poll_send(PacPlaySDK *sdk, uint8_t **outPayload,
                           size_t *outLen)
{
    return sdk_poll_send(sdk, outPayload, outLen);
}

void pacplay_cli_push_received(PacPlaySDK *sdk, const uint8_t *payload,
                               size_t len)
{
    sdk_push_received(sdk, payload, len);
}

void pacplay_cli_poll(PacPlaySDK *sdk) { sdk_poll(sdk); }

void pacplay_cli_on_receive(PacPlaySDK *sdk, PacPlayOnReceive callback,
                            void *userData)
{
    sdk_on_receive(sdk, callback, userData);
}

void pacplay_cli_free_payload(PacPlaySDK *sdk, uint8_t *payload)
{
    sdk_free_payload(sdk, payload);
}
