/**
 * @file auth.h
 * @brief Server-side authentication handlers.
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

#ifndef SERVER_AUTH_H
#define SERVER_AUTH_H

#include "server.h"

/**
 * @brief Handle MsgLoginReq — validate payload, verify credentials, challenge
 * TOTP if registered, or grant immediate room access.
 *
 * On success the session is advanced to @c SessionTOTPVerify (if TOTP is
 * registered) or @c SessionRoom (if no TOTP).  The server always sends a
 * @c MsgLoginResp with @c uid=0 on failure (no user enumeration).
 *
 * @param s   Server instance (must have an open UserDB).
 * @param cs  Sending client session.
 * @param pkt Decrypted incoming MsgLoginReq packet.
 * @return @c SERVER_SUCC on success, @c SERVER_FAIL on fatal error.
 */
int serverHandleLogin(Server *s, ClientSession *cs, const Packet *pkt);

/**
 * @brief Handle MsgRegisterReq — validate payload and create a new user.
 *
 * The server assigns a random unique UID and generates a per-user CDBKey
 * encrypted with the DEK.  A single-byte status response (0 = success,
 * 1 = failure) is sent back.
 *
 * @param s   Server instance.
 * @param cs  Sending client session.
 * @param pkt Decrypted incoming MsgRegisterReq packet.
 * @return @c SERVER_SUCC on success, @c SERVER_FAIL on fatal error.
 */
int serverHandleRegister(Server *s, ClientSession *cs, const Packet *pkt);

/**
 * @brief Handle MsgTOTPSetupReq — generate a fresh TOTP secret for the
 * authenticated user, encrypt it with the DEK, and store it in UserDB.
 *
 * If TOTP is already registered the request is rejected (status 1).
 * On success the Base32-encoded secret is returned to the client via
 * @c MsgTOTPSetupResp.
 *
 * @param s   Server instance.
 * @param cs  Authenticated client session.
 * @return @c SERVER_SUCC on success, @c SERVER_FAIL on fatal error.
 */
int serverHandleTOTPSetup(Server *s, ClientSession *cs);

/**
 * @brief Handle MsgTOTPVerifyResp — verify the user-supplied TOTP code
 * against the stored secret.
 *
 * On success the session is advanced to @c SessionRoom and a final
 * @c MsgLoginResp with @c totpEnabled=1 is sent.  On failure
 * @c SERVER_FAIL is returned to disconnect the client.
 *
 * @param s   Server instance.
 * @param cs  Client session awaiting TOTP verification.
 * @param pkt Decrypted incoming MsgTOTPVerifyResp packet.
 * @return @c SERVER_SUCC on success, @c SERVER_FAIL on failure.
 */
int serverHandleTOTPVerify(Server *s, ClientSession *cs, const Packet *pkt);

/**
 * @brief Handle MsgDBKeyReq — retrieve and decrypt the per-user CDBKey
 * from UserDB and send it to the client via @c MsgDBKeyResp.
 *
 * @param s   Server instance.
 * @param cs  Authenticated client session.
 * @return @c SERVER_SUCC on success, @c SERVER_FAIL on failure.
 */
int serverHandleDBKeyReq(Server *s, ClientSession *cs);

#endif /* SERVER_AUTH_H */
