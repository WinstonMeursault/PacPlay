/**
 * @file utils.h
 * @brief General-purpose utility macros and functions for PacPlay.
 *
 * Provides common helper macros (MIN/MAX) and cross-platform utility
 * functions such as timestamp retrieval.
 *
 * @date 2026-05-17
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

#ifndef UTILS_H
#define UTILS_H

#include <time.h>

#include <stddef.h>
#include <vterm.h>

/* ───────────────────────────── generic macros ───────────────────────────── */

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

/* ─────────────────────────── platform utilities ─────────────────────────── */

#ifdef _WIN32
#include <direct.h>
/** @brief Cross-platform mkdir wrapper (Windows ignores mode). */
#define PLATFORM_MKDIR(path, mode) _mkdir(path)
#else
/** @brief Cross-platform mkdir wrapper (POSIX). */
#define PLATFORM_MKDIR(path, mode) mkdir(path, mode)
#endif

/* ───────────────────────────── hex utilities ────────────────────────────── */

/**
 * @brief Convert a single hex character to its 4-bit nibble value.
 *
 * @param c  Hex character (0-9, a-f, A-F).
 * @return Nibble value 0-15, or -1 if @p c is not a valid hex digit.
 */
int hexCharToNibble(char c);

/* ───────────────────────────── time utilities ───────────────────────────── */

/**
 * @brief Get the current UNIX timestamp in seconds (UTC).
 *
 * Uses the ISO C @c time() function, which is portable across all major
 * platforms (POSIX, Windows, macOS).
 *
 * @return Current time as @c time_t (seconds since 1970-01-01 00:00:00 UTC),
 *         or @c (time_t)-1 on failure.
 */
time_t getCurrentTimestamp(void);

/**
 * @brief Read a password from stdin with masked input (asterisks).
 *
 * When stdin is a terminal, disables echo, reads up to
 * @p bufsize - 1 characters, displays @c '*' for each keystroke,
 * handles backspace, and restores terminal settings on completion.
 * When stdin is not a terminal (pipe / redirect), falls back to a
 * single @c fgets() call without masking.
 *
 * The buffer is always NUL-terminated.  The trailing newline is
 * consumed but **not** stored.  Callers should @c printf(@"\\n")
 * afterwards to advance the cursor.
 *
 * @param buf      Output buffer (must be at least @p bufsize bytes).
 * @param bufsize  Size of @p buf in bytes.
 * @return Length of the password read (excluding NUL), or @c 0 on EOF
 *         or error.
 */
size_t readPasswordMasked(char *buf, size_t bufsize);

VTermKey ncursesKeyToVTerm(int ncursesKey);

#endif /* UTILS_H */