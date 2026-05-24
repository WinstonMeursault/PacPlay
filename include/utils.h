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

/* ──────────────────────── generic macros ───────────────────────────────── */

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

/* ──────────────────────── time utilities ───────────────────────────────── */

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

#endif /* UTILS_H */