/**
 * @file serverLog.h
 * @brief Server file-logging subsystem — dedicated log thread with UTC-day
 *        file rotation, background log compression (zlib-ng), automatic
 *        restart on thread failure, and a TUI-facing log fetch API.
 *
 * @date 2026-06-10
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

#ifndef SERVER_LOG_H
#define SERVER_LOG_H

#include "log.h"

/**
 * @brief Initialise the server file-logging subsystem.
 *
 * Creates the @c ./logs/ directory, spawns a dedicated log-writer thread
 * and a background compression thread, initialises the TUI-facing log
 * ring buffer, and registers a log callback that enqueues formatted
 * messages for asynchronous file I/O.
 *
 * The file name follows the pattern @c server-YYYY-MM-DD.log and the
 * log thread automatically rotates at UTC midnight, triggering the
 * compression thread to scan for and gzip files older than seven days.
 *
 * Must be called once at startup — re-entrant calls are safe no-ops.
 *
 * @note The compression thread is best-effort: if it fails to spawn the
 *       subsystem continues with file logging only and no crash-restart
 *       is attempted for it.
 *
 * @return 0 on success, -1 on failure (server continues with stderr-only
 *         logging).
 */
int serverLogInit(void);

/**
 * @brief Check whether the log thread is alive and restart it if needed.
 *
 * This function is designed to be called periodically from the server main
 * loop (roughly once per second).  When the call rate is higher the function
 * is effectively a no-op because the running-flag check is cheap.
 *
 * On the first three consecutive log-thread failures a fresh thread is
 * spawned and a warning is emitted.  After the third failure the subsystem
 * gives up and stays silent — the server continues to operate normally with
 * stderr-only logging.
 *
 * When the log thread is restarted the ring buffers (file-writer and TUI)
 * are cleared along with the compression failure counter.  The compression
 * thread itself is **not** restarted — its absence is non-critical.
 */
void serverLogCheckAndRestart(void);

/**
 * @brief Gracefully shut down the log subsystem.
 *
 * Signals the log thread to stop, waits for it to drain any remaining
 * queued messages and write them to the file.  Stops and joins the
 * background compression thread.  Destroys all synchronisation
 * primitives and frees all resources.
 *
 * Safe to call when @c serverLogInit() was never called or failed.
 */
void serverLogClose(void);

/**
 * @brief Drain and return log messages produced since the previous call.
 *
 * Retrieves all log lines at or above @p minLevel that have been
 * accumulated in the TUI ring buffer since the last call to this
 * function.  The buffer is emptied regardless of whether any lines
 * matched the filter.
 *
 * @param minLevel Minimum severity to include in the result.
 * @param outLines Receives a newly-allocated NULL-terminated array of
 *                 owned strings.  Free with serverLogFetchFree().
 * @param outCount Receives the number of lines (excluding the NULL
 *                 terminator).  May be NULL if the count is not needed.
 * @return 0 on success (empty result yields count=0 and a valid array),
 *         -1 on allocation failure (the buffer is still drained).
 *
 * @note Thread-safe — may be called from any thread concurrent with
 *       logging activity.
 */
int serverLogFetch(LogLevel minLevel, char ***outLines, int *outCount);

/**
 * @brief Free the result array returned by serverLogFetch().
 *
 * @param lines The array returned by the last serverLogFetch() call.
 * @param count The line count returned alongside @p lines.
 */
void serverLogFetchFree(char **lines, int count);

#endif /* SERVER_LOG_H */
