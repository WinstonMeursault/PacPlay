/**
 * Copyright (c) 2020 rxi
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See `log.c` for details.
 */

#ifndef LOG_H
#define LOG_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>

/**
 * @brief Severity levels for log messages.
 *
 * Levels are ordered from least severe (LogLevelTrace) to most severe
 * (LogLevelFatal). The global log level acts as a filter: only messages
 * at or above the configured level are emitted.
 */
typedef enum {
    LogLevelTrace, /**< Fine-grained diagnostic information. */
    LogLevelDebug, /**< Debugging information useful during development. */
    LogLevelInfo,  /**< Informational messages highlighting progress. */
    LogLevelWarn,  /**< Potentially harmful situations. */
    LogLevelError, /**< Error events that might still allow continued running.
                    */
    LogLevelFatal  /**< Severe error events that will presumably abort. */
} LogLevel;

/**
 * @brief Context passed to every logging callback.
 *
 * Populated by logLog() before each callback invocation. The @c ap field
 * is valid only for the duration of the callback.
 */
typedef struct {
    va_list ap;       /**< Variable argument list for the format string. */
    const char *fmt;  /**< printf-style format string. */
    const char *file; /**< Source file name of the log call site. */
    struct tm time;   /**< Local time at the moment of the log call. */
    void *udata;      /**< User data associated with this callback. */
    int line;         /**< Source line number of the log call site. */
    LogLevel level;   /**< Severity level of this log event. */
} LogEvent;

/**
 * @brief Signature for logging callback functions.
 *
 * @param ev Pointer to the LogEvent describing the current log message.
 */
typedef void (*LogLogFn)(LogEvent *ev);

/**
 * @brief Signature for the lock/unlock callback used for thread safety.
 *
 * @param lock @c true to acquire the lock, @c false to release it.
 * @param udata Opaque user data passed during logSetLock() registration.
 */
typedef void (*LogLockFn)(bool lock, void *udata);

/**
 * @brief Return the human-readable name of a log level.
 *
 * @param level The log level to convert.
 * @return const char* A static string such as "TRACE", "DEBUG", ..., "FATAL",
 *                     or "UNKNOWN" if @p level is out of range.
 *
 * The returned pointer references static storage and must not be freed.
 */
const char *logLevelString(LogLevel level);

/**
 * @brief Register a lock/unlock function for thread-safe logging.
 *
 * @param fn  The lock callback, or @c NULL to disable locking.
 * @param udata Opaque pointer forwarded to @p fn on each call.
 *
 * When set, the library calls @p fn(true, udata) before writing and
 * @p fn(false, udata) after writing, allowing the caller to serialise
 * access with a mutex or similar primitive.
 */
void logSetLock(LogLockFn fn, void *udata);

/**
 * @brief Set the minimum log level for stderr output.
 *
 * @param level Messages below this level are suppressed.
 *
 * The default level is LogLevelTrace (everything is printed).
 */
void logSetLevel(LogLevel level);

/**
 * @brief Enable or disable stderr output.
 *
 * @param enable @c true to suppress all stderr output, @c false to re-enable.
 *
 * When quiet mode is enabled, the built-in stderr callback is skipped.
 * Registered file and custom callbacks are unaffected.
 */
void logSetQuiet(bool enable);

/**
 * @brief Register a custom logging callback.
 *
 * @param fn    The callback function invoked for each qualifying log event.
 * @param udata Opaque pointer stored and forwarded to @p fn via LogEvent.
 * @param level Minimum level required to trigger this callback.
 * @return int  0 on success, -1 if the callback table is full.
 *
 * Up to 32 callbacks may be registered simultaneously. Each callback has
 * its own independent level filter.
 */
int logAddCallback(LogLogFn fn, void *udata, LogLevel level);

/**
 * @brief Register a FILE* as a log destination.
 *
 * @param fp    An open FILE pointer (e.g. from fopen()).
 * @param level Minimum level required to write to this file.
 * @return int  0 on success, -1 if the callback table is full.
 *
 * Convenience wrapper around logAddCallback() that uses an internal
 * file-writing callback. Each log line is flushed immediately.
 */
int logAddFp(FILE *fp, LogLevel level);

/**
 * @brief Emit a log message.
 *
 * @param level Severity level of the message.
 * @param file  Source file name (typically passed via __FILE__).
 * @param line  Source line number (typically passed via __LINE__).
 * @param fmt   printf-style format string.
 * @param ...   Format arguments.
 *
 * This is the core logging entry point. The LOG_TRACE .. LOG_FATAL
 * convenience macros expand to calls to this function with the correct
 * file and line filled in automatically.
 */
void logLog(LogLevel level, const char *file, int line, const char *fmt, ...);

/** @brief Log a message at TRACE level. */
#define LOG_TRACE(...) logLog(LogLevelTrace, __FILE__, __LINE__, __VA_ARGS__)
/** @brief Log a message at DEBUG level. */
#define LOG_DEBUG(...) logLog(LogLevelDebug, __FILE__, __LINE__, __VA_ARGS__)
/** @brief Log a message at INFO level. */
#define LOG_INFO(...) logLog(LogLevelInfo, __FILE__, __LINE__, __VA_ARGS__)
/** @brief Log a message at WARN level. */
#define LOG_WARN(...) logLog(LogLevelWarn, __FILE__, __LINE__, __VA_ARGS__)
/** @brief Log a message at ERROR level. */
#define LOG_ERROR(...) logLog(LogLevelError, __FILE__, __LINE__, __VA_ARGS__)
/** @brief Log a message at FATAL level. */
#define LOG_FATAL(...) logLog(LogLevelFatal, __FILE__, __LINE__, __VA_ARGS__)

#endif
