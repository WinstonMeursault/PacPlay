/*
 * Copyright (c) 2020 rxi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "log.h"

/** @brief Maximum number of simultaneously registered logging callbacks. */
#define MAX_CALLBACKS 32
/** @brief Buffer size for short time strings (HH:MM:SS). */
#define TIME_BUF_SIZE 16
/** @brief Buffer size for full datetime strings (YYYY-MM-DD HH:MM:SS). */
#define DATETIME_BUF_SIZE 64

/**
 * @brief Internal representation of a registered callback entry.
 */
typedef struct {
    LogLogFn fn;    /**< The callback function. */
    void *udata;    /**< Opaque user data forwarded via LogEvent. */
    LogLevel level; /**< Minimum severity to trigger this callback. */
} Callback;

/** @brief Global logger state (file-scoped). */
static struct {
    void *udata;                       /**< User data for the lock function. */
    LogLockFn lock;                    /**< Lock/unlock callback. */
    LogLevel level;                    /**< Minimum level for stderr output. */
    bool quiet;                        /**< Suppress stderr when true. */
    Callback callbacks[MAX_CALLBACKS]; /**< Registered callback table. */
} logger;

/** @brief Human-readable names indexed by LogLevel. */
static const char *levelStrings[] = {"TRACE", "DEBUG", "INFO",
                                     "WARN",  "ERROR", "FATAL"};

#ifdef LOG_USE_COLOR
/** @brief ANSI colour escape sequences indexed by LogLevel. */
static const char *levelColors[] = {"\x1b[94m", "\x1b[36m", "\x1b[32m",
                                    "\x1b[33m", "\x1b[31m", "\x1b[35m"};
#endif

/**
 * @brief Thread-safe wrapper around localtime.
 *
 * @param t      Pointer to the calendar time to convert.
 * @param result Pointer to a struct tm that receives the broken-down time.
 * @return struct tm* @p result on success, or @c NULL on failure.
 *
 * Delegates to localtime_s on MSVC and localtime_r on POSIX, ensuring
 * no shared static buffer is used.
 */
static struct tm *safeLocaltime(const time_t *t, struct tm *result) {
#if defined(_MSC_VER)
    return localtime_s(result, t) == 0 ? result : NULL;
#else
    return localtime_r(t, result);
#endif
}

/**
 * @brief Built-in callback that writes log messages to stderr.
 *
 * @param ev Pointer to the current log event.
 *
 * Formats the message as "HH:MM:SS LEVEL file:line: message\n".
 * When LOG_USE_COLOR is defined, ANSI escape codes are used for
 * coloured level names and dimmed source locations.
 */
static void stdoutCallback(LogEvent *ev) {
    char buf[TIME_BUF_SIZE];
    buf[strftime(buf, sizeof(buf), "%H:%M:%S", &ev->time)] = '\0';
#ifdef LOG_USE_COLOR
    fprintf((FILE *)ev->udata, "%s %s%-5s\x1b[0m \x1b[90m%s:%d:\x1b[0m ", buf,
            levelColors[ev->level], levelStrings[ev->level], ev->file,
            ev->line);
#else
    fprintf((FILE *)ev->udata, "%s %-5s %s:%d: ", buf, levelStrings[ev->level],
            ev->file, ev->line);
#endif
    vfprintf((FILE *)ev->udata, ev->fmt, ev->ap);
    fprintf((FILE *)ev->udata, "\n");
    fflush((FILE *)ev->udata);
}

/**
 * @brief Built-in callback that writes log messages to a file.
 *
 * @param ev Pointer to the current log event.
 *
 * Formats the message as "YYYY-MM-DD HH:MM:SS LEVEL file:line: message\n".
 * Each line is flushed immediately to avoid data loss on crash.
 */
static void fileCallback(LogEvent *ev) {
    char buf[DATETIME_BUF_SIZE];
    buf[strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &ev->time)] = '\0';
    fprintf((FILE *)ev->udata, "%s %-5s %s:%d: ", buf, levelStrings[ev->level],
            ev->file, ev->line);
    vfprintf((FILE *)ev->udata, ev->fmt, ev->ap);
    fprintf((FILE *)ev->udata, "\n");
    fflush((FILE *)ev->udata);
}

/**
 * @brief Acquire the logger lock if a lock function is registered.
 *
 * No-op when no lock callback has been set via logSetLock().
 */
static void loggerLock(void) {
    if (logger.lock) {
        logger.lock(true, logger.udata);
    }
}

/**
 * @brief Release the logger lock if a lock function is registered.
 *
 * No-op when no lock callback has been set via logSetLock().
 */
static void loggerUnlock(void) {
    if (logger.lock) {
        logger.lock(false, logger.udata);
    }
}

const char *logLevelString(LogLevel level) {
    if (level < LogLevelTrace || level > LogLevelFatal) {
        return "UNKNOWN";
    }
    return levelStrings[level];
}

void logSetLock(LogLockFn fn, void *udata) {
    logger.lock = fn;
    logger.udata = udata;
}

void logSetLevel(LogLevel level) { logger.level = level; }

void logSetQuiet(bool enable) { logger.quiet = enable; }

int logAddCallback(LogLogFn fn, void *udata, LogLevel level) {
    for (int i = 0; i < MAX_CALLBACKS; i++) {
        if (!logger.callbacks[i].fn) {
            logger.callbacks[i] = (Callback){fn, udata, level};
            return 0;
        }
    }
    return -1;
}

int logAddFp(FILE *fp, LogLevel level) {
    return logAddCallback(fileCallback, fp, level);
}

/**
 * @brief Initialise a LogEvent with callback-specific user data.
 *
 * @param ev    Pointer to the log event to initialise.
 * @param udata Opaque user data to attach (typically a FILE*).
 */
static void initEvent(LogEvent *ev, void *udata) { ev->udata = udata; }

void logLog(LogLevel level, const char *file, int line, const char *fmt, ...) {
    time_t t = time(NULL);
    struct tm timeInfo = {0};
    safeLocaltime(&t, &timeInfo);

    LogEvent ev = {
        .fmt = fmt,
        .file = file,
        .line = line,
        .level = level,
        .time = timeInfo,
    };

    loggerLock();

    if (!logger.quiet && level >= logger.level) {
        initEvent(&ev, stderr);
        va_start(ev.ap, fmt);
        stdoutCallback(&ev);
        va_end(ev.ap);
    }

    for (int i = 0; i < MAX_CALLBACKS && logger.callbacks[i].fn; i++) {
        Callback *cb = &logger.callbacks[i];
        if (level >= cb->level) {
            initEvent(&ev, cb->udata);
            va_start(ev.ap, fmt);
            cb->fn(&ev);
            va_end(ev.ap);
        }
    }

    loggerUnlock();
}
