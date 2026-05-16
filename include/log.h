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

typedef enum {
    LogLevelTrace,
    LogLevelDebug,
    LogLevelInfo,
    LogLevelWarn,
    LogLevelError,
    LogLevelFatal
} LogLevel;

typedef struct {
    va_list ap;
    const char *fmt;
    const char *file;
    struct tm time;
    void *udata;
    int line;
    LogLevel level;
} LogEvent;

typedef void (*LogLogFn)(LogEvent *ev);
typedef void (*LogLockFn)(bool lock, void *udata);

const char *logLevelString(LogLevel level);
void logSetLock(LogLockFn fn, void *udata);
void logSetLevel(LogLevel level);
void logSetQuiet(bool enable);
int logAddCallback(LogLogFn fn, void *udata, LogLevel level);
int logAddFp(FILE *fp, LogLevel level);

void logLog(LogLevel level, const char *file, int line, const char *fmt, ...);

#define LOG_TRACE(...) logLog(LogLevelTrace, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_DEBUG(...) logLog(LogLevelDebug, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_INFO(...) logLog(LogLevelInfo, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_WARN(...) logLog(LogLevelWarn, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_ERROR(...) logLog(LogLevelError, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_FATAL(...) logLog(LogLevelFatal, __FILE__, __LINE__, __VA_ARGS__)

#endif
