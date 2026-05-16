#include "log.h"

#define MAX_CALLBACKS 32
#define TIME_BUF_SIZE 16
#define DATETIME_BUF_SIZE 64

typedef struct {
    LogLogFn fn;
    void *udata;
    LogLevel level;
} Callback;

static struct {
    void *udata;
    LogLockFn lock;
    LogLevel level;
    bool quiet;
    Callback callbacks[MAX_CALLBACKS];
} logger;

static const char *levelStrings[] = {"TRACE", "DEBUG", "INFO",
                                     "WARN",  "ERROR", "FATAL"};

#ifdef LOG_USE_COLOR
static const char *levelColors[] = {"\x1b[94m", "\x1b[36m", "\x1b[32m",
                                    "\x1b[33m", "\x1b[31m", "\x1b[35m"};
#endif

static struct tm *safeLocaltime(const time_t *t, struct tm *result) {
#if defined(_MSC_VER)
    return localtime_s(result, t) == 0 ? result : NULL;
#else
    return localtime_r(t, result);
#endif
}

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

static void fileCallback(LogEvent *ev) {
    char buf[DATETIME_BUF_SIZE];
    buf[strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &ev->time)] = '\0';
    fprintf((FILE *)ev->udata, "%s %-5s %s:%d: ", buf, levelStrings[ev->level],
            ev->file, ev->line);
    vfprintf((FILE *)ev->udata, ev->fmt, ev->ap);
    fprintf((FILE *)ev->udata, "\n");
    fflush((FILE *)ev->udata);
}

static void loggerLock(void) {
    if (logger.lock) {
        logger.lock(true, logger.udata);
    }
}

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
