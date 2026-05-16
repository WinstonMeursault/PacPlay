# PacPlay

局域网内游戏平台 🎮

## Makefile

### 构建

```make all``` 可以自动编译出 ```bin/server``` 和 ``` bin/client ```

```make server``` 和 ```make client``` 可以分别编译PacPlay的服务器端和客户端

### 执行

```make run``` 自动运行PacPlay服务器端

```make run-server``` 和 ```make run-client``` 可以分别运行PacPlay的服务器端和客户端

### 清理

```make clean``` 即可清理构建文件

### 生成索引

```make json``` 可以自动生成项目完整索引

```make json-server``` 和 ```make json-client``` 可以分别生成服务器端和客户端的索引

## Log 日志模块

轻量日志库。实现在 `src/common/log.c`，接口在 `include/log.h`，server/client
共用。

### 级别

`
LogLevelTrace < LogLevelDebug < LogLevelInfo < LogLevelWarn < LogLevelError < LogLevelFatal
`

低于全局阈值的消息直接丢弃。默认阈值 `LogLevelTrace`（即全部输出）。

### 基本用法

```c
#include "log.h"

LOG_INFO("listening on port %d", port);
LOG_ERROR("bind failed: %s", strerror(errno));
```

宏自动捕获 `__FILE__` 和 `__LINE__`，输出到 `stderr`，格式：

`
HH:MM:SS LEVEL file.c:line: message
`

### 便捷宏

| 宏 | 等价展开 |
| --- | --- |
| `LOG_TRACE(fmt, ...)` | `logLog(LogLevelTrace, __FILE__, __LINE__, fmt, ...)` |
| `LOG_DEBUG(fmt, ...)` | `logLog(LogLevelDebug, __FILE__, __LINE__, fmt, ...)` |
| `LOG_INFO(fmt, ...)` | `logLog(LogLevelInfo, __FILE__, __LINE__, fmt, ...)` |
| `LOG_WARN(fmt, ...)` | `logLog(LogLevelWarn, __FILE__, __LINE__, fmt, ...)` |
| `LOG_ERROR(fmt, ...)` | `logLog(LogLevelError, __FILE__, __LINE__, fmt, ...)` |
| `LOG_FATAL(fmt, ...)` | `logLog(LogLevelFatal, __FILE__, __LINE__, fmt, ...)` |

所有宏都是对 `logLog()` 的薄封装，自动填充源文件名和行号。参数与 `printf`
语义一致，支持变参。日常使用只需要这些宏，不必直接调用 `logLog()`。

### 配置函数

| 函数 | 作用 |
| --- | --- |
| `logSetLevel(LogLevel level)` | 设置全局最低输出级别 |
| `logSetQuiet(bool enable)` | `true` 关闭 stderr 输出，不影响回调 |
| `logSetLock(LogLockFn fn, void *udata)` | 注册加锁/解锁回调，多线程必须设置 |
| `logAddFp(FILE *fp, LogLevel level)` | 添加文件输出，级别独立于全局阈值 |
| `logAddCallback(LogLogFn fn, void *udata, LogLevel level)` | 注册自定义日志后端 |
| `logLevelString(LogLevel level)` | 返回级别对应的字符串（如 `"INFO"`） |

最多注册 32 个回调（含 `logAddFp`）。超出返回 `-1`。

### 文件输出

```c
FILE *fp = fopen("server.log", "a");
if (fp == NULL) {
    LOG_ERROR("failed to open log file: %s", strerror(errno));
} else {
    if (logAddFp(fp, LogLevelDebug) != 0) {
        LOG_ERROR("log callback slots full, file logging disabled");
        fclose(fp);
    }
}
```

`logAddFp` 成功返回 `0`，回调槽满时返回 `-1`。

文件格式带完整日期：`YYYY-MM-DD HH:MM:SS LEVEL file.c:line: message`。
日志库不负责关闭传入的 `FILE *`，调用者须自行管理其生命周期（程序退出或不再
需要文件日志时 `fclose`）。

### 线程安全

库内部无锁。多线程场景在初始化阶段注册锁回调：

```c
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;

void lockFn(bool lock, void *udata) {
    lock ? pthread_mutex_lock(&mu) : pthread_mutex_unlock(&mu);
}

logSetLock(lockFn, NULL);
```

未注册锁时并发写入行为未定义。

### 自定义回调

```c
void myHandler(LogEvent *ev) {
    // ev->fmt, ev->ap: printf 风格格式串和参数
    // ev->file, ev->line: 源码位置
    // ev->level, ev->time: 级别和时间戳
    // ev->udata: 注册时传入的用户数据
}

logAddCallback(myHandler, ctx, LogLevelWarn);
```

### 颜色输出

编译时定义 `LOG_USE_COLOR` 启用 ANSI 色彩（仅影响 stderr 输出）：

```bash
clang -DLOG_USE_COLOR ...
```
