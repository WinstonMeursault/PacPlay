# API 文档

## Protocol 通信协议

接口位于 `include/protocol.h` ，实现在 `src/common/protocol.c`

实现 PacPlay 的二进制网络协议栈，涵盖 TCP 套接字管理、数据包序列化、AES-256-GCM authenticated encryption 以及阻塞式收发。所有公共 API 均使用 C17 标准与 OpenSSL 密码学原语。

### 常量与宏

| 宏 | 值 | 说明 |
| --- | --- | --- |
| `PROTOCOL_SUCC` | `0` | 函数执行成功 |
| `PROTOCOL_FAIL` | `-1` | 通用失败 |
| `PROTOCOL_AUTH_FAIL` | `-2` | AES-GCM 认证标签校验失败或 AAD 不匹配 |
| `MAX_PAYLOAD_LEN` | `1024` | 明文载荷最大字节数 |
| `AES_GCM_KEY_LEN` | `32` | AES-256 对称密钥长度（字节） |
| `AES_GCM_NONCE_LEN` | `12` | GCM 模式随机 nonce 长度（字节） |
| `AES_GCM_TAG_LEN` | `16` | GCM 认证标签长度（字节） |
| `AES_PACKET_EXTRA_LEN` | `28` | 加密后额外开销：`AES_GCM_NONCE_LEN + AES_GCM_TAG_LEN` |
| `BACKLOG` | `5` | `listen()` 连接队列长度 |
| `NULL_SOCKETFD` | `-1` | 无效套接字描述符标识 |
| `PACKET_MAGIC` | `0x5050504D` | 包魔术字，ASCII `'PPPM'` |

### 类型定义

#### SocketFD

```c
typedef int SocketFD;
```

套接字文件描述符的别名。取值为 `NULL_SOCKETFD` 表示无效或已关闭。

#### PacketType

```c
typedef enum {
    PlaintextPacket = 1,
    AES256GCMPacket
} PacketType;
```

标识数据包的加密状态。`PlaintextPacket` 表示明文；`AES256GCMPacket` 表示已使用 AES-256-GCM 加密。

#### MessageType

```c
typedef enum {
    MsgLoginReq = 1,
    MsgLoginResp,
    MsgChat,
    MsgCreateRoom,
    MsgJoinRoom,
    MsgGameStart,
    MsgGameStop,
    MsgHeartbeat
} MessageType;
```

应用层消息类型枚举。服务端与客户端依据该字段分发业务逻辑。

#### PacketHeader

```c
typedef struct {
    uint32_t magic;
    PacketType packetType;
    MessageType messageType;
    size_t payloadLength;
    uint32_t sequenceID;
} PacketHeader;
```

协议头结构，以 `#pragma pack(push, 1)` 打包，确保无填充、跨平台尺寸一致。字段顺序即为网络传输时的字节顺序，接收端须校验 `magic == PACKET_MAGIC`。

#### Packet

```c
typedef struct {
    PacketHeader header;
    uint8_t *payload;
} Packet;
```

完整数据包结构。`header` 与 `payload` 在内存中**不连续**，`payload` 由调用者或接收函数动态分配，使用后必须调用 `packetClear` 释放。

### 网络连接管理

#### `SocketFD serverSetup(uint16_t port)`

在指定端口创建 TCP 监听套接字，绑定 `INADDR_ANY`，并将队列长度设为 `BACKLOG`。

- 成功：返回监听套接字描述符。
- 失败：返回 `NULL_SOCKETFD`，并向日志输出错误信息。

关闭监听套接字请使用 `socketClose`。

#### `SocketFD clientSetup(const char *serverAddress, uint16_t serverPort)`

创建客户端 TCP 套接字并连接到目标地址。`serverAddress` 须为 IPv4 点分十进制字符串。

- 成功：返回已连接套接字描述符。
- 失败：返回 `NULL_SOCKETFD`。

#### `void socketClose(SocketFD *socketFD)`

关闭套接字并将其值重置为 `NULL_SOCKETFD`。内部自动忽略非法描述符（如 `-1`），因此允许对同一指针重复调用。Windows 与 POSIX 平台行为一致。

### 数据包序列化与反序列化

#### `int packetSerialize(const Packet *packet, uint8_t *buffer, size_t bufferSize, size_t *serializedSize)`

将 `Packet` 写入连续字节缓冲区。输出顺序为 `PacketHeader` 后紧跟 `payload`。不执行任何加密操作；若需加密，须先调用 `packetAESEncrypt`。

- 参数 `serializedSize` 输出实际写入的字节数，等于 `sizeof(PacketHeader) + packet->header.payloadLength`。
- 返回 `PROTOCOL_SUCC` 或 `PROTOCOL_FAIL`。

缓冲区容量不足时将记录日志并返回失败。

#### `int packetDeserialize(const uint8_t *buffer, size_t bufferSize, Packet *packet)`

从字节缓冲区解析 `PacketHeader`，校验魔术字，随后为 `payload` 动态分配内存并拷贝数据。

- 调用前必须保证 `packet->payload == NULL`，否则返回 `PROTOCOL_FAIL`。
- 成功时 `packet->payload` 由 `malloc` 分配，调用者须使用 `packetClear` 释放。
- 魔术字不匹配或缓冲区长度不足时返回 `PROTOCOL_FAIL`。

### 数据包加密与解密

#### `int packetAESEncrypt(Packet *packet, uint8_t key[AES_GCM_KEY_LEN])`

对明文数据包执行原地 AES-256-GCM 加密。

**前置条件**：`packet->header.packetType == PlaintextPacket`，且 `payloadLength <= MAX_PAYLOAD_LEN`。

**加密流程**：
1. 生成 12 字节随机 nonce。
2. 构造 AAD：`uint64_t` 值 `(payloadLength << 32) | sequenceID`。
3. 以 OpenSSL `EVP_aes_256_gcm` 加密原载荷。
4. 将原载荷替换为 `nonce || ciphertext || tag`，新长度为 `AES_GCM_NONCE_LEN + ciphertext_len + AES_GCM_TAG_LEN`。
5. 更新 `packet->header.packetType = AES256GCMPacket`，`payloadLength` 同步更新。

返回 `PROTOCOL_SUCC` 或 `PROTOCOL_FAIL`。失败时原 `packet` 状态保持不变（旧载荷已被释放并替换为新分配块，若后续步骤失败则整体回退为失败状态，但实现中失败前已释放旧载荷，调用者不应再依赖原指针）。

#### `int packetAESDecrypt(Packet *packet, uint8_t key[AES_GCM_KEY_LEN])`

对加密数据包执行原地 AES-256-GCM 解密。

**前置条件**：`packet->header.packetType == AES256GCMPacket`，且 `payloadLength >= AES_PACKET_EXTRA_LEN`。

**解密流程**：
1. 从载荷前端提取 nonce，末端提取 tag，中间段为 ciphertext。
2. 重建 AAD：`uint64_t` 值 `(ciphertext_len << 32) | sequenceID`。
3. 调用 OpenSSL 解密并校验认证标签。
4. 解密成功后，二次校验 AAD 与明文长度、序列号的一致性，防止篡改。
5. 替换载荷为明文，恢复 `packetType = PlaintextPacket`，`payloadLength` 恢复为原明文长度。

返回值为：
- `PROTOCOL_SUCC`：解密与校验均通过。
- `PROTOCOL_AUTH_FAIL`：认证标签错误或 AAD 不匹配，表明数据被篡改。
- `PROTOCOL_FAIL`：内部操作失败（内存分配、OpenSSL 错误等）。

### 数据包生命周期管理

#### `void packetClear(Packet *packet)`

释放 `packet->payload` 指向的动态内存，并将其置为 `NULL`。对同一 `Packet` 重复调用安全（仅第二次起无实际作用）。所有通过 `packetDeserialize`、`packetRecv` 或加密函数获得载荷的 `Packet` 对象，在生命周期结束前必须调用此函数，防止内存泄漏。

### 网络收发

#### `int packetSend(Packet *packet, SocketFD socketFD)`

通过套接字发送完整数据包。因 `Packet` 的 `header` 与 `payload` 内存不连续，实现分两次发送：先发送 `PacketHeader`，再发送 `payload`。内部使用 `sendAll` 循环处理部分写，直至全部字节发出或出错。

- 要求 `packet->payload != NULL`。
- 返回 `PROTOCOL_SUCC` 或 `PROTOCOL_FAIL`。

#### `int packetRecv(Packet *dest, SocketFD socketFD)`

从套接字阻塞接收完整数据包。

- 调用前必须保证 `dest->payload == NULL`。
- 先接收 `sizeof(PacketHeader)` 字节，校验 `magic` 与 `payloadLength`。
- 若 `packetType == AES256GCMPacket`，则允许的最大长度为 `MAX_PAYLOAD_LEN + AES_PACKET_EXTRA_LEN`；否则为 `MAX_PAYLOAD_LEN`。超出限制时返回 `PROTOCOL_FAIL`。
- 根据 `payloadLength` 动态分配内存，随后接收载荷。
- 成功时 `dest->payload` 由 `malloc` 分配，调用者须使用 `packetClear` 释放。

内部使用 `recvAll` 循环处理部分读，直至目标字节全部到达或连接异常。

### 使用注意事项

1. **内存所有权**：`Packet.payload` 的生命周期由调用者管理。凡是导致 `payload` 非 `NULL` 的 API（`packetDeserialize`、`packetRecv`、`packetAESEncrypt`），后续必须配对 `packetClear`。
2. **非连续内存**：`packetSerialize` 负责将分离的 `header` 与 `payload` 拼接为连续缓冲区；`packetSend` 分两次传输。直接对 `Packet` 结构取地址发送 `sizeof(Packet)` 是错误用法。
3. **加密顺序**：发送加密包时，应先 `packetAESEncrypt` 再 `packetSerialize` 或 `packetSend`。接收后应先 `packetRecv` 再 `packetAESDecrypt`。
4. **序列号与 AAD**：AES-GCM 的 AAD 同时绑定载荷长度与序列号，任何对 `header.payloadLength` 或 `header.sequenceID` 的篡改均会导致解密端 `PROTOCOL_AUTH_FAIL`。
5. **线程安全**：本模块未内置线程同步。套接字与 `Packet` 对象在多线程间共享时，须由调用者提供外部锁。
6. **密钥管理**：`packetAESEncrypt` 与 `packetAESDecrypt` 仅接受 32 字节密钥指针，不持有密钥副本，也不负责密钥协商或派生。

## Log 日志

其实现在 `src/common/log.c`，接口在 `include/log.h`

轻量日志库模块，修改自 [rxi/log.c](https://github.com/rxi/log.c)

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
