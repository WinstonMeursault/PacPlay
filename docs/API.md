# API 文档

## Crypto 密码学模块

接口位于 `include/crypto.h` ，实现在 `src/common/crypto.c` 。

提供与上层协议解耦的低级密码学封装，涵盖 AES-256-GCM authenticated encryption、ECDH(X25519) 密钥协商、HKDF-SHA256 密钥派生及密码学安全随机数生成。所有实现基于 OpenSSL 3.x EVP API，符合 C17 标准。

### 常量与宏

| 宏                          | 值                   | 说明                                                                |
| --------------------------- | -------------------- | ------------------------------------------------------------------- |
| `CRYPTO_SUCC` | `0` | 函数执行成功                                                        |
| `CRYPTO_FAIL` | `-1` | 通用失败，包括参数校验未通过、内存分配失败、OpenSSL 内部错误等      |
| `CRYPTO_AUTH_FAIL` | `-2` | AES-GCM 认证标签校验失败，表明密文或附加数据在传输过程中被篡改      |
| `AES_GCM_KEY_LEN` | `32` | AES-256 对称密钥长度（字节）                                        |
| `AES_GCM_NONCE_LEN` | `12` | GCM 模式 nonce 长度（字节）                                         |
| `AES_GCM_TAG_LEN` | `16` | GCM 认证标签长度（字节）                                            |
| `ECDH_SHARED_SECRET_SIZE` | `32` | X25519 ECDH 协商后的原始共享密钥长度（字节）                        |
| `ECDH_PUBLIC_KEY_SIZE` | `32` | X25519 ECDH 原始公钥长度（字节），可直接用于网络传输                       |
| `HKDF_INFO_AES_KEY` | `"PacPlay-AESKey"` | HKDF-SHA256 派生 AES 密钥时使用的固定 info 字符串，提供应用级域隔离 |

### 类型定义

#### AESGCMKey

```c
typedef struct {
    uint8_t key[AES_GCM_KEY_LEN];
    uint8_t nonce[AES_GCM_NONCE_LEN];
} AESGCMKey;
```

AES-256-GCM 的完整密钥材料。 `key` 为 32 字节对称密钥； `nonce` 为每次加密前须单独生成的 12 字节随机值。**禁止在任何两次加密操作中复用同一 nonce**，否则将严重破坏 GCM 的机密性与完整性保证。

#### AESGCMBuffer

```c
typedef struct {
    uint8_t *data;
    size_t capacity;
    size_t len;
} AESGCMBuffer;
```

通用字节缓冲区描述符。 `data` 指向由调用者或 `aesGCMBufferInit` 分配的内存； `capacity` 为该内存块的实际容量； `len` 为当前有效数据长度。 `encryptAESGCM` 与 `decryptAESGCM` 均要求调用者预先为输入/输出缓冲区分配足够内存，函数本身不执行动态分配。

#### AESGCMCipher

```c
typedef struct {
    AESGCMBuffer buffer;
    uint8_t tag[AES_GCM_TAG_LEN];
} AESGCMCipher;
```

AES-GCM 加密输出结构。 `buffer.data` 存放密文， `buffer.len` 为密文长度； `tag` 存放 16 字节认证标签，须随密文一并传输给解密端。

### 缓冲区辅助函数

#### `int aesGCMBufferInit(AESGCMBuffer *buf, size_t capacity)`

为 `AESGCMBuffer` 分配 `capacity` 字节的堆内存，并将 `buf->data` 指向该内存。 `capacity` 被设为传入值， `len` 初始化为 `0` 。

* 成功：返回 `CRYPTO_SUCC`。
* 失败：返回 `CRYPTO_FAIL`，`buf->data` 置为 `NULL`，`capacity` 与 `len` 仍被归零。

调用者须在不再使用该缓冲区时，显式调用 `aesGCMBufferDeinit` 释放内存，防止泄漏。

#### `void aesGCMBufferDeinit(AESGCMBuffer *buf)`

释放 `buf->data` 指向的内存，并将指针置为 `NULL` 。对同一缓冲区重复调用安全。

### AES-256-GCM 加密与解密

#### `int encryptAESGCM(const AESGCMBuffer *plaintext, const AESGCMBuffer *aad, const AESGCMKey *key, AESGCMCipher *output)`

对给定明文执行 AES-256-GCM 加密。

**参数约束**：

* `plaintext`、`key`、`output` 均不得为 `NULL`。
* `output->buffer.data` 不得为 `NULL`，且 `output->buffer.capacity` 必须大于或等于 `plaintext->len`。函数内部不重新分配输出缓冲区内存。
* `aad` 可为 `NULL` 或长度为零，表示不使用附加认证数据（AAD）。

**执行流程**：

01. 以 `EVP_aes_256_gcm()` 初始化加密上下文。
02. 设置 nonce 长度为 `AES_GCM_NONCE_LEN`（12 字节）。
03. 注入密钥与 nonce。
04. 若提供了 AAD，将其作为认证但不加密的数据喂入。
05. 执行 `EVP_EncryptUpdate` 加密明文，结果写入 `output->buffer.data`。
06. 执行 `EVP_EncryptFinal_ex` 完成加密（GCM 模式下主要确认内部状态）。
07. 通过 `EVP_CTRL_GCM_GET_TAG` 提取 16 字节认证标签，存入 `output->tag`。

**返回值**：

* `CRYPTO_SUCC`：加密成功，`output->buffer.len` 为实际密文长度，`output->tag` 有效。
* `CRYPTO_FAIL`：参数非法、缓冲区容量不足、或 OpenSSL 内部错误。此时 `output` 内容不可信任。

**内存所有权**：函数不拥有 `output->buffer.data` 的分配与释放责任，仅向其中写入数据。调用者须保证 `output->buffer.data` 指向的内存在整个加密过程中保持有效。

#### `int decryptAESGCM(const AESGCMCipher *cipher, const AESGCMBuffer *aad, const AESGCMKey *key, AESGCMBuffer *plaintext)`

对给定密文执行 AES-256-GCM 解密并校验认证标签。

**参数约束**：

* `cipher`、`key`、`plaintext` 均不得为 `NULL`。
* `plaintext->data` 不得为 `NULL`，且 `plaintext->capacity` 必须大于或等于 `cipher->buffer.len`。函数内部不重新分配输出缓冲区内存。
* `aad` 必须与加密时传入的 AAD 在内容与长度上完全一致，否则解密将失败。

**执行流程**：

01. 以 `EVP_aes_256_gcm()` 初始化解密上下文。
02. 设置 nonce 长度并注入密钥与 nonce。
03. 若提供了 AAD，将其喂入（必须与加密端一致）。
04. 执行 `EVP_DecryptUpdate` 解密密文，结果写入 `plaintext->data`。
05. 通过 `EVP_CTRL_GCM_SET_TAG` 注入待校验的认证标签。
06. 执行 `EVP_DecryptFinal_ex`；若标签校验失败，OpenSSL 返回错误。

**返回值**：

* `CRYPTO_SUCC`：解密与认证均通过，`plaintext->len` 为实际明文长度。
* `CRYPTO_AUTH_FAIL`：认证标签不匹配或 AAD 不一致，表明数据已被篡改。此时函数会立即释放内部 EVP 上下文并返回，但 `plaintext->data` 可能已被部分写入。**调用者在收到 `CRYPTO_AUTH_FAIL` 后不得信任 `plaintext->data` 中的任何内容**。
* `CRYPTO_FAIL`：参数非法、缓冲区容量不足、或 OpenSSL 内部错误。

### ECDH (X25519) 密钥协商

#### `EVP_PKEY *genECDHKeypair(void)`

生成一个 ephemeral X25519 密钥对，用于 ECDH 密钥协商。

* 成功：返回新分配的 `EVP_PKEY *`，包含公私钥对。
* 失败：返回 `NULL`，内部已通过 `LOG_ERROR_SSL` 记录 OpenSSL 错误原因。

**内存所有权**：返回的 `EVP_PKEY *` 由调用者完全所有，不再使用时**必须**调用 `EVP_PKEY_free()` 释放。禁止直接访问或修改其内部结构。

#### `int exportECDHPublicKey(EVP_PKEY *pkey, uint8_t pub[ECDH_PUBLIC_KEY_SIZE])`

从 X25519 密钥对中提取 32 字节原始公钥。

* `pkey` 不得为 `NULL`，且必须为包含公钥的 X25519 密钥对。
* `pub` 不得为 `NULL`，其缓冲区大小至少为 `ECDH_PUBLIC_KEY_SIZE`（32 字节）。
* 成功：返回 `CRYPTO_SUCC`，`pub` 中写入 32 字节公钥。
* 失败：返回 `CRYPTO_FAIL`。失败原因包括参数为 `NULL`、密钥类型不匹配、OpenSSL 导出错误、或返回长度非 32 字节。

提取后的 32 字节公钥可直接通过网络发送给对端。

#### `EVP_PKEY *importECDHPeerPublicKey(const uint8_t pub[ECDH_PUBLIC_KEY_SIZE])`

将对端发送的 32 字节原始 X25519 公钥重新构造为 `EVP_PKEY *` 。

* `pub` 不得为 `NULL`。
* 成功：返回新分配的 `EVP_PKEY *`，仅包含公钥组件。
* 失败：返回 `NULL`，内部已通过 `LOG_ERROR_SSL` 记录原因。

**内存所有权**：返回的指针由调用者负责以 `EVP_PKEY_free()` 释放。

#### `int deriveECDHSharedSecret(EVP_PKEY *localKey, EVP_PKEY *peerKey, uint8_t secret[ECDH_SHARED_SECRET_SIZE])`

执行 ECDH 密钥协商，使用本地密钥对的私钥与对端公钥计算共享密钥。

* `localKey`、`peerKey`、`secret` 均不得为 `NULL`。
* `localKey` 必须包含私钥；`peerKey` 可为仅含公钥的密钥对象。
* 成功：返回 `CRYPTO_SUCC`，`secret` 中写入 32 字节原始共享密钥。
* 失败：返回 `CRYPTO_FAIL`。失败时，函数会调用 `OPENSSL_cleanse(secret, ECDH_SHARED_SECRET_SIZE)` 将输出缓冲区安全清零，防止部分共享密钥泄漏。

**安全提示**： `secret` 为高度敏感材料，派生完成后应尽快通过 `deriveAESKey` 转化为 AES 密钥，并在不再需要时由调用者显式清零。

### HKDF-SHA256 密钥派生

#### `int deriveAESKey(const uint8_t *sharedSecret, size_t secretLen, AESGCMKey *outKey)`

基于 HKDF（RFC 5869）从原始共享密钥派生 AES-256-GCM 密钥材料。

**参数约束**：

* `sharedSecret` 不得为 `NULL`，`secretLen` 必须大于 `0`。
* `outKey` 不得为 `NULL`。

**派生参数**：

* 摘要算法：SHA-256
* 模式：`EXTRACT_AND_EXPAND`（完整 HKDF：先提取，后扩展）
* 输入密钥材料（IKM）：`sharedSecret`
* Salt：省略（OpenSSL 默认使用 HashLen 个零字节，符合 RFC 5869 Section 2.2）
* Info：固定字符串 `HKDF_INFO_AES_KEY`（`"PacPlay-AESKey"`），提供应用级域隔离
* 输出长度：`AES_GCM_KEY_LEN`（32 字节）

**执行流程**：

01. 调用 `memset(outKey, 0, sizeof(*outKey))` 将输出结构整体清零，包括 `key` 与 `nonce` 字段。
02. 通过 OpenSSL EVP_KDF 接口执行 HKDF-SHA256 派生，结果写入 `outKey->key`。

**返回值**：

* `CRYPTO_SUCC`：派生成功，`outKey->key` 包含 32 字节 AES 密钥，`outKey->nonce` 已清零。
* `CRYPTO_FAIL`：参数非法、或 OpenSSL KDF 失败。失败时函数会调用 `OPENSSL_cleanse(outKey, sizeof(*outKey))` 安全擦除已写入的部分密钥材料。

**重要**：本函数将 `outKey->nonce` 清零。调用者在每次执行加密前，**必须**通过 `cryptoRandomBytes` 生成新的随机 nonce 填入 `outKey->nonce` ，严禁复用同一 nonce。

### 安全随机数

#### `int cryptoRandomBytes(uint8_t *buf, int len)`

填充密码学安全随机字节。

* `buf` 不得为 `NULL`，`len` 必须大于 `0`。
* 内部调用 OpenSSL `RAND_bytes`。
* 成功：返回 `CRYPTO_SUCC`。
* 失败：返回 `CRYPTO_FAIL`，内部记录 OpenSSL 错误。

### 使用注意事项与推荐流程

#### 1. 内存所有权与缓冲区管理

`aesGCMBufferInit` 与 `aesGCMBufferDeinit` 构成对称的分配/释放对。 `encryptAESGCM` 与 `decryptAESGCM` 本身不拥有缓冲区的分配权，仅要求调用者预先提供容量足够的 `data` 指针。任何由 `aesGCMBufferInit` 分配的内存，最终必须通过 `aesGCMBufferDeinit` 或等价的 `free` 释放。

#### 2. nonce 管理

AES-GCM 的安全性完全依赖于 nonce 的唯一性。 `deriveAESKey` 输出的 `AESGCMKey.nonce` 为零字节，这并非有效 nonce。**每次调用 `encryptAESGCM` 之前，都必须重新生成随机 nonce**（通过 `cryptoRandomBytes(aesKey.nonce, AES_GCM_NONCE_LEN)` ），并将该 nonce 与密文一并传送给解密端。

#### 3. 完整的端到端加密密钥协商流程

以下为 PacPlay 推荐的从密钥协商到加密通信的标准流程：

**步骤一：生成临时密钥对**

通信双方（Alice 与 Bob）各自调用：

```c
EVP_PKEY *myKeypair = genECDHKeypair();
```

**步骤二：交换公钥**

双方各自导出 32 字节公钥并发送给对方：

```c
uint8_t myPub[ECDH_PUBLIC_KEY_SIZE];
exportECDHPublicKey(myKeypair, myPub);
// 通过网络将 myPub 发送给对端
```

接收方将对端公钥导入：

```c
EVP_PKEY *peerKey = importECDHPeerPublicKey(peerPub);
```

**步骤三：协商共享密钥**

```c
uint8_t sharedSecret[ECDH_SHARED_SECRET_SIZE];
deriveECDHSharedSecret(myKeypair, peerKey, sharedSecret);
```

**步骤四：派生 AES-256 密钥**

```c
AESGCMKey aesKey;
deriveAESKey(sharedSecret, ECDH_SHARED_SECRET_SIZE, &aesKey);
```

**步骤五：安全清理临时敏感材料**

共享密钥协商完成后，应立即安全擦除原始共享密钥，并释放临时 EVP_PKEY 对象：

```c
OPENSSL_cleanse(sharedSecret, sizeof(sharedSecret));
EVP_PKEY_free(myKeypair);
EVP_PKEY_free(peerKey);
```

**步骤六：加密通信**

每次发送加密消息前，生成新 nonce，构造 `AESGCMKey` ，调用 `encryptAESGCM` ；接收方提取 nonce 与 tag，构造对应的 `AESGCMKey` ，调用 `decryptAESGCM` 。

#### 4. AAD 一致性要求

`encryptAESGCM` 与 `decryptAESGCM` 的 `aad` 参数必须在内容、长度上完全一致。任何差异都将导致 `decryptAESGCM` 返回 `CRYPTO_AUTH_FAIL` 。在 Protocol 层，AAD 被构造为 `uint64_t` 值 `(payloadLength << 32) | sequenceID` ，同时绑定载荷长度与序列号。

#### 5. 认证标签处理

`encryptAESGCM` 将认证标签输出到 `output->tag` 。调用者负责将 `tag` 与密文一并传输给解密端； `decryptAESGCM` 则从 `cipher->tag` 读取标签以执行校验。若标签在传输中丢失或被截断，解密必定失败。

#### 6. 线程安全

本模块未内置线程同步。 `EVP_CIPHER_CTX` 、 `EVP_PKEY` 、 `EVP_KDF_CTX` 等 OpenSSL 对象以及 `AESGCMBuffer` 结构在多线程间共享时，须由调用者提供外部锁保护。 `cryptoRandomBytes` 底层依赖 OpenSSL `RAND_bytes` ，在绝大多数 OpenSSL 构建中线程安全，但为保守起见仍建议在并发场景下由调用者统一加锁。

#### 7. 错误诊断

所有返回 `CRYPTO_FAIL` 的函数均会通过 `LOG_ERROR` 或 `LOG_ERROR_SSL` 宏向日志系统输出具体的失败原因，包括参数非法、OpenSSL 错误码及错误字符串。生产环境中应确保日志级别至少为 `LogLevelError` ，以便及时捕获密码学操作失败。

---

## Protocol 通信协议

接口位于 `include/protocol.h` ，实现在 `src/common/protocol.c` 。

实现 PacPlay 的二进制网络协议栈，涵盖 TCP 套接字管理、数据包序列化、AES-256-GCM authenticated encryption（通过 `crypto` 模块实现）以及阻塞式收发。所有公共 API 均使用 C17 标准。 `protocol.h` 通过 `#include "crypto.h"` 引入密码学模块的全部类型与常量。

### 常量与宏

| 宏                       | 值             | 说明                                                    |
| ------------------------ | -------------- | ------------------------------------------------------- |
| `PROTOCOL_SUCC` | `0` | 函数执行成功                                            |
| `PROTOCOL_FAIL` | `-1` | 通用失败                                                |
| `PROTOCOL_AUTH_FAIL` | `-2` | AES-GCM 认证标签校验失败或 AAD 不匹配                   |
| `MAX_PAYLOAD_LEN` | `1024` | 明文载荷最大字节数                                      |
| `AES_GCM_KEY_LEN` | `32` | AES-256 对称密钥长度（字节），定义于 `crypto.h` |
| `AES_GCM_NONCE_LEN` | `12` | GCM 模式随机 nonce 长度（字节），定义于 `crypto.h` |
| `AES_GCM_TAG_LEN` | `16` | GCM 认证标签长度（字节），定义于 `crypto.h` |
| `AES_PACKET_EXTRA_LEN` | `28` | 加密后额外开销： `AES_GCM_NONCE_LEN + AES_GCM_TAG_LEN` |
| `BACKLOG` | `5` | `listen()` 连接队列长度                               |
| `NULL_SOCKETFD` | `-1` | 无效套接字描述符标识                                    |
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

标识数据包的加密状态。 `PlaintextPacket` 表示明文； `AES256GCMPacket` 表示已使用 AES-256-GCM 加密。

#### MessageType

```c
typedef enum {
    MsgLoginReq = 1,
    MsgLoginResp,
    MsgKeyExchangeReq,
    MsgKeyExchangeResp,
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

协议头结构，以 `#pragma pack(push, 1)` 打包，确保无填充、跨平台尺寸一致。字段顺序即为网络传输时的字节顺序，接收端须校验 `magic == PACKET_MAGIC` 。

#### Packet

```c
typedef struct {
    PacketHeader header;
    uint8_t *payload;
} Packet;
```

完整数据包结构。 `header` 与 `payload` 在内存中**不连续**， `payload` 由调用者或接收函数动态分配，使用后必须调用 `packetClear` 释放。

#### KeyExchangePacketPayload

```c
#pragma pack(push, 1)
typedef struct {
    uint8_t publicKey[ECDH_PUBLIC_KEY_SIZE];
} KeyExchangePacketPayload;
#pragma pack(pop)
```

ECDH 密钥交换阶段的数据包载荷，仅包含 32 字节 X25519 原始公钥。通过 `#pragma pack(push, 1)` 显式消除填充（与 `PacketHeader` 一致），确保跨平台内存布局与网络传输格式完全匹配。

### 网络连接管理

#### `SocketFD serverSetup(uint16_t port)`

在指定端口创建 TCP 监听套接字，绑定 `INADDR_ANY` ，并将队列长度设为 `BACKLOG` 。

* 成功：返回监听套接字描述符。
* 失败：返回 `NULL_SOCKETFD`，并向日志输出错误信息。

关闭监听套接字请使用 `socketClose` 。

#### `SocketFD clientSetup(const char *serverAddress, uint16_t serverPort)`

创建客户端 TCP 套接字并连接到目标地址。 `serverAddress` 须为 IPv4 点分十进制字符串。

* 成功：返回已连接套接字描述符。
* 失败：返回 `NULL_SOCKETFD`。

#### `void socketClose(SocketFD *socketFD)`

关闭套接字并将其值重置为 `NULL_SOCKETFD` 。内部自动忽略非法描述符（如 `-1` ），因此允许对同一指针重复调用。Windows 与 POSIX 平台行为一致。

### 数据包序列化与反序列化

#### `int packetSerialize(const Packet *packet, uint8_t *buffer, size_t bufferSize, size_t *serializedSize)`

将 `Packet` 写入连续字节缓冲区。输出顺序为 `PacketHeader` 后紧跟 `payload` 。不执行任何加密操作；若需加密，须先调用 `packetAESEncrypt` 。

* 参数 `serializedSize` 输出实际写入的字节数，等于 `sizeof(PacketHeader) + packet->header.payloadLength`。
* 返回 `PROTOCOL_SUCC` 或 `PROTOCOL_FAIL`。

缓冲区容量不足时将记录日志并返回失败。

#### `int packetDeserialize(const uint8_t *buffer, size_t bufferSize, Packet *packet)`

从字节缓冲区解析 `PacketHeader` ，校验魔术字，随后为 `payload` 动态分配内存并拷贝数据。

* 调用前必须保证 `packet->payload == NULL`，否则返回 `PROTOCOL_FAIL`。
* 成功时 `packet->payload` 由 `malloc` 分配，调用者须使用 `packetClear` 释放。
* 魔术字不匹配或缓冲区长度不足时返回 `PROTOCOL_FAIL`。

### 数据包加密与解密

Protocol 层的 AES-256-GCM 加密与解密**不再直接调用 OpenSSL EVP 接口**，而是通过 `crypto` 模块提供的 `encryptAESGCM` 与 `decryptAESGCM` 实现。Protocol 模块负责数据包的上下文封装：构造 AAD、管理 nonce / ciphertext / tag 的拼接与解析、以及 Packet 结构的状态转换。

#### `int packetAESEncrypt(Packet *packet, uint8_t key[AES_GCM_KEY_LEN])`

对明文数据包执行原地 AES-256-GCM 加密。

**前置条件**： `packet->header.packetType == PlaintextPacket` ，且 `packet->header.payloadLength <= MAX_PAYLOAD_LEN` 。

**加密流程**：

01. 调用 `cryptoRandomBytes` 生成 12 字节随机 nonce。
02. 构造 AAD：`uint64_t` 值 `(payloadLength << 32) | sequenceID`。该 AAD 同时绑定载荷长度与序列号，防止对长度或序列号的单独篡改。
03. 以 `AESGCMBuffer` 包装现有 `packet->payload`（零拷贝引用），准备 `AESGCMKey` 密钥材料。
04. 通过 `aesGCMBufferInit` 分配密文输出缓冲区。
05. 调用 `encryptAESGCM` 执行加密。
06. 分配新的 `payload` 内存块，按顺序拼接 `nonce || ciphertext || tag`。拼接后的新长度为 `AES_GCM_NONCE_LEN + ciphertext_len + AES_GCM_TAG_LEN`。
07. 释放旧 `payload`，将 `packet->payload` 指向新内存块。
08. 更新 `packet->header.packetType = AES256GCMPacket`，`payloadLength` 同步更新为新长度。
09. 释放临时的密文输出缓冲区。

**返回值**：

* `PROTOCOL_SUCC`：加密成功，数据包已转换为加密状态。
* `PROTOCOL_FAIL`：参数非法、载荷超限、随机数生成失败、内存分配失败、或 `crypto` 模块加密失败。

**失败时的状态保证**：若函数返回 `PROTOCOL_FAIL` ， `packet` 的原有状态保持不变。旧 `payload` 不会被释放， `packetType` 与 `payloadLength` 也不会被修改。调用者可安全地重试或执行其他错误恢复逻辑。

#### `int packetAESDecrypt(Packet *packet, uint8_t key[AES_GCM_KEY_LEN])`

对加密数据包执行原地 AES-256-GCM 解密。

**前置条件**： `packet->header.packetType == AES256GCMPacket` ，且 `packet->header.payloadLength >= AES_PACKET_EXTRA_LEN` 。

**解密流程**：

01. 从载荷前端提取 `nonce`（12 字节），末端提取 `tag`（16 字节），中间段为 `ciphertext`。
02. 以提取的 `nonce` 与传入的 `key` 构造 `AESGCMKey`。
03. 重建 AAD：`uint64_t` 值 `(ciphertext_len << 32) | sequenceID`。`ciphertext_len` 由 `payloadLength - AES_PACKET_EXTRA_LEN` 计算得出。
04. 以 `AESGCMCipher` 包装 `ciphertext` 段与 `tag`（零拷贝引用）。
05. 通过 `aesGCMBufferInit` 分配明文输出缓冲区。
06. 调用 `decryptAESGCM` 执行解密与认证标签校验。
07. 若 `decryptAESGCM` 返回 `CRYPTO_AUTH_FAIL`，释放明文缓冲区并返回 `PROTOCOL_AUTH_FAIL`。
08. 解密成功后，执行二次 AAD 校验：重新计算 `verifyAAD = (plaintext.len << 32) | sequenceID`，并与原始 AAD 比较。若不一致，释放明文缓冲区并返回 `PROTOCOL_AUTH_FAIL`。该步骤为防御性校验，进一步排除任何潜在的数据篡改。
09. 释放旧加密 `payload`，将明文缓冲区所有权转移给 `packet->payload`。
10. 更新 `packetType = PlaintextPacket`，`payloadLength` 恢复为原始明文长度。

**返回值**：

* `PROTOCOL_SUCC`：解密与校验均通过。
* `PROTOCOL_AUTH_FAIL`：认证标签错误或 AAD 不匹配，表明数据被篡改。
* `PROTOCOL_FAIL`：参数非法、格式错误、内存分配失败、或 `crypto` 模块内部错误。

### 数据包生命周期管理

#### `int packetInit(Packet *packet, MessageType msgType, uint32_t seqID, PacketType pktType, const void *data, size_t dataLen)`

构造一个完整的 `Packet` 对象，是创建数据包的**唯一推荐入口**。禁止调用方手动填充 `Packet.header` 字段。

调用前须确保 `packet->payload == NULL`（若先前已持有载荷，须先调用 `packetClear`）。函数内部分配堆内存拷贝 `data` 中的 `dataLen` 字节作为载荷，并正确设置所有头部字段（包括魔术字 `PACKET_MAGIC`）。

* 成功：`packet->payload` 为新分配内存，返回 `PROTOCOL_SUCC`。
* 失败：返回 `PROTOCOL_FAIL`，原因包括 `packet == NULL`、`payload` 非 `NULL`、`dataLen > MAX_PAYLOAD_LEN`、`dataLen > 0` 但 `data == NULL`、或 `malloc` 失败。

区别于 `packetDeserialize`（从网络字节流恢复）与 `packetRecv`（从套接字接收），本函数用于在本地构造待发送的数据包。使用后须调用 `packetClear` 释放载荷。

#### `void packetClear(Packet *packet)`

释放 `packet->payload` 指向的动态内存，并将其置为 `NULL` 。对同一 `Packet` 重复调用安全（仅第二次起无实际作用）。所有通过 `packetDeserialize` 、 `packetRecv` 或加密函数获得载荷的 `Packet` 对象，在生命周期结束前必须调用此函数，防止内存泄漏。

### 网络收发

#### `int packetSend(Packet *packet, SocketFD socketFD)`

通过套接字发送完整数据包。因 `Packet` 的 `header` 与 `payload` 内存不连续，实现分两次发送：先发送 `PacketHeader` ，再发送 `payload` 。内部使用 `sendAll` 循环处理部分写，直至全部字节发出或出错。

* 要求 `packet->payload != NULL`。
* 返回 `PROTOCOL_SUCC` 或 `PROTOCOL_FAIL`。

#### `int packetRecv(Packet *dest, SocketFD socketFD)`

从套接字阻塞接收完整数据包。

* 调用前必须保证 `dest->payload == NULL`。
* 先接收 `sizeof(PacketHeader)` 字节，校验 `magic` 与 `payloadLength`。
* 若 `packetType == AES256GCMPacket`，则允许的最大长度为 `MAX_PAYLOAD_LEN + AES_PACKET_EXTRA_LEN`；否则为 `MAX_PAYLOAD_LEN`。超出限制时返回 `PROTOCOL_FAIL`。
* 根据 `payloadLength` 动态分配内存，随后接收载荷。
* 成功时 `dest->payload` 由 `malloc` 分配，调用者须使用 `packetClear` 释放。

内部使用 `recvAll` 循环处理部分读，直至目标字节全部到达或连接异常。

### 使用注意事项

01. **内存所有权**：`Packet.payload` 的生命周期由调用者管理。凡是导致 `payload` 非 `NULL` 的 API（`packetDeserialize`、`packetRecv`、`packetAESEncrypt`），后续必须配对 `packetClear`。
02. **非连续内存**：`packetSerialize` 负责将分离的 `header` 与 `payload` 拼接为连续缓冲区；`packetSend` 分两次传输。直接对 `Packet` 结构取地址发送 `sizeof(Packet)` 是错误用法。
03. **加密顺序**：发送加密包时，应先 `packetAESEncrypt` 再 `packetSerialize` 或 `packetSend`。接收后应先 `packetRecv` 再 `packetAESDecrypt`。严禁在加密后再次调用 `packetAESEncrypt`，或在解密后再次调用 `packetAESDecrypt`。
04. **序列号与 AAD**：AES-GCM 的 AAD 同时绑定载荷长度与序列号，任何对 `header.payloadLength` 或 `header.sequenceID` 的篡改均会导致解密端 `PROTOCOL_AUTH_FAIL`。
05. **线程安全**：本模块未内置线程同步。套接字与 `Packet` 对象在多线程间共享时，须由调用者提供外部锁。
06. **密钥管理与端到端加密完整流程**：Protocol 模块本身不负责密钥协商。完整的加密通信流程须结合 `crypto` 模块：

   a. 通信双方各自调用 `genECDHKeypair` 生成 X25519 临时密钥对。
   b. 双方通过 `exportECDHPublicKey` 导出 32 字节公钥并通过网络交换。
   c. 收到对方公钥后，以 `importECDHPeerPublicKey` 导入。
   d. 调用 `deriveECDHSharedSecret` 计算 32 字节共享密钥。
   e. 调用 `deriveAESKey` 将共享密钥派生为 32 字节 AES-256 密钥。
   f. 安全擦除原始共享密钥，释放临时 `EVP_PKEY` 对象。
   g. 此后，每次发送消息前以 `cryptoRandomBytes` 生成随机 nonce，再通过 `packetAESEncrypt` 加密数据包；接收方以提取的 nonce 调用 `packetAESDecrypt` 解密。

   Protocol 模块仅持有 32 字节 AES 密钥的指针，不持有密钥副本，也不负责密钥的生命周期管理。密钥的安全存储、传输与销毁由调用者全权负责。

---

## Log 日志

其实现在 `src/common/log.c` ，接口在 `include/log.h`

轻量日志库模块，修改自 [rxi/log.c](https://github.com/rxi/log.c)

### 级别

 `LogLevelTrace < LogLevelDebug < LogLevelInfo < LogLevelWarn < LogLevelError < LogLevelFatal`

低于全局阈值的消息直接丢弃。默认阈值 `LogLevelTrace` （即全部输出）。

### 基本用法

```c
#include "log.h"

LOG_INFO("listening on port %d", port);
LOG_ERROR("bind failed: %s", strerror(errno));
```

宏自动捕获 `__FILE__` 和 `__LINE__` ，输出到 `stderr` ，格式：

 `HH:MM:SS LEVEL file.c:line: message`

### 便捷宏

| 宏                      | 等价展开                                                |
| ----------------------- | ------------------------------------------------------- |
| `LOG_TRACE(fmt, ...)` | `logLog(LogLevelTrace, __FILE__, __LINE__, fmt, ...)` |
| `LOG_DEBUG(fmt, ...)` | `logLog(LogLevelDebug, __FILE__, __LINE__, fmt, ...)` |
| `LOG_INFO(fmt, ...)` | `logLog(LogLevelInfo, __FILE__, __LINE__, fmt, ...)` |
| `LOG_WARN(fmt, ...)` | `logLog(LogLevelWarn, __FILE__, __LINE__, fmt, ...)` |
| `LOG_ERROR(fmt, ...)` | `logLog(LogLevelError, __FILE__, __LINE__, fmt, ...)` |
| `LOG_FATAL(fmt, ...)` | `logLog(LogLevelFatal, __FILE__, __LINE__, fmt, ...)` |

所有宏都是对 `logLog()` 的薄封装，自动填充源文件名和行号。参数与 `printf`

语义一致，支持变参。日常使用只需要这些宏，不必直接调用 `logLog()` 。

### 配置函数

| 函数                                                         | 作用                                  |
| ------------------------------------------------------------ | ------------------------------------- |
| `logSetLevel(LogLevel level)` | 设置全局最低输出级别                  |
| `logSetQuiet(bool enable)` | `true` 关闭 stderr 输出，不影响回调 |
| `logSetLock(LogLockFn fn, void *udata)` | 注册加锁/解锁回调，多线程必须设置     |
| `logAddFp(FILE *fp, LogLevel level)` | 添加文件输出，级别独立于全局阈值      |
| `logAddCallback(LogLogFn fn, void *udata, LogLevel level)` | 注册自定义日志后端                    |
| `logLevelString(LogLevel level)` | 返回级别对应的字符串（如 `"INFO"` ） |

最多注册 32 个回调（含 `logAddFp` ）。超出返回 `-1` 。

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

`logAddFp` 成功返回 `0` ，回调槽满时返回 `-1` 。

文件格式带完整日期： `YYYY-MM-DD HH:MM:SS LEVEL file.c:line: message` 。
日志库不负责关闭传入的 `FILE *` ，调用者须自行管理其生命周期（程序退出或不再
需要文件日志时 `fclose` ）。

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

---

## Communication 通信模块

通信模块封装了 ECDH+HKDF 端到端密钥协商流程，位于 `src/client/communication.c`（客户端）和 `src/server/communication.c`（服务端），接口分别声明于 `src/client/communication.h` 和 `src/server/communication.h`。

两个模块共享相同的一组返回值宏；`COMM_SUCC` / `COMM_FAIL` 在各自的头文件中独立定义，值分别为 `0` 与 `-1`。

### 安全设计

通信模块在接收到来自网络的数据后执行严格的**零信任校验**：

01. 消息类型必须为预期的 `MsgKeyExchangeReq` 或 `MsgKeyExchangeResp`。
02. 包类型必须为 `PlaintextPacket`（密钥交换阶段的包不加密）。
03. 载荷长度必须精确等于 `ECDH_PUBLIC_KEY_SIZE`（32 字节）。
04. 拒绝对方发回的己方公钥（反射 / 自环攻击）。
05. 提取对端公钥后立即以 `OPENSSL_cleanse` 清零接收缓冲区的载荷区域。

### 客户端

**接口**：`src/client/communication.h`

**实现**：`src/client/communication.c`

#### `int clientExchangeAESKey(SocketFD socketFD, AESGCMKey *outKey)`

执行客户端侧的 ECDH+HKDF 密钥交换。

**完整流程**：

01. 调用 `genECDHKeypair` 生成临时 X25519 密钥对。
02. 调用 `exportECDHPublicKey` 导出己方 32 字节原始公钥。
03. 将公钥填入 `KeyExchangePacketPayload`，通过 `packetInit` 构造 `MsgKeyExchangeReq` 包，再通过 `packetSend` 发给服务端。
04. 通过 `packetRecv` 阻塞接收服务端的 `MsgKeyExchangeResp` 包。
05. 对接收到的包执行零信任校验（见上文）。
06. 从接收包中提取服务端公钥，调用 `importECDHPeerPublicKey` 导入。
07. 调用 `deriveECDHSharedSecret` 计算 32 字节共享密钥。
08. 调用 `deriveAESKey` 将共享密钥派生为 32 字节 AES-256-GCM 密钥。
09. 清理所有敏感缓冲： `OPENSSL_cleanse` 己方公钥、对端公钥、共享密钥、`KeyExchangePacketPayload`；`EVP_PKEY_free` 己方与对端密钥对象；`packetClear` 发送与接收包。

* `socketFD`：已与服务端建立 TCP 连接的套接字描述符。函数不负责创建或关闭此套接字。
* `outKey`：输出参数，接收派生的 AES-256 密钥。成功时 `outKey->nonce` 已清零，调用者须在每次加密前通过 `cryptoRandomBytes` 生成新的随机 nonce。
* 返回 `COMM_SUCC` 或 `COMM_FAIL`。

### 服务端

**接口**：`src/server/communication.h`

**实现**：`src/server/communication.c`

#### `int serverExchangeAESKey(SocketFD clientFD, Packet *reqPacket, AESGCMKey *outKey)`

完成服务端侧的 ECDH+HKDF 密钥交换。

**完整流程**：

01. 对传入的 `reqPacket`（由调用方事先通过 `packetRecv` 接收）执行零信任校验（见上文）。
02. 调用 `genECDHKeypair` 生成临时 X25519 密钥对。
03. 调用 `exportECDHPublicKey` 导出己方 32 字节原始公钥。
04. 提取客户端公钥，随后用 `OPENSSL_cleanse` 清零 `reqPacket->payload` 中的公钥数据。
05. 将服务端公钥填入 `KeyExchangePacketPayload`，通过 `packetInit` 构造 `MsgKeyExchangeResp` 包，再通过 `packetSend` 发给客户端。
06. 调用 `importECDHPeerPublicKey` 导入客户端公钥。
07. 调用 `deriveECDHSharedSecret` 计算 32 字节共享密钥。
08. 调用 `deriveAESKey` 将共享密钥派生为 32 字节 AES-256-GCM 密钥。
09. 清理所有敏感缓冲： `OPENSSL_cleanse` 己方公钥、对端公钥、共享密钥、`KeyExchangePacketPayload`；`EVP_PKEY_free` 己方与对端密钥对象；`packetClear` 发送包。

* `clientFD`：与客户端连接的 TCP 套接字描述符。函数不负责创建或关闭此套接字。
* `reqPacket`：调用方事先通过 `packetRecv` 接收到的客户端 `MsgKeyExchangeReq` 包。函数不承担接收责任。返回后，`reqPacket->payload` 已被清零，但**未被释放**；调用者须随后调用 `packetClear(reqPacket)` 释放内存。
* `outKey`：输出参数，接收派生的 AES-256 密钥，与客户端接口语义一致。
* 返回 `COMM_SUCC` 或 `COMM_FAIL`。

### 端到端密钥协商典型用法

以下为基于 Communication 模块的完整密钥协商伪代码，展示了客户端与服务端的调用顺序：

**客户端**：

```c
SocketFD fd = clientSetup("192.168.1.100", 12345);
AESGCMKey sessionKey;
if (clientExchangeAESKey(fd, &sessionKey) != COMM_SUCC) {
    LOG_ERROR("Key exchange failed");
    socketClose(&fd);
    return;
}
/* sessionKey 已就绪，可用于后续 packetAESEncrypt / packetAESDecrypt */
```

**服务端**：

```c
SocketFD listenFd = serverSetup(12345);
SocketFD clientFd = accept(listenFd, NULL, NULL);
Packet req;
memset(&req, 0, sizeof(req));
packetRecv(&req, clientFd);

AESGCMKey sessionKey;
if (serverExchangeAESKey(clientFd, &req, &sessionKey) != COMM_SUCC) {
    LOG_ERROR("Key exchange failed");
}
packetClear(&req);
/* sessionKey 已就绪，可用于后续 packetAESEncrypt / packetAESDecrypt */
```
