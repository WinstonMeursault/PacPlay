# GameRoom 设计文档

## 1. 概述

GameRoom 是一个与现有 Room 完全独立的新子系统。它由用户发起创建，绑定一个 gameID，遵循房主制，由房主手动启动游戏。每个活跃 GameRoom 持有一个独立的游戏 server 实例（通过动态链接库 dlopen 加载）。

## 2. 架构总览

```
┌─ gameRoomDB (SQLCipher) ─────────────────────────────────┐
│  game_rooms 表: gameRoomId | gameId | hostUid | createdAt │
└───────────────────────────────────────────────────────────┘

┌─ ActiveGameRoom (内存) ───────────────────────────────────┐
│  gameRoomId, gameId, hostUid                              │
│  members[] (ClientSession*), memberCount                  │
│  state: Lobby / Playing                                   │
│  GameInstance { gameHandle, sdk*, thread, running }       │
└───────────────────────────────────────────────────────────┘

┌─ 协议 ───────────────────────────────────────────────────┐
│  MsgGameRoomCreate/Resp, MsgGameRoomList/Resp,            │
│  MsgGameRoomJoin/Resp, MsgGameRoomQuit/Resp,              │
│  MsgGameRoomStart/Resp, MsgGameRoomPlayData               │
└───────────────────────────────────────────────────────────┘

┌─ Session 状态 ───────────────────────────────────────────┐
│  SessionGameRoomLobby → SessionGameRoomPlay               │
└───────────────────────────────────────────────────────────┘

┌─ gameRunner 改造 ────────────────────────────────────────┐
│  从 Server 单例 → ActiveGameRoom 持有独立的 GameInstance   │
│  每个 gameRoom 独立 SDK / dlopen / pthread                 │
└───────────────────────────────────────────────────────────┘
```

## 3. 与现有 Room 的边界

| 维度 | Room | GameRoom |
|------|------|----------|
| 数据库 | `rooms` 表 (roomId, creatorUid, createdAt) | `game_rooms` 表 (gameRoomId, gameId, hostUid, createdAt) |
| DBType 枚举 | RoomDB = 3 | 新增 GameRoomDB = 6 |
| 内存结构 | ActiveRoom | 新增 ActiveGameRoom |
| Session 状态 | SessionRoom → SessionChat | SessionGameRoomLobby → SessionGameRoomPlay |
| 消息前缀 | MsgCreateRoom, MsgJoinRoom... | MsgGameRoomCreate, MsgGameRoomJoin... |
| 游戏关联 | 无 | gameId 字段，Playing 状态时持有独立 GameInstance |
| 生命周期 | 创建者离开/最后一成员离开 | 房主离开即解散（不管是否已有成员） |

## 4. 数据库：gameRoomDB

### 4.1 Schema

```sql
CREATE TABLE IF NOT EXISTS game_rooms (
    gameRoomId INTEGER PRIMARY KEY,
    gameId INTEGER NOT NULL,
    hostUid INTEGER NOT NULL,
    createdAt INTEGER NOT NULL
);
```

### 4.2 DBType

- 新增 `GameRoomDB = 6` 到 `DBType` 枚举
- 数据库文件：`./db/gameRoom.db`
- 使用 SQLCipher 加密，独立 DEK

### 4.3 操作函数（gameRoomDb.c）

| 函数 | 说明 |
|------|------|
| `createGameRoom(DB *database, uint32_t gameRoomId, uint32_t gameId, uint32_t hostUid)` | INSERT，自动填 `createdAt = time(NULL)` |
| `deleteGameRoom(DB *database, uint32_t gameRoomId)` | DELETE，strict 模式（0 rows affected 则失败） |
| `listGameRooms(DB *database, uint32_t **outIds, size_t *count)` | SELECT 所有 gameRoomId，按 ASC 排序，调用者释放数组 |
| `gameRoomExists(DB *database, uint32_t gameRoomId)` | SELECT 1 FROM game_rooms WHERE gameRoomId = ?，返回 DB_SUCC 表示存在 |

### 4.4 预编译语句

- `stmtGameRoomInsert`：INSERT INTO game_rooms(gameRoomId, gameId, hostUid, createdAt) VALUES(?, ?, ?, ?)
- `stmtGameRoomDelete`：DELETE FROM game_rooms WHERE gameRoomId = ?
- `stmtGameRoomSelect`：SELECT gameRoomId, gameId, hostUid, createdAt FROM game_rooms ORDER BY gameRoomId ASC
- `stmtGameRoomExists`：SELECT 1 FROM game_rooms WHERE gameRoomId = ?

### 4.5 需修改的文件

| 文件 | 改动 |
|------|------|
| `src/server/database.h` | `DBType` 加 `GameRoomDB = 6`；声明 4 个操作函数 |
| `src/server/database/common.c` | `dbInit()` 加 `case GameRoomDB` 分支 |
| `src/server/database/gameRoomDb.c` | **新文件**——实现全部 GameRoomDB 操作 |

## 5. 内存结构：ActiveGameRoom

### 5.1 Struct 定义（server.h）

```c
typedef struct {
    uint32_t gameRoomId;
    uint32_t gameId;
    uint32_t hostUid;
    ClientSession *members[MAX_CLIENTS_PER_ROOM];
    int memberCount;
    enum { GameRoomLobby, GameRoomPlaying } state;
    void *gameHandle;
    PacPlaySDK *sdk;
    pthread_t gameThread;
    bool gameRunning;
} ActiveGameRoom;
```

### 5.2 Server 新增字段（server.h）

```c
ActiveGameRoom **activeGameRooms;
int activeGameRoomCount;
int activeGameRoomCapacity;
```

### 5.3 生命周期函数（gameRoom.c）

| 函数 | 说明 |
|------|------|
| `serverFindActiveGameRoom(Server *s, uint32_t gameRoomId)` | 线性查找，返回指针或 NULL |
| `serverGetOrCreateActiveGameRoom(Server *s, uint32_t gameRoomId, uint32_t gameId, uint32_t hostUid)` | 获取或创建，需要时 realloc 扩容 |
| `serverRemoveActiveGameRoom(Server *s, uint32_t gameRoomId)` | 停止游戏（如正在运行），释放内存，compact 数组 |
| `serverRemoveClientFromGameRoom(Server *s, ClientSession *cs)` | 从 members[] 移除，compact；若成员数为 0 则调用 `serverRemoveActiveGameRoom` |
| `serverDissolveGameRoom(Server *s, uint32_t gameRoomId)` | 房主离开专用——踢出所有成员，停止游戏，销毁 gameRoom |

### 5.4 ClientSession 新增字段

```c
uint32_t currentGameRoomId;  /* 0 = 不在任何 gameRoom 中 */
```

### 5.5 房主离开解散流程

1. 停止 game server（如已启动）：`gameRoomStopGame()`
2. 遍历所有成员，逐出并重置 `cs->currentGameRoomId = 0`、`cs->state = SessionRoom`
3. 从数据库删除：`deleteGameRoom()`
4. 从内存删除：`serverRemoveActiveGameRoom()`

## 6. 游戏实例管理（gameRunner 改造）

### 6.1 从单例到多实例

**现状：** `gameRunner.c` 中 gameHandle / sdk / gameThread 挂在 `Server` 结构体上，全局仅允许一个游戏运行。

**改造后：** 所有游戏状态移到 `ActiveGameRoom` 内。gameRunner 提供操作 `ActiveGameRoom` 粒度的接口。

### 6.2 新接口

```c
int gameRoomStartGame(ActiveGameRoom *gr, const char *soPath);
void gameRoomStopGame(ActiveGameRoom *gr);
```

- `gameRoomStartGame`：创建 `pacplay_srv_create()` 获得独立 SDK 实例 → 构造 `GameThreadArg` → `pthread_create`
- `gameRoomStopGame`：设置 `gr->running = false` → pthread_join → dlclose → SDK destroy
- `gameThreadFunc` 内部逻辑不变，但参数类型从 `(Server*)` 改为 `(ActiveGameRoom*)`，SDK 操作通过 `gr->sdk`

### 6.3 Server shutdown 集成

`serverCleanup()` 中遍历所有 `activeGameRooms`，若 `gameRunning == true` 则调用 `gameRoomStopGame()`。

### 6.4 SDK 通信路由

每个 ActiveGameRoom 持有独立 `PacPlaySDK *sdk`。GameRoomPlay 状态下，`MsgGameRoomPlayData` 消息的 payload 通过对应 gameRoom 的 SDK ring buffer 路由：

- server 收到 client 的 `MsgGameRoomPlayData` → 查 `cs->currentGameRoomId` → 找到 ActiveGameRoom → `pacplay_srv_send(gr->sdk, payload)`
- game server 通过 SDK 发回的数据 → `pacplay_srv_recv` → 封装为 `MsgGameRoomPlayData` → 广播给该 gameRoom 所有成员

### 6.5 需修改的文件

| 文件 | 改动 |
|------|------|
| `src/server/server.h` | ActiveGameRoom struct + Server 新增 activeGameRooms 字段 + ClientSession 新增 currentGameRoomId 字段 |
| `src/server/gameRoom.h` | **新文件**——声明所有 ActiveGameRoom 操作 |
| `src/server/gameRoom.c` | **新文件**——实现所有 ActiveGameRoom 操作 |
| `src/server/gameRunner.h` | 新函数声明 `gameRoomStartGame` / `gameRoomStopGame` |
| `src/server/gameRunner.c` | 重写为 ActiveGameRoom 粒度 |
| `src/server/server.c` | `serverCleanup()` 遍历 activeGameRooms 停止游戏 |

## 7. 协议层

### 7.1 新增 MessageType（protocol.h）

```c
MsgGameRoomListReq   = 41,
MsgGameRoomListResp  = 42,
MsgGameRoomCreate    = 43,
MsgGameRoomCreateResp = 44,
MsgGameRoomJoin      = 45,
MsgGameRoomJoinResp  = 46,
MsgGameRoomQuit      = 47,
MsgGameRoomQuitResp  = 48,
MsgGameRoomStart     = 49,
MsgGameRoomStartResp = 50,
MsgGameRoomPlayData  = 51,
```

### 7.2 Payload 结构（protocol.h）

```c
/* MsgGameRoomCreate / Resp */
typedef struct {
    uint32_t gameRoomId;  /* 用户指定，与现有 Room 创建行为一致 */
    uint32_t gameId;
} GameRoomCreatePayload;

typedef struct {
    uint8_t status;
    uint32_t gameRoomId;
} GameRoomCreateRespPayload;

/* MsgGameRoomListResp: uint32_t count + GameRoomListEntry[] */
/* count 由服务端根据活跃 ActiveGameRoom 动态计算 */
typedef struct {
    uint32_t gameRoomId;
    uint32_t gameId;
    uint32_t hostUid;
    uint32_t memberCount;
    uint8_t state;
} GameRoomListEntry;

/* MsgGameRoomJoin */
/* payload: uint32_t gameRoomId */
/* MsgGameRoomJoinResp: uint8_t status */

/* MsgGameRoomQuit: 无 payload */
/* MsgGameRoomQuitResp: uint8_t status */

/* MsgGameRoomStart: uint32_t gameRoomId */
/* MsgGameRoomStartResp: uint8_t status */

/* MsgGameRoomPlayData: 透明转发，原样 payload */
```

### 7.3 新增 Session 状态

```c
SessionGameRoomLobby,   /* 在 gameRoom 但游戏尚未启动 */
SessionGameRoomPlay,    /* 游戏运行中，期间仅接受 MsgGameRoomPlayData / MsgGameRoomQuit */
```

### 7.4 客户端对应状态

```c
ClientGameRoomLobby,
ClientGameRoomPlay,
```

客户端 IO 层支持这些状态下的消息接收和处理。

## 8. 服务端状态机

### 8.1 processClient 新增分支

```
SessionRoom:
  MsgGameRoomCreate    → 创建 gameRoom，进入 SessionGameRoomLobby，当前用户变为房主
  MsgGameRoomList      → 查询 gameRoomDB，返回列表，留在 SessionRoom
  MsgGameRoomJoin      → 校验存在性、容量，加入，进入 SessionGameRoomLobby

SessionGameRoomLobby:
  MsgGameRoomQuit      → 退出 gameRoom。若是房主 → 解散 gameRoom。回 SessionRoom
  MsgGameRoomStart     → 仅房主可调用。验证 gameId 在 GameDB 中存在，找到 .so 路径，gameRoomStartGame()，所有成员进入 SessionGameRoomPlay
  MsgChat              → lobby 内聊天（可选）

SessionGameRoomPlay:
  MsgGameRoomPlayData  → 查 cs->currentGameRoomId → ActiveGameRoom → SDK send，或 SDK recv → 广播
  MsgGameRoomQuit      → 退出 gameRoom。若是房主 → 停止游戏 + 解散。回 SessionRoom
```

### 8.2 sessionStateToString 扩展

`src/server/server.c` 的 `sessionStateToString()` 函数新增两条映射。

## 9. 与现有系统的交互

### 9.1 gameDistribution 不变

`gameDistribution.c` 仍负责游戏元数据的列表/下载，与 gameRoom 无关。gameRoom 创建时只需从 GameDB 校验 `gameId` 存在。

### 9.2 客户端 Socket 复用

客户端在 gameRoom 内的所有通信复用现有的 TCP socket 和加密通道，不新开连接。

### 9.3 与 Room 互斥

用户不能同时在一 room 和一 gameRoom 中。加入 gameRoom 前自动离开当前 room（如有），反之亦然。此逻辑集成在 `serverRemoveClientFromRoom` / `serverRemoveClientFromGameRoom` 中。

### 9.4 数据库加密

gameRoomDB 使用独立的 DEK，遵循 `keyManager` 体系。初始化 server 时调用 `dbInit(GameRoomDB, gameRoomDbEncKey)`。

## 10. 文件清单

### 新增文件

| 文件 | 说明 |
|------|------|
| `src/server/gameRoom.h` | ActiveGameRoom 操作声明 |
| `src/server/gameRoom.c` | ActiveGameRoom 操作实现 |
| `src/server/database/gameRoomDb.c` | GameRoomDB CRUD |

### 修改文件

| 文件 | 改动 |
|------|------|
| `include/protocol.h` | 新增 MessageType 枚举值 + Payload struct |
| `src/server/server.h` | ActiveGameRoom struct + Server 新增字段 |
| `src/server/server.c` | 状态机扩展、cleanup 遍历、sessionStateToString 扩展 |
| `src/server/database.h` | DBType 加 GameRoomDB=6、声明函数 |
| `src/server/database/common.c` | dbInit() 加分支、dbClose() 加清理 |
| `src/server/database/internal.h` | GameRoomDB 内部常量 |
| `src/server/gameRunner.h` | 新接口声明 |
| `src/server/gameRunner.c` | 重写为 ActiveGameRoom 粒度 |
| `src/client/client.h` | ClientState 新增 ClientGameRoomLobby/Play |
| `src/client/connection.c` | 客户端状态机扩展 |

## 11. 测试计划

### 11.1 数据库测试

- `test_game_room_db.c`：测试 createGameRoom / deleteGameRoom / listGameRooms / gameRoomExists
- 边界：gameRoomId = 0 / UINT32_MAX，重复创建，删除不存在的 room，空列表

### 11.2 ActiveGameRoom 测试

- 仿照 `test_server_room.c` 的全套测试
- 容量增长、查找、移除（首/尾/仅/双次）、房主离开解散

### 11.3 协议测试

- GameRoomCreate 合法/非法 gameId
- GameRoomJoin 不存在/满员/重复加入
- GameRoomStart 非房主调用/游戏不存在
- GameRoomPlayData 路由验证

### 11.4 集成测试

- 完整流程：创建 → 加入 → 房主开始游戏 → 房主退出解散
- 多个 gameRoom 并行 + 各自游戏 server 独立运行
