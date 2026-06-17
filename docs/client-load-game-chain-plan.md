# PacPlay Client Load Game Chain 后续计划

## 背景

在审阅 Snake 接入 PacPlay Client 的加载链路时，发现客户端进入游戏页后显示 `No game running`。根因是 `src/client/gameLoad.c` 中启动 loader 的 `execl` 参数列表缺少 `argv[0]`，导致 `src/client/loader/main.c` 看到的参数数量不符合要求并立即退出。

本轮已完成最小修复：将 loader 启动参数调整为 `execl("./loader", "loader", path, NULL)`，使游戏库路径作为 loader 的第一个业务参数传入。

## 已完成验证

新增测试文件：`tests/test_game_load.c`。

测试覆盖点：`clientRunGame` 必须把游戏库路径传递为 loader 的第一个参数。

验证过程：修复前测试失败，loader 退出码为 `42`；修复后测试通过。

## 后续问题

### 1. loader 启动路径依赖当前工作目录

当前 `clientRunGame` 使用 `./loader`。在 `make run-client` 场景下，客户端会进入 `bin/client` 目录运行，因此可以找到 `bin/client/loader`。如果用户从项目根目录直接执行 `bin/client/client`，则 `./loader` 会解析到项目根目录下的 loader，启动失败。

建议后续改进：根据客户端可执行文件路径或固定安装布局解析 loader 绝对路径，避免依赖当前工作目录。

### 2. loader 缺少 `pacplayMain` 空指针保护

当前 `src/client/loader/main.c` 在 `dlsym(handle, "pacplayMain")` 失败后只记录日志，随后仍调用 `gameFunctions.pacplayMain()`。

建议后续改进：当 `pacplayMain` 缺失时立即 `dlclose(handle)` 并返回失败，避免空函数指针调用导致崩溃。

### 3. 游戏进程与客户端 IO 线程的 SDK 队列不共享

当前游戏通过 `fork` 加 `execl` 在 loader 子进程中运行。`pacplay_cli_create()` 创建的是进程内 SDK 队列；子进程里的 `pacplay_cli_send` 和 `pacplay_cli_request_start_server` 无法被父进程的 `clientEventLoop` 读取。

建议后续改进：选择一种明确的桥接架构。方案一是在客户端主进程内直接 `dlopen` 游戏库。方案二是保留 loader 子进程，但增加父子进程 IPC，将游戏 SDK 队列消息转发给客户端 IO 线程。

### 4. 启动游戏时没有向游戏库传递游戏标识和平台

当前 `mainPage.c` 调用 `controlGameViewRun(&gameView, cur->gamePath)`，只传递本地 `.so` 路径。`GameRecord` 中已有 `gameId` 和 `platform`，但没有传入 loader 或游戏库。

建议后续改进：扩展 `controlGameViewRun` 和 `clientRunGame` 参数，传入 `gameId` 与 `platform`，并通过环境变量 `PACPLAY_GAME_ID` 与 `PACPLAY_SERVER_PLATFORM` 传递给游戏库。

### 5. Snake 未发起服务端游戏启动请求

PacMan 客户端会读取 `PACPLAY_GAME_ID` 和 `PACPLAY_SERVER_PLATFORM`，并调用 `pacplay_cli_request_start_server`。Snake 当前只创建 SDK 并发送本地状态消息，没有请求服务端启动 `snakeServer.so`。

建议后续改进：在 Snake 客户端 `pacplayMain` 中补齐与 PacMan 相同的服务端启动请求逻辑。

### 6. loader 未纳入 `compile_commands.json`

当前 `Makefile` 中 `CLIENT_SRC` 排除了 `src/client/loader/*`，而 `json` 与 `json-client` 目标没有额外加入 `LOADER_SRC`。这会导致 `make analyze` 生成的静态分析数据库漏掉 loader 源文件。

建议后续改进：在 `json` 和 `json-client` 目标中加入 `LOADER_SRC`，确保 loader 也接受 clang-tidy 检查。

## 建议实施顺序

1. 为 loader 增加 `pacplayMain` 缺失保护，并补充测试。
2. 扩展游戏启动参数，将 `gameId` 与 `platform` 传递给游戏库。
3. 为 Snake 补齐 `pacplay_cli_request_start_server` 调用。
4. 决定并实现客户端父进程与游戏进程之间的 SDK 消息桥接方式。
5. 修复 loader 路径解析，支持从不同工作目录启动客户端。
6. 将 loader 源文件纳入 `compile_commands.json`。
