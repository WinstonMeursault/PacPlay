# Build 构建

## 系统依赖

### 链接库（需通过包管理器安装）

| 库 | 链接标志 | 用途 | Arch Linux | Debian/Ubuntu |
|---|---------|------|-----------|---------------|
| OpenSSL 3.x | `-lssl -lcrypto` | AES-GCM、ECDH、HKDF、SHA-256、TOTP | `pacman -S openssl` | `apt install libssl-dev` |
| SQLCipher | `-lsqlcipher` | 加密数据库（SQLite + AES-256-CBC） | `pacman -S sqlcipher` | `apt install libsqlcipher-dev` |
| ncursesw | `-lncursesw` | TUI 终端界面 | `pacman -S ncurses` | `apt install libncursesw5-dev` |
| zlib-ng | `-lz-ng` | 日志压缩、tar.gz 解压 | `pacman -S zlib-ng` | `apt install libz-ng-dev` |
| pthread | `-lpthread` | 多线程（日志、下载线程池） | 系统内置 | 系统内置 |

### 构建工具

| 工具 | 用途 | Arch Linux | Debian/Ubuntu |
|------|------|-----------|---------------|
| clang | C 编译器（gnu17 方言） | `pacman -S clang` | `apt install clang` |
| GNU Make | 构建系统 | `pacman -S make` | `apt install make` |
| run-clang-tidy | 静态分析（`make all` 需要） | `pacman -S clang-tools-extra` | `apt install clang-tools` |

### 一键安装（Arch Linux）

```bash
sudo pacman -S clang clang-tools-extra make openssl sqlcipher ncurses zlib-ng
```

### 一键安装（Debian/Ubuntu）

```bash
sudo apt install clang clang-tools make libssl-dev libsqlcipher-dev libncursesw5-dev libz-ng-dev
```

## Makefile

### 构建

`make all` 可以自动编译出 `bin/server` 和 `bin/client`

`make server` 和 `make client` 可以分别编译 PacPlay 的服务器端和客户端

### 执行

`make run` 自动运行 PacPlay 服务器端

`make run-server` 和 `make run-client` 可以分别运行 PacPlay 的服务器端和客户端

### 测试

`make test` 即可自动编译测试文件并执行测试

### 清理

`make clean` 即可清理构建文件

### 生成索引

`make json` 可以自动生成项目完整索引

`make json-server` 和 `make json-client` 可以分别生成服务器端和客户端的索引

### 静态分析

`make analyze` 运行 `run-clang-tidy` 全项目静态分析（`make all` 自动包含此步骤）
