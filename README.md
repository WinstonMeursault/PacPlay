# PacPlay

局域网内游戏平台 🎮

## 快速开始

### 手动构建

#### 下载并构建项目

克隆仓库

```bash
git clone https://github.com/WinstonMeursault/PacPlay.git ./PacPlay
cd ./PacPlay
```

随后执行 ```make all``` 构建项目

#### 部署

在一台主机上执行 ```make run-server``` 运行服务器端

在另外的主机上执行 ```make run-client``` 即可运行客户端

## Third-Party Libraries

This project includes the following vendored third-party libraries:

| Library | License | Source | Purpose |
|---------|---------|--------|---------|
| log.c | MIT | [rxi/log.c](https://github.com/rxi/log.c) | Logging framework |
| qrcodegen | MIT | [nayuki/QR-Code-generator](https://www.nayuki.io/page/qr-code-generator-library) | QR code generation |
| cJSON | MIT | [DaveGamble/cJSON](https://github.com/DaveGamble/cJSON) | JSON parsing |
| microtar | MIT | [rxi/microtar](https://github.com/rxi/microtar) | tar archive reading |
