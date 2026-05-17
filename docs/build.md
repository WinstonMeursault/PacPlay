# Build 构建

## Makefile

### 构建

```make all``` 可以自动编译出 ```bin/server``` 和 ``` bin/client ```

```make server``` 和 ```make client``` 可以分别编译PacPlay的服务器端和客户端

### 执行

```make run``` 自动运行PacPlay服务器端

```make run-server``` 和 ```make run-client``` 可以分别运行PacPlay的服务器端和客户端

### 测试

```make test``` 即可自动编译测试文件并执行测试

### 清理

```make clean``` 即可清理构建文件

### 生成索引

```make json``` 可以自动生成项目完整索引

```make json-server``` 和 ```make json-client``` 可以分别生成服务器端和客户端的索引
