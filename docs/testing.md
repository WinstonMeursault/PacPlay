# Testing 测试

## 概述

PacPlay 使用位于 `tests/test_utils.h` 的轻量宏测试框架。该框架不依赖任何
第三方库，仅通过 C 预处理器宏实现断言、用例执行和结果汇总。

每个测试源文件编译为独立的可执行文件。构建系统自动发现 `tests/` 目录下所有
`test_*.c` 文件，逐一编译、链接并执行。

## 运行测试

```bash
make test
```

该命令自动完成以下步骤：

1. 编译 `tests/` 下所有 `test_*.c` 源文件。
2. 将每个测试对象文件与 `src/common/`、`src/server/`、`src/client/` 的构建产物
   链接（`src/server/main.o` 和 `src/client/main.o` 除外），生成
   `bin/tests/test_*` 可执行文件。
3. 依次执行所有测试二进制文件，汇总结果。若任一测试套件返回非零退出码，
   `make test` 整体失败。

## 编写测试

### 文件命名与放置

测试源文件必须放置在 `tests/` 目录下，文件名以 `test_` 为前缀，扩展名
为 `.c`。例如：

`
tests/test_protocol.c
tests/test_log.c
`

构建系统通过 `find tests/ -type f -name 'test_*.c'` 发现测试文件。不符合此
命名规则的文件不会被自动编译和执行。

### 文件结构

一个完整的测试文件包含以下部分：

1. 引入被测模块的头文件。
2. 引入 `test_utils.h`。
3. 定义测试所需的常量（以规避 `readability-magic-numbers` 检查）。
4. 编写若干 `static void testXxx(void)` 形式的测试函数。
5. 在 `main` 中使用 `RUN_TEST` 宏逐一调用，最后以 `return TEST_REPORT();`
   结束。

以下是一个最小完整示例：

```c
#include "protocol.h"
#include "test_utils.h"

enum { ExpectedHeaderSize = 14 };

static void testPacketHeaderSize(void) {
    ASSERT_UINT_EQ(sizeof(PacketHeader), ExpectedHeaderSize);
}

int main(void) {
    printf("test_protocol:\n");

    RUN_TEST(testPacketHeaderSize);

    return TEST_REPORT();
}
```

### 测试函数签名

所有测试函数必须遵循以下签名：

```c
static void testXxx(void);
```

- 返回值为 `void`。
- 无参数。
- 使用 `static` 限定，避免符号导出冲突。
- 函数名遵循项目 `camelBack` 命名规范。

### 数值常量

项目启用了 `readability-magic-numbers` 检查，裸数字字面量将触发编译错误。
测试中使用的所有预期值必须通过匿名枚举或宏定义为命名常量：

```c
/* 推荐：匿名枚举 */
enum { ExpectedMaxPayload = 1024 };

/* 亦可使用宏 */
#define EXPECTED_MAX_PAYLOAD 1024
```

唯一的例外是 `ASSERT_INT_EQ` 中作为枚举成员值的小整数（如 `1`、`2`），因其
直接对应枚举定义本身的值，属于协议稳定性验证而非任意魔术数字。

## test_utils.h 参考

### 内部状态

`test_utils.h` 在文件作用域定义了两个静态计数器：

```c
static int testsPassed = 0;
static int testsFailed = 0;
```

由于每个测试文件编译为独立的可执行文件，计数器不会在不同测试文件之间产生
冲突。

### 断言宏

所有断言宏在判定失败时执行以下操作：

1. 向 `stderr` 输出包含文件名、行号和实际值的错误信息。
2. 递增 `testsFailed` 计数器。
3. 通过 `return` 语句立即退出当前测试函数。

因此，同一测试函数中位于失败断言之后的代码不会被执行。

#### ASSERT_INT_EQ(actual, expected)

比较两个有符号整数值。双方均被转型为 `long long` 后进行比较。适用于
`int`、`enum` 等有符号类型。

```c
ASSERT_INT_EQ(MsgLoginReq, 1);
```

#### ASSERT_UINT_EQ(actual, expected)

比较两个无符号整数值。双方均被转型为 `unsigned long long` 后进行比较。适用于
`uint32_t`、`size_t`、`sizeof` 表达式和 `offsetof` 等无符号类型，可避免
有符号/无符号比较产生的编译警告。

```c
ASSERT_UINT_EQ(sizeof(PacketHeader), ExpectedHeaderSize);
ASSERT_UINT_EQ(offsetof(PacketHeader, magic), ExpectedMagicFieldOffset);
```

#### ASSERT_TRUE(expr)

断言表达式为真。若 `expr` 求值为零，则判定失败。

```c
ASSERT_TRUE(MAX_PAYLOAD_LEN > 0);
```

#### ASSERT_FALSE(expr)

断言表达式为假。若 `expr` 求值为非零，则判定失败。

```c
ASSERT_FALSE(errorOccurred);
```

#### ASSERT_STR_EQ(actual, expected)

使用 `strcmp` 比较两个 C 字符串。失败时输出两个字符串的实际内容。

```c
ASSERT_STR_EQ(logLevelString(LogLevelInfo), "INFO");
```

#### ASSERT_MEM_EQ(a, b, n)

使用 `memcmp` 比较两段长度为 `n` 字节的内存区域。适用于验证序列化输出或
二进制数据。

```c
ASSERT_MEM_EQ(&hdr, expectedBytes, sizeof(PacketHeader));
```

### 执行宏

#### RUN_TEST(fn)

调用指定的测试函数并记录结果。该宏通过比较调用前后 `testsFailed` 的值判断
测试是否通过：

- 若 `testsFailed` 未变化，输出 `PASS` 并递增 `testsPassed`。
- 若 `testsFailed` 增加，说明函数内部的某个断言已失败并提前返回，不再重复
  输出失败信息。

```c
RUN_TEST(testPacketHeaderSize);
RUN_TEST(testPacketMagicValue);
```

#### TEST_REPORT()

输出测试汇总信息（通过数和失败数），并返回退出码：全部通过时返回 `0`，
存在失败时返回 `1`。此宏必须作为 `main` 函数的返回值使用：

```c
return TEST_REPORT();
```

## 链接与编译细节

- 测试文件的编译标志与主项目一致：`-Wall -Wextra -Werror -g`。
- 编译时包含路径：`-Iinclude -Itests -Isrc/server -Isrc/client`。`-Iinclude`
  用于引入项目公共头文件，`-Itests` 用于引入 `test_utils.h`，`-Isrc/server`
  和 `-Isrc/client` 用于引入服务器端和客户端的内部头文件。
- 每个测试二进制文件与以下构建产物链接：
  - `src/common/` 的服务器构建产物（`build/server/common/*.o`）。
  - `src/server/` 的构建产物（`build/server/*.o`），**排除** `main.o`。
  - `src/client/` 的构建产物（`build/client/*.o`），**排除** `main.o`。
- 测试中可直接使用 `src/common/`、`src/server/`、`src/client/` 中定义的所有
  函数和类型（入口函数 `main` 除外）。

## 添加新测试文件后

新增测试文件后，须执行以下命令更新 `compile_commands.json`，以确保
`clang-tidy` 能正确分析新文件：

```bash
make json
```
