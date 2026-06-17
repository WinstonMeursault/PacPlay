# Snake Game Makefile
# Builds snake_server.so (stub) and snake_client.so (full game) shared libraries
# with pacplayMain() entry points, linking against PacPlay SDK.

CC       := clang
CFLAGS   := -fsanitize=address -fno-omit-frame-pointer -Wall -Wextra -Werror -g -Wno-unused-command-line-argument -fPIC
CFLAGS   += -I../../../include -I../../../src -I../../../sdk/include
CFLAGS   += -Icommon -Iserver -Iclient

PROJ_ROOT   := $(CURDIR)/../../..

LDFLAGS_SRV := -shared -L$(PROJ_ROOT)/sdk/lib -lpacplay_server_sdk -Wl,-rpath,$(PROJ_ROOT)/sdk/lib -lpthread
LDFLAGS_CLI := -shared -L$(PROJ_ROOT)/sdk/lib -lpacplay_client_sdk -Wl,-rpath,$(PROJ_ROOT)/sdk/lib -lpthread

OUT_DIR   := ../../../bin
BUILD_DIR := build

SRV_SRC   := server/snake_server.c common/snake_common.c
CLI_SRC   := client/snake_client.c common/snake_common.c

SRV_OBJ   := $(patsubst %.c,$(BUILD_DIR)/%.o,$(SRV_SRC))
CLI_OBJ   := $(patsubst %.c,$(BUILD_DIR)/%.o,$(CLI_SRC))

.PHONY: all clean server client

all: server client

server: $(OUT_DIR)/snake_server.so

client: $(OUT_DIR)/snake_client.so

$(OUT_DIR)/snake_server.so: $(SRV_OBJ) | $(OUT_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS_SRV)

$(OUT_DIR)/snake_client.so: $(CLI_OBJ) | $(OUT_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS_CLI)

$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OUT_DIR):
	@mkdir -p $(OUT_DIR)

clean:
	rm -rf $(BUILD_DIR) $(OUT_DIR)/snake_server.so $(OUT_DIR)/snake_client.so
