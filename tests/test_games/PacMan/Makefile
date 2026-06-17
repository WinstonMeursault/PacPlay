# PacMan Game Makefile
# Builds pacman_server.so and pacman_client.so shared libraries
# with pacplayMain() entry points, linking against PacPlay SDK.

CC       := clang
CFLAGS   := -fsanitize=address -fno-omit-frame-pointer -Wall -Wextra -Werror -g -Wno-unused-command-line-argument -fPIC
CFLAGS   += -I../../../include -I../../../src -I../../../sdk/include
CFLAGS   += -Icommon -Iserver -Iclient

LDFLAGS_SRV := -shared -L../../../sdk/lib -lpacplay_server_sdk -Wl,-rpath,../../../sdk/lib -lpthread
LDFLAGS_CLI := -shared -L../../../sdk/lib -lpacplay_client_sdk -Wl,-rpath,../../../sdk/lib -lpthread

OUT_DIR   := ../../../bin
BUILD_DIR := build

SRV_SRC   := server/pacman_server.c common/pacman_common.c
CLI_SRC   := client/pacman_client.c common/pacman_common.c

SRV_OBJ   := $(patsubst %.c,$(BUILD_DIR)/%.o,$(SRV_SRC))
CLI_OBJ   := $(patsubst %.c,$(BUILD_DIR)/%.o,$(CLI_SRC))

.PHONY: all clean server client

all: server client

server: $(OUT_DIR)/pacman_server.so

client: $(OUT_DIR)/pacman_client.so

$(OUT_DIR)/pacman_server.so: $(SRV_OBJ) | $(OUT_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS_SRV)

$(OUT_DIR)/pacman_client.so: $(CLI_OBJ) | $(OUT_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS_CLI)

$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OUT_DIR):
	@mkdir -p $(OUT_DIR)

clean:
	rm -rf $(BUILD_DIR) $(OUT_DIR)/pacman_server.so $(OUT_DIR)/pacman_client.so
