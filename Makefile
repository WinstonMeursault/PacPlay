# Variable Section

## Automatically enable multi-threaded compilation based on CPU cores to improve speed
MAKEFLAGS += -j $(shell nproc)

## Compiler and compilation flags
CC := clang
CFLAGS := -Wall -Wextra -Werror -g -Wno-unused-command-line-argument
LDLIBS := -lssl -lcrypto -lsqlite3
## Compiler flags for auto-generating dependency files (modern approach, replaces the old sed method)
DEPFLAGS = -MMD -MP -MF $(@:%.o=%.d)

## Code Analysis
CLANG_TIDY := clang-tidy

## Directories
SRC_DIR := src
BUILD_DIR := build
BIN_DIR := bin
INC_DIR := include $(SRC_DIR)
INC_FLAGS := $(addprefix -I, $(INC_DIR))
TEST_DIR := tests

# Targets
SERVER_BIN := $(BIN_DIR)/server
CLIENT_BIN := $(BIN_DIR)/client

# Source File Discovery

# Target-specific sources
SERVER_SRC := $(shell find $(SRC_DIR)/server -type f -name '*.c')
CLIENT_SRC := $(shell find $(SRC_DIR)/client -type f -name '*.c')

# Shared common sources
COMMON_SRC := $(shell find $(SRC_DIR)/common -type f -name '*.c')

# Object File Mapping

# Server-specific objects under build/server/
SERVER_OBJ := $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SERVER_SRC))

# Client-specific objects under build/client/
CLIENT_OBJ := $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(CLIENT_SRC))

# Common objects compiled separately for each target to avoid main() conflicts
COMMON_SERVER_OBJ := $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/server/%.o, $(COMMON_SRC))
COMMON_CLIENT_OBJ := $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/client/%.o, $(COMMON_SRC))

# Full object lists for linking
SERVER_ALL_OBJ := $(SERVER_OBJ) $(COMMON_SERVER_OBJ)
CLIENT_ALL_OBJ := $(CLIENT_OBJ) $(COMMON_CLIENT_OBJ)

# Dependency files for incremental rebuilds
SERVER_DEP := $(SERVER_ALL_OBJ:.o=.d)
CLIENT_DEP := $(CLIENT_ALL_OBJ:.o=.d)

# Test Discovery
TEST_SRC := $(shell find $(TEST_DIR) -type f -name 'test_*.c')
TEST_BIN := $(patsubst $(TEST_DIR)/%.c, $(BIN_DIR)/tests/%, $(TEST_SRC))

# Server and client objects excluding main.o, for test linking
SERVER_OBJ_NO_MAIN := $(filter-out $(BUILD_DIR)/server/main.o, $(SERVER_OBJ))
CLIENT_OBJ_NO_MAIN := $(filter-out $(BUILD_DIR)/client/main.o, $(CLIENT_OBJ))

# Each test binary links against common, server, and client objects (excluding main.o)
TEST_OBJ_PER_BIN = $(patsubst $(TEST_DIR)/%.c, $(BUILD_DIR)/tests/%.o, $(1))

# Terminal Output Colors
C_GREEN := \033[92m
C_RED   := \033[91m
C_BLUE  := \033[94m
C_RESET := \033[0m

# Build Rules
.PHONY: all server client clean run run-server run-client analyze test json json-server json-client debug

all: analyze $(SERVER_BIN) $(CLIENT_BIN)

server: $(SERVER_BIN)

client: $(CLIENT_BIN)

# Link server executable
$(SERVER_BIN): $(SERVER_ALL_OBJ) | $(BIN_DIR)
	@echo -e '$(C_GREEN)Linking server: $@$(C_RESET)'
	@$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

# Link client executable
$(CLIENT_BIN): $(CLIENT_ALL_OBJ) | $(BIN_DIR)
	@echo -e '$(C_GREEN)Linking client: $@$(C_RESET)'
	@$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

# Compile server-specific .c files
$(BUILD_DIR)/server/%.o: $(SRC_DIR)/server/%.c
	@if [ ! -d $(dir $@) ]; then \
		echo -e '$(C_GREEN)Creating directory: $(dir $@)$(C_RESET)'; \
		mkdir -p $(dir $@); \
	fi
	@echo -e '$(C_BLUE)Compiling: $<$(C_RESET)'
	@$(CC) $(CFLAGS) $(DEPFLAGS) $(INC_FLAGS) -c $< -o $@

# Compile client-specific .c files
$(BUILD_DIR)/client/%.o: $(SRC_DIR)/client/%.c
	@if [ ! -d $(dir $@) ]; then \
		echo -e '$(C_GREEN)Creating directory: $(dir $@)$(C_RESET)'; \
		mkdir -p $(dir $@); \
	fi
	@echo -e '$(C_BLUE)Compiling: $<$(C_RESET)'
	@$(CC) $(CFLAGS) $(DEPFLAGS) $(INC_FLAGS) -c $< -o $@

# Compile shared common code for the server target
$(BUILD_DIR)/server/common/%.o: $(SRC_DIR)/common/%.c
	@if [ ! -d $(dir $@) ]; then \
		echo -e '$(C_GREEN)Creating directory: $(dir $@)$(C_RESET)'; \
		mkdir -p $(dir $@); \
	fi
	@echo -e '$(C_BLUE)Compiling: $<$(C_RESET)'
	@$(CC) $(CFLAGS) $(DEPFLAGS) $(INC_FLAGS) -c $< -o $@

# Compile shared common code for the client target
$(BUILD_DIR)/client/common/%.o: $(SRC_DIR)/common/%.c
	@if [ ! -d $(dir $@) ]; then \
		echo -e '$(C_GREEN)Creating directory: $(dir $@)$(C_RESET)'; \
		mkdir -p $(dir $@); \
	fi
	@echo -e '$(C_BLUE)Compiling: $<$(C_RESET)'
	@$(CC) $(CFLAGS) $(DEPFLAGS) $(INC_FLAGS) -c $< -o $@

# Ensure output bin directory exists
$(BIN_DIR):
	@echo -e '$(C_GREEN)Creating directory: $@/$(C_RESET)'
	@mkdir -p $@

# Include auto-generated dependency files
-include $(SERVER_DEP)
-include $(CLIENT_DEP)

# Test Rules

## Build and run all tests
test: $(TEST_BIN)
	@echo -e '$(C_GREEN)Running tests...$(C_RESET)'
	@failCount=0; \
	for t in $(TEST_BIN); do \
		if ! ./$$t; then failCount=$$((failCount + 1)); fi; \
	done; \
	if [ $$failCount -ne 0 ]; then \
		echo -e '$(C_RED)$$failCount test suite(s) failed.$(C_RESET)'; \
		exit 1; \
	fi; \
	echo -e '$(C_GREEN)All test suites passed.$(C_RESET)'

# Compile test source files
$(BUILD_DIR)/tests/%.o: $(TEST_DIR)/%.c
	@if [ ! -d $(dir $@) ]; then \
		echo -e '$(C_GREEN)Creating directory: $(dir $@)$(C_RESET)'; \
		mkdir -p $(dir $@); \
	fi
	@echo -e '$(C_BLUE)Compiling: $<$(C_RESET)'
	@$(CC) $(CFLAGS) $(DEPFLAGS) $(INC_FLAGS) -I$(TEST_DIR) -c $< -o $@

# Link each test binary against its object + server & client build of common objects (excluding main.o)
$(BIN_DIR)/tests/%: $(BUILD_DIR)/tests/%.o $(COMMON_SERVER_OBJ) $(SERVER_OBJ_NO_MAIN) $(CLIENT_OBJ_NO_MAIN) | $(BIN_DIR)/tests
	@echo -e '$(C_GREEN)Linking test: $@$(C_RESET)'
	@$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

$(BIN_DIR)/tests:
	@echo -e '$(C_GREEN)Creating directory: $@/$(C_RESET)'
	@mkdir -p $@

# Run Targets
run: run-server

run-server: $(SERVER_BIN)
	@echo -e '$(C_GREEN)Running server...$(C_RESET)'
	@./$(SERVER_BIN)

run-client: $(CLIENT_BIN)
	@echo -e '$(C_GREEN)Running client...$(C_RESET)'
	@./$(CLIENT_BIN)

analyze: json
	@echo -e '$(C_BLUE)Analyzing code..$(C_RESET)'
	@run-clang-tidy -quiet | (grep -E "warning:|error:" || true)

# compile_commands.json Generation
json:
	@echo -e '$(C_GREEN)Generating compile_commands.json for all targets...$(C_RESET)'
	@rm -f compile_commands.json
	@echo "[" > compile_commands.json
	@$(foreach src, $(SERVER_SRC) $(COMMON_SRC), \
		obj=$(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/server/%.o,$(src)); \
		echo "  { \"directory\": \"$(CURDIR)\", \"command\": \"$(CC) $(CFLAGS) $(INC_FLAGS) -c $(src) -o $$obj\", \"file\": \"$(src)\" }," >> compile_commands.json;)
	@$(foreach src, $(CLIENT_SRC) $(COMMON_SRC), \
		obj=$(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/client/%.o,$(src)); \
		echo "  { \"directory\": \"$(CURDIR)\", \"command\": \"$(CC) $(CFLAGS) $(INC_FLAGS) -c $(src) -o $$obj\", \"file\": \"$(src)\" }," >> compile_commands.json;)
	@$(foreach src, $(TEST_SRC), \
		obj=$(patsubst $(TEST_DIR)/%.c,$(BUILD_DIR)/tests/%.o,$(src)); \
		echo "  { \"directory\": \"$(CURDIR)\", \"command\": \"$(CC) $(CFLAGS) $(INC_FLAGS) -I$(TEST_DIR) -c $(src) -o $$obj\", \"file\": \"$(src)\" }," >> compile_commands.json;)
	@sed -i '$$ s/,$$//' compile_commands.json
	@echo "]" >> compile_commands.json
	@echo -e '$(C_GREEN)compile_commands.json generated$(C_RESET)'

json-server:
	@echo -e '$(C_GREEN)Generating compile_commands.json for server...$(C_RESET)'
	@rm -f compile_commands.json
	@echo "[" > compile_commands.json
	@$(foreach src, $(SERVER_SRC) $(COMMON_SRC), \
		obj=$(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/server/%.o,$(src)); \
		echo "  { \"directory\": \"$(CURDIR)\", \"command\": \"$(CC) $(CFLAGS) $(INC_FLAGS) -c $(src) -o $$obj\", \"file\": \"$(src)\" }," >> compile_commands.json;)
	@sed -i '$$ s/,$$//' compile_commands.json
	@echo "]" >> compile_commands.json
	@echo -e '$(C_GREEN)compile_commands.json generated for server$(C_RESET)'

json-client:
	@echo -e '$(C_GREEN)Generating compile_commands.json for client...$(C_RESET)'
	@rm -f compile_commands.json
	@echo "[" > compile_commands.json
	@$(foreach src, $(CLIENT_SRC) $(COMMON_SRC), \
		obj=$(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/client/%.o,$(src)); \
		echo "  { \"directory\": \"$(CURDIR)\", \"command\": \"$(CC) $(CFLAGS) $(INC_FLAGS) -c $(src) -o $$obj\", \"file\": \"$(src)\" }," >> compile_commands.json;)
	@sed -i '$$ s/,$$//' compile_commands.json
	@echo "]" >> compile_commands.json
	@echo -e '$(C_GREEN)compile_commands.json generated for client$(C_RESET)'

# Debug & Clean
debug:
	@echo -e '$(C_BLUE)Server SRC Files:$(C_RESET) \n$(SERVER_SRC)\n'
	@echo -e '$(C_BLUE)Client SRC Files:$(C_RESET) \n$(CLIENT_SRC)\n'
	@echo -e '$(C_BLUE)Common SRC Files:$(C_RESET) \n$(COMMON_SRC)\n'
	@echo -e '$(C_BLUE)Server OBJ Files:$(C_RESET) \n$(SERVER_ALL_OBJ)\n'
	@echo -e '$(C_BLUE)Client OBJ Files:$(C_RESET) \n$(CLIENT_ALL_OBJ)\n'

## Clean build artifacts
clean:
	@echo -e '$(C_GREEN)Cleaning workspace...$(C_RESET)'
	@rm -rf $(BUILD_DIR) $(BIN_DIR)
