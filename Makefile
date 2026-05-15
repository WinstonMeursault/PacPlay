# Variable Section

## Automatically enable multi-threaded compilation based on CPU cores to improve speed
MAKEFLAGS += -j $(shell nproc)

## Compiler and compilation flags
CC := clang
CFLAGS := -Wall -Wextra -Werror -g
## Compiler flags for auto-generating dependency files (modern approach, replaces the old sed method)
DEPFLAGS = -MMD -MP -MF $(@:%.o=%.d)

## Code Analysis
CLANG_TIDY := clang-tidy

## Directories
SRC_DIR := src
BUILD_DIR := build
BIN_DIR := bin
INC_DIR := include
LIB_DIR := lib

## Target & Libraries
TARGET := main
TARGET_PATH := $(BIN_DIR)/$(TARGET)

LIBS := # e.g., -lm -lpthread
LIB_PATHS := -L$(LIB_DIR)


## File Discovery
### Recursively search for all .c files in the src directory using find (supports unlimited subdirectories)
SRC := $(shell find $(SRC_DIR) -type f -name '*.c')
### Map src/xxx.c to build/xxx.o (maintains multi-level directory structure)
OBJ := $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRC))
### Corresponding .d dependency file list
DEP := $(OBJ:.o=.d)


## Terminal Output Colors
C_GREEN := \033[92m
C_BLUE  := \033[94m
C_RESET := \033[0m


# Build Rules
.PHONY: all clean debug

all: $(TARGET_PATH)

## Link to generate the final executable
## The pipe | before $(BIN_DIR) indicates an order-only prerequisite, creating the directory only if it doesn't exist
$(TARGET_PATH): $(OBJ) | $(BIN_DIR)
	@echo -e '$(C_GREEN)Linking executable: $@$(C_RESET)'
	@$(CC) $(CFLAGS) $^ $(LIB_PATHS) $(LIBS) -o $@

## Compile .c files to .o files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@# Analyze the code using clang-tidy. Use -quiet to hide suppressed warnings
	@$(CLANG_TIDY) -quiet $< -- $(CFLAGS)
	@# Check if the directory exists; if not, create it and print a message
	@if [ ! -d $(dir $@) ]; then \
		echo -e '$(C_GREEN)Creating directory: $(dir $@)$(C_RESET)'; \
		mkdir -p $(dir $@); \
	fi
	@echo -e '$(C_BLUE)Compiling: $<$(C_RESET)'
	@$(CC) $(CFLAGS) $(DEPFLAGS) -I$(INC_DIR) -c $< -o $@

## Automatically create the bin directory
$(BIN_DIR):
	@echo -e '$(C_GREEN)Creating directory: $@/$(C_RESET)'
	@mkdir -p $@

## Include all auto-generated .d dependency files (if they exist)
-include $(DEP)


# Utilities

## Print current variable environment (for debugging)
debug:
	@echo -e '$(C_BLUE)SRC Files:$(C_RESET) \n$(SRC)\n'
	@echo -e '$(C_BLUE)OBJ Files:$(C_RESET) \n$(OBJ)\n'

## Clean build artifacts
clean:
	@echo -e '$(C_GREEN)Cleaning workspace...$(C_RESET)'
	@rm -rf $(BUILD_DIR) $(BIN_DIR)