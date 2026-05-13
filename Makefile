# Tools
CC = clang
CFLAGS = -Wall -Wextra -Werror -g
# CFLAGS = -Wall -Wextra -g
RM = rm -f

# Directories
SRC_DIR = src
BUILD_DIR = build
BIN_DIR = bin
INC_DIR = include
LIB_DIR = lib

# Files
SRC = $(wildcard $(SRC_DIR)/*.c)
OBJ = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRC))
DEP = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o.d, $(SRC))
TARGET = main
TARGET_PATH = $(BIN_DIR)/$(TARGET)

# Libraries
LIB = 

# Colors
C_GREEN = \033[92m
C_RESET = \033[0m

all: $(TARGET_PATH)

$(TARGET_PATH): $(OBJ)
	@echo -e '$(C_GREEN)Linking $(TARGET_PATH):$(C_RESET)'
	$(CC) $^ -L$(LIB_DIR) $(addprefix -l, $(LIB)) -o $@

$(BUILD_DIR)/%.o.d: $(SRC_DIR)/%.c
	@echo -e '$(C_GREEN)Getting dependency file $@:$(C_RESET)'
	$(CC) -I$(INC_DIR) -MM $< | sed -r 's|($*).o:|$(BUILD_DIR)/\1.o $@:|g' > $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@echo -e '$(C_GREEN)Compiling $<:$(C_RESET)'
	$(CC) $(CFLAGS) -I$(INC_DIR) -c $< -o $@

-include $(DEP)

.PHONY: clean print

clean:
	@echo -e '$(C_GREEN)Cleaning:$(C_RESET)'
	$(RM) $(OBJ) $(DEP) $(TARGET_PATH)
