#ifndef SNAKE_COMMON_H
#define SNAKE_COMMON_H

#include <stdbool.h>
#include <stdint.h>

#define SNAKE_MAP_WIDTH 40
#define SNAKE_MAP_HEIGHT 20
#define SNAKE_MAP_CELLS (SNAKE_MAP_WIDTH * SNAKE_MAP_HEIGHT)

#define SNAKE_INITIAL_LIVES 3
#define SNAKE_INITIAL_LENGTH 3
#define SNAKE_INITIAL_TICK_MS 150
#define SNAKE_MIN_TICK_MS 50
#define SNAKE_TICK_DECREASE_MS 20
#define SNAKE_FOOD_PER_SPEEDUP 5
#define SNAKE_FOOD_SCORE 10
#define SNAKE_MAX_LENGTH SNAKE_MAP_CELLS

#define SNAKE_MS_PER_SEC 1000
#define SNAKE_NS_PER_MS  1000000
#define SNAKE_NS_PER_US  1000
#define SNAKE_SRV_POLL_US 100000

enum SnakeDirection {
    SnakeDirUp = 0,
    SnakeDirDown = 1,
    SnakeDirLeft = 2,
    SnakeDirRight = 3,
    SnakeDirCount = 4,
};

enum SnakeCellType {
    SnakeCellEmpty = 0,
    SnakeCellWall = 1,
    SnakeCellObstacle = 2,
};

enum SnakeMsgType {
    SnakeMsgMove = 1,
    SnakeMsgState = 2,
};

enum SnakeInputCode {
    SnakeInputNone = -1,
    SnakeInputPause = -2,
    SnakeInputQuit = -3,
    SnakeInputRestart = -4,
};

#pragma pack(push, 1)
typedef struct {
    uint16_t x;
    uint16_t y;
} SnakeSegment;

typedef struct {
    uint8_t msgType;
    uint8_t direction;
} SnakeMoveMsg;

typedef struct {
    uint8_t msgType;
    uint32_t seqNum;
    uint8_t lives;
    uint32_t score;
    uint8_t speedLevel;
    uint16_t snakeLength;
    uint8_t gameOver;
} SnakeStateMsg;
#pragma pack(pop)

#endif
