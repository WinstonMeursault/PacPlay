#ifndef SNAKE_CLIENT_H
#define SNAKE_CLIENT_H

#include "snake_common.h"
#include <stdbool.h>

typedef struct {
    SnakeSegment body[SNAKE_MAX_LENGTH];
    uint16_t length;
    uint8_t direction;
    uint8_t nextDirection;
    uint8_t mapData[SNAKE_MAP_CELLS];
    SnakeSegment food;
    uint32_t score;
    uint8_t lives;
    uint8_t speedLevel;
    uint32_t tickMs;
    uint32_t seqNum;
    bool paused;
    bool gameOver;
    bool quit;
    uint16_t foodEaten;
} SnakeClient;

void snakeClientInit(SnakeClient *cli);
void snakeClientGenerateFood(SnakeClient *cli);
bool snakeClientTick(SnakeClient *cli);
void snakeClientRespawn(SnakeClient *cli);
void snakeClientRender(const SnakeClient *cli);
void snakeClientTermInit(void);
void snakeClientTermRestore(void);
int snakeClientReadInput(void);

#endif
