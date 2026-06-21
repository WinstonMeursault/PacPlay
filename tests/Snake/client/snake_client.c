#include "snake_client.h"
#include "pacplay_sdk.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define SNAKE_OBS_SIZE 2
#define SNAKE_OBS_OFFSET 5
#define SNAKE_OBS_MARGIN 7

static const int dirDx[SnakeDirCount] = {0, 0, -1, 1};
static const int dirDy[SnakeDirCount] = {-1, 1, 0, 0};

static struct termios gOrigTermios;
static bool gTermReady;

static int snakeDirDx(int dir) { return dirDx[dir]; }

static int snakeDirDy(int dir) { return dirDy[dir]; }

static bool snakeIsOpposite(int d1, int d2) {
    if (d1 == SnakeDirUp && d2 == SnakeDirDown)
        return true;
    if (d1 == SnakeDirDown && d2 == SnakeDirUp)
        return true;
    if (d1 == SnakeDirLeft && d2 == SnakeDirRight)
        return true;
    if (d1 == SnakeDirRight && d2 == SnakeDirLeft)
        return true;
    return false;
}

static int snakeWrapX(int x) {
    int w = SNAKE_MAP_WIDTH;
    return (x % w + w) % w;
}

static int snakeWrapY(int y) {
    int h = SNAKE_MAP_HEIGHT;
    return (y % h + h) % h;
}

static void snakeClientPlaceObstacles(SnakeClient *cli) {
    int x1;
    int y1;
    int x2;
    int y2;
    int dx;
    int dy;
    int w = SNAKE_MAP_WIDTH;
    int h = SNAKE_MAP_HEIGHT;

    x1 = SNAKE_OBS_OFFSET;
    y1 = SNAKE_OBS_OFFSET;
    for (dy = 0; dy < SNAKE_OBS_SIZE; dy++) {
        for (dx = 0; dx < SNAKE_OBS_SIZE; dx++) {
            cli->mapData[(y1 + dy) * w + (x1 + dx)] = SnakeCellObstacle;
        }
    }

    x2 = w - SNAKE_OBS_MARGIN;
    y2 = SNAKE_OBS_OFFSET;
    for (dy = 0; dy < SNAKE_OBS_SIZE; dy++) {
        for (dx = 0; dx < SNAKE_OBS_SIZE; dx++) {
            cli->mapData[(y2 + dy) * w + (x2 + dx)] = SnakeCellObstacle;
        }
    }

    x1 = SNAKE_OBS_OFFSET;
    y1 = h - SNAKE_OBS_MARGIN;
    for (dy = 0; dy < SNAKE_OBS_SIZE; dy++) {
        for (dx = 0; dx < SNAKE_OBS_SIZE; dx++) {
            cli->mapData[(y1 + dy) * w + (x1 + dx)] = SnakeCellObstacle;
        }
    }

    x2 = w - SNAKE_OBS_MARGIN;
    y2 = h - SNAKE_OBS_MARGIN;
    for (dy = 0; dy < SNAKE_OBS_SIZE; dy++) {
        for (dx = 0; dx < SNAKE_OBS_SIZE; dx++) {
            cli->mapData[(y2 + dy) * w + (x2 + dx)] = SnakeCellObstacle;
        }
    }
}

void snakeClientInit(SnakeClient *cli) {
    int x;
    int y;
    int w = SNAKE_MAP_WIDTH;
    int h = SNAKE_MAP_HEIGHT;
    int headX;
    int headY;
    uint16_t i;

    memset(cli, 0, sizeof(*cli));

    for (y = 0; y < h; y++) {
        for (x = 0; x < w; x++) {
            if (x == 0 || x == w - 1 || y == 0 || y == h - 1) {
                cli->mapData[y * w + x] = SnakeCellWall;
            } else {
                cli->mapData[y * w + x] = SnakeCellEmpty;
            }
        }
    }

    snakeClientPlaceObstacles(cli);

    headX = w / 2;
    headY = h / 2;
    cli->direction = (uint8_t)SnakeDirRight;
    cli->nextDirection = (uint8_t)SnakeDirRight;
    cli->length = SNAKE_INITIAL_LENGTH;

    for (i = 0; i < cli->length; i++) {
        cli->body[i].x = (uint16_t)(headX - (int)i);
        cli->body[i].y = (uint16_t)headY;
    }

    cli->score = 0;
    cli->lives = SNAKE_INITIAL_LIVES;
    cli->speedLevel = 0;
    cli->tickMs = SNAKE_INITIAL_TICK_MS;
    cli->paused = false;
    cli->gameOver = false;
    cli->quit = false;
    cli->foodEaten = 0;
    cli->seqNum = 0;

    snakeClientGenerateFood(cli);
}

void snakeClientGenerateFood(SnakeClient *cli) {
    const int maxAttempts = SNAKE_MAP_CELLS * 2;
    int attempts;
    int w = SNAKE_MAP_WIDTH;
    int h = SNAKE_MAP_HEIGHT;

    for (attempts = 0; attempts < maxAttempts; attempts++) {
        uint16_t fx = (uint16_t)(rand() % w);
        uint16_t fy = (uint16_t)(rand() % h);
        uint8_t cell = cli->mapData[fy * w + fx];

        if (cell == SnakeCellWall || cell == SnakeCellObstacle) {
            continue;
        }

        bool onSnake = false;
        uint16_t i;
        for (i = 0; i < cli->length; i++) {
            if (cli->body[i].x == fx && cli->body[i].y == fy) {
                onSnake = true;
                break;
            }
        }

        if (!onSnake) {
            cli->food.x = fx;
            cli->food.y = fy;
            return;
        }
    }
}

bool snakeClientTick(SnakeClient *cli) {
    int w = SNAKE_MAP_WIDTH;
    int nx;
    int ny;
    uint8_t cell;
    bool eating;
    uint16_t i;
    uint16_t checkEnd;

    cli->direction = cli->nextDirection;

    nx = snakeWrapX((int)cli->body[0].x + snakeDirDx((int)cli->direction));
    ny = snakeWrapY((int)cli->body[0].y + snakeDirDy((int)cli->direction));

    cell = cli->mapData[ny * w + nx];
    if (cell == SnakeCellWall || cell == SnakeCellObstacle) {
        return false;
    }

    eating = (nx == (int)cli->food.x && ny == (int)cli->food.y);

    /* Self-collision: if eating, check all segments (tail stays).
     * If not eating, exclude tail (it will move away). */
    checkEnd = eating ? cli->length : (uint16_t)(cli->length - 1);
    for (i = 0; i < checkEnd; i++) {
        if ((int)cli->body[i].x == nx && (int)cli->body[i].y == ny) {
            return false;
        }
    }

    /* Shift body right by 1, then place new head. */
    for (i = cli->length; i > 0; i--) {
        cli->body[i] = cli->body[i - 1];
    }
    cli->body[0].x = (uint16_t)nx;
    cli->body[0].y = (uint16_t)ny;

    if (eating) {
        cli->length++;
        cli->score += SNAKE_FOOD_SCORE;
        cli->foodEaten++;

        snakeClientGenerateFood(cli);

        if ((cli->foodEaten % SNAKE_FOOD_PER_SPEEDUP) == 0 &&
            cli->tickMs > SNAKE_MIN_TICK_MS) {
            cli->tickMs -= SNAKE_TICK_DECREASE_MS;
            cli->speedLevel++;
        }
    }

    cli->seqNum++;
    return true;
}

void snakeClientRespawn(SnakeClient *cli) {
    int headX = SNAKE_MAP_WIDTH / 2;
    int headY = SNAKE_MAP_HEIGHT / 2;
    uint16_t i;

    cli->direction = (uint8_t)SnakeDirRight;
    cli->nextDirection = (uint8_t)SnakeDirRight;
    cli->length = SNAKE_INITIAL_LENGTH;

    for (i = 0; i < cli->length; i++) {
        cli->body[i].x = (uint16_t)(headX - (int)i);
        cli->body[i].y = (uint16_t)headY;
    }
}

void snakeClientRender(const SnakeClient *cli) {
    char display[SNAKE_MAP_CELLS];
    int x;
    int y;
    int w = SNAKE_MAP_WIDTH;
    int h = SNAKE_MAP_HEIGHT;

    for (y = 0; y < h; y++) {
        for (x = 0; x < w; x++) {
            uint8_t cell = cli->mapData[y * w + x];
            display[y * w + x] =
                (cell == SnakeCellWall || cell == SnakeCellObstacle) ? '#'
                                                                     : ' ';
        }
    }

    display[cli->food.y * w + cli->food.x] = '*';

    {
        int idx;
        for (idx = (int)cli->length - 1; idx >= 0; idx--) {
            int sx = (int)cli->body[idx].x;
            int sy = (int)cli->body[idx].y;
            display[sy * w + sx] = (idx == 0) ? 'O' : 'o';
        }
    }

    fputs("\033[H", stdout);

    for (y = 0; y < h; y++) {
        for (x = 0; x < w; x++) {
            char c = display[y * w + x];
            switch (c) {
            case 'O':
                fputs("\033[1;32m", stdout);
                putchar('O');
                fputs("\033[0m", stdout);
                break;
            case 'o':
                fputs("\033[32m", stdout);
                putchar('o');
                fputs("\033[0m", stdout);
                break;
            case '*':
                fputs("\033[31m", stdout);
                putchar('*');
                fputs("\033[0m", stdout);
                break;
            case '#':
                fputs("\033[37m", stdout);
                putchar('#');
                fputs("\033[0m", stdout);
                break;
            default:
                putchar(' ');
                break;
            }
        }
        putchar('\n');
    }

    printf("Score: %u  Speed: Lv.%u  Lives: ", cli->score,
           (unsigned int)(cli->speedLevel + 1));
    {
        uint8_t lf;
        for (lf = 0; lf < cli->lives; lf++) {
            fputs("\033[31m♥\033[0m", stdout);
        }
    }
    printf("\n[WASD/Arrows: Move] [P: Pause] [Q: Quit]\n");

    if (cli->gameOver) {
        fputs(
            "\033[31m*** GAME OVER! Press R to restart, Q to quit ***\033[0m\n",
            stdout);
    } else if (cli->paused) {
        fputs("\033[33m*** PAUSED ***\033[0m\n", stdout);
    }

    fflush(stdout);
}

void snakeClientTermInit(void) {
    if (gTermReady)
        return;

    if (tcgetattr(STDIN_FILENO, &gOrigTermios) != 0)
        return;

    struct termios raw = gOrigTermios;
    raw.c_lflag &= (tcflag_t) ~(ICANON | ECHO);
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 0;

    if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) != 0)
        return;

    gTermReady = true;

    fputs("\033[2J\033[H", stdout);
    fflush(stdout);
}

void snakeClientTermRestore(void) {
    if (!gTermReady)
        return;
    tcsetattr(STDIN_FILENO, TCSANOW, &gOrigTermios);
    gTermReady = false;

    fputs("\033[2J\033[H", stdout);
    fflush(stdout);
}

int snakeClientReadInput(void) {
    char buf[4];
    ssize_t n;

    memset(buf, 0, sizeof(buf));
    n = read(STDIN_FILENO, buf, sizeof(buf));
    if (n <= 0)
        return SnakeInputNone;

    if (buf[0] == '\033') {
        if (n >= 3 && buf[1] == '[') {
            switch (buf[2]) {
            case 'A':
                return SnakeDirUp;
            case 'B':
                return SnakeDirDown;
            case 'C':
                return SnakeDirRight;
            case 'D':
                return SnakeDirLeft;
            default:
                return SnakeInputNone;
            }
        }
        return SnakeInputNone;
    }

    switch (buf[0]) {
    case 'w':
    case 'W':
        return SnakeDirUp;
    case 's':
    case 'S':
        return SnakeDirDown;
    case 'a':
    case 'A':
        return SnakeDirLeft;
    case 'd':
    case 'D':
        return SnakeDirRight;
    case 'p':
    case 'P':
        return SnakeInputPause;
    case 'q':
    case 'Q':
        return SnakeInputQuit;
    case 'r':
    case 'R':
        return SnakeInputRestart;
    default:
        return SnakeInputNone;
    }
}

void pacplayMain(void) {
    SnakeClient cli;
    PacPlaySDK *sdk;

    srand((unsigned int)time(NULL));
    snakeClientInit(&cli);

    sdk = pacplay_cli_create();
    if (sdk == NULL)
        return;

    snakeClientTermInit();

    while (!cli.quit) {
        pacplay_cli_poll(sdk);

        int input = snakeClientReadInput();
        if (input == SnakeInputQuit) {
            cli.quit = true;
            break;
        }
        if (input == SnakeInputPause) {
            cli.paused = !cli.paused;
        }
        if (input == SnakeInputRestart && cli.gameOver) {
            snakeClientInit(&cli);
        }
        if (input >= 0 && input < SnakeDirCount) {
            if (!snakeIsOpposite((int)cli.direction, input)) {
                cli.nextDirection = (uint8_t)input;
            }
        }

        if (!cli.paused && !cli.gameOver) {
            bool alive = snakeClientTick(&cli);
            if (!alive) {
                if (cli.lives > 1) {
                    cli.lives--;
                    snakeClientRespawn(&cli);
                } else {
                    cli.lives = 0;
                    cli.gameOver = true;
                }
            }

            SnakeStateMsg stateMsg;
            stateMsg.msgType = (uint8_t)SnakeMsgState;
            stateMsg.seqNum = cli.seqNum;
            stateMsg.lives = cli.lives;
            stateMsg.score = cli.score;
            stateMsg.speedLevel = cli.speedLevel;
            stateMsg.snakeLength = cli.length;
            stateMsg.gameOver = (uint8_t)(cli.gameOver ? 1 : 0);
            pacplay_cli_send(sdk, &stateMsg, sizeof(stateMsg));
        }

        snakeClientRender(&cli);
        struct timespec ts = {
            .tv_sec = cli.tickMs / SNAKE_MS_PER_SEC,
            .tv_nsec = (long)(cli.tickMs % SNAKE_MS_PER_SEC) * SNAKE_NS_PER_MS,
        };
        nanosleep(&ts, NULL);
    }

    snakeClientTermRestore();
    pacplay_cli_destroy(sdk);
}
