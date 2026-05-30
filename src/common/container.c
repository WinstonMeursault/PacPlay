/**
 * @file container.c
 * @brief Container data structures for PacPlay.
 *
 * @date 2026-05-30
 * @copyright GPLv3 License
 * @section LICENSE
 * PacPlay
 * Copyright (C) 2026 Winston Meursault & Kiraterin
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https: //www.gnu.org/licenses/>.
 */

#include "container.h"
#include "log.h"
#include <errno.h>
#include <string.h>

/**
 * @brief Generate the full implementation of a circular queue for type @c T.
 *
 * Must be called exactly once (in a single @c .c file) for each type
 * instantiated via @c QUEUE_DECLARE.  Provides the function bodies for
 * @c Init, @c Deinit, @c Front, @c Push, @c Pop, @c IsEmpty, and the
 * internal @c Reserve.
 *
 * @param T The element type (must match a prior @c QUEUE_DECLARE(T)).
 *
 * ### Implementation notes
 *
 * - @c Init uses @c QUEUE_DEFAULT_CAPACITY when @p capacity is @c 0.
 *   The caller must @c Deinit before calling @c Init again to avoid
 *   leaking the old buffer.
 * - @c Deinit is NULL-safe and double-call safe.  It does @b not free
 *   memory owned by individual elements.
 * - @c Reserve (static) doubles the buffer size when the queue is full.
 *   It atomically copies all elements from the old buffer to the new one,
 *   then frees the old buffer.  If allocation fails, the original queue
 *   state is fully restored (atomicity guarantee).
 *   Elements are **shallow-copied** via struct assignment — pointers
 *   inside elements are transferred, not duplicated or freed.
 * - @c Push writes the new element, advances @c tail, then tests for
 *   fullness (@c tail @c == @c head).  If full, @c Reserve is called.
 * - @c Pop advances @c head without returning or freeing the element.
 *   To retrieve the value, call @c Front first.
 */
#define QUEUE_IMPLEMENT(T)                                                     \
    /** @cond PRIVATE */                                                       \
    static ContainerRes queue##T##Reserve(Queue##T *self);                     \
    /** @endcond */                                                            \
    ContainerRes queue##T##Init(Queue##T *self, size_t capacity) {             \
        if (capacity == 0) {                                                   \
            capacity = QUEUE_DEFAULT_CAPACITY;                                 \
        }                                                                      \
        self->capacity = capacity;                                             \
        self->buf = malloc(sizeof(T) * self->capacity);                        \
        if (self->buf == NULL) {                                               \
            LOG_ERROR("Failed to allocate queue with type " #T ": %s (%d)",    \
                      strerror(errno), errno);                                 \
            return ContainerFail;                                              \
        }                                                                      \
        self->head = 0;                                                        \
        self->tail = 0;                                                        \
        return ContainerSucc;                                                  \
    }                                                                          \
    void queue##T##Deinit(Queue##T *self) {                                    \
        if (self == NULL) {                                                    \
            return;                                                            \
        }                                                                      \
        free(self->buf);                                                       \
        self->buf = NULL;                                                      \
    }                                                                          \
    /**                                                                        \
     * @brief Double the capacity of the queue and linearise its contents.     \
     *                                                                         \
     * Takes a snapshot of the current queue, allocates a new buffer of        \
     * @c 2*capacity slots, copies all elements from the old buffer in FIFO    \
     * order (head-to-tail), then frees the old buffer.  If allocation         \
     * fails, the original queue state is restored atomically.                 \
     *                                                                         \
     * @note Elements are copied via struct assignment (shallow copy).         \
     * @return @c ContainerSucc on success, @c ContainerFail on OOM.           \
     */                                                                        \
    static ContainerRes queue##T##Reserve(Queue##T *self) {                    \
        Queue##T before = *self;                                               \
        self->buf = malloc(sizeof(T) * self->capacity * 2);                    \
        if (self->buf == NULL) {                                               \
            LOG_ERROR("Failed to allocate queue with type " #T ": %s (%d)",    \
                      strerror(errno), errno);                                 \
            self->buf = before.buf;                                            \
            return ContainerFail;                                              \
        }                                                                      \
        self->capacity *= 2;                                                   \
        self->head = 0;                                                        \
        self->tail = 0;                                                        \
        do {                                                                   \
            self->buf[self->tail] = before.buf[before.head];                   \
            ++self->tail;                                                      \
            before.head = (before.head + 1) % before.capacity;                 \
        } while (before.head != before.tail);                                  \
        free(before.buf);                                                      \
        return ContainerSucc;                                                  \
    }                                                                          \
    ContainerRes queue##T##Front(                                              \
        Queue##T *self, T *result) { /*NOLINT(bugprone-macro-parentheses)*/    \
        if (!queue##T##IsEmpty(self)) {                                        \
            *result = self->buf[self->head];                                   \
            return ContainerSucc;                                              \
        }                                                                      \
        return ContainerFail;                                                  \
    }                                                                          \
    ContainerRes queue##T##Push(Queue##T *self, T data) {                      \
        self->buf[self->tail] = data;                                          \
        self->tail = (self->tail + 1) % self->capacity;                        \
        if (self->tail == self->head) {                                        \
            return queue##T##Reserve(self);                                    \
        }                                                                      \
        return ContainerSucc;                                                  \
    }                                                                          \
    ContainerRes queue##T##Pop(Queue##T *self) {                               \
        if (queue##T##IsEmpty(self)) {                                         \
            return ContainerFail;                                              \
        }                                                                      \
        self->head = (self->head + 1) % self->capacity;                        \
        return ContainerSucc;                                                  \
    }                                                                          \
    bool queue##T##IsEmpty(Queue##T *self) { return self->head == self->tail; }

QUEUE_IMPLEMENT(Packet)
