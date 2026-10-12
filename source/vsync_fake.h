#ifndef VSYNC_FAKE_H
#define VSYNC_FAKE_H

#include <stdint.h>
#include <stdbool.h>

/* Bind the vsync counter address (called when vsync mutex is detected) */
void vsync_bind_counter(uintptr_t mutex_addr);

/* Start/stop the vsync bumping thread */
void vsync_start(void);
void vsync_stop(void);

/* Get the bound counter (for debugging) */
volatile uint64_t *vsync_get_counter(void);

#endif /* VSYNC_FAKE_H */
