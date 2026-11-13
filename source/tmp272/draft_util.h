/* util.h -- misc utility functions
 *
 * Copyright (C) 2021 fgsfds, Andy Nguyen
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#ifndef __UTIL_H__
#define __UTIL_H__

#include <stdint.h>

int debugPrintf(char *text, ...);

/* #270: lock-free gtid record (see util.c). Writes one line per call
 * to sdmc:/switch/aota/gtid.log; raw open/write, no g_log_lock.
 * #272: each line also carries the caller's tpidrro_el0 (tp=), the true
 * per-thread identity -- TLS[0x1e4] (gtid) is a process-global. */
void gtid270_log(const char *tag, uintptr_t id, unsigned gtid);

/* #272: lock-free lock-wait record, same file/fd as gtid270_log.
 * One line per contended wait: mutex, holder gtid, waiter tpidrro,
 * holder tpidrro (0 = mutex not in the holder table). */
void lock272_log_wait(uintptr_t mutex, unsigned holder_gtid, uintptr_t waiter_tp, uintptr_t holder_tp);

void cpu_boost(int on);

// libff4.so reads its stack-protector canary from tpidr_el0 + 0x28.

int ret0(void);
int retm1(void);

/* Point TPIDR_EL0 at a zeroed per-thread block so the engine's stack-protector
 * prologues (which read the canary from TPIDR_EL0+0x28) have a valid, stable
 * bionic TLS. `buf` must outlive the thread. libnx keeps its own thread state in
 * TPIDR_RO_EL0, so commandeering TPIDR_EL0 is safe. EACH THREAD NEEDS ITS OWN
 * BLOCK -- sharing one corrupts the guard slot across threads. */
#define BIONIC_TLS_SIZE 0x400
#define BIONIC_TLS_TP_OFFSET 0x200   /* tp points into the block: headroom for any negative bionic TLS slots */
void install_bionic_tls(void *buf);

static inline void* armGetTlsRw(void) {
  void* ret;
  __asm__ ("mrs %x[data], s3_3_c13_c0_2" : [data] "=r" (ret));
  return ret;
}

static inline void armSetTlsRw(void *addr) {
  __asm__  ("msr s3_3_c13_c0_2, %0" : : "r"(addr));
}

static inline uint64_t umin(uint64_t a, uint64_t b) {
  return (a < b) ? a : b;
}

#endif
