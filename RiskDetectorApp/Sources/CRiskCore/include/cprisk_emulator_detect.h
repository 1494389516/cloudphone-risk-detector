#ifndef CPRISK_EMULATOR_DETECT_H
#define CPRISK_EMULATOR_DETECT_H

/*
 * cprisk_emulator_detect.h
 * CRiskCore
 *
 * C-layer emulator / unidbg detection.
 *
 * ## Why C-layer?
 * Swift-layer detectors (EmulatorLayoutDetector, EmulatorBehaviorDetector) only
 * execute when the caller enters through the Swift call stack.  Attackers using
 * unidbg commonly call specific exported C functions directly, bypassing Swift
 * entirely.  This module runs at the C level and is called from the VM
 * interpreter's init path, so it executes regardless of entry point.
 *
 * ## Design
 * `cprisk_emulator_probe()` returns a bitmask of detected anomalies.  Each bit
 * corresponds to one structural or behavioural invariant that holds on real iOS
 * but is violated or absent in a unidbg-on-Linux environment.
 *
 * The probe is cheap (< 2 ms) and is called once per VM execution frame.  The
 * result is stored in `cprisk_vm_interp_frame_t.emulator_flags` and fed into
 * the VM hardening integrity chain — a high score poisons the chain and taints
 * the final VM output, making the risk-detection result unreliable for the
 * attacker without triggering a visible crash.
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Anomaly flag bits ───────────────────────────────────────────────────── */

/** dyld shared cache absent (unidbg Linux has no dyld shared cache). */
#define CPRISK_EMU_FLAG_DYLD_CACHE_ABSENT   (1u << 0)

/** Fewer than 40 vm_region_64 regions (unidbg synthesises a sparse map). */
#define CPRISK_EMU_FLAG_LOW_VM_REGIONS      (1u << 1)

/** Main-thread stack pointer below 0x0001_0000_0000 (iOS always above). */
#define CPRISK_EMU_FLAG_LOW_STACK_ADDR      (1u << 2)

/** kern.ostype sysctl does not return "Darwin" (Linux or query failure). */
#define CPRISK_EMU_FLAG_OSTYPE_NOT_DARWIN   (1u << 3)

/** Fewer than 4 Mach threads (unidbg harness typically spawns 1–3). */
#define CPRISK_EMU_FLAG_LOW_THREAD_COUNT    (1u << 4)

/** A JVM indicator env var is set (JAVA_HOME, CLASSPATH, etc.). */
#define CPRISK_EMU_FLAG_JVM_ENV_VAR         (1u << 5)

/** mach_timebase_info returns 1:1 AND dyld shared cache is absent. */
#define CPRISK_EMU_FLAG_TIMEBASE_FLAT       (1u << 6)

/** CLOCK_PROCESS_CPUTIME_ID does not advance over a busy loop. */
#define CPRISK_EMU_FLAG_CPU_CLOCK_FROZEN    (1u << 7)

/** VM sync barrier: watchdog thread appears not running. */
#define CPRISK_EMU_FLAG_WATCHDOG_STUCK      (1u << 8)

/* ── API ─────────────────────────────────────────────────────────────────── */

/**
 * Run all emulator detection probes and return a bitmask of anomaly flags.
 *
 * Thread-safe; does not allocate.  First call may take up to ~2 ms (CPU-clock
 * probe).  Subsequent calls within the same process are fast (< 50 µs) due to
 * a cached result.
 *
 * @returns Bitmask of CPRISK_EMU_FLAG_* bits for each detected anomaly.
 */
uint32_t cprisk_emulator_probe(void);

/**
 * Convert an anomaly flags bitmask into a weighted integer score (0–100).
 * Weights mirror those in the Swift-layer detectors.
 */
int cprisk_emulator_score(uint32_t flags);

/**
 * Returns non-zero if the emulator score exceeds the threshold at which the
 * VM hardening integrity chain should be poisoned.
 */
int cprisk_emulator_is_hostile(uint32_t flags);

#ifdef __cplusplus
}
#endif

#endif /* CPRISK_EMULATOR_DETECT_H */
