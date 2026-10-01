#ifndef CPRISK_IOS_DIFFERENTIAL_H
#define CPRISK_IOS_DIFFERENTIAL_H
#include <stdint.h>
typedef struct {
    unsigned cases, known_answer_checks, failure_line;
    uint64_t seed;
} CPRiskDifferentialResult;
/* All RNG/input/result state belongs to this invocation, including under concurrency. */
int cprisk_ios_differential(uint64_t seed, CPRiskDifferentialResult *result);
typedef struct {
    CPRiskDifferentialResult serial, concurrent[4];
    int serial_status, concurrent_status[4], thread_error;
    unsigned workers_ready;
} CPRiskDifferentialSuiteResult;
/* Four workers wait at a shared start gate before running independent invocations. */
int cprisk_ios_differential_suite(CPRiskDifferentialSuiteResult *result);
#endif
