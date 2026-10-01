#include "differential.h"
#include <stddef.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#define DECLARE(P) uint64_t P##cprisk_gf2_xorshift64(uint64_t); \
    uint64_t P##cprisk_gf2_fnv1a(const uint8_t *, size_t);
DECLARE(plain_)
DECLARE(protected_)
static uint64_t next_u64(uint64_t *seed) {
    *seed ^= *seed << 13; *seed ^= *seed >> 7; *seed ^= *seed << 17;
    return *seed;
}
#define CHECK(c) do { if (!(c)) { result->failure_line = __LINE__; return 1; } } while (0)
#define KAT(c) do { CHECK(c); ++result->known_answer_checks; } while (0)
int cprisk_ios_differential(uint64_t seed, CPRiskDifferentialResult *result) {
    memset(result, 0, sizeof(*result)); result->seed = seed;
    const uint64_t edges[] = {0, 1, UINT64_MAX, UINT64_C(0x8000000000000000),
        UINT64_C(0x7fffffffffffffff), UINT64_C(0xaaaaaaaaaaaaaaaa)};
    uint8_t data[258], before[258];
    KAT(plain_cprisk_gf2_xorshift64(0) == 0);
    KAT(protected_cprisk_gf2_xorshift64(0) == 0);
    KAT(plain_cprisk_gf2_xorshift64(1) == UINT64_C(1082269761));
    KAT(protected_cprisk_gf2_xorshift64(1) == UINT64_C(1082269761));
    KAT(plain_cprisk_gf2_fnv1a(NULL, 0) == UINT64_C(0xcbf29ce484222325));
    KAT(protected_cprisk_gf2_fnv1a(NULL, 0) == UINT64_C(0xcbf29ce484222325));
    KAT(plain_cprisk_gf2_fnv1a((const uint8_t *)"hello", 5) == UINT64_C(0xa430d84680aabd0b));
    KAT(protected_cprisk_gf2_fnv1a((const uint8_t *)"hello", 5) == UINT64_C(0xa430d84680aabd0b));
    for (unsigned i = 0; i < 4096; ++i) {
        uint64_t x = i < 6 ? edges[i] : next_u64(&seed);
        CHECK(plain_cprisk_gf2_xorshift64(x) == protected_cprisk_gf2_xorshift64(x));
        for (unsigned j = 0; j < sizeof(data); ++j) data[j] = (uint8_t)next_u64(&seed);
        if (i < 2) memset(data, i ? 255 : 0, sizeof(data));
        memcpy(before, data, sizeof(data));
        CHECK(plain_cprisk_gf2_fnv1a(data + 1, i % 257) == protected_cprisk_gf2_fnv1a(data + 1, i % 257));
        CHECK(memcmp(data, before, sizeof(data)) == 0);
        ++result->cases;
    }
    return 0;
}

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    unsigned ready;
    int released;
} StartGate;
typedef struct {
    StartGate *gate;
    CPRiskDifferentialResult *result;
    int *status;
    uint64_t seed;
} Worker;
/* A synchronization failure cannot safely return stack-owned worker state. */
static void require_sync(int error) { if (error) abort(); }
static void *run_worker(void *context) {
    Worker *worker = context;
    StartGate *gate = worker->gate;
    require_sync(pthread_mutex_lock(&gate->mutex));
    ++gate->ready;
    require_sync(pthread_cond_broadcast(&gate->condition));
    while (!gate->released) require_sync(pthread_cond_wait(&gate->condition, &gate->mutex));
    require_sync(pthread_mutex_unlock(&gate->mutex));
    *worker->status = cprisk_ios_differential(worker->seed, worker->result);
    return NULL;
}
int cprisk_ios_differential_suite(CPRiskDifferentialSuiteResult *result) {
    memset(result, 0, sizeof(*result));
    const uint64_t seed = UINT64_C(0x783cb86db73074ac);
    result->serial_status = cprisk_ios_differential(seed, &result->serial);
    StartGate gate = {0};
    require_sync(pthread_mutex_init(&gate.mutex, NULL));
    require_sync(pthread_cond_init(&gate.condition, NULL));
    Worker workers[4]; pthread_t threads[4]; unsigned created = 0;
    for (unsigned i = 0; i < 4; ++i) {
        workers[i] = (Worker){&gate, &result->concurrent[i], &result->concurrent_status[i],
                             seed ^ ((uint64_t)(i + 1) << 32)};
        int error = pthread_create(&threads[i], NULL, run_worker, &workers[i]);
        if (error) { result->thread_error = error; break; }
        ++created;
    }
    require_sync(pthread_mutex_lock(&gate.mutex));
    while (gate.ready < created) require_sync(pthread_cond_wait(&gate.condition, &gate.mutex));
    result->workers_ready = gate.ready;
    gate.released = 1;
    require_sync(pthread_cond_broadcast(&gate.condition));
    require_sync(pthread_mutex_unlock(&gate.mutex));
    for (unsigned i = 0; i < created; ++i) require_sync(pthread_join(threads[i], NULL));
    require_sync(pthread_cond_destroy(&gate.condition));
    require_sync(pthread_mutex_destroy(&gate.mutex));
    int failed = result->serial_status != 0 || created != 4 || result->thread_error != 0;
    for (unsigned i = 0; i < created; ++i) failed |= result->concurrent_status[i] != 0;
    return failed;
}
