// KernelSnitch scan-cost microbenchmark. Mirrors the leak grid:
//   for coarse (1 GiB): for slab (outer): for candidate (inner):
//     validations x (collisions-1) futex bucket comparisons.
// No kernel access; runs as shell on the device.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <pthread.h>

#include "futex_hash.h"

namespace ks = ghostlock::kernelsnitch;

static constexpr uint64_t IDENTITY_START = 0xffffff8000000000ULL;
static constexpr uint64_t COARSE = 1ULL << 30;

struct Job {
    uint64_t start;
    uint64_t end;
    uint64_t inner;
    uint64_t outer;
    uint64_t validations;
    uint32_t collisions;
    uint32_t futex[8];
    uint64_t checksum;
};

static uint64_t now_ns() {
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL + static_cast<uint64_t>(ts.tv_nsec);
}

static void *worker(void *arg) {
    Job *job = static_cast<Job *>(arg);
    ks::FutexHashContext ctx{};
    ks::futex_hash_context_init(&ctx, ks::futex_hash_table_size_for(8));
    uint64_t sum = 0;
    for (uint64_t coarse = job->start; coarse < job->end; coarse += COARSE) {
        uint64_t coarse_end = coarse + COARSE;
        if (coarse_end > job->end) coarse_end = job->end;
        for (uint64_t slab = coarse; slab < coarse_end; slab += job->outer) {
            uint64_t slab_end = slab + job->outer;
            if (slab_end > coarse_end) slab_end = coarse_end;
            for (uint64_t candidate = slab; candidate < slab_end; candidate += job->inner) {
                for (uint64_t v = 0; v < job->validations; ++v) {
                    uint32_t first = ks::futex_hash_context_bucket(&ctx, job->futex[0], candidate);
                    for (uint32_t i = 1; i < job->collisions; ++i) {
                        sum += first == ks::futex_hash_context_bucket(&ctx, job->futex[i], candidate);
                    }
                }
            }
        }
    }
    job->checksum = sum;
    return nullptr;
}

int main(int argc, char **argv) {
    if (argc != 7) {
        std::fprintf(stderr,
                     "usage: %s <length_GiB> <inner> <outer> <validations> <threads> <collisions>\n",
                     argv[0]);
        return 2;
    }
    const uint64_t length = static_cast<uint64_t>(std::strtoull(argv[1], nullptr, 0)) << 30;
    const uint64_t inner = std::strtoull(argv[2], nullptr, 0);
    const uint64_t outer = std::strtoull(argv[3], nullptr, 0);
    const uint64_t validations = std::strtoull(argv[4], nullptr, 0);
    const uint64_t threads = std::strtoull(argv[5], nullptr, 0);
    const uint32_t collisions = static_cast<uint32_t>(std::strtoul(argv[6], nullptr, 0));
    if (!inner || !outer || !threads || collisions > 8) return 2;

    Job jobs[8]{};
    pthread_t tids[8]{};
    const uint64_t slice = length / threads;
    for (uint64_t i = 0; i < threads; ++i) {
        jobs[i].start = IDENTITY_START + i * slice;
        jobs[i].end = (i + 1 == threads) ? IDENTITY_START + length : IDENTITY_START + (i + 1) * slice;
        jobs[i].inner = inner;
        jobs[i].outer = outer;
        jobs[i].validations = validations;
        jobs[i].collisions = collisions;
        for (uint32_t k = 0; k < 8; ++k)
            jobs[i].futex[k] = static_cast<uint32_t>(0x7f0000000000ULL + 0x1000ULL * k);
    }
    const uint64_t t0 = now_ns();
    for (uint64_t i = 0; i < threads; ++i) pthread_create(&tids[i], nullptr, worker, &jobs[i]);
    for (uint64_t i = 0; i < threads; ++i) pthread_join(tids[i], nullptr);
    const uint64_t t1 = now_ns();

    uint64_t checksum = 0;
    for (uint64_t i = 0; i < threads; ++i) checksum += jobs[i].checksum;
    const double seconds = static_cast<double>(t1 - t0) / 1e9;
    const double candidates = static_cast<double>(length / inner);
    std::printf(
        "len=%lluGiB inner=%llu outer=%llu validations=%llu threads=%llu collisions=%u "
        "candidates=%.0f seconds=%.3f ns_per_candidate=%.2f checksum=%llu\n",
        static_cast<unsigned long long>(length >> 30), static_cast<unsigned long long>(inner),
        static_cast<unsigned long long>(outer), static_cast<unsigned long long>(validations),
        static_cast<unsigned long long>(threads), collisions, candidates, seconds,
        seconds * 1e9 / candidates, static_cast<unsigned long long>(checksum));
    return 0;
}
