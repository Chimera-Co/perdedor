/*
 * cpuid_rdtsc -- tiny helper exposing two x86-only primitives to the Python
 * Linux agent, which cannot reach CPUID/RDTSC from pure Python:
 *
 *   cpuid_rdtsc cpuid <leaf_hex> <subleaf_hex>
 *       prints "eax=0x.. ebx=0x.. ecx=0x.. edx=0x.." for the given leaf.
 *
 *   cpuid_rdtsc rdtsc_jitter <iterations>
 *       times <iterations> RDTSC-around-CPUID round trips (CPUID always
 *       forces a VM exit under KVM) and prints min/median/mean/max cycle
 *       deltas -- the same class of measurement PAfish uses to detect
 *       virtualization (see CHIMERA KVM report, Section 5.5).
 *
 * On non-x86 hosts (e.g. an ARM64 analysis workstation) neither primitive
 * exists, so the binary still builds and runs but exits 2 with a clear
 * message; the Python agent treats exit code 2 as "skipped: not
 * applicable on this architecture" rather than a probe failure.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ERR_USAGE 1
#define ERR_NOT_X86 2

#if defined(__x86_64__) || defined(__i386__)

#include <stdint.h>

static void cpuid(uint32_t leaf, uint32_t subleaf, uint32_t out[4]) {
    __asm__ volatile("cpuid"
                      : "=a"(out[0]), "=b"(out[1]), "=c"(out[2]), "=d"(out[3])
                      : "a"(leaf), "c"(subleaf));
}

static uint64_t rdtsc_now(void) {
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static int cmd_cpuid(int argc, char **argv) {
    if (argc != 4) return ERR_USAGE;
    uint32_t leaf = (uint32_t)strtoul(argv[2], NULL, 0);
    uint32_t subleaf = (uint32_t)strtoul(argv[3], NULL, 0);
    uint32_t out[4] = {0};
    cpuid(leaf, subleaf, out);
    printf("eax=0x%08x ebx=0x%08x ecx=0x%08x edx=0x%08x\n", out[0], out[1], out[2], out[3]);
    return 0;
}

static int cmd_rdtsc_jitter(int argc, char **argv) {
    if (argc != 3) return ERR_USAGE;
    long n = strtol(argv[2], NULL, 10);
    if (n < 1) n = 1;
    if (n > 1000000) n = 1000000;

    uint64_t *deltas = malloc((size_t)n * sizeof(uint64_t));
    if (!deltas) return ERR_USAGE;

    uint32_t junk[4];
    for (long i = 0; i < n; i++) {
        uint64_t t0 = rdtsc_now();
        cpuid(0, 0, junk); /* leaf 0: always forces a VM exit under KVM */
        uint64_t t1 = rdtsc_now();
        deltas[i] = t1 - t0;
    }

    qsort(deltas, (size_t)n, sizeof(uint64_t), cmp_u64);
    uint64_t min = deltas[0];
    uint64_t max = deltas[n - 1];
    uint64_t median = deltas[n / 2];
    double sum = 0;
    for (long i = 0; i < n; i++) sum += (double)deltas[i];
    double mean = sum / (double)n;

    printf("min=%llu median=%llu mean=%.2f max=%llu n=%ld\n",
           (unsigned long long)min, (unsigned long long)median, mean,
           (unsigned long long)max, n);
    free(deltas);
    return 0;
}

#else /* not x86 */

static int cmd_cpuid(int argc, char **argv) {
    (void)argc;
    (void)argv;
    fprintf(stderr, "cpuid_rdtsc: CPUID is not available on this architecture\n");
    return ERR_NOT_X86;
}

static int cmd_rdtsc_jitter(int argc, char **argv) {
    (void)argc;
    (void)argv;
    fprintf(stderr, "cpuid_rdtsc: RDTSC is not available on this architecture\n");
    return ERR_NOT_X86;
}

#endif

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s cpuid <leaf_hex> <subleaf_hex> | rdtsc_jitter <iterations>\n", argv[0]);
        return ERR_USAGE;
    }
    if (strcmp(argv[1], "cpuid") == 0) return cmd_cpuid(argc, argv);
    if (strcmp(argv[1], "rdtsc_jitter") == 0) return cmd_rdtsc_jitter(argc, argv);
    fprintf(stderr, "unknown command: %s\n", argv[1]);
    return ERR_USAGE;
}
