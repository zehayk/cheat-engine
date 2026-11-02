/* A process shaped like a game, for measuring Cheat Engine's Turing-HV backend:
 *   - 8000 allocations of 128 KiB, every page touched, protections alternating RW / R, so the page tables hold
 *     ~8000 distinct regions (a big game's memory map is this fragmented);
 *   - one BUSY page: 63 dwords rewritten all the time, and one dword ("rare") written only once every 1000 rounds --
 *     the case a page-granular one-shot write watch keeps missing;
 *   - one dword ("readme") that is only ever READ (once every 1000 rounds), for an access watch.
 * Writes its layout to thvbig.info (key=value). */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

#define NALLOC 8000
#define ASIZE  (128u * 1024u)

static void bump_busy(volatile int32_t *p, int k) { p[k]++; }          /* the frequent writers */
static void bump_rare(volatile int32_t *p) { (*p) += 3; }              /* the rare writer: what a watch must find */
static int32_t read_rare(const volatile int32_t *p) { return *p; }     /* the rare reader */

int main(int argc, char **argv) {
    const char *dir = argc > 1 ? argv[1] : ".";
    for (int i = 0; i < NALLOC; i++) {
        uint8_t *m = (uint8_t *)VirtualAlloc(NULL, ASIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!m) break;
        for (uint32_t o = 0; o < ASIZE; o += 4096) m[o] = (uint8_t)i;
        DWORD old;
        if (i & 1) VirtualProtect(m, ASIZE, PAGE_READONLY, &old);
    }
    volatile int32_t *busy = (volatile int32_t *)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    volatile int32_t *rare = busy + 40;      /* the 41st dword of the busy page */
    volatile int32_t *readme = busy + 80;    /* only read */
    *readme = 4242;

    char path[MAX_PATH];
    snprintf(path, sizeof path, "%s\\thvbig.info", dir);
    FILE *f = fopen(path, "w");
    fprintf(f, "pid=%lu\nbusy=%llu\nrare=%llu\nreadme=%llu\nbumprare=%llu\nreadrare=%llu\n", GetCurrentProcessId(),
            (unsigned long long)(uintptr_t)busy, (unsigned long long)(uintptr_t)rare,
            (unsigned long long)(uintptr_t)readme, (unsigned long long)(uintptr_t)&bump_rare,
            (unsigned long long)(uintptr_t)&read_rare);
    fclose(f);

    volatile int32_t sink = 0;
    for (uint64_t round = 0; round < 600000000ull; round++) {   /* minutes, then exit on its own */
        for (int k = 0; k < 64; k++) if (k != 40 && k != 80) bump_busy(busy, k);
        if (round % 1000 == 0) { bump_rare(rare); sink += read_rare(readme); }
        if (round % 5000 == 0) Sleep(1);
    }
    return (int)sink;
}
