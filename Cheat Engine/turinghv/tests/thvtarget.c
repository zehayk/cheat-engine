/* A process with known memory, for testing Cheat Engine's Turing-HV backend.
 * Writes its layout to thvtarget.info (key=value) and reports writes to its mailbox in thvtarget.log. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

typedef struct {
    char marker[16];          /* "THVTEST!MARKER!" */
    volatile int32_t fixed;   /* 123456 */
    volatile int32_t counter; /* increments every 50 ms (a writer for the write watch) */
    volatile int32_t mailbox; /* the test writes 777 here */
    volatile double  health;  /* 100.0 */
    void *self;               /* pointer to this block (pointer test) */
} block_t;

static block_t g_static = { "STATICMARKER!!!", 424242, 0, 0, 55.5, 0 };

static void bump(volatile int32_t *p) { (*p)++; }   /* the writing instruction lives here */

int main(int argc, char **argv) {
    const char *dir = argc > 1 ? argv[1] : ".";
    block_t *b = (block_t *)VirtualAlloc(NULL, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    memcpy(b->marker, "THVTEST!MARKER!", 16);
    b->fixed = 123456; b->counter = 0; b->mailbox = 0; b->health = 100.0; b->self = b;
    g_static.self = &g_static;

    char path[MAX_PATH];
    snprintf(path, sizeof path, "%s\\thvtarget.info", dir);
    FILE *f = fopen(path, "w");
    fprintf(f, "pid=%lu\nblock=%llu\nfixed=%llu\ncounter=%llu\nmailbox=%llu\nhealth=%llu\nstatic=%llu\nbump=%llu\n"
               "base=%llu\nvirtualalloc=%llu\n",
            GetCurrentProcessId(), (unsigned long long)(uintptr_t)b, (unsigned long long)(uintptr_t)&b->fixed,
            (unsigned long long)(uintptr_t)&b->counter, (unsigned long long)(uintptr_t)&b->mailbox,
            (unsigned long long)(uintptr_t)&b->health, (unsigned long long)(uintptr_t)&g_static,
            (unsigned long long)(uintptr_t)&bump, (unsigned long long)(uintptr_t)GetModuleHandleW(NULL),
            (unsigned long long)(uintptr_t)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "VirtualAlloc"));
    fclose(f);

    snprintf(path, sizeof path, "%s\\thvtarget.log", dir);
    int32_t last = 0;
    for (int i = 0; i < 20 * 60 * 10; i++) {    /* up to 10 minutes */
        bump(&b->counter);
        if (b->mailbox != last) {
            last = b->mailbox;
            FILE *l = fopen(path, "a");
            if (l) { fprintf(l, "mailbox=%d\n", last); fclose(l); }
        }
        Sleep(50);
    }
    return 0;
}
