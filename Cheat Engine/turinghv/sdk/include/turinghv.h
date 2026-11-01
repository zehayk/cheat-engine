/*
 * turinghv.h - stable user-mode SDK for turing-hv.
 *
 * This is the only turing-hv header an application should include.  The DLL
 * translates this public API to the private firmware ABI used by the matching
 * turinghv.efi build.  Existing v1 declarations are append-only: firmware ABI
 * changes must be handled inside turinghv.dll, not in applications.
 */
#ifndef TURINGHV_H
#define TURINGHV_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#  if defined(TURINGHV_BUILD)
#    define THV_API __declspec(dllexport)
#  elif !defined(TURINGHV_STATIC)
#    define THV_API __declspec(dllimport)
#  else
#    define THV_API
#  endif
#  define THV_CALL __cdecl
#else
#  define THV_API
#  define THV_CALL
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define THV_CLIENT_API_VERSION 0x00010007u   /* 1.1: batched transfers; 1.2: physical reads; 1.3: the caller gate;
                                                1.4: the operator's trusted programs; 1.5: trusted at once, a
                                                connection without a session, the boot recorder's hook sites;
                                                1.6: the write watch, enriched watch hits, recording now;
                                                1.7: the hypervisor's text log */
#define THV_CR3_SCAN_VALIDATORS 4u

/* Hypervisor statuses retain their firmware values.  Client-side failures use
 * the high bit so they can never collide with a firmware status. */
enum thv_status {
    THV_OK                    = 0,
    THV_E_BAD_POINTER         = 1,
    THV_E_BAD_COMMAND         = 2,
    THV_E_NOT_LIVE            = 3,
    THV_E_UNSUPPORTED         = 4,
    THV_E_NO_SPACE            = 5,
    THV_E_NOT_FOUND           = 6,
    THV_E_BAD_ARGUMENT        = 7,
    /* 1.3: the hypervisor's caller gate refused this process -- thv_get_access() says exactly why */
    THV_E_NO_SESSION          = 8,
    THV_E_NOT_ELEVATED        = 9,
    THV_E_NOT_TRUSTED         = 10,
    THV_E_NOT_CLEAN           = 11,
    THV_E_NO_CAPABILITY       = 12,
    THV_E_INTROSPECTION       = 13,
    THV_E_NOT_CONNECTED       = 0x80000001u,
    THV_E_VERSION_MISMATCH    = 0x80000002u,
    THV_E_OUT_OF_MEMORY       = 0x80000003u,
    THV_E_PARTIAL_TRANSFER    = 0x80000004u,
    THV_E_BAD_RESPONSE        = 0x80000005u,
    THV_E_ALREADY_CONNECTED   = 0x80000006u
};

enum thv_open_flags {
    THV_OPEN_DEFAULT     = 0,
    THV_OPEN_NO_DOORBELL = 1u << 0,
    THV_OPEN_NO_SESSION  = 1u << 1     /* 1.5: do not ask for a session (a program that only asks to be trusted, or
                                          reads the status: no refusal in the hypervisor's log) */
};

enum thv_intro_status {
    THV_INTRO_OK          = 0,
    THV_INTRO_ERR_NTBASE  = 1,
    THV_INTRO_ERR_SYSPROC = 2,
    THV_INTRO_ERR_MODLIST = 3,
    THV_INTRO_ERR_WALK    = 4
};

enum thv_cr3_method {
    THV_CR3_METHOD_SELF       = 1,
    THV_CR3_METHOD_SAMPLE     = 2,
    THV_CR3_METHOD_SWEEP      = 3,
    THV_CR3_METHOD_KPCR       = 4,
    THV_CR3_METHOD_INTROSPECT = 5,
    THV_CR3_METHOD_SIGNATURE  = 6,
    THV_CR3_METHOD_ACTIVE     = 7  /* thv_cr3_watch: the watch-only CR3-write window (rev145) */
};

#define THV_CR3_ACCEPT(method) (1u << (method))
#define THV_CR3_ACCEPT_ALL     0xFFFFFFFFu
#define THV_CR3_SCAN_NEED_NONZERO (1u << 0)

typedef struct thv_connection_info {
    uint32_t client_api_version;
    uint32_t hypervisor_abi_version;
    uint32_t doorbell_active;
    uint32_t reserved;
} thv_connection_info;

typedef struct thv_enum_info {
    uint32_t count;       /* records copied into the caller's array */
    uint32_t more;        /* more records exist after next_index */
    uint32_t status2;     /* enum thv_intro_status where applicable */
    uint32_t reserved;
    uint64_t next_index;  /* pass this as start_index to continue */
} thv_enum_info;

typedef struct thv_hypervisor_status {
    uint32_t abi_version;
    uint32_t hv_live;
    uint64_t exits_total;
    uint64_t exits_cpuid;
    uint64_t exits_other;
    uint64_t apic_base_live;
    uint32_t cpu_index;
    uint32_t ap_virt_armed;
    uint32_t ap_redirected;
    uint32_t ap_entered_c;
    uint32_t ap_svm_on;
    uint32_t ap_vmrun;
    uint32_t slat_ready;
    uint32_t slat_caps;
    uint32_t tsc_hiding;
    uint32_t cpuid_passthrough;
    uint64_t stealth_target;
    uint64_t uptime_tsc;        /* TSC ticks since go-live (BSP clock)          */
} thv_hypervisor_status;

typedef struct thv_intro_diagnostics {
    uint64_t idt_base;
    uint64_t idt0_handler;
    uint64_t lstar;
    uint64_t cr3_used;
    uint64_t nt_base;
    uint64_t nt_first8;
    uint64_t exp_first8;
    uint64_t name0_rva;
    uint64_t sysproc_addr;
    uint64_t sysproc;
    uint64_t mod_list;
    uint32_t e_lfanew;
    uint32_t opt_magic;
    uint32_t exp_rva;
    uint32_t exp_size;
    uint32_t n_names;
    uint32_t n_funcs;
    uint32_t size_of_image;
    char name0[40];
} thv_intro_diagnostics;

typedef struct thv_process {
    uint64_t eprocess;
    uint64_t dirbase;
    uint64_t pid;
    uint64_t ppid;
    uint32_t thread_count;
    uint32_t flags;
    char name[16];
} thv_process;

typedef struct thv_process_info {
    uint64_t eprocess;
    uint64_t dirbase;
    uint64_t pid;
    uint64_t ppid;
    uint64_t image_base;
    uint64_t image_size;
    char name[16];
} thv_process_info;

typedef struct thv_module {
    uint64_t base;
    uint64_t size;
    uint64_t entry;
    char name[40];
} thv_module;

typedef struct thv_thread {
    uint64_t ethread;
    uint64_t tid;
    uint64_t start_address;
    uint32_t state;
    uint32_t reserved;
} thv_thread;

enum thv_memory_flags {
    THV_MEMORY_READ  = 1u << 0,
    THV_MEMORY_WRITE = 1u << 1,
    THV_MEMORY_EXEC  = 1u << 2,
    THV_MEMORY_USER  = 1u << 3,
    THV_MEMORY_LARGE = 1u << 4
};

typedef struct thv_memory_region {
    uint64_t base;
    uint64_t size;
    uint32_t flags;
    uint32_t reserved;
} thv_memory_region;

typedef struct thv_physical_range {
    uint64_t base;
    uint64_t size;
} thv_physical_range;

typedef struct thv_cr3_query {
    uint32_t accept;
    uint32_t pid;
    uint8_t name[16];
} thv_cr3_query;

typedef struct thv_cr3_result {
    uint64_t cr3;
    uint64_t eprocess;
    uint32_t pid;
    uint32_t method;
    uint8_t name[16];
} thv_cr3_result;

/* rev145: the watch-only CR3-write window's report (thv_cr3_watch). */
#define THV_CR3_WATCH_MAX 32
typedef struct thv_cr3_watch_entry {
    uint64_t cr3;          /* the value written (no-flush bit 63 removed, PCID bits kept) */
    uint64_t count;        /* times the target's threads were switched in with it          */
} thv_cr3_watch_entry;

typedef struct thv_cr3_watch_result {
    uint64_t window_us;    /* how long every CR3 write was watched                         */
    uint64_t writes;       /* CR3 writes seen in that time, every process's                */
    uint64_t target;       /* the target's (the entries' counts plus overflow)             */
    uint64_t other;        /* another process's                                            */
    uint64_t unknown;      /* no TEB to tell by (kernel threads, foreign attaches)         */
    uint64_t overflow;     /* target writes whose value found no free entry                */
    uint32_t pid;
    uint32_t count;        /* entries used, the most frequent first                        */
    thv_cr3_watch_entry entries[THV_CR3_WATCH_MAX];
} thv_cr3_watch_result;

typedef struct thv_cr3_scan {
    uint64_t image_base;
    uint64_t validate[THV_CR3_SCAN_VALIDATORS];
    uint64_t resume_pa;
    uint64_t stride;
    uint64_t suffix;
    uint32_t budget;
    uint32_t flags;
} thv_cr3_scan;

typedef struct thv_cr3_scan_result {
    uint64_t cr3;
    uint64_t next_pa;
    uint64_t tested;
    uint64_t swept;
    uint32_t done;
    uint32_t reserved;
} thv_cr3_scan_result;

/* Connection lifetime.  One process-wide connection is shared and serialized
 * by the DLL.  Call thv_close before unloading the DLL. */
THV_API uint32_t THV_CALL thv_open(uint32_t flags, thv_connection_info *info);
THV_API void THV_CALL thv_close(void);
THV_API uint32_t THV_CALL thv_get_connection_info(thv_connection_info *info);
THV_API const char *THV_CALL thv_status_string(uint32_t status);

/*
 * 1.3: THE CALLER GATE. Reading or writing memory, listing processes and the like need a SESSION, which
 * the hypervisor grants only to one of the build's measured tools, running as administrator, with no
 * foreign code in it. thv_open opens it (after keeping this program's and this DLL's code in memory, which
 * the hypervisor measures) and reopens it when it lapses; ping, status and the licence need none. When it
 * was refused, every gated call returns the refusal and thv_get_access says why, in one sentence.
 */
#define THV_CAP_READ   0x1u
#define THV_CAP_WRITE  0x2u
#define THV_CAP_PHYS   0x4u
typedef struct thv_access {
    uint32_t status;          /* THV_OK: a session is open; otherwise the refusal (THV_E_NOT_ELEVATED, ...) */
    uint32_t reason;          /* the hypervisor's precise cause (HVGATE_* in hvctl_abi.h), 0 when open     */
    uint32_t capabilities;    /* THV_CAP_* the session allows                                               */
    uint32_t integrity;       /* this process's integrity level (0x3000 High, 0x4000 System), when read    */
    uint64_t address;         /* the page, image or instruction the reason is about                        */
    uint64_t value;
    char     image[32];       /* the file the reason is about, when known                                  */
    char     tool[32];        /* the allowlist's name for this program, when open                         */
    char     text[192];       /* the cause, in one sentence                                                */
} thv_access;
THV_API uint32_t THV_CALL thv_get_access(thv_access *access);

/* Core memory and introspection operations. */
THV_API uint32_t THV_CALL thv_get_status(thv_hypervisor_status *status);
THV_API uint32_t THV_CALL thv_get_intro_diagnostics(thv_intro_diagnostics *diagnostics);
THV_API uint32_t THV_CALL thv_get_process_info(uint64_t pid, thv_process_info *info);
THV_API uint32_t THV_CALL thv_read_virtual(
    uint64_t cr3, uint64_t address, void *buffer, uint32_t size, uint32_t *bytes_read);
THV_API uint32_t THV_CALL thv_write_virtual(
    uint64_t cr3, uint64_t address, const void *buffer, uint32_t size, uint32_t *bytes_written);

/* Enumerations fill as much of the supplied array as possible and transparently
 * consume multiple firmware pages.  If result.more is set, continue at
 * result.next_index. */
THV_API uint32_t THV_CALL thv_enumerate_processes(
    uint64_t start_index, thv_process *records, uint32_t capacity, thv_enum_info *result);
THV_API uint32_t THV_CALL thv_enumerate_kernel_modules(
    uint64_t start_index, thv_module *records, uint32_t capacity, thv_enum_info *result);
THV_API uint32_t THV_CALL thv_enumerate_user_modules(
    uint64_t pid, uint64_t start_index, thv_module *records, uint32_t capacity,
    thv_enum_info *result);
THV_API uint32_t THV_CALL thv_enumerate_threads(
    uint64_t eprocess, uint64_t start_index, thv_thread *records, uint32_t capacity,
    thv_enum_info *result);
THV_API uint32_t THV_CALL thv_enumerate_memory(
    uint64_t cr3, uint64_t start_address, thv_memory_region *records, uint32_t capacity,
    thv_enum_info *result);
/* The physical map is returned as one snapshot. If result.more is set, call
 * again with a larger array; next_index is not a continuation cursor here. */
THV_API uint32_t THV_CALL thv_get_physical_ranges(
    thv_physical_range *records, uint32_t capacity, thv_enum_info *result);

/* Batched transfers (v1.1, append-only).  Many regions per call, each copied
 * directly between the target address space and the caller's buffer -- no 4 KiB
 * window per call, one hypervisor round trip per up to 125 regions.  `cr3` 0
 * means the caller's own address space.  Each entry's `done` reports the bytes
 * moved; a short entry stopped at a page that does not translate (or, for a
 * read, at a destination page the process cannot write).  Returns THV_OK when
 * the hypervisor answered, whatever the individual entries moved, and adds the
 * bytes moved into *total_done when it is not NULL.  Against a hypervisor
 * without batch support the DLL falls back to one thv_read_virtual /
 * thv_write_virtual per entry, transparently. */
typedef struct thv_batch_entry {
    uint64_t cr3;
    uint64_t address;
    void *buffer;
    uint32_t size;
    uint32_t done;
} thv_batch_entry;

#define THV_BATCH_MAX_ENTRIES 125u

THV_API uint32_t THV_CALL thv_read_batch(
    thv_batch_entry *entries, uint32_t count, uint64_t *total_done);
THV_API uint32_t THV_CALL thv_write_batch(
    thv_batch_entry *entries, uint32_t count, uint64_t *total_done);

/* Physical reads (v1.2, append-only).  The same batch, but each entry's
 * `address` is a PHYSICAL address of the machine as Windows sees it (`cr3` is
 * ignored).  Read only.  What Windows' own view of physical memory cannot reach
 * -- VBS-protected pages, the hypervisor's memory -- is not readable either: an
 * entry stops there, as at a page that does not translate.  Against a hypervisor
 * without physical reads (before rev135): THV_E_UNSUPPORTED. */
THV_API uint32_t THV_CALL thv_read_physical_batch(
    thv_batch_entry *entries, uint32_t count, uint64_t *total_done);

/* CR3 discovery. thv_query_cr3 answers the tracker's methods; it refuses
 * THV_CR3_METHOD_ACTIVE alone (THV_E_BAD_ARGUMENT): that method is thv_cr3_watch.
 * thv_cr3_scan_step intentionally performs one bounded scan
 * slice; feed result.next_pa back into request.resume_pa until found or done. */
THV_API uint32_t THV_CALL thv_query_cr3(
    const thv_cr3_query *query, thv_cr3_result *result);

/* rev145: the WATCH-ONLY CR3-WRITE WINDOW (THV_CR3_METHOD_ACTIVE). One call is one
 * step. The first arms a one-second window in which every CR3 write the OS makes
 * exits to the hypervisor, which only reads the value and lets the processor do
 * the write itself. Each value is attributed by the incoming thread's TEB, read
 * through the new page tables (it must point at itself and name `pid`); EPROCESS
 * is never read. THV_E_NOT_FOUND: still watching -- sleep and call again (the
 * window always runs its full length). THV_OK: *result holds the report, and the
 * window is closed (consumed once). THV_E_NO_SPACE: another session's window.
 * THV_E_UNSUPPORTED: not a nested hypervisor image. No call waits in the
 * hypervisor. */
THV_API uint32_t THV_CALL thv_cr3_watch(uint32_t pid, thv_cr3_watch_result *result);
THV_API uint32_t THV_CALL thv_cr3_scan_step(
    const thv_cr3_scan *request, thv_cr3_scan_result *result);

/*
 * 1.4 (rev137): THE OPERATOR'S TRUSTED PROGRAMS. A program the build does not trust can ASK to be: measure it into
 * a request record (tools/trust/trustreq.exe does) and send it with thv_trust_request (thv_trust_query lists them).
 * 1.5 (rev138): it is trusted AT ONCE with what it asked for -- administrator is the confirmation -- and kept for later
 * boots; the same program asking again with other caps (or a new build at the same path) replaces its entry.
 * thv_trust_request_ex(.., THV_TRUST_AT_BOOT, ..) asks for rev137's way instead: nothing is trusted until the NEXT
 * BOOT shows the request with a random code that only a person at the keyboard can type back (a rev137 hypervisor
 * always works that way). thv_trust_revoke takes one back at once. No session is needed (the program asking is not
 * trusted), but administrator is. Needs the TPM store (UMBRA). Before rev137: THV_E_BAD_COMMAND.
 */
typedef struct thv_trust_entry {
    uint8_t  id[8];           /* thv_trust_revoke names it by this (the pending request: all zero)          */
    uint16_t capabilities;    /* granted THV_CAP_*; for the pending request, what it asks for                */
    uint16_t images;          /* the program and its own DLLs                                                */
    uint32_t pages;           /* executable pages measured                                                   */
    uint32_t revoked;         /* revoked at this boot (gone at the next)                                     */
    uint32_t pending;         /* the request waiting for the boot screen                                     */
    char     name[44];
    char     path[224];       /* as the request named it                                                     */
} thv_trust_entry;
#define THV_TRUST_MAX 9u
typedef struct thv_trust_list {
    uint32_t count;
    uint32_t store;           /* 1 = the hypervisor keeps state across boots: requests can be made             */
    uint32_t reserved[2];
    thv_trust_entry entries[THV_TRUST_MAX];
} thv_trust_list;
/* `record` (size bytes, kept in memory by the call) is the request; `message` gets the hypervisor's answer in words. */
THV_API uint32_t THV_CALL thv_trust_request(const void *record, uint32_t size, char *message, uint32_t message_size);
#define THV_TRUST_AT_BOOT 1u        /* 1.5: kept for the boot screen's typed code instead of trusted at once */
THV_API uint32_t THV_CALL thv_trust_request_ex(const void *record, uint32_t size, uint32_t flags, char *message,
                                               uint32_t message_size);
THV_API uint32_t THV_CALL thv_trust_query(thv_trust_list *list);
/* An all-zero id cancels the pending request. */
THV_API uint32_t THV_CALL thv_trust_revoke(const uint8_t id[8]);

/*
 * 1.4 (rev137): THE EXECUTE WATCH (nested images: the VBS build). Arm a range of a process's code -- virtual through
 * `cr3` (0 = this process; a process's from thv_get_process_info), or physical with THV_XWATCH_PHYS -- and the FIRST
 * instruction fetch from each of its pages is recorded: where (RIP), with what (RSP, RAX), in which address space
 * (CR3), at what privilege, on which vCPU, when. One-shot and non-stop: the page then runs on, nothing waits, nothing
 * is single-stepped; any process that maps the page is caught (the hit's CR3 says which). Up to 1024 pages armed;
 * the last 512 hits are kept. A session with READ is enough. Not a nested image: THV_E_UNSUPPORTED.
 */
#define THV_XWATCH_PHYS 1u
typedef struct thv_xwatch_status {
    uint32_t supported, armed, total, count, added, skipped;
    uint64_t tsc_hz;          /* the hits' clock (tsc / tsc_hz = seconds since the machine started) */
} thv_xwatch_status;
typedef struct thv_xwatch_hit {
    uint64_t page, rip, rsp, rax, cr3, tsc;
    uint32_t vcpu, cpl;
} thv_xwatch_hit;
THV_API uint32_t THV_CALL thv_xwatch_arm(uint64_t cr3, uint64_t address, uint64_t length, uint32_t flags,
                                         thv_xwatch_status *status);
/* Hits from index `from` (thv_xwatch_status.total is the next one): up to `max` into `hits`, status->count of them. */
THV_API uint32_t THV_CALL thv_xwatch_read(uint32_t from, thv_xwatch_hit *hits, uint32_t max, thv_xwatch_status *status);
THV_API uint32_t THV_CALL thv_xwatch_clear(thv_xwatch_status *status);

/*
 * 1.6 (rev141): THE HITS ENRICHED, AND THE WRITE WATCH. Every hit (either watch) also carries the address fetched or
 * written, the argument registers (RCX, RDX, R8, R9) and 16 qwords from the top of the stack -- the return addresses:
 * who called. thv_xwatch_arm_deref arms the execute watch so that each hit also captures up to 32 bytes at
 * [[reg + off1] + off2] (reg 1 RCX, 2 RDX, 3 R8, 4 R9) -- a dispatch routine's IRP (RDX) -> its current stack location
 * (+0xB8): an IOCTL's code and sizes -- until thv_xwatch_clear. THE WRITE WATCH: the FIRST WRITE to each armed page is
 * recorded the same way (its own table: arming one never disarms the other). A session with READ is enough.
 */
typedef struct thv_watch_hit {
    uint64_t page, addr;      /* the page; the address fetched (execute) or written (write) -- physical             */
    uint64_t rip, rsp, rax, cr3, tsc;
    uint64_t rcx, rdx, r8, r9;
    uint64_t stack[16];
    uint8_t  deref[32];
    uint32_t vcpu, cpl;
    uint32_t nstack, nderef;  /* how many of stack[] / deref[] were read (0: not enriched)                          */
    uint32_t gpt, pad;        /* gpt: a write by the processor's page walker (A/D bits), not by an instruction      */
} thv_watch_hit;
THV_API uint32_t THV_CALL thv_xwatch_arm_deref(uint64_t cr3, uint64_t address, uint64_t length, uint32_t flags,
                                               uint32_t reg, uint64_t off1, uint64_t off2, uint32_t bytes,
                                               thv_xwatch_status *status);
THV_API uint32_t THV_CALL thv_xwatch_read_ext(uint32_t from, thv_watch_hit *hits, uint32_t max, thv_xwatch_status *status);
/* pages (may be NULL): each page of the range's physical address as armed (0 = not mapped), up to cap -- a hit names
 * the physical page it took (thv_watch_hit.page/addr), this names the virtual page it belongs to */
THV_API uint32_t THV_CALL thv_wwatch_arm(uint64_t cr3, uint64_t address, uint64_t length, uint32_t flags,
                                         uint64_t *pages, uint32_t cap, thv_xwatch_status *status);
THV_API uint32_t THV_CALL thv_wwatch_read(uint32_t from, thv_watch_hit *hits, uint32_t max, thv_xwatch_status *status);
THV_API uint32_t THV_CALL thv_wwatch_clear(thv_xwatch_status *status);

/*
 * 1.4 (rev137): THE BOOT RECORDER. Asked for once (THV_BOOTMON_ARM, 30..600 seconds), the NEXT boot looks at
 * Windows' loaded-module list every 250 ms from the moment its kernel is up: every driver present at the first look,
 * then each one that appeared or vanished, with the time after the hypervisor's launch -- a driver that loads, acts
 * and unloads between two looks of Windows' own tools still shows. One boot only (the request is used up). Needs the
 * TPM store; a session with READ. THV_BOOTMON_READ: this boot's record from event `arg`.
 */
#define THV_BOOTMON_READ   1u
#define THV_BOOTMON_ARM    2u
#define THV_BOOTMON_DISARM 3u
#define THV_BOOTMON_STATUS 4u
typedef struct thv_bootmon_status {
    uint32_t state;           /* 0 off this boot, 1 recording, 2 done                                     */
    uint32_t armed_next;      /* the next boot records                                                   */
    uint32_t events, count, samples, seconds, store;
    uint32_t hooks;           /* 1.5: hook sites read this boot (0: modules only)                        */
    uint64_t first_us;        /* the first successful look, microseconds after launch                    */
    uint32_t live;            /* 1.6: the record was started while Windows ran (thv_bootmon_live)        */
    uint32_t writers;         /* 1.6: callback-table pages under the write watch now                     */
    uint64_t started_us;      /* 1.6: when a live record was started                                     */
} thv_bootmon_status;
typedef struct thv_bootmon_event {
    uint64_t t_us, base, size;
    uint32_t kind;            /* 1 present at the first look, 2 loaded, 3 unloaded, 4 the record is full;
                                 1.5: 5 hook registered, 6 hook removed, 7 hook sites off (another ntoskrnl build),
                                 8 hook present at the first look -- then base = the routine, size = its offset in
                                 the module named (~0: in NO module), where = site << 16 | index (| 0x8000: post) */
    uint32_t where;
    char     name[40];
} thv_bootmon_event;
THV_API uint32_t THV_CALL thv_bootmon(uint32_t op, uint32_t arg, thv_bootmon_status *status, thv_bootmon_event *events,
                                      uint32_t max);
/* 1.5 (rev138): arm the NEXT boot's recorder with HOOK SITES as well -- the kernel's registration tables by their RVA
 * in ntoskrnl (argus --bootmon arm finds them in the PDB), bound to its build. A rev137 hypervisor records modules. */
#define THV_BOOTMON_SITES_MAX 8u
enum { THV_SITE_PROCESS = 1, THV_SITE_THREAD, THV_SITE_IMAGE, THV_SITE_REGISTRY, THV_SITE_OBJ_PROCESS, THV_SITE_OBJ_THREAD,
       THV_SITE_OBJ_DESKTOP };
enum { THV_FORM_EXCB = 1, THV_FORM_LIST = 2, THV_FORM_OBJTYPE = 3 };
typedef struct thv_bootmon_site { uint32_t site, form, rva, slots; uint16_t fn_off, fn2_off, list_off, back_off; } thv_bootmon_site;
typedef struct thv_bootmon_hooks {
    uint32_t nt_stamp, nt_size;   /* ntoskrnl's TimeDateStamp and SizeOfImage: the build the RVAs belong to     */
    uint32_t count;
    thv_bootmon_site sites[THV_BOOTMON_SITES_MAX];
} thv_bootmon_hooks;
THV_API uint32_t THV_CALL thv_bootmon_arm_hooks(uint32_t seconds, const thv_bootmon_hooks *hooks, thv_bootmon_status *status);
/* 1.6 (rev141): RECORD NOW, while Windows runs (10..3600 s; hooks may be NULL): this boot's record gives way to a live
 * one whose first look lists what is loaded and hooked at that moment; thv_bootmon_stop ends whatever records. Event
 * kind 9 (1.6): WHO WROTE a callback table -- base = the first return address on the writer's stack in a loaded module
 * other than ntoskrnl (0: none), size = the writing instruction, where = site << 16 | the slot written, name = the
 * module base is in. */
#define THV_BOOTMON_LIVE 5u
#define THV_BOOTMON_STOP 6u
THV_API uint32_t THV_CALL thv_bootmon_live(uint32_t seconds, const thv_bootmon_hooks *hooks, thv_bootmon_status *status);
THV_API uint32_t THV_CALL thv_bootmon_stop(thv_bootmon_status *status);

/*
 * 1.4 (rev137): WHAT A PAGE MAY DO, TWICE OVER. For up to 128 pages from `address` through `cr3` (0 = this process):
 * the guest's own page tables (present, writable, user, executable) and -- under Hyper-V, where VBS/HVCI enforces --
 * what Hyper-V's SLAT allows on the page (read, write, execute as the kernel, execute as user). `slat` = 1 when the
 * SLAT bits are that verdict (0: no Hyper-V under Windows; they are then 0). A session with READ.
 */
#define THV_SLAT_G_PRESENT 0x01u
#define THV_SLAT_G_WRITE   0x02u
#define THV_SLAT_G_USER    0x04u
#define THV_SLAT_G_EXEC    0x08u
#define THV_SLAT_S_READ    0x10u
#define THV_SLAT_S_WRITE   0x20u
#define THV_SLAT_S_XKERNEL 0x40u
#define THV_SLAT_S_XUSER   0x80u
typedef struct thv_slat_page { uint64_t va, pa; uint32_t flags, reserved; } thv_slat_page;
THV_API uint32_t THV_CALL thv_slat_query(uint64_t cr3, uint64_t address, uint32_t pages, thv_slat_page *out, uint32_t *slat);

/*
 * 1.7 (rev141b): THE HYPERVISOR'S TEXT LOG -- what a -Log image writes to its debug port, kept in its memory (the last
 * 4 MiB), so a machine with no debug port reads it. From byte `from` (an absolute offset into everything ever written;
 * older than info->oldest is gone, and info->first says where these bytes start), up to `max` bytes into `out`, *got
 * of them. info->total = bytes ever written: the next call's `from` to follow it. info->capacity 0 = this image keeps
 * no text log (a textless release image). Needs a session (READ), like a memory read: it names kernel addresses.
 */
typedef struct thv_log_info { uint64_t total, oldest, first; uint32_t capacity, reserved; } thv_log_info;
THV_API uint32_t THV_CALL thv_log_read(uint64_t from, void *out, uint32_t max, uint32_t *got, thv_log_info *info);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* TURINGHV_H */
