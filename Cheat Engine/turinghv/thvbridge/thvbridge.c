/*
 * thvbridge.c -- Cheat Engine's broker to turing-hv.  See thvbridge_proto.h for why it exists and the wire format.
 *
 *   thvbridge.exe --section <handle>     started by Cheat Engine (handles inherited); serves until CE exits
 *   thvbridge.exe --selftest             open a session and say whether the caller gate accepted this program
 *   thvbridge.exe --version
 *
 * Rules this file keeps, because the broker holds the hypervisor session on Cheat Engine's behalf:
 *   - every request header is copied out of the shared section before it is looked at;
 *   - every length / offset is checked against the slot's data area, and every buffer handed to the SDK lies
 *     inside that slot's data area -- never anywhere else in this process;
 *   - no pointer of this process is ever written into the section;
 *   - nothing is named: the channel is only reachable through handles Cheat Engine let this process inherit;
 *   - it never asks the hypervisor for trust (thv_trust_request is not reachable from the protocol).
 * It links only turinghv.dll and Windows' own DLLs, with the C runtime static, so the caller gate finds nothing
 * foreign in it.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#include "thvbridge_proto.h"

#define THVB_VERSION "thvbridge 1.0"

_Static_assert(offsetof(thvb_shared, req_event) == 48, "layout");
_Static_assert(offsetof(thvb_shared, rsp_event) == 560, "layout");
_Static_assert(offsetof(thvb_shared, conn) == 1072, "layout");
_Static_assert(offsetof(thvb_shared, access) == 1088, "layout");
_Static_assert(sizeof(thv_access) == 288, "layout");
_Static_assert(offsetof(thvb_shared, version) == 1376, "layout");
_Static_assert(sizeof(thvb_shared) <= THVB_PAGE, "header page");
_Static_assert(offsetof(thvb_slot, arg) == 24, "layout");
_Static_assert(offsetof(thvb_slot, ret) == 152, "layout");
_Static_assert(offsetof(thvb_slot, ret_seq) == 280, "layout");
_Static_assert(sizeof(thvb_slot) <= THVB_PAGE, "slot header page");
_Static_assert(sizeof(thvb_xfer) == 32, "layout");

static thvb_shared *g_shared;
static uint8_t     *g_view;
static uint32_t     g_slots, g_data;
static HANDLE       g_req[THVB_MAX_SLOTS], g_rsp[THVB_MAX_SLOTS];
static HANDLE       g_quit;
static HANDLE       g_ready;
/* Every SDK call runs under this lock shared; REOPEN (close + open) takes it exclusive, so no request can land
 * between the close and the open, and no reopen can interleave with another. */
static SRWLOCK      g_sdk_lock = SRWLOCK_INIT;
/* This process's own page-table root (low 12 bits clear): requests through it, or through CR3 0 ("the caller's
 * own address space" to the SDK), are refused -- the channel must not be usable against the broker itself. */
static volatile uint64_t g_self_cr3;

static void refresh_self_cr3(void) {
    thv_process_info self;
    memset(&self, 0, sizeof self);
    if (thv_get_process_info(GetCurrentProcessId(), &self) == THV_OK && self.dirbase)
        g_self_cr3 = self.dirbase & ~0xFFFull;
}

/* May a request use this CR3?  0 is the broker; so is the broker's own root. */
static int foreign_cr3(uint64_t cr3) {
    if (!cr3) return 0;
    const uint64_t self = g_self_cr3;
    if (self && ((cr3 & 0x000FFFFFFFFFF000ull) == (self & 0x000FFFFFFFFFF000ull))) return 0;
    return 1;
}

static thvb_slot *slot_hdr(uint32_t i) {
    return (thvb_slot *)(g_view + THVB_PAGE + (size_t)i * (THVB_PAGE + g_data));
}
static uint8_t *slot_data(uint32_t i) {
    return g_view + THVB_PAGE + (size_t)i * (THVB_PAGE + g_data) + THVB_PAGE;
}

static uint32_t min_u32(uint64_t a, uint64_t b) { return (uint32_t)(a < b ? a : b); }

/* Status of a single transfer the SDK reported as answered: whole, partial, or nothing. */
static uint32_t xfer_status(uint32_t st, uint32_t done, uint32_t size) {
    if (st != THV_OK) return st;
    if (done == size) return THV_OK;
    return done ? (uint32_t)THV_E_PARTIAL_TRANSFER : (uint32_t)THV_E_BAD_POINTER;
}

static void put_enum(thvb_slot *r, const thv_enum_info *e) {
    r->ret[0] = e->count;
    r->ret[1] = e->more;
    r->ret[2] = e->status2;
    r->ret[3] = e->next_index;
}

/* Per-worker scratch for scatter transfers: private copies, never the section. */
typedef struct worker {
    uint32_t index;
    thvb_xfer xfer[THVB_SCATTER_MAX];
    thv_batch_entry batch[THVB_SCATTER_MAX];
} worker;

/* Close and reopen the connection (and with it the session).  Caller holds g_sdk_lock EXCLUSIVE (or is startup,
 * before any worker exists).  Returns thv_open's status; the shared snapshot is refreshed either way. */
static uint32_t do_reopen_locked(uint32_t flags, thv_connection_info *out) {
    thv_close();
    memset(out, 0, sizeof *out);
    const uint32_t st = thv_open(flags, out);
    thv_access acc;
    memset(&acc, 0, sizeof acc);
    if (st == THV_OK) {
        thv_get_access(&acc);
        refresh_self_cr3();
    } else {
        acc.status = st;
        snprintf(acc.text, sizeof acc.text, "%s", thv_status_string(st));
    }
    memcpy((void *)&g_shared->conn, out, sizeof *out);
    memcpy((void *)&g_shared->access, &acc, sizeof acc);
    g_shared->open_status = st;
    return st;
}

/* One request.  `q` is the private copy of the header; `r` receives the answer (also private, copied back). */
static void dispatch(worker *w, const thvb_slot *q, thvb_slot *r, uint8_t *d, int *shutdown) {
    const uint32_t cap = g_data;
    r->status = THV_OK;
    r->out_len = 0;
    if (!g_self_cr3) refresh_self_cr3();

    switch (q->cmd) {
    case THVB_CMD_PING:
        r->ret[0] = GetCurrentProcessId();
        r->ret[1] = THVB_PROTO;
        r->ret[2] = THV_CLIENT_API_VERSION;
        break;

    case THVB_CMD_CONNECTION_INFO:
        r->status = thv_get_connection_info((thv_connection_info *)d);
        r->out_len = sizeof(thv_connection_info);
        break;

    case THVB_CMD_GET_ACCESS:
        memset(d, 0, sizeof(thv_access));
        r->status = thv_get_access((thv_access *)d);
        r->out_len = sizeof(thv_access);
        break;

    case THVB_CMD_REOPEN:              /* handled by worker_main under the exclusive lock */
        r->status = THV_E_BAD_COMMAND;
        break;

    case THVB_CMD_STATUS:
        memset(d, 0, sizeof(thv_hypervisor_status));
        r->status = thv_get_status((thv_hypervisor_status *)d);
        r->out_len = sizeof(thv_hypervisor_status);
        break;

    case THVB_CMD_INTRO_DIAG:
        memset(d, 0, sizeof(thv_intro_diagnostics));
        r->status = thv_get_intro_diagnostics((thv_intro_diagnostics *)d);
        r->out_len = sizeof(thv_intro_diagnostics);
        break;

    case THVB_CMD_PROCESS_INFO:
        memset(d, 0, sizeof(thv_process_info));
        r->status = thv_get_process_info(q->arg[0], (thv_process_info *)d);
        r->out_len = sizeof(thv_process_info);
        break;

    case THVB_CMD_READ:
    case THVB_CMD_READ_PHYS: {
        const int phys = q->cmd == THVB_CMD_READ_PHYS;
        const uint64_t addr = phys ? q->arg[0] : q->arg[1];
        const uint64_t size = phys ? q->arg[1] : q->arg[2];
        if (size > cap || (!phys && !foreign_cr3(q->arg[0]))) { r->status = THV_E_BAD_ARGUMENT; break; }
        if (!size) break;
        thv_batch_entry e;
        memset(&e, 0, sizeof e);
        e.cr3 = phys ? 0 : q->arg[0];
        e.address = addr;
        e.buffer = d;
        e.size = (uint32_t)size;
        const uint32_t st = phys ? thv_read_physical_batch(&e, 1, NULL) : thv_read_batch(&e, 1, NULL);
        const uint32_t done = e.done > e.size ? 0 : e.done;
        r->ret[0] = done;
        r->out_len = done;
        r->status = xfer_status(st, done, e.size);
        break;
    }

    case THVB_CMD_WRITE: {
        const uint64_t size = q->arg[2];
        if (size > cap || size > q->in_len || !foreign_cr3(q->arg[0])) { r->status = THV_E_BAD_ARGUMENT; break; }
        if (!size) break;
        thv_batch_entry e;
        memset(&e, 0, sizeof e);
        e.cr3 = q->arg[0];
        e.address = q->arg[1];
        e.buffer = d;
        e.size = (uint32_t)size;
        const uint32_t st = thv_write_batch(&e, 1, NULL);
        const uint32_t done = e.done > e.size ? 0 : e.done;
        r->ret[0] = done;
        r->status = xfer_status(st, done, e.size);
        break;
    }

    case THVB_CMD_READ_SCATTER:
    case THVB_CMD_WRITE_SCATTER:
    case THVB_CMD_READ_PHYS_SCATTER: {
        const uint64_t n = q->arg[0];
        const uint64_t table = n * sizeof(thvb_xfer);
        if (!n || n > THVB_SCATTER_MAX || table > cap || table > q->in_len) { r->status = THV_E_BAD_ARGUMENT; break; }
        memcpy(w->xfer, d, (size_t)table);                 /* private copy: checked below, used below */
        for (uint32_t i = 0; i < n; i++) {
            const thvb_xfer *x = &w->xfer[i];
            if (x->size > cap || x->data_off < table || (uint64_t)x->data_off + x->size > cap ||
                (q->cmd == THVB_CMD_WRITE_SCATTER && (uint64_t)x->data_off + x->size > q->in_len) ||
                (q->cmd != THVB_CMD_READ_PHYS_SCATTER && !foreign_cr3(x->cr3))) {
                r->status = THV_E_BAD_ARGUMENT;
                break;
            }
            w->batch[i].cr3 = q->cmd == THVB_CMD_READ_PHYS_SCATTER ? 0 : x->cr3;
            w->batch[i].address = x->address;
            w->batch[i].buffer = d + x->data_off;
            w->batch[i].size = x->size;
            w->batch[i].done = 0;
        }
        if (r->status != THV_OK) break;
        uint64_t total = 0;
        uint32_t st;
        if (q->cmd == THVB_CMD_READ_SCATTER)      st = thv_read_batch(w->batch, (uint32_t)n, &total);
        else if (q->cmd == THVB_CMD_WRITE_SCATTER) st = thv_write_batch(w->batch, (uint32_t)n, &total);
        else                                       st = thv_read_physical_batch(w->batch, (uint32_t)n, &total);
        for (uint32_t i = 0; i < n; i++) {
            w->xfer[i].done = w->batch[i].done > w->xfer[i].size ? 0 : w->batch[i].done;
        }
        memcpy(d, w->xfer, (size_t)table);
        r->ret[0] = total;
        r->out_len = (uint32_t)table;
        r->status = st;
        break;
    }

    case THVB_CMD_ENUM_PROCESSES: {
        thv_enum_info e; memset(&e, 0, sizeof e);
        const uint32_t n = min_u32(q->arg[1], cap / sizeof(thv_process));
        r->status = thv_enumerate_processes(q->arg[0], (thv_process *)d, n, &e);
        if (e.count > n) e.count = n;
        put_enum(r, &e);
        r->out_len = e.count * (uint32_t)sizeof(thv_process);
        break;
    }
    case THVB_CMD_ENUM_KMODULES: {
        thv_enum_info e; memset(&e, 0, sizeof e);
        const uint32_t n = min_u32(q->arg[1], cap / sizeof(thv_module));
        r->status = thv_enumerate_kernel_modules(q->arg[0], (thv_module *)d, n, &e);
        if (e.count > n) e.count = n;
        put_enum(r, &e);
        r->out_len = e.count * (uint32_t)sizeof(thv_module);
        break;
    }
    case THVB_CMD_ENUM_UMODULES: {
        thv_enum_info e; memset(&e, 0, sizeof e);
        const uint32_t n = min_u32(q->arg[2], cap / sizeof(thv_module));
        r->status = thv_enumerate_user_modules(q->arg[0], q->arg[1], (thv_module *)d, n, &e);
        if (e.count > n) e.count = n;
        put_enum(r, &e);
        r->out_len = e.count * (uint32_t)sizeof(thv_module);
        break;
    }
    case THVB_CMD_ENUM_THREADS: {
        thv_enum_info e; memset(&e, 0, sizeof e);
        const uint32_t n = min_u32(q->arg[2], cap / sizeof(thv_thread));
        r->status = thv_enumerate_threads(q->arg[0], q->arg[1], (thv_thread *)d, n, &e);
        if (e.count > n) e.count = n;
        put_enum(r, &e);
        r->out_len = e.count * (uint32_t)sizeof(thv_thread);
        break;
    }
    case THVB_CMD_ENUM_MEMORY: {
        thv_enum_info e; memset(&e, 0, sizeof e);
        const uint32_t n = min_u32(q->arg[2], cap / sizeof(thv_memory_region));
        if (!foreign_cr3(q->arg[0])) { r->status = THV_E_BAD_ARGUMENT; break; }
        r->status = thv_enumerate_memory(q->arg[0], q->arg[1], (thv_memory_region *)d, n, &e);
        if (e.count > n) e.count = n;
        put_enum(r, &e);
        r->out_len = e.count * (uint32_t)sizeof(thv_memory_region);
        break;
    }
    case THVB_CMD_PHYS_RANGES: {
        thv_enum_info e; memset(&e, 0, sizeof e);
        const uint32_t n = min_u32(q->arg[0], cap / sizeof(thv_physical_range));
        r->status = thv_get_physical_ranges((thv_physical_range *)d, n, &e);
        if (e.count > n) e.count = n;
        put_enum(r, &e);
        r->out_len = e.count * (uint32_t)sizeof(thv_physical_range);
        break;
    }

    case THVB_CMD_CR3_QUERY: {
        if (q->in_len < sizeof(thv_cr3_query)) { r->status = THV_E_BAD_ARGUMENT; break; }
        thv_cr3_query cq;
        memcpy(&cq, d, sizeof cq);
        memset(d, 0, sizeof(thv_cr3_result));
        r->status = thv_query_cr3(&cq, (thv_cr3_result *)d);
        r->out_len = sizeof(thv_cr3_result);
        break;
    }
    case THVB_CMD_CR3_WATCH:
        memset(d, 0, sizeof(thv_cr3_watch_result));
        r->status = thv_cr3_watch((uint32_t)q->arg[0], (thv_cr3_watch_result *)d);
        r->out_len = sizeof(thv_cr3_watch_result);
        break;
    case THVB_CMD_CR3_SCAN_STEP: {
        if (q->in_len < sizeof(thv_cr3_scan)) { r->status = THV_E_BAD_ARGUMENT; break; }
        thv_cr3_scan cs;
        memcpy(&cs, d, sizeof cs);
        memset(d, 0, sizeof(thv_cr3_scan_result));
        r->status = thv_cr3_scan_step(&cs, (thv_cr3_scan_result *)d);
        r->out_len = sizeof(thv_cr3_scan_result);
        break;
    }

    case THVB_CMD_XWATCH_ARM:
        if (!(q->arg[3] & THV_XWATCH_PHYS) && !foreign_cr3(q->arg[0])) { r->status = THV_E_BAD_ARGUMENT; break; }
        memset(d, 0, sizeof(thv_xwatch_status));
        r->status = thv_xwatch_arm(q->arg[0], q->arg[1], q->arg[2], (uint32_t)q->arg[3], (thv_xwatch_status *)d);
        r->out_len = sizeof(thv_xwatch_status);
        break;
    case THVB_CMD_XWATCH_ARM_DEREF:
        if (!(q->arg[3] & THV_XWATCH_PHYS) && !foreign_cr3(q->arg[0])) { r->status = THV_E_BAD_ARGUMENT; break; }
        memset(d, 0, sizeof(thv_xwatch_status));
        r->status = thv_xwatch_arm_deref(q->arg[0], q->arg[1], q->arg[2], (uint32_t)q->arg[3], (uint32_t)q->arg[4],
                                         q->arg[5], q->arg[6], (uint32_t)q->arg[7], (thv_xwatch_status *)d);
        r->out_len = sizeof(thv_xwatch_status);
        break;
    case THVB_CMD_XWATCH_READ:
    case THVB_CMD_WWATCH_READ: {
        const uint32_t n = min_u32(q->arg[1], (cap - THVB_ARRAY_OFF) / sizeof(thv_watch_hit));
        thv_xwatch_status *s = (thv_xwatch_status *)d;
        memset(s, 0, sizeof *s);
        thv_watch_hit *hits = (thv_watch_hit *)(d + THVB_ARRAY_OFF);
        r->status = q->cmd == THVB_CMD_XWATCH_READ ? thv_xwatch_read_ext((uint32_t)q->arg[0], hits, n, s)
                                                    : thv_wwatch_read((uint32_t)q->arg[0], hits, n, s);
        const uint32_t got = s->count > n ? n : s->count;
        r->ret[0] = got;
        r->out_len = THVB_ARRAY_OFF + got * (uint32_t)sizeof(thv_watch_hit);
        break;
    }
    case THVB_CMD_XWATCH_CLEAR:
        memset(d, 0, sizeof(thv_xwatch_status));
        r->status = thv_xwatch_clear((thv_xwatch_status *)d);
        r->out_len = sizeof(thv_xwatch_status);
        break;
    case THVB_CMD_WWATCH_ARM: {
        if (!(q->arg[3] & THV_XWATCH_PHYS) && !foreign_cr3(q->arg[0])) { r->status = THV_E_BAD_ARGUMENT; break; }
        const uint32_t n = min_u32(q->arg[4], (cap - THVB_ARRAY_OFF) / sizeof(uint64_t));
        memset(d, 0, THVB_ARRAY_OFF);
        uint64_t *pages = n ? (uint64_t *)(d + THVB_ARRAY_OFF) : NULL;
        if (pages) memset(pages, 0, (size_t)n * sizeof(uint64_t));
        r->status = thv_wwatch_arm(q->arg[0], q->arg[1], q->arg[2], (uint32_t)q->arg[3], pages, n,
                                   (thv_xwatch_status *)d);
        r->ret[0] = n;
        r->out_len = THVB_ARRAY_OFF + n * (uint32_t)sizeof(uint64_t);
        break;
    }
    case THVB_CMD_WWATCH_CLEAR:
        memset(d, 0, sizeof(thv_xwatch_status));
        r->status = thv_wwatch_clear((thv_xwatch_status *)d);
        r->out_len = sizeof(thv_xwatch_status);
        break;

    case THVB_CMD_SLAT_QUERY: {
        uint32_t n = min_u32(q->arg[2], cap / sizeof(thv_slat_page));
        if (n > 128) n = 128;
        if (!foreign_cr3(q->arg[0])) { r->status = THV_E_BAD_ARGUMENT; break; }
        uint32_t slat = 0;
        memset(d, 0, (size_t)n * sizeof(thv_slat_page));
        r->status = thv_slat_query(q->arg[0], q->arg[1], n, (thv_slat_page *)d, &slat);
        r->ret[0] = slat;
        r->ret[1] = n;
        r->out_len = n * (uint32_t)sizeof(thv_slat_page);
        break;
    }

    case THVB_CMD_LOG_READ: {
        const uint32_t n = min_u32(q->arg[1], cap - THVB_ARRAY_OFF);
        uint32_t got = 0;
        memset(d, 0, sizeof(thv_log_info));
        r->status = thv_log_read(q->arg[0], d + THVB_ARRAY_OFF, n, &got, (thv_log_info *)d);
        if (got > n) got = n;
        r->ret[0] = got;
        r->out_len = THVB_ARRAY_OFF + got;
        break;
    }

    case THVB_CMD_TRUST_QUERY:
        memset(d, 0, sizeof(thv_trust_list));
        r->status = thv_trust_query((thv_trust_list *)d);
        r->out_len = sizeof(thv_trust_list);
        break;

    case THVB_CMD_SHUTDOWN:
        *shutdown = 1;                 /* the worker answers first, then signals quit */
        break;

    default:
        r->status = THV_E_BAD_COMMAND;
        break;
    }
}

static DWORD WINAPI worker_main(LPVOID param) {
    worker *w = (worker *)param;
    const uint32_t i = w->index;
    HANDLE waits[2] = { g_req[i], g_quit };
    for (;;) {
        const DWORD wr = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
        if (wr != WAIT_OBJECT_0) return 0;      /* quit (or a wait failure): stop serving this slot */

        volatile thvb_slot *shared = slot_hdr(i);
        thvb_slot q, r;
        memcpy(&q, (const void *)shared, sizeof q);     /* private copy before anything is looked at */
        memset(&r, 0, sizeof r);
        if (q.in_len > g_data) q.in_len = g_data;
        int shutdown = 0;
        if (q.cmd == THVB_CMD_REOPEN) {
            AcquireSRWLockExclusive(&g_sdk_lock);
            r.status = do_reopen_locked((uint32_t)q.arg[0], (thv_connection_info *)slot_data(i));
            ReleaseSRWLockExclusive(&g_sdk_lock);
            r.out_len = sizeof(thv_connection_info);
        } else {
            AcquireSRWLockShared(&g_sdk_lock);
            dispatch(w, &q, &r, slot_data(i), &shutdown);
            ReleaseSRWLockShared(&g_sdk_lock);
        }
        if (r.out_len > g_data) r.out_len = g_data;

        memcpy((void *)shared->ret, r.ret, sizeof r.ret);
        shared->out_len = r.out_len;
        shared->status = r.status;
        MemoryBarrier();
        shared->ret_seq = q.seq;
        MemoryBarrier();
        SetEvent(g_rsp[i]);
        if (shutdown) SetEvent(g_quit);         /* only after the answer is published */
    }
}

/* ---- startup ------------------------------------------------------------------------------------------ */

static int valid_handle(uint64_t v) {
    if (!v || v > 0xFFFFFFFFull) return 0;
    DWORD flags = 0;
    return GetHandleInformation((HANDLE)(uintptr_t)v, &flags) != 0;
}

/* An inherited handle that must be an event we may signal and reset: ResetEvent fails for anything else. */
static int valid_event(uint64_t v) {
    return valid_handle(v) && ResetEvent((HANDLE)(uintptr_t)v);
}

/* The parent: a process handle we can wait on, for a process still running. */
static int valid_parent(uint64_t v) {
    if (!valid_handle(v)) return 0;
    HANDLE h = (HANDLE)(uintptr_t)v;
    return GetProcessId(h) != 0 && WaitForSingleObject(h, 0) == WAIT_TIMEOUT;
}

/* Startup failed: say so in the header (when there is one) and wake Cheat Engine (when it gave a usable event). */
static volatile thvb_shared *g_hdr_for_fail;
static int start_failed(int code) {
    if (g_hdr_for_fail) { g_hdr_for_fail->state = THVB_STATE_FAILED; MemoryBarrier(); }
    if (g_ready) SetEvent(g_ready);
    return code;
}

static int serve(HANDLE section) {
    /* Map the header page first to learn the geometry, then the whole thing. */
    thvb_shared *probe = (thvb_shared *)MapViewOfFile(section, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, THVB_PAGE);
    if (!probe) return 3;
    g_hdr_for_fail = probe;
    {
        const uint64_t ready = probe->ready_event;
        if (valid_event(ready)) g_ready = (HANDLE)(uintptr_t)ready;
    }
    const uint32_t magic = probe->magic, proto = probe->proto, slots = probe->slot_count, data = probe->slot_data;
    if (!g_ready || magic != THVB_MAGIC || proto != THVB_PROTO || !slots || slots > THVB_MAX_SLOTS ||
        data < THVB_MIN_DATA || data > THVB_MAX_DATA || (data % THVB_PAGE))
        return start_failed(4);

    const SIZE_T total = (SIZE_T)THVB_PAGE + (SIZE_T)slots * (THVB_PAGE + (SIZE_T)data);
    g_view = (uint8_t *)MapViewOfFile(section, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, total);
    if (!g_view) return start_failed(5);
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(g_view, &mbi, sizeof mbi) || mbi.RegionSize < total) return start_failed(6);

    g_shared = (thvb_shared *)g_view;
    g_hdr_for_fail = g_shared;
    UnmapViewOfFile(probe);
    g_slots = slots;
    g_data = data;

    /* The handles Cheat Engine gave us, by value, into private storage: each must be what it claims to be, and no
     * two may be the same object handle. */
    const uint64_t parent = g_shared->parent_process;
    if (!valid_parent(parent)) return start_failed(8);
    for (uint32_t i = 0; i < slots; i++) {
        const uint64_t rq = g_shared->req_event[i], rs = g_shared->rsp_event[i];
        if (!valid_event(rq) || !valid_event(rs)) return start_failed(7);
        g_req[i] = (HANDLE)(uintptr_t)rq;
        g_rsp[i] = (HANDLE)(uintptr_t)rs;
    }
    {
        HANDLE all[2 * THVB_MAX_SLOTS + 2];
        uint32_t n = 0;
        all[n++] = (HANDLE)(uintptr_t)parent;
        all[n++] = g_ready;
        for (uint32_t i = 0; i < slots; i++) { all[n++] = g_req[i]; all[n++] = g_rsp[i]; }
        for (uint32_t a = 0; a < n; a++)
            for (uint32_t b = a + 1; b < n; b++)
                if (all[a] == all[b]) return start_failed(10);
    }

    g_quit = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_quit) return start_failed(11);

    /* Open the hypervisor connection (and with it the session) before any request is served.  A failure is not
     * fatal: every call then answers it, and REOPEN can retry once the hypervisor trusts this program. */
    g_shared->broker_pid = GetCurrentProcessId();
    g_shared->sdk_api_version = THV_CLIENT_API_VERSION;
    snprintf((char *)g_shared->version, sizeof g_shared->version, "%s", THVB_VERSION);
    thv_connection_info info;
    AcquireSRWLockExclusive(&g_sdk_lock);
    do_reopen_locked(g_shared->open_flags, &info);
    ReleaseSRWLockExclusive(&g_sdk_lock);

    static worker workers[THVB_MAX_SLOTS];
    static HANDLE threads[THVB_MAX_SLOTS];
    uint32_t started = 0;
    for (uint32_t i = 0; i < slots; i++) {
        workers[i].index = i;
        threads[i] = CreateThread(NULL, 0, worker_main, &workers[i], 0, NULL);
        if (!threads[i]) break;
        started++;
    }
    if (started != slots) {
        SetEvent(g_quit);
        if (started) WaitForMultipleObjects(started, threads, TRUE, 5000);
        thv_close();
        return start_failed(9);
    }

    g_shared->state = THVB_STATE_READY;
    MemoryBarrier();
    if (!SetEvent(g_ready)) {
        SetEvent(g_quit);
        WaitForMultipleObjects(started, threads, TRUE, 5000);
        thv_close();
        return 12;
    }

    /* Serve until Cheat Engine exits or asks us to.  Then stop taking requests, let every worker finish the one
     * it is answering (each publishes its answer before it looks at quit again), and only then close. */
    HANDLE waits[2] = { (HANDLE)(uintptr_t)parent, g_quit };
    WaitForMultipleObjects(2, waits, FALSE, INFINITE);
    SetEvent(g_quit);
    WaitForMultipleObjects(started, threads, TRUE, 10000);
    AcquireSRWLockExclusive(&g_sdk_lock);
    thv_close();
    ReleaseSRWLockExclusive(&g_sdk_lock);
    return 0;
}

static int selftest(void) {
    thv_connection_info info;
    memset(&info, 0, sizeof info);
    const uint32_t st = thv_open(THV_OPEN_DEFAULT, &info);
    if (st != THV_OK) {
        printf("no hypervisor connection: %s (%u)\n", thv_status_string(st), st);
        return 2;
    }
    printf("connected, hypervisor abi %u.%u, sdk %u.%u%s\n", info.hypervisor_abi_version >> 16,
           info.hypervisor_abi_version & 0xFFFF, THV_CLIENT_API_VERSION >> 16, THV_CLIENT_API_VERSION & 0xFFFF,
           info.doorbell_active ? ", doorbell" : "");

    thv_access acc;
    memset(&acc, 0, sizeof acc);
    thv_get_access(&acc);
    if (acc.status != THV_OK) {
        printf("caller gate REFUSED this program: %s (status %u, reason %u)\n",
               acc.text[0] ? acc.text : thv_status_string(acc.status), acc.status, acc.reason);
        printf("Trust this exact file (UMBRA > Trusted programs, or trustreq request <path> --write --phys), then run again.\n");
        thv_close();
        return 1;
    }
    printf("session open as %s: %s%s%s\n", acc.tool[0] ? acc.tool : "thvbridge.exe",
           (acc.capabilities & THV_CAP_READ) ? "read" : "", (acc.capabilities & THV_CAP_WRITE) ? ", write" : "",
           (acc.capabilities & THV_CAP_PHYS) ? ", physical" : "");

    thv_process_info self;
    memset(&self, 0, sizeof self);
    if (thv_get_process_info(GetCurrentProcessId(), &self) == THV_OK) {
        uint8_t mz[2] = { 0, 0 };
        uint32_t got = 0;
        const uint32_t rs = thv_read_virtual(self.dirbase, self.image_base, mz, 2, &got);
        printf("own process: eprocess %016llx cr3 %016llx image %016llx -> %s\n",
               (unsigned long long)self.eprocess, (unsigned long long)self.dirbase,
               (unsigned long long)self.image_base,
               (rs == THV_OK && mz[0] == 'M' && mz[1] == 'Z') ? "reads MZ through the hypervisor" : "READ FAILED");
    }

    static thv_process procs[64];
    thv_enum_info e;
    memset(&e, 0, sizeof e);
    if (thv_enumerate_processes(0, procs, 64, &e) == THV_OK)
        printf("process list: %u entr%s in the first page%s\n", e.count, e.count == 1 ? "y" : "ies",
               e.more ? " (more follow)" : "");
    thv_close();
    return 0;
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--version")) { printf("%s (sdk %08x, proto %u)\n", THVB_VERSION, THV_CLIENT_API_VERSION, THVB_PROTO); return 0; }
        if (!strcmp(argv[i], "--selftest")) return selftest();
        if (!strcmp(argv[i], "--section") && i + 1 < argc) {
            const unsigned long long h = strtoull(argv[i + 1], NULL, 0);
            if (!valid_handle(h)) return 2;
            return serve((HANDLE)(uintptr_t)h);
        }
    }
    printf("%s -- Cheat Engine's bridge to turing-hv.\n"
           "  thvbridge --selftest    check that the hypervisor serves this program (run as administrator)\n"
           "  thvbridge --version\n"
           "Cheat Engine starts it by itself (--section <handle>).\n", THVB_VERSION);
    return 2;
}
