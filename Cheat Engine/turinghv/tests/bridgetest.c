/* IPC smoke test for thvbridge.exe: plays Cheat Engine's side of the protocol. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "thvbridge_proto.h"

#define SLOTS 4
#define DATA  (1u << 20)

static uint8_t *g_view;
static HANDLE req[SLOTS], rsp[SLOTS], broker;
static thvb_slot *hdr(int i) { return (thvb_slot *)(g_view + THVB_PAGE + (size_t)i * (THVB_PAGE + DATA)); }
static uint8_t *dat(int i) { return g_view + THVB_PAGE + (size_t)i * (THVB_PAGE + DATA) + THVB_PAGE; }
static uint64_t seqn = 100;

static uint32_t call(int i, uint32_t cmd, const uint64_t *args, int nargs, uint32_t in_len) {
    thvb_slot *s = hdr(i);
    s->cmd = cmd; s->in_len = in_len; s->status = 0xDEAD; s->out_len = 0;
    memset(s->arg, 0, sizeof s->arg);
    for (int k = 0; k < nargs; k++) s->arg[k] = args[k];
    s->seq = ++seqn;
    MemoryBarrier();
    SetEvent(req[i]);
    HANDLE w[2] = { rsp[i], broker };
    DWORD r = WaitForMultipleObjects(2, w, FALSE, 10000);
    if (r != WAIT_OBJECT_0) { printf("  !! wait failed %lu\n", r); return 0xFFFFFFFF; }
    if (s->ret_seq != s->seq) printf("  !! seq mismatch\n");
    return s->status;
}

int main(int argc, char **argv) {
    const char *exe = argc > 1 ? argv[1] : "thvbridge.exe";
    SECURITY_ATTRIBUTES sa = { sizeof sa, NULL, TRUE };
    const uint64_t total = THVB_PAGE + (uint64_t)SLOTS * (THVB_PAGE + DATA);
    HANDLE sec = CreateFileMappingW(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE, (DWORD)(total >> 32), (DWORD)total, NULL);
    g_view = MapViewOfFile(sec, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    thvb_shared *sh = (thvb_shared *)g_view;
    sh->magic = THVB_MAGIC; sh->proto = THVB_PROTO; sh->slot_count = SLOTS; sh->slot_data = DATA;
    HANDLE ready = CreateEventW(&sa, FALSE, FALSE, NULL);
    HANDLE me;
    DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(), &me, SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, TRUE, 0);
    sh->parent_process = (uint64_t)(uintptr_t)me; sh->ready_event = (uint64_t)(uintptr_t)ready;
    for (int i = 0; i < SLOTS; i++) {
        req[i] = CreateEventW(&sa, FALSE, FALSE, NULL); rsp[i] = CreateEventW(&sa, FALSE, FALSE, NULL);
        sh->req_event[i] = (uint64_t)(uintptr_t)req[i]; sh->rsp_event[i] = (uint64_t)(uintptr_t)rsp[i];
    }
    char cmd[512];
    snprintf(cmd, sizeof cmd, "\"%s\" --section %llu", exe, (unsigned long long)(uintptr_t)sec);
    STARTUPINFOA si = { sizeof si }; PROCESS_INFORMATION pi;
    if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) { printf("CreateProcess %lu\n", GetLastError()); return 1; }
    broker = pi.hProcess;
    HANDLE w[2] = { ready, broker };
    DWORD r = WaitForMultipleObjects(2, w, FALSE, 15000);
    if (r != WAIT_OBJECT_0) { DWORD ec = 0; GetExitCodeProcess(broker, &ec); printf("broker not ready (%lu), exit code %lu\n", r, ec); return 1; }
    printf("ready: state %d open_status %u pid %u version '%s' abi %08x access.status %u text '%s'\n", sh->state,
           sh->open_status, sh->broker_pid, sh->version, sh->conn.hypervisor_abi_version, sh->access.status, sh->access.text);

    uint32_t st = call(0, THVB_CMD_PING, NULL, 0, 0);
    printf("PING: st %u ret0 %llu ret1 %llu ret2 %llx\n", st, hdr(0)->ret[0], hdr(0)->ret[1], hdr(0)->ret[2]);

    st = call(1, THVB_CMD_CONNECTION_INFO, NULL, 0, 0);
    thv_connection_info *ci = (thv_connection_info *)dat(1);
    printf("CONNECTION_INFO: st %u client %08x hv %08x bell %u\n", st, ci->client_api_version, ci->hypervisor_abi_version, ci->doorbell_active);

    st = call(2, THVB_CMD_GET_ACCESS, NULL, 0, 0);
    thv_access *ac = (thv_access *)dat(2);
    printf("GET_ACCESS: st %u access.status %u reason %u caps %x tool '%s' text '%s'\n", st, ac->status, ac->reason, ac->capabilities, ac->tool, ac->text);

    uint64_t a[3] = { GetCurrentProcessId() };
    st = call(3, THVB_CMD_PROCESS_INFO, a, 1, 0);
    printf("PROCESS_INFO(self): st %u (%s)\n", st, thv_status_string(st));

    uint64_t ra[3] = { 0, 0x7ffe0000, (uint64_t)DATA + 1 };
    st = call(0, THVB_CMD_READ, ra, 3, 0);
    printf("READ oversize: st %u (expect %u BAD_ARGUMENT)\n", st, THV_E_BAD_ARGUMENT);

    thvb_xfer *x = (thvb_xfer *)dat(1);
    memset(x, 0, sizeof *x); x->address = 0x7ffe0000; x->size = 16; x->data_off = 8; /* inside the table: refused */
    uint64_t sa1[1] = { 1 };
    st = call(1, THVB_CMD_READ_SCATTER, sa1, 1, sizeof *x);
    printf("SCATTER bad offset: st %u (expect %u)\n", st, THV_E_BAD_ARGUMENT);
    x->data_off = DATA - 8;  /* runs past the end: refused */
    st = call(1, THVB_CMD_READ_SCATTER, sa1, 1, sizeof *x);
    printf("SCATTER past end: st %u (expect %u)\n", st, THV_E_BAD_ARGUMENT);

    uint64_t z[3] = { 0, 0x7ffe0000, 16 };
    st = call(2, THVB_CMD_READ, z, 3, 0);
    printf("READ cr3 0: st %u (expect %u)\n", st, THV_E_BAD_ARGUMENT);
    st = call(2, THVB_CMD_WRITE, z, 3, 16);
    printf("WRITE cr3 0: st %u (expect %u)\n", st, THV_E_BAD_ARGUMENT);
    x = (thvb_xfer *)dat(3);
    memset(x, 0, sizeof *x); x->cr3 = 0x1234000; x->address = 0x7ffe0000; x->size = 16; x->data_off = 64;
    st = call(3, THVB_CMD_WRITE_SCATTER, sa1, 1, sizeof *x);   /* payload not declared in in_len */
    printf("WRITE_SCATTER undeclared payload: st %u (expect %u)\n", st, THV_E_BAD_ARGUMENT);
    uint64_t rp[2] = { 0, 0 };
    st = call(0, THVB_CMD_REOPEN, rp, 1, 0);
    printf("REOPEN: st %u, access now %u '%s'\n", st, sh->access.status, sh->access.text);
    st = call(2, 9999, NULL, 0, 0);
    printf("bad command: st %u (expect %u)\n", st, THV_E_BAD_COMMAND);

    uint64_t ma[3] = { 0, 0, 64 };
    st = call(3, THVB_CMD_ENUM_MEMORY, ma, 3, 0);
    printf("ENUM_MEMORY(no session): st %u (%s)\n", st, thv_status_string(st));

    st = call(0, THVB_CMD_SHUTDOWN, NULL, 0, 0);
    printf("SHUTDOWN: st %u\n", st);
    r = WaitForSingleObject(broker, 5000);
    DWORD ec = 0; GetExitCodeProcess(broker, &ec);
    printf("broker exited: %s, code %lu\n", r == WAIT_OBJECT_0 ? "yes" : "NO", ec);
    return 0;
}
