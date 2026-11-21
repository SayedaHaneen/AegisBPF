#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/in.h>

#define EVENT_EXEC    1
#define EVENT_CONNECT 2
#define EVENT_PTRACE  3

// Telemetry event structure passed to user space
struct event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 event_type;
    char comm[16];
    char filename[128];
    u32 daddr;
    u16 dport;
    u32 target_pid;
    u32 ptrace_req;
};

BPF_PERF_OUTPUT(events);

// Hook 1: Process Execution (execve)
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct event_t event = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.event_type = EVENT_EXEC;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
    event.ppid = task->real_parent->tgid;
    #else
    event.ppid = 0;
    #endif

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), args->filename);

    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

// Hook 2: Socket Outbound Network Handshakes (connect)
TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct sockaddr_in *addr = (struct sockaddr_in *)args->uservaddr;
    struct sockaddr_in sa = {};

    // Only inspect IPv4 (AF_INET = 2)
    if (bpf_probe_read_user(&sa, sizeof(sa), addr) < 0) {
        return 0;
    }
    if (sa.sin_family != AF_INET) {
        return 0;
    }

    struct event_t event = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.event_type = EVENT_CONNECT;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.daddr = sa.sin_addr.s_addr;
    event.dport = bpf_ntohs(sa.sin_port);

    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

// Hook 3: Process Memory Tampering & Injection (ptrace)
TRACEPOINT_PROBE(syscalls, sys_enter_ptrace) {
    struct event_t event = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.event_type = EVENT_PTRACE;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.ptrace_req = args->request;
    event.target_pid = args->pid;

    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
