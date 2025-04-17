#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <librex.h>
#include <time.h>
#include <errno.h>

#define EXE "./target/x86_64-unknown-none/release/syscount"

static const char *syscall_names[] = {
    "read", "write", "open", "close", "stat", "fstat",
    "lstat", "poll", "lseek", "mmap", "mprotect", "munmap",
    "brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
    "ioctl", "pread64", "pwrite64", "readv", "writev", "access",
    "pipe", "select", "sched_yield", "mremap", "msync", "mincore",
    "madvise", "shmget", "shmat", "shmctl", "dup", "dup2",
    "pause", "nanosleep", "getitimer", "alarm", "setitimer",
    "getpid", "sendfile", "socket", "connect", "accept",
    "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown",
    "bind", "listen", "getsockname", "getpeername", "socketpair",
    "setsockopt", "getsockopt", "clone", "fork", "vfork",
    "execve", "exit", "wait4", "kill", "uname", "semget",
    "semop", "semctl", "shmdt", "msgget", "msgsnd", "msgrcv",
    "msgctl", "fcntl", "flock", "fsync", "fdatasync", "truncate",
    "ftruncate", "getdents", "getcwd", "chdir", "fchdir", "rename",
    "mkdir", "rmdir", "creat", "link", "unlink", "symlink",
    "readlink", "chmod", "fchmod", "chown", "fchown", "lchown",
    "umask", "gettimeofday", "getrlimit", "getrusage", "sysinfo",
    "times", "ptrace", "getuid", "syslog", "getgid", "setuid",
    "setgid", "geteuid", "getegid", "setpgid", "getppid", "getpgrp",
    "setsid", "setreuid", "setregid", "getgroups", "setgroups",
    "setresuid", "getresuid", "setresgid", "getresgid", "getpgid",
    "setfsuid", "setfsgid", "getsid", "capget", "capset",
    "rt_sigpending", "rt_sigtimedwait", "rt_sigqueueinfo",
    "rt_sigsuspend", "sigaltstack", "utime", "mknod", "uselib",
    "personality", "ustat", "statfs", "fstatfs", "sysfs", "getpriority",
    "setpriority", "sched_setparam", "sched_getparam",
    "sched_setscheduler", "sched_getscheduler", "sched_get_priority_max",
    "sched_get_priority_min", "sched_rr_get_interval", "mlock",
    "munlock", "mlockall", "munlockall", "vhangup", "modify_ldt",
    "pivot_root", "_sysctl", "prctl", "arch_prctl", "adjtimex",
    "setrlimit", "chroot", "sync", "acct", "settimeofday", "mount",
    "umount2", "swapon", "swapoff", "reboot", "sethostname",
    "setdomainname", "iopl", "ioperm", "create_module", "init_module",
    "delete_module", "get_kernel_syms", "query_module", "quotactl",
    "nfsservctl", "getpmsg", "putpmsg", "afs_syscall", "tuxcall",
    "security", "gettid", "readahead", "setxattr", "lsetxattr",
    "fsetxattr", "getxattr", "lgetxattr", "fgetxattr", "listxattr",
    "llistxattr", "flistxattr", "removexattr", "lremovexattr",
    "fremovexattr", "tkill", "time", "futex", "sched_setaffinity",
    "sched_getaffinity", "set_thread_area", "io_setup", "io_destroy",
    "io_getevents", "io_submit", "io_cancel", "get_thread_area",
    "lookup_dcookie", "epoll_create", "epoll_ctl_old", "epoll_wait_old",
    "remap_file_pages", "getdents64", "set_tid_address", "restart_syscall",
    "semtimedop", "fadvise64", "timer_create", "timer_settime",
    "timer_gettime", "timer_getoverrun", "timer_delete",
    "clock_settime", "clock_gettime", "clock_getres", "clock_nanosleep",
    "exit_group", "epoll_wait", "epoll_ctl", "tgkill", "utimes",
    "vserver", "mbind", "set_mempolicy", "get_mempolicy", "mq_open",
    "mq_unlink", "mq_timedsend", "mq_timedreceive", "mq_notify",
    "mq_getsetattr", "kexec_load", "waitid", "add_key", "request_key",
    "keyctl", "ioprio_set", "ioprio_get", "inotify_init", "inotify_add_watch",
    "inotify_rm_watch", "migrate_pages", "openat", "mkdirat", "mknodat",
    "fchownat", "futimesat", "newfstatat", "unlinkat", "renameat",
    "linkat", "symlinkat", "readlinkat", "fchmodat", "faccessat",
    "pselect6", "ppoll", "unshare", "set_robust_list",
    "get_robust_list", "splice", "tee", "sync_file_range", "vmsplice",
    "move_pages", "utimensat", "epoll_pwait", "signalfd", "timerfd_create",
    "eventfd", "fallocate", "timerfd_settime", "timerfd_gettime",
    "accept4", "signalfd4", "eventfd2", "epoll_create1", "dup3",
    "pipe2", "inotify_init1", "preadv", "pwritev", "rt_tgsigqueueinfo",
    "perf_event_open", "recvmmsg", "fanotify_init", "fanotify_mark",
    "prlimit64", "name_to_handle_at", "open_by_handle_at", "clock_adjtime",
    "syncfs", "sendmmsg", "setns", "getcpu", "process_vm_readv",
    "process_vm_writev", "kcmp", "finit_module", "sched_setattr",
    "sched_getattr", "renameat2", "seccomp", "getrandom", "memfd_create",
    "kexec_file_load", "bpf", "execveat", "userfaultfd", "membarrier",
    "mlock2", "copy_file_range", "preadv2", "pwritev2", "pkey_mprotect",
    "pkey_alloc", "pkey_free", "statx", "io_pgetevents", "rseq",
    /* Add more as needed */
};

#define MAX_SYSCALL_ID (sizeof(syscall_names) / sizeof(syscall_names[0]))

static volatile bool exiting = false;

static void sig_handler(int sig) {
    exiting = true;
}

typedef enum {
    COUNT_ONLY,    
    SHOW_ERRORS,   
    SHOW_LATENCY,  
    SHOW_BOTH      
} stats_type_t;

void print_header(bool timestamp, stats_type_t type) {
    if (timestamp) {
        printf("%-8s ", "TIME(s)");
    }
    
    switch (type) {
        case COUNT_ONLY:
            printf("%-20s %-10s\n", "SYSCALL", "COUNT");
            break;
        case SHOW_ERRORS:
            printf("%-20s %-10s %-10s\n", "SYSCALL", "COUNT", "ERRORS");
            break;
        case SHOW_LATENCY:
            printf("%-20s %-10s %-15s\n", "SYSCALL", "COUNT", "TIME(us)");
            break;
        case SHOW_BOTH:
            printf("%-20s %-10s %-10s %-15s\n", "SYSCALL", "COUNT", "ERRORS", "TIME(us)");
            break;
    }
    
    if (timestamp) {
        printf("%-8s ", "--------");
    }
    
    switch (type) {
        case COUNT_ONLY:
            printf("%-20s %-10s\n", "--------------------", "----------");
            break;
        case SHOW_ERRORS:
            printf("%-20s %-10s %-10s\n", "--------------------", "----------", "----------");
            break;
        case SHOW_LATENCY:
            printf("%-20s %-10s %-15s\n", "--------------------", "----------", "---------------");
            break;
        case SHOW_BOTH:
            printf("%-20s %-10s %-10s %-15s\n", "--------------------", "----------", "----------", "---------------");
            break;
    }
}


typedef struct {
    int interval;          
    bool timestamp;        
    bool clear_screen;     
    bool sort_by_count;    
    int top_n;             
    stats_type_t type;    
    int pid;              
    char *filter_syscalls; 
} options_t;

void print_usage(const char *prog_name) {
    printf("Usage: %s [options]\n\n", prog_name);
    printf("Options:\n");
    printf("  -i <seconds>   Set the output interval (default: 1 second)\n");
    printf("  -t             Include timestamp in output\n");
    printf("  -c             Clear the screen between outputs\n");
    printf("  -s             Sort by syscall name instead of count\n");
    printf("  -n <count>     Display only the top N syscalls\n");
    printf("  -e             Show errors count\n");
    printf("  -l             Show latency (average time per syscall in microseconds)\n");
    printf("  -p <pid>       Filter by process ID\n");
    printf("  -x <syscalls>  Trace only comma-separated syscalls\n");
    printf("  -h             Display this help message\n");
}


options_t parse_options(int argc, char *argv[]) {
    options_t opts = {
        .interval = 1,
        .timestamp = false,
        .clear_screen = false,
        .sort_by_count = true,
        .top_n = -1,
        .type = COUNT_ONLY,
        .pid = -1,
        .filter_syscalls = NULL
    };
    
    int c;
    while ((c = getopt(argc, argv, "i:tcn:selp:x:h")) != -1) {
        switch (c) {
            case 'i':
                opts.interval = atoi(optarg);
                if (opts.interval <= 0) opts.interval = 1;
                break;
            case 't':
                opts.timestamp = true;
                break;
            case 'c':
                opts.clear_screen = true;
                break;
            case 'n':
                opts.top_n = atoi(optarg);
                break;
            case 's':
                opts.sort_by_count = false;
                break;
            case 'e':
                if (opts.type == SHOW_LATENCY)
                    opts.type = SHOW_BOTH;
                else
                    opts.type = SHOW_ERRORS;
                break;
            case 'l':
                if (opts.type == SHOW_ERRORS)
                    opts.type = SHOW_BOTH;
                else
                    opts.type = SHOW_LATENCY;
                break;
            case 'p':
                opts.pid = atoi(optarg);
                break;
            case 'x':
                opts.filter_syscalls = optarg;
                break;
            case 'h':
                print_usage(argv[0]);
                exit(0);
            default:
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    
    return opts;
}

int main(int argc, char *argv[]) {
    struct bpf_object *obj;
    struct bpf_link **links = NULL;
    int link_count = 0;
    int syscall_counts_map_fd = -1;
    int syscall_errors_map_fd = -1;
    int syscall_latency_map_fd = -1;
    time_t start_time;
    int err = 0;

    options_t opts = parse_options(argc, argv);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);


    obj = rex_obj_get_bpf(rex_obj_load(EXE));
    if (!obj) {
        fprintf(stderr, "Failed to load BPF program\n");
        return 1;
    }

    int prog_count = 0;
    struct bpf_program *prog;
    
    bpf_object__for_each_program(prog, obj) {
        prog_count++;
    }
    
    links = calloc(prog_count, sizeof(struct bpf_link *));
    if (!links) {
        fprintf(stderr, "Failed to allocate memory for links\n");
        return 1;
    }
    
    bpf_object__for_each_program(prog, obj) {
        links[link_count] = bpf_program__attach(prog);
        if (libbpf_get_error(links[link_count])) {
            fprintf(stderr, "Failed to attach program: %s\n", bpf_program__name(prog));
            err = -1;
        } else {
            printf("Attached program: %s\n", bpf_program__name(prog));
            link_count++;
        }
    }
    
    if (err != 0) {
        fprintf(stderr, "Failed to attach some programs\n");
        goto cleanup;
    }
    syscall_counts_map_fd = bpf_object__find_map_fd_by_name(obj, "SYSCALL_COUNTS");
    if (syscall_counts_map_fd < 0) {
        fprintf(stderr, "Failed to find syscall counts map\n");
        err = -1;
        goto cleanup;
    }

    if (opts.type == SHOW_ERRORS || opts.type == SHOW_BOTH) {
        syscall_errors_map_fd = bpf_object__find_map_fd_by_name(obj, "SYSCALL_ERRORS");
        if (syscall_errors_map_fd < 0) {
            fprintf(stderr, "Failed to find syscall errors map\n");
            opts.type = opts.type == SHOW_BOTH ? SHOW_LATENCY : COUNT_ONLY;
        }
    }
    
    if (opts.type == SHOW_LATENCY || opts.type == SHOW_BOTH) {
        syscall_latency_map_fd = bpf_object__find_map_fd_by_name(obj, "SYSCALL_LATENCY");
        if (syscall_latency_map_fd < 0) {
            fprintf(stderr, "Failed to find syscall latency map\n");
            opts.type = opts.type == SHOW_BOTH ? SHOW_ERRORS : COUNT_ONLY;
        }
    }

    printf("Tracing syscalls... Hit Ctrl-C to end.\n");
    start_time = time(NULL);

    while (!exiting) {
        sleep(opts.interval);
        
        if (opts.clear_screen) {
            printf("\033[2J\033[1;1H"); 
        }
        

        print_header(opts.timestamp, opts.type);
        
        __u32 key = 0, next_key;
        __u64 count_value, error_value = 0, latency_value = 0;
        
        struct {
            __u32 id;
            __u64 count;
            __u64 errors;
            __u64 latency;
        } stats[512]; 
        int stat_count = 0;
        

        while (bpf_map_get_next_key(syscall_counts_map_fd, &key, &next_key) == 0) {
            if (bpf_map_lookup_elem(syscall_counts_map_fd, &next_key, &count_value) == 0) {
                stats[stat_count].id = next_key;
                stats[stat_count].count = count_value;
                
                if (syscall_errors_map_fd >= 0 && 
                    bpf_map_lookup_elem(syscall_errors_map_fd, &next_key, &error_value) == 0) {
                    stats[stat_count].errors = error_value;
                } else {
                    stats[stat_count].errors = 0;
                }
                
                if (syscall_latency_map_fd >= 0 && 
                    bpf_map_lookup_elem(syscall_latency_map_fd, &next_key, &latency_value) == 0) {
                    stats[stat_count].latency = latency_value;
                } else {
                    stats[stat_count].latency = 0;
                }
                
                stat_count++;
            }
            key = next_key;
        }
        
        if (opts.sort_by_count) {
    for (int i = 0; i < stat_count - 1; i++) {
        for (int j = 0; j < stat_count - i - 1; j++) {
            if (stats[j].count < stats[j + 1].count) {
                __u32 temp_id = stats[j].id;
                __u64 temp_count = stats[j].count;
                __u64 temp_errors = stats[j].errors;
                __u64 temp_latency = stats[j].latency;
                
                stats[j].id = stats[j + 1].id;
                stats[j].count = stats[j + 1].count;
                stats[j].errors = stats[j + 1].errors;
                stats[j].latency = stats[j + 1].latency;
                
                stats[j + 1].id = temp_id;
                stats[j + 1].count = temp_count;
                stats[j + 1].errors = temp_errors;
                stats[j + 1].latency = temp_latency;
            }
        }
    }
} else {
    for (int i = 0; i < stat_count - 1; i++) {
        for (int j = 0; j < stat_count - i - 1; j++) {
            if (stats[j].id > stats[j + 1].id) {
                __u32 temp_id = stats[j].id;
                __u64 temp_count = stats[j].count;
                __u64 temp_errors = stats[j].errors;
                __u64 temp_latency = stats[j].latency;
                
                stats[j].id = stats[j + 1].id;
                stats[j].count = stats[j + 1].count;
                stats[j].errors = stats[j + 1].errors;
                stats[j].latency = stats[j + 1].latency;
                
                stats[j + 1].id = temp_id;
                stats[j + 1].count = temp_count;
                stats[j + 1].errors = temp_errors;
                stats[j + 1].latency = temp_latency;
            }
        }
    }
}
        
        int display_count = stat_count;
        if (opts.top_n > 0 && opts.top_n < stat_count) {
            display_count = opts.top_n;
        }
        
        for (int i = 0; i < display_count; i++) {
            const char *name;
            if (stats[i].id < MAX_SYSCALL_ID) {
                name = syscall_names[stats[i].id];
            } else {
                name = "unknown";
            }
            
            if (opts.timestamp) {
                printf("%-8ld ", time(NULL) - start_time);
            }
            
            switch (opts.type) {
                case COUNT_ONLY:
                    printf("%-20s %-10llu\n", name, stats[i].count);
                    break;
                    
                case SHOW_ERRORS:
                    printf("%-20s %-10llu %-10llu\n", 
                        name, stats[i].count, stats[i].errors);
                    break;
                    
                case SHOW_LATENCY: {
                    double avg_us = 0;
                    if (stats[i].count > 0) {
                        avg_us = (double)stats[i].latency / stats[i].count / 1000.0; // ns to us
                    }
                    printf("%-20s %-10llu %-15.2f\n", 
                        name, stats[i].count, avg_us);
                    break;
                }
                
                case SHOW_BOTH: {
                    double avg_us = 0;
                    if (stats[i].count > 0) {
                        avg_us = (double)stats[i].latency / stats[i].count / 1000.0; // ns to us
                    }
                    printf("%-20s %-10llu %-10llu %-15.2f\n", 
                        name, stats[i].count, stats[i].errors, avg_us);
                    break;
                }
            }
        }
        

        __u64 total_count = 0, total_errors = 0, total_latency = 0;
        for (int i = 0; i < stat_count; i++) {
            total_count += stats[i].count;
            total_errors += stats[i].errors;
            total_latency += stats[i].latency;
        }
        
        if (opts.timestamp) {
            printf("%-8ld ", time(NULL) - start_time);
        }
        
        switch (opts.type) {
            case COUNT_ONLY:
                printf("%-20s %-10llu\n", "TOTAL", total_count);
                break;
                
            case SHOW_ERRORS:
                printf("%-20s %-10llu %-10llu\n", 
                    "TOTAL", total_count, total_errors);
                break;
                
            case SHOW_LATENCY: {
                double avg_us = 0;
                if (total_count > 0) {
                    avg_us = (double)total_latency / total_count / 1000.0; // ns to us
                }
                printf("%-20s %-10llu %-15.2f\n", 
                    "TOTAL", total_count, avg_us);
                break;
            }
            
            case SHOW_BOTH: {
                double avg_us = 0;
                if (total_count > 0) {
                    avg_us = (double)total_latency / total_count / 1000.0; // ns to us
                }
                printf("%-20s %-10llu %-10llu %-15.2f\n", 
                    "TOTAL", total_count, total_errors, avg_us);
                break;
            }
        }
        
        printf("\n");
    }
    
cleanup:
    printf("\nDetaching programs\n");
    for (int i = 0; i < link_count; i++) {
        bpf_link__destroy(links[i]);
    }
    free(links);
    return err;
}
