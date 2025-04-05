// Functions
#define KSYM_FUNC(func) \
  int func() { return 0; }

KSYM_FUNC(bpf_get_current_pid_tgid)
KSYM_FUNC(bpf_trace_printk)
KSYM_FUNC(bpf_map_lookup_elem)
KSYM_FUNC(bpf_map_update_elem)
KSYM_FUNC(bpf_map_delete_elem)
KSYM_FUNC(bpf_map_push_elem)
KSYM_FUNC(bpf_map_pop_elem)
KSYM_FUNC(bpf_map_peek_elem)
KSYM_FUNC(bpf_probe_read_kernel)
KSYM_FUNC(ktime_get_mono_fast_ns)
KSYM_FUNC(ktime_get_boot_fast_ns)
KSYM_FUNC(get_random_u32)
KSYM_FUNC(bpf_snprintf)
KSYM_FUNC(vprintk)
KSYM_FUNC(rex_landingpad)
KSYM_FUNC(bpf_spin_lock)
KSYM_FUNC(bpf_spin_unlock)
KSYM_FUNC(just_return_func)
KSYM_FUNC(bpf_get_stackid_pe)
KSYM_FUNC(bpf_perf_prog_read_value)
KSYM_FUNC(bpf_xdp_adjust_head)
KSYM_FUNC(bpf_xdp_adjust_tail)
KSYM_FUNC(bpf_clone_redirect)
KSYM_FUNC(bpf_ringbuf_reserve)
KSYM_FUNC(bpf_ringbuf_submit)
KSYM_FUNC(bpf_ringbuf_discard)
KSYM_FUNC(bpf_ringbuf_query)
KSYM_FUNC(bpf_ktime_get_ns)
KSYM_FUNC(bpf_ktime_get_boot_ns)
KSYM_FUNC(bpf_ktime_get_coarse_ns)
KSYM_FUNC(rex_trace_printk)

// Global variables
unsigned long jiffies;
int numa_node;
void *rex_cleanup_entries;
unsigned long rex_stack_ptr;
void *pcpu_hot;
unsigned char rex_termination_state;
unsigned long this_cpu_off;
char *rex_log_buf;
