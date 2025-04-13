#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

#include <linux/unistd.h>
#include <linux/perf_event.h>

#include "trace_helpers.h"
#include <librex.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define EXE "target/x86_64-unknown-none/release/trace_event_kern"

#define SAMPLE_FREQ 50

static int pid;
/* counts, stackmap */
static int map_fd[2];
struct bpf_program *prog;
static bool sys_read_seen, sys_write_seen;

static inline long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
				   int cpu, int group_fd, unsigned long flags)
{
	return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd,
		       flags);
}

static void read_trace_pipe(void)
{
	int trace_pipe_fd;

	trace_pipe_fd = openat(AT_FDCWD, "/sys/kernel/debug/tracing/trace_pipe",
			       O_RDONLY);

	for (;;) {
		char c;
		if (read(trace_pipe_fd, &c, 1) == 1)
			putchar(c);
	}
}

static void print_ksym(__u64 addr)
{
	struct ksym *sym;

	if (!addr)
		return;
	sym = ksym_search(addr);
	if (!sym) {
		printf("ksym not found. Is kallsyms loaded?\n");
		return;
	}

	printf("%s;", sym->name);
	if (!strstr(sym->name, "sys_read"))
		sys_read_seen = true;
	else if (!strstr(sym->name, "sys_write"))
		sys_write_seen = true;
}

static void print_addr(__u64 addr)
{
	if (!addr)
		return;
	printf("%llx;", addr);
}

#define TASK_COMM_LEN 16

struct key_t {
	char comm[TASK_COMM_LEN];
	__u32 kernstack;
	__u32 userstack;
};

static void print_stack(struct key_t *key, __u64 count)
{
	__u64 ip[PERF_MAX_STACK_DEPTH] = {};
	static bool warned;
	int i;

	printf("%3lld %s;", count, key->comm);
	if (bpf_map_lookup_elem(map_fd[1], &key->kernstack, ip) != 0) {
		printf("---;");
	} else {
		for (i = PERF_MAX_STACK_DEPTH - 1; i >= 0; i--)
			print_ksym(ip[i]);
	}
	printf("-;");
	if (bpf_map_lookup_elem(map_fd[1], &key->userstack, ip) != 0) {
		printf("---;");
	} else {
		for (i = PERF_MAX_STACK_DEPTH - 1; i >= 0; i--)
			print_addr(ip[i]);
	}
	if (count < 6)
		printf("\r");
	else
		printf("\n");

	if (key->kernstack == -EEXIST && !warned) {
		printf("stackmap collisions seen. Consider increasing size\n");
		warned = true;
	} else if ((int)key->kernstack < 0 && (int)key->userstack < 0) {
		printf("err stackid %d %d\n", key->kernstack, key->userstack);
	}
}

static void err_exit(int err)
{
	if (pid)
		kill(pid, SIGKILL);
	exit(err);
}

static void print_stacks(void)
{
	struct key_t key = {}, next_key;
	__u64 value;
	__u32 stackid = 0, next_id;
	int error = 1, fd = map_fd[0], stack_map = map_fd[1];

	sys_read_seen = sys_write_seen = false;
	while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
		bpf_map_lookup_elem(fd, &next_key, &value);
		print_stack(&next_key, value);
		bpf_map_delete_elem(fd, &next_key);
		key = next_key;
	}
	printf("\n");
	if (!sys_read_seen || !sys_write_seen) {
		printf("BUG kernel stack doesn't contain sys_read() and sys_write()\n");
		err_exit(error);
	}

	/* clear stack map */
	while (bpf_map_get_next_key(stack_map, &stackid, &next_id) == 0) {
		bpf_map_delete_elem(stack_map, &next_id);
		stackid = next_id;
	}
}

static inline int generate_load(void)
{
	if (system("dd if=/dev/zero of=/dev/null count=5000k status=none") <
	    0) {
		printf("failed to generate some load with dd: %s\n",
		       strerror(errno));
		return -1;
	}

	return 0;
}

static void test_perf_event_all_cpu(struct perf_event_attr *attr)
{
	int nr_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	struct bpf_link **links = calloc(nr_cpus, sizeof(struct bpf_link *));
	int i, pmu_fd, error = 1;

	if (!links) {
		printf("malloc of links failed\n");
		goto err;
	}

	/* system wide perf event, no need to inherit */
	attr->inherit = 0;

	/* open perf_event on all cpus */
	for (i = 0; i < nr_cpus; i++) {
		pmu_fd = perf_event_open(attr, -1, i, -1, 0);
		if (pmu_fd < 0) {
			printf("perf_event_open failed\n");
			goto all_cpu_err;
		}
		links[i] = bpf_program__attach_perf_event(prog, pmu_fd);
		if (libbpf_get_error(links[i])) {
			printf("bpf_program__attach_perf_event failed\n");
			links[i] = NULL;
			close(pmu_fd);
			goto all_cpu_err;
		}
	}

	if (generate_load() < 0)
		goto all_cpu_err;

	print_stacks();
	error = 0;
all_cpu_err:
	for (i--; i >= 0; i--)
		bpf_link__destroy(links[i]);
err:
	free(links);
	if (error)
		err_exit(error);
}

static void test_perf_event_task(struct perf_event_attr *attr)
{
	struct bpf_link *link = NULL;
	int pmu_fd, error = 1;

	/* per task perf event, enable inherit so the "dd ..." command can be traced properly.
	 * Enabling inherit will cause bpf_perf_prog_read_time helper failure.
	 */
	attr->inherit = 1;

	/* open task bound event */
	pmu_fd = perf_event_open(attr, 0, -1, -1, 0);
	if (pmu_fd < 0) {
		printf("perf_event_open failed\n");
		goto err;
	}
	link = bpf_program__attach_perf_event(prog, pmu_fd);
	if (libbpf_get_error(link)) {
		printf("bpf_program__attach_perf_event failed\n");
		link = NULL;
		close(pmu_fd);
		goto err;
	}

	if (generate_load() < 0)
		goto err;

	print_stacks();
	error = 0;
err:
	bpf_link__destroy(link);
	if (error)
		err_exit(error);
}

static void test_bpf_perf_event(void)
{
	struct perf_event_attr attr_type_hw = {
		.sample_freq = SAMPLE_FREQ,
		.freq = 1,
		.type = PERF_TYPE_HARDWARE,
		.config = PERF_COUNT_HW_CPU_CYCLES,
	};
	struct perf_event_attr attr_type_sw = {
		.sample_freq = SAMPLE_FREQ,
		.freq = 1,
		.type = PERF_TYPE_SOFTWARE,
		.config = PERF_COUNT_SW_CPU_CLOCK,
	};
	struct perf_event_attr attr_hw_cache_l1d = {
		.sample_freq = SAMPLE_FREQ,
		.freq = 1,
		.type = PERF_TYPE_HW_CACHE,
		.config = PERF_COUNT_HW_CACHE_L1D |
			  (PERF_COUNT_HW_CACHE_OP_READ << 8) |
			  (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16),
	};
	struct perf_event_attr attr_type_raw = {
		.sample_freq = SAMPLE_FREQ,
		.freq = 1,
		.type = PERF_TYPE_RAW,
		/* Intel Instruction Retired */
		.config = 0xc0,
	};

	printf("Test HW_CPU_CYCLES\n");
	test_perf_event_all_cpu(&attr_type_hw);
	test_perf_event_task(&attr_type_hw);

	printf("Test SW_CPU_CLOCK\n");
	test_perf_event_all_cpu(&attr_type_sw);
	test_perf_event_task(&attr_type_sw);

	printf("Test HW_CACHE_L1D\n");
	test_perf_event_all_cpu(&attr_hw_cache_l1d);
	test_perf_event_task(&attr_hw_cache_l1d);

	printf("Test Instruction Retired\n");
	test_perf_event_all_cpu(&attr_type_raw);
	test_perf_event_task(&attr_type_raw);

	printf("*** PASS ***\n");
}

int main(int argc, char **argv)
{
	struct bpf_object *obj = NULL;
	char filename[256];
	int error = 1;

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	signal(SIGINT, err_exit);
	signal(SIGTERM, err_exit);

	if (load_kallsyms()) {
		printf("failed to process /proc/kallsyms\n");
		goto cleanup;
	}

	obj = rex_obj_get_bpf(rex_obj_load(EXE));
	if (libbpf_get_error(obj)) {
		printf("opening BPF object file failed\n");
		obj = NULL;
		goto cleanup;
	}

	prog = bpf_object__find_program_by_name(obj, "rex_prog1");
	if (!prog) {
		printf("finding a prog in obj file failed\n");
		goto cleanup;
	}

	map_fd[0] = bpf_object__find_map_fd_by_name(obj, "counts");
	map_fd[1] = bpf_object__find_map_fd_by_name(obj, "stackmap");
	if (map_fd[0] < 0 || map_fd[1] < 0) {
		printf("finding a counts/stackmap map in obj file failed\n");
		goto cleanup;
	}

	pid = fork();
	if (pid == 0) {
		read_trace_pipe();
		return 0;
	} else if (pid == -1) {
		printf("couldn't spawn process\n");
		goto cleanup;
	}

	test_bpf_perf_event();
	error = 0;

	kill(pid, SIGTERM);
	waitpid(pid, NULL, 0);

cleanup:
	return error;
}
