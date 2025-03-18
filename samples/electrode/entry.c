#include <arpa/inet.h>
#include <asm-generic/posix_types.h>
#include <assert.h>
#include <bpf.h>
#include <libbpf.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/limits.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "fast_common.h"
#include <librex.h>

#define BPF_SYSFS_ROOT "/sys/fs/bpf"

#define EXE "./target/x86_64-unknown-linux-gnu/release/electrode"

struct bpf_progs_desc {
	char name[256];
	enum bpf_prog_type type;
	unsigned char pin;
	int map_prog_idx;
	struct bpf_program *prog;
};

struct bpf_object *obj;
struct bpf_object_load_attr *load_attr;
struct bpf_program *rx_prog, *tx_prog;
int err, prog_count;
int base_fd, rx_prog_fd, tx_prog_fd, xdp_main_prog_fd;
char filename[PATH_MAX];
char prog_name[PATH_MAX];
char commandname[PATH_MAX];
__u32 xdp_flags = 0;
int *interfaces_idx;

struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };

int opt;

int map_progs_fd, map_progs_xdp_fd, map_progs_tc_fd, map_paxos_ctr_state_fd;
int map_prepare_buffer_fd, map_configure_fd, map_request_buffer_fd;
int interface_count = 0;
static int nr_cpus = 0;

// define our eBPF program.
static struct bpf_progs_desc progs[] = {
	{ "fast_paxos", BPF_PROG_TYPE_XDP, 0, -1, NULL },
	{ "FastBroadCast", BPF_PROG_TYPE_SCHED_CLS, 1, -1, NULL },
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG || level == LIBBPF_INFO) {
		return vfprintf(stderr, format, args);
	}
	return 0;
}

void read_config()
{
	map_configure_fd =
		bpf_object__find_map_fd_by_name(obj, "map_configure");
	if (map_configure_fd < 0) {
		fprintf(stderr,
			"Error: bpf_object__find_map_fd_by_name failed\n");
		exit(1); // return 1;
	}

	FILE *fp;
	char buff[255];
	int f = 0, port = 0;

	struct sockaddr_in sa;
	char str[INET_ADDRSTRLEN];
	struct paxos_configure conf;
	int ret = 0;

	const char *eths[FAST_REPLICA_MAX] = { "9c:dc:71:56:8f:45",
					       "9c:dc:71:56:bf:45",
					       "9c:dc:71:5e:2f:51", "", "" };

	fp = fopen("./config.txt", "r");
	if (fp == NULL) {
		fprintf(stderr, "Error: failed to open config.txt\n");
		exit(1);
	}

	ret = fscanf(fp, "%s", buff); // must be 'f'
	ret = fscanf(fp, "%d", &f);
	for (int i = 0; i < 2 * f + 1; ++i) {
		ret = fscanf(fp, "%s", buff); // must be 'replica'
		ret = fscanf(fp, "%s", buff);

		char *ipv4 = strtok(buff, ":");
		assert(ipv4 != NULL);
		char *port = strtok(NULL, ":");

		// store this IP address in sa:
		inet_pton(AF_INET, ipv4, &(sa.sin_addr));
		// now get it back and print it
		inet_ntop(AF_INET, &(sa.sin_addr), str, INET_ADDRSTRLEN);
		conf.port = htons(atoi(port));
		conf.addr = sa.sin_addr.s_addr;
		int items_read =
			sscanf(eths[i], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
			       &conf.eth[0], &conf.eth[1], &conf.eth[2],
			       &conf.eth[3], &conf.eth[4], &conf.eth[5]);

		err = bpf_map_update_elem(map_configure_fd, &i, &conf, 0);
	}

	fclose(fp);
	return;
}

void create_object()
{
	map_prepare_buffer_fd =
		bpf_object__find_map_fd_by_name(obj, "map_prepare_buffer");
	if (map_prepare_buffer_fd < 0) {
		fprintf(stderr,
			"Error: bpf_object__find_map_fd_by_name failed\n");
		exit(1); // return 1;
	}
	map_request_buffer_fd =
		bpf_object__find_map_fd_by_name(obj, "map_request_buffer");
	if (map_request_buffer_fd < 0) {
		fprintf(stderr,
			"Error: bpf_object__find_map_fd_by_name failed\n");
		exit(1); // return 1;
	}
	map_paxos_ctr_state_fd =
		bpf_object__find_map_fd_by_name(obj, "map_ctr_state");
	if (map_paxos_ctr_state_fd < 0) {
		fprintf(stderr,
			"Error: bpf_object__find_map_fd_by_name failed\n");
		exit(1); // return 1;
	}
}

void add_interrupt()
{
	/* asd123www:
          !!!!!! the user-space program shouldn't quit here.
                          Otherwise the program will be lost, due to fd lost???
  */
	sigset_t signal_mask;
	sigemptyset(&signal_mask);
	sigaddset(&signal_mask, SIGINT);
	sigaddset(&signal_mask, SIGTERM);
	sigaddset(&signal_mask, SIGUSR1);

	int sig, cur_poll_count = 0, quit = 0;
	// FILE *fp = NULL;

	err = sigprocmask(SIG_BLOCK, &signal_mask, NULL);
	if (err != 0) {
		fprintf(stderr, "Error: Failed to set signal mask\n");
		exit(EXIT_FAILURE);
	}

	while (!quit) {
		err = sigwait(&signal_mask, &sig);
		if (err != 0) {
			fprintf(stderr, "Error: Failed to wait for signal\n");
			exit(EXIT_FAILURE);
		}

		switch (sig) {
		case SIGINT:
		case SIGTERM:
			quit = 1;
			break;

		default:
			fprintf(stderr, "Unknown signal\n");
			break;
		}
	}
	return;
}

int main(int argc, char *argv[])
{
	int ret = 0;
	libbpf_set_print(libbpf_print_fn);
	rex_set_debug(1); // enable debug info

	obj = rex_obj_get_bpf(rex_obj_load(EXE));
	if (!obj) {
		fprintf(stderr, "Object could not be opened\n");
		return 1;
	}

	interface_count = argc - optind;
	if (interface_count <= 0) {
		fprintf(stderr,
			"Missing at least one required interface index\n");
		return 1;
	}

	interfaces_idx = calloc(sizeof(int), interface_count);
	if (interfaces_idx == NULL) {
		fprintf(stderr, "Error: failed to allocate memory\n");
		return 1;
	}

	for (int i = 0; i < interface_count && optind < argc; optind++, i++) {
		interfaces_idx[i] = atoi(argv[optind]);
	}
	nr_cpus = libbpf_num_possible_cpus();

	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		perror("setrlimit failed");
		return 1;
	}

	create_object();
	read_config();
	assert(bpf_obj_pin(map_prepare_buffer_fd,
			   "/sys/fs/bpf/paxos_prepare_buffer") == 0);
	assert(bpf_obj_pin(map_request_buffer_fd,
			   "/sys/fs/bpf/paxos_request_buffer") == 0);
	assert(bpf_obj_pin(map_paxos_ctr_state_fd,
			   "/sys/fs/bpf/paxos_ctr_state") == 0);

	rx_prog = bpf_object__find_program_by_name(obj, progs[0].name);
	if (!rx_prog) {
		fprintf(stderr, "start not found\n");
		exit(1);
	}

	xdp_main_prog_fd = bpf_program__fd(rx_prog);
	if (xdp_main_prog_fd < 0) {
		fprintf(stderr, "Error: bpf_program__fd failed\n");
		return 1;
	}

	xdp_flags |= XDP_FLAGS_DRV_MODE;
	/* xdp_flags |= XDP_FLAGS_SKB_MODE; */
	for (int i = 0; i < interface_count; i++) {
		if (bpf_set_link_xdp_fd(interfaces_idx[i], xdp_main_prog_fd,
					xdp_flags) < 0) {
			fprintf(stderr,
				"Error: bpf_set_link_xdp_fd failed for interface %d\n",
				interfaces_idx[i]);
			return 1;
		} else {
			printf("Main BPF program attached to XDP on interface %d\n",
			       interfaces_idx[i]);
		}
	}

	tx_prog = bpf_object__find_program_by_name(obj, progs[1].name);
	if (!tx_prog) {
		fprintf(stderr, "tx_prog not found\n");
		exit(1);
	}
	printf("tx_prog: %s\n", bpf_program__name(tx_prog));

	int len = snprintf(filename, PATH_MAX, "%s/%s", BPF_SYSFS_ROOT,
			   progs[1].name);
	if (len < 0) {
		fprintf(stderr, "Error: Program name '%s' is invalid\n",
			"xdp_tx_filter");
		return -1;
	} else if (len >= PATH_MAX) {
		fprintf(stderr, "Error: Program name '%s' is too long\n",
			progs[1].name);
		return -1;
	}

	// pin sched_cls
	ret = bpf_program__pin(tx_prog, filename);
	if (ret != 0) {
		fprintf(stderr,
			"Error: Failed to pin program '%s' to path %s with error code %d\n",
			prog_name, filename, ret);
		return ret;
	}

	for (int i = 0; i < interface_count && optind < argc; i++) {
		snprintf(commandname, PATH_MAX, "tc qdisc add dev %s clsact",
			 argv[optind + i]);
		assert(system(commandname) == 0);
		snprintf(commandname, PATH_MAX,
			 "tc filter add dev %s egress bpf object-pinned "
			 "/sys/fs/bpf/FastBroadCast",
			 argv[optind + i]);
		assert(system(commandname) == 0);
		printf("Main BPF program attached to TC on interface %d\n",
		       interfaces_idx[i]);
	}

	add_interrupt();

	assert(remove("/sys/fs/bpf/paxos_prepare_buffer") == 0);
	assert(remove("/sys/fs/bpf/paxos_request_buffer") == 0);
	assert(remove("/sys/fs/bpf/paxos_ctr_state") == 0);

	for (int i = 0; i < interface_count; i++) {
		bpf_set_link_xdp_fd(interfaces_idx[i], -1, xdp_flags);
	}
	for (int i = 0; i < interface_count && optind < argc; i++) {
		snprintf(commandname, PATH_MAX, "tc filter del dev %s egress",
			 argv[optind + i]);
		assert(system(commandname) == 0);
		snprintf(commandname, PATH_MAX, "tc qdisc del dev %s clsact",
			 argv[optind + i]);
		assert(system(commandname) == 0);
	}
	assert(system("rm -f /sys/fs/bpf/FastBroadCast") == 0);
	printf("\nasd123www: quit safely!\n");

	return 0;
}
