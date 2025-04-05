#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <linux/perf_event.h>
#include <linux/unistd.h>

#include <librex.h>
#include <bpf/libbpf.h>

#define EXE "./target/x86_64-unknown-none/release/hello"

int main(void)
{
	int trace_pipe_fd;
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_link *link = NULL;

	obj = rex_obj_get_bpf(rex_obj_load(EXE));
	if (!obj) {
		fprintf(stderr, "Object could not be opened\n");
		return 1;
	}

	prog = bpf_object__find_program_by_name(obj, "rex_prog1");
	if (!prog) {
		fprintf(stderr, "_start not found\n");
		return 1;
	}

	link = bpf_program__attach(prog);
	if (libbpf_get_error(link)) {
		fprintf(stderr, "ERROR: bpf_program__attach failed\n");
		link = NULL;
		return 1;
	}

	trace_pipe_fd = openat(AT_FDCWD, "/sys/kernel/debug/tracing/trace_pipe",
			       O_RDONLY);

	for (;;) {
		char c;
		fflush(stdout);
		if (read(trace_pipe_fd, &c, 1) == 1)
			putchar(c);
	}

	bpf_link__destroy(link);
	return 0;
}
