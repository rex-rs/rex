#ifndef LOADER_H
#define LOADER_H

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#ifdef __cplusplus
extern "C" {
#endif

struct bpf_object* load_rex_program(const char* file_path);

int attach_program(struct bpf_object* obj, const char* prog_name, struct bpf_link** link);

int get_map_fd(struct bpf_object* obj, const char* map_name);

int lookup_map_value(int map_fd, const void* key, void* value, size_t value_size);

int get_next_map_key(int map_fd, const void* key, void* next_key);

void detach_programs(struct bpf_link** links, int count);

#ifdef __cplusplus
}
#endif

#endif // LOADER_H
