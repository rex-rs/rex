#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <librex.h>

#include "loader.h"

struct bpf_object* load_rex_program(const char* file_path) {
    struct rex_obj* obj = rex_obj_load(file_path);
    if (!obj) {
        fprintf(stderr, "Failed to load Rex object\n");
        return NULL;
    }
    
    struct bpf_object* bpf_obj = rex_obj_get_bpf(obj);
    if (!bpf_obj) {
        fprintf(stderr, "Failed to get BPF object\n");
        return NULL;
    }
    
    return bpf_obj;
}


int attach_program(struct bpf_object* obj, const char* prog_name, struct bpf_link** link) {
    struct bpf_program* prog = bpf_object__find_program_by_name(obj, prog_name);
    if (!prog) {
        fprintf(stderr, "Failed to find program: %s\n", prog_name);
        return -1;
    }
    
    *link = bpf_program__attach(prog);
    if (libbpf_get_error(*link)) {
        fprintf(stderr, "Failed to attach program: %s\n", prog_name);
        *link = NULL;
        return -1;
    }
    
    printf("Attached program: %s\n", prog_name);
    return 0;
}


int get_map_fd(struct bpf_object* obj, const char* map_name) {
    int fd = bpf_object__find_map_fd_by_name(obj, map_name);
    if (fd < 0) {
        fprintf(stderr, "Failed to find map: %s\n", map_name);
    }
    return fd;
}


int lookup_map_value(int map_fd, const void* key, void* value, size_t value_size) {
    return bpf_map_lookup_elem(map_fd, key, value);
}


int get_next_map_key(int map_fd, const void* key, void* next_key) {
    return bpf_map_get_next_key(map_fd, key, next_key);
}


void detach_programs(struct bpf_link** links, int count) {
    for (int i = 0; i < count; i++) {
        if (links[i]) {
            bpf_link__destroy(links[i]);
            links[i] = NULL;
        }
    }
}
