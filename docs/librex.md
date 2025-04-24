# LIBREX

`librex` serves as the loader library for Rex programs -- similar to what
`libbpf` is to eBPF programs -- but in a simpler way.

### APIs

`librex` only contains the code that loads Rex programs from ELF binaries,
other operations (e.g., attachment, map manipulation, etc) are delegated to
the existing code in `libbpf`.

Therefore, the library only exposes the following simple APIs:
```c
struct rex_obj *rex_obj_load(const char *file_path);
struct bpf_object *rex_obj_get_bpf(struct rex_obj *obj);
void rex_set_debug(int val);
```

The `rex_obj_load` function loads the Rex programs from the ELF binary
identified by the `file_path` argument into the kernel. It returns a
pointer to the corresponding `rex_obj` that encapsulates information about
the loaded programs and created maps. If there is an error, a null pointer
is returned.

The `rex_obj_get_bpf` returns a pointer to the equivalent `bpf_object` of
the `obj` argument, which can be subsequently passed to `libbpf` APIs. If
there is an error, a null pointer is returned.

**Note**: The returned pointer from both functions above are **non-owning**
pointers, which means the caller of these function should not try to
`free`/`realloc`/`delete` the pointer. The ownership of the pointers is
managed by `librex` internally and will be automatically freed after the
program terminates.

The `rex_set_debug` function can be used to toggle the internal logging
mechanism of `librex` (with `(bool)val` determining whether logging is
enabled). This will most likely be helpful during debugging.

### Build

Building `librex` requires a `c++23` compatible compiler and the `mold`
linker. With dependencies installed, simply invoke the Makefile:

```bash
make
```
