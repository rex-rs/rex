// This file contains the non-portable part, it has to mirror some libbpf types

#ifndef _LIBREX_BINDINGS_H
#define _LIBREX_BINDINGS_H

#include <bpf/libbpf.h>
#include <gelf.h>

/* From tools/lib/bpf/libbpf_internal.h */
#define SHA256_DIGEST_LENGTH 32

struct elf_state {
  int fd;
  const void *obj_buf;
  size_t obj_buf_sz;
  Elf *elf;
  Elf64_Ehdr *ehdr;
  Elf_Data *symbols;
  Elf_Data *arena_data;
  size_t shstrndx; /* section index for section name strings */
  size_t strtabidx;
  struct elf_sec_desc *secs;
  size_t sec_cnt;
  int btf_maps_shndx;
  __u32 btf_maps_sec_btf_id;
  int text_shndx;
  int symbols_shndx;
  bool has_st_ops;
  int arena_data_shndx;
};

struct bpf_sec_def {
  char *sec;
  enum bpf_prog_type prog_type;
  enum bpf_attach_type expected_attach_type;
  long cookie;
  int handler_id;

  libbpf_prog_setup_fn_t prog_setup_fn;
  libbpf_prog_prepare_load_fn_t prog_prepare_load_fn;
  libbpf_prog_attach_fn_t prog_attach_fn;
};

enum bpf_object_state {
  OBJ_OPEN,
  OBJ_PREPARED,
  OBJ_LOADED,
};

struct bpf_object {
  char name[BPF_OBJ_NAME_LEN];
  char license[64];
  __u32 kern_version;

  enum bpf_object_state state;
  struct bpf_program *programs;
  size_t nr_programs;
  struct bpf_map *maps;
  size_t nr_maps;
  size_t maps_cap;

  char *kconfig;
  struct extern_desc *externs;
  int nr_extern;
  int kconfig_map_idx;

  bool has_subcalls;
  bool has_rodata;

  struct bpf_gen *gen_loader;

  /* Information when doing ELF related work. Only valid if efile.elf is not
   * NULL */
  struct elf_state efile;

  unsigned char byteorder;

  struct btf *btf;
  struct btf_ext *btf_ext;

  /* Parse and load BTF vmlinux if any of the programs in the object need
   * it at load time.
   */
  struct btf *btf_vmlinux;
  /* Path to the custom BTF to be used for BPF CO-RE relocations as an
   * override for vmlinux BTF.
   */
  char *btf_custom_path;
  /* vmlinux BTF override for CO-RE relocations */
  struct btf *btf_vmlinux_override;
  /* Lazily initialized kernel module BTFs */
  struct module_btf *btf_modules;
  bool btf_modules_loaded;
  size_t btf_module_cnt;
  size_t btf_module_cap;

  /* optional log settings passed to BPF_BTF_LOAD and BPF_PROG_LOAD commands */
  char *log_buf;
  size_t log_size;
  __u32 log_level;

  int *fd_array;
  size_t fd_array_cap;
  size_t fd_array_cnt;

  struct usdt_manager *usdt_man;

  int arena_map_idx;
  void *arena_data;
  size_t arena_data_sz;

  struct kern_feature_cache *feat_cache;
  char *token_path;
  int token_fd;

  char path[];
};

/*
 * bpf_prog should be a better name but it has been used in
 * linux/filter.h.
 */
struct bpf_program {
  char *name;
  char *sec_name;
  size_t sec_idx;
  const struct bpf_sec_def *sec_def;
  /* this program's instruction offset (in number of instructions)
   * within its containing ELF section
   */
  size_t sec_insn_off;
  /* number of original instructions in ELF section belonging to this
   * program, not taking into account subprogram instructions possible
   * appended later during relocation
   */
  size_t sec_insn_cnt;
  /* Offset (in number of instructions) of the start of instruction
   * belonging to this BPF program  within its containing main BPF
   * program. For the entry-point (main) BPF program, this is always
   * zero. For a sub-program, this gets reset before each of main BPF
   * programs are processed and relocated and is used to determined
   * whether sub-program was already appended to the main program, and
   * if yes, at which instruction offset.
   */
  size_t sub_insn_off;

  /* instructions that belong to BPF program; insns[0] is located at
   * sec_insn_off instruction within its ELF section in ELF file, so
   * when mapping ELF file instruction index to the local instruction,
   * one needs to subtract sec_insn_off; and vice versa.
   */
  struct bpf_insn *insns;
  /* actual number of instruction in this BPF program's image; for
   * entry-point BPF programs this includes the size of main program
   * itself plus all the used sub-programs, appended at the end
   */
  size_t insns_cnt;

  struct reloc_desc *reloc_desc;
  int nr_reloc;

  /* BPF verifier log settings */
  char *log_buf;
  size_t log_size;
  __u32 log_level;

  struct bpf_object *obj;

  int fd;
  bool autoload;
  bool autoattach;
  bool sym_global;
  bool mark_btf_static;
  enum bpf_prog_type type;
  enum bpf_attach_type expected_attach_type;
  int exception_cb_idx;

  int prog_ifindex;
  __u32 attach_btf_obj_fd;
  __u32 attach_btf_id;
  __u32 attach_prog_fd;

  void *func_info;
  __u32 func_info_rec_size;
  __u32 func_info_cnt;

  void *line_info;
  __u32 line_info_rec_size;
  __u32 line_info_cnt;
  __u32 prog_flags;
  __u8 hash[SHA256_DIGEST_LENGTH];
};

enum libbpf_map_type {
  LIBBPF_MAP_UNSPEC,
  LIBBPF_MAP_DATA,
  LIBBPF_MAP_BSS,
  LIBBPF_MAP_RODATA,
  LIBBPF_MAP_KCONFIG,
};

struct bpf_map_def {
  unsigned int type;
  unsigned int key_size;
  unsigned int value_size;
  unsigned int max_entries;
  unsigned int map_flags;
};

struct bpf_map {
  struct bpf_object *obj;
  char *name;
  /* real_name is defined for special internal maps (.rodata*,
   * .data*, .bss, .kconfig) and preserves their original ELF section
   * name. This is important to be able to find corresponding BTF
   * DATASEC information.
   */
  char *real_name;
  int fd;
  int sec_idx;
  size_t sec_offset;
  int map_ifindex;
  int inner_map_fd;
  struct bpf_map_def def;
  __u32 numa_node;
  __u32 btf_var_idx;
  int mod_btf_fd;
  __u32 btf_key_type_id;
  __u32 btf_value_type_id;
  __u32 btf_vmlinux_value_type_id;
  enum libbpf_map_type libbpf_type;
  void *mmaped;
  struct bpf_struct_ops *st_ops;
  struct bpf_map *inner_map;
  void **init_slots;
  int init_slots_sz;
  char *pin_path;
  bool pinned;
  bool reused;
  bool autocreate;
  bool autoattach;
  __u64 map_extra;
  struct bpf_program *excl_prog;
};

#endif // _LIBREX_BINDINGS_H
