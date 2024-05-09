#include <fcntl.h>
#include <libelf.h>
#include <linux/bpf.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <concepts>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <list>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

#include "bindings.h"
#include "librex.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

// Yes, this is opposite to the idea of not doing 'using namespace', but it
// seems to be the only way one can get access to operator""s
// See https://en.cppreference.com/w/cpp/string/basic_string/operator%22%22s
using namespace std::literals::string_literals;

static int debug = 0;

// FIXME: Temporary fix until kernel migrates from iu to rex
using rex_rela_dyn = iu_rela_dyn;
using rex_dyn_sym = iu_dyn_sym;

static const bpf_sec_def *find_sec_def(const char *sec_name) {
  int i, n = ARRAY_SIZE(section_defs);

  for (i = 0; i < n; i++) {
    if (strncmp(sec_name, section_defs[i].sec, section_defs[i].len))
      continue;
    return &section_defs[i];
  }

  return nullptr;
}

template <std::integral T>
static inline T val_from_buf(const unsigned char *buf) {
  return *reinterpret_cast<const T *>(buf);
}

template <std::integral T>
static inline void val_to_buf(unsigned char *buf, const T val) {
  *reinterpret_cast<T *>(buf) = val;
}

static inline long bpf(__u64 cmd, union bpf_attr *attr, unsigned int size) {
  return syscall(__NR_bpf, cmd, attr, size);
}

// This struct is POD, meaning the C++ standard guarantees the same memory
// layout as that of the equivalent C struct
// https://stackoverflow.com/questions/422830/structure-of-a-c-object-in-memory-vs-a-struct
struct map_def {
  uint32_t map_type;
  uint32_t key_size;
  uint32_t val_size;
  uint32_t max_size;
  uint32_t map_flag;
  void *kptr;
};

struct rex_map {
private:
  map_def def;
  std::optional<int> map_fd;
  std::string name;

public:
  rex_map() = delete;
  rex_map(const Elf_Data *data, Elf64_Addr base, Elf64_Off off,
          const char *c_name)
      : map_fd(), name(c_name) {
    auto def_addr = reinterpret_cast<uint64_t>(data->d_buf) + off - base;
    this->def = *reinterpret_cast<map_def *>(def_addr);

    if (debug) {
      std::clog << "sym_name=" << c_name << std::endl;
      std::clog << "map_type=" << this->def.map_type << std::endl;
      std::clog << "key_size=" << this->def.key_size << std::endl;
      std::clog << "val_size=" << this->def.val_size << std::endl;
      std::clog << "max_size=" << this->def.max_size << std::endl;
      std::clog << "map_flag=" << this->def.map_flag << std::endl;
    }
  }

  rex_map(const rex_map &) = delete;
  rex_map(rex_map &&) = delete;

  ~rex_map() {
    map_fd.transform([](int fd) { return close(fd); });
  }

  rex_map &operator=(const rex_map &) = delete;
  rex_map &operator=(rex_map &&) = delete;

  std::optional<int> create() {
    int ret;

    union bpf_attr attr {
      .map_type = def.map_type, .key_size = def.key_size,
      .value_size = def.val_size, .max_entries = def.max_size,
      .map_flags = def.map_flag,
    };

    memcpy(attr.map_name, name.c_str(),
           std::min(name.size(), sizeof(attr.map_name) - 1));

    ret = bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
    if (ret >= 0)
      this->map_fd = ret;

    return this->map_fd;
  }

  // rename bpf_map into bpfmap to avoid name collision
  std::optional<bpf_map> bpfmap() {
    // Do not create a bpf_map if the map has not been loaded
    if (!map_fd)
      return {};

    return bpf_map{
        .name = name.data(),
        .fd = map_fd.value(),
        .inner_map_fd = -1,
        .libbpf_type = LIBBPF_MAP_UNSPEC,
    };
  }

  friend struct ::rex_obj;
};

struct rex_prog {
private:
  std::string name;
  std::string scn_name;
  enum bpf_prog_type prog_type;
  Elf64_Off offset;
  std::optional<int> prog_fd;
  rex_obj &obj;

public:
  rex_prog() = delete;
  rex_prog(const char *nm, const char *scn_nm, Elf64_Off off, rex_obj &obj)
      : name(nm), scn_name(scn_nm), offset(off), obj(obj) {
    prog_type = find_sec_def(scn_name.c_str())->prog_type;
  }

  rex_prog(const rex_prog &) = delete;
  rex_prog(rex_prog &&) = delete;

  ~rex_prog() {
    prog_fd.transform([](int fd) { return close(fd); });
  }

  rex_prog &operator=(const rex_prog &) = delete;
  rex_prog &operator=(rex_prog &&) = delete;

  std::optional<bpf_program> bpf_prog() {
    // Do not create a bpf_program if the prog has not been loaded
    if (!prog_fd)
      return {};

    // bpf_program::obj will be initliazed by the caller
    // bpf_program will never outlive "this" as both are managed by rex_obj,
    // so just redirect pointers
    return bpf_program{
        .sec_name = scn_name.data(),
        .name = name.data(),
        .instances =
            {
                .nr = 1,
                .fds = &prog_fd.value(),
            },
        .type = prog_type,
    };
  }

  friend struct ::rex_obj;
};

struct rex_obj {
private:
  struct elf_del {
    [[gnu::always_inline]] void operator()(Elf *ep) const { elf_end(ep); }
  };

  struct file_map_del {
    size_t size;

    file_map_del() = default;
    explicit file_map_del(size_t sz) : size(sz) {}

    [[gnu::always_inline]] void operator()(unsigned char *addr) const {
      munmap(addr, size);
    }
  };

  struct bpf_obj_del {
    [[gnu::always_inline]] void operator()(bpf_object *bp) const {
      delete[] bp->programs;
      delete[] bp->maps;
      delete bp;
    }
  };

  // std::vector requires T to be move-constructible
  std::list<rex_prog> progs;
  std::unordered_map<Elf64_Off, rex_map> map_defs;

  std::unique_ptr<Elf, elf_del> elf;
  Elf_Scn *symtab_scn;
  Elf_Scn *dynsym_scn;
  Elf_Scn *maps_scn;

  // Global Offset Table for PIE
  Elf_Scn *got_scn;

  // Dynamic relocation for PIE
  Elf_Scn *rela_dyn_scn;
  std::vector<rex_rela_dyn> dyn_relas;
  std::vector<rex_dyn_sym> dyn_syms;
  std::vector<std::string> rela_sym_name;

  std::unique_ptr<unsigned char[], file_map_del> file_map;
  std::optional<int> prog_fd;
  bool loaded;
  std::string basename;
  std::unique_ptr<bpf_object, bpf_obj_del> bpf_obj_ptr;

  int parse_scns();
  int parse_maps();
  int parse_progs();
  int parse_got();
  int parse_rela_dyn();

public:
  rex_obj() = delete;
  explicit rex_obj(const char *);
  rex_obj(const rex_obj &) = delete;
  rex_obj(rex_obj &&) = delete;
  ~rex_obj();

  rex_obj &operator=(const rex_obj &) = delete;
  rex_obj &operator=(rex_obj &&) = delete;

  int parse_elf();
  int fix_maps();
  int load();
  bpf_object *bpf_obj();
};

rex_obj::rex_obj(const char *c_path)
    : map_defs(), symtab_scn(nullptr), dynsym_scn(nullptr), maps_scn(nullptr),
      prog_fd(-1), loaded(false) {
  struct stat st;
  void *mmap_ret;
  int fd = open(c_path, 0, O_RDONLY);
  Elf *ep = elf_begin(fd, ELF_C_READ_MMAP, NULL);
  if (!ep)
    throw std::invalid_argument("elf: failed to open file "s + c_path);

  elf = std::unique_ptr<Elf, elf_del>(ep, elf_del());

  if (fstat(fd, &st) < 0)
    throw std::system_error(errno, std::system_category(), "fstat");

  // MAP_PRIVATE ensures the changes to the memory mapped by mmap(2) are not
  // carried through to the backing file
  mmap_ret = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
  if (mmap_ret == MAP_FAILED)
    throw std::system_error(errno, std::system_category(), "mmap");

  file_map = std::unique_ptr<unsigned char[], file_map_del>(
      reinterpret_cast<unsigned char *>(mmap_ret), file_map_del(st.st_size));

  std::string copy(c_path);
  copy += ".base";
  basename = ::basename(copy.data());
  close(fd);
}

rex_obj::~rex_obj() {
  prog_fd.transform([](int fd) { return close(fd); });
}

int rex_obj::parse_scns() {
  size_t shstrndx;

  if (elf_getshdrstrndx(elf.get(), &shstrndx)) {
    std::cerr << "elf: failed to get section names section index for "
              << std::endl;
    return -1;
  }

  for (auto scn = elf_nextscn(elf.get(), NULL); scn;
       scn = elf_nextscn(elf.get(), scn)) {
    char *name;
    int idx = elf_ndxscn(scn);
    Elf64_Shdr *sh = elf64_getshdr(scn);
    if (!sh) {
      std::cerr << "elf: failed to get section header, idx=" << idx
                << std::endl;
      return -1;
    }

    name = elf_strptr(elf.get(), shstrndx, sh->sh_name);

    if (!name) {
      std::cerr << "elf: failed to get section name" << std::endl;
      return -1;
    }

    if (debug)
      std::clog << "section " << name << ", idx=" << idx << std::endl;

    if (sh->sh_type == SHT_SYMTAB && !strcmp(".symtab", name))
      this->symtab_scn = scn;
    else if (sh->sh_type == SHT_DYNSYM && !strcmp(".dynsym", name))
      this->dynsym_scn = scn;
    else if (!strcmp(".maps", name))
      this->maps_scn = scn;
    else if (sh->sh_type == SHT_RELA && !strcmp(".rela.dyn", name))
      this->rela_dyn_scn = scn;
  }

  if (!this->maps_scn && debug)
    std::clog << "section .maps not found" << std::endl;

  if (!this->rela_dyn_scn && debug)
    std::clog << "section .rela.dyn not found" << std::endl;

  return 0;
}

int rex_obj::parse_maps() {
  Elf_Data *maps, *syms;
  int nr_syms, nr_maps = 0, maps_shndx;
  size_t strtabidx;
  Elf64_Addr maps_shaddr;

  if (!this->maps_scn)
    return 0;

  maps = elf_getdata(maps_scn, 0);
  syms = elf_getdata(symtab_scn, 0);

  if (!syms) {
    std::cerr << "elf: failed to get symbol definitions" << std::endl;
    return -1;
  }

  if (!maps) {
    std::cerr << "elf: failed to get map definitions" << std::endl;
    return -1;
  }

  strtabidx = elf64_getshdr(symtab_scn)->sh_link;
  maps_shndx = elf_ndxscn(maps_scn);
  maps_shaddr = elf64_getshdr(maps_scn)->sh_addr;
  nr_syms = syms->d_size / sizeof(Elf64_Sym);

  for (int i = 0; i < nr_syms; i++) {
    Elf64_Sym *sym = reinterpret_cast<Elf64_Sym *>(syms->d_buf) + i;
    char *name;

    if (sym->st_shndx != maps_shndx ||
        ELF64_ST_TYPE(sym->st_info) != STT_OBJECT)
      continue;

    name = elf_strptr(elf.get(), strtabidx, sym->st_name);
    if (debug) {
      std::clog << "symbol: " << name << ", st_value=0x" << std::hex
                << sym->st_value << ", st_size=" << std::dec << sym->st_size
                << std::endl;
    }

    if (sym->st_size == sizeof(map_def)) {
      map_defs.try_emplace(sym->st_value, maps, maps_shaddr, sym->st_value,
                           name);
    }

    nr_maps++;
  }

  if (debug)
    std::clog << "# of symbols in \".maps\": " << nr_maps << std::endl;

  return 0;
}

// get sec name
// get function symbols
int rex_obj::parse_progs() {
  size_t shstrndx, strtabidx;
  Elf_Data *syms;
  int nr_syms;

  strtabidx = elf64_getshdr(symtab_scn)->sh_link;

  if (elf_getshdrstrndx(elf.get(), &shstrndx)) {
    std::cerr << "elf: failed to get section names section index" << std::endl;
    return -1;
  }

  syms = elf_getdata(symtab_scn, 0);

  if (!syms) {
    std::cerr << "elf: failed to get symbol definitions" << std::endl;
    return -1;
  }

  nr_syms = syms->d_size / sizeof(Elf64_Sym);

  for (int i = 0; i < nr_syms; i++) {
    Elf64_Sym *sym = reinterpret_cast<Elf64_Sym *>(syms->d_buf) + i;
    Elf_Scn *scn = elf_getscn(elf.get(), sym->st_shndx);
    char *scn_name, *sym_name;
    const bpf_sec_def *sec_def;

    if (!scn || ELF64_ST_TYPE(sym->st_info) != STT_FUNC)
      continue;

    scn_name = elf_strptr(elf.get(), shstrndx, elf64_getshdr(scn)->sh_name);
    sym_name = elf_strptr(elf.get(), strtabidx, sym->st_name);
    /*if (debug) {
            std::clog << "section: \"" << scn_name << "\"" << std::endl;
            std::clog << "symbol: \"" << sym_name << "\"" << std::endl;
    }*/

    sec_def = find_sec_def(scn_name);
    if (!sec_def)
      continue;

    sym_name = elf_strptr(elf.get(), strtabidx, sym->st_name);
    progs.emplace_back(sym_name, scn_name, sym->st_value, *this);
  }
  return 0;
};

int rex_obj::parse_rela_dyn() {
  Elf64_Shdr *rela_dyn;
  rex_rela_dyn *rela_dyn_data;
  uint64_t rela_dyn_addr, rela_dyn_size, nr_dyn_relas;
  size_t idx;

  if (!this->rela_dyn_scn)
    return 0;

  rela_dyn = elf64_getshdr(rela_dyn_scn);

  if (!rela_dyn) {
    std::cerr << "elf: failed to get .rela.dyn section" << std::endl;
    return -1;
  }

  rela_dyn_data =
      reinterpret_cast<rex_rela_dyn *>(elf_getdata(rela_dyn_scn, 0)->d_buf);
  rela_dyn_addr = rela_dyn->sh_addr;
  rela_dyn_size = rela_dyn->sh_size;

  if (debug) {
    std::clog << ".rela.dyn offset=" << std::hex << rela_dyn_addr
              << ", .rela.dyn size=" << std::dec << rela_dyn_size << std::endl;
  }

  if (rela_dyn_size % sizeof(rex_rela_dyn)) {
    std::cerr << "elf: ill-formed .rela.dyn section" << std::endl;
    return -1;
  }

  nr_dyn_relas = rela_dyn_size / sizeof(rex_rela_dyn);

  for (idx = 0; idx < nr_dyn_relas; idx++) {
    // Need to skip the map relocs, these are handled differently in the kernel
    if (map_defs.find(rela_dyn_data[idx].addend) != map_defs.end())
      continue;

    if (ELF64_R_TYPE(rela_dyn_data[idx].info) == R_X86_64_RELATIVE) {
      dyn_relas.push_back(rela_dyn_data[idx]);
    } else if (ELF64_R_TYPE(rela_dyn_data[idx].info) == R_X86_64_GLOB_DAT) {
      uint32_t dynsym_idx = ELF64_R_SYM(rela_dyn_data[idx].info);
      Elf_Data *syms = elf_getdata(dynsym_scn, 0);
      size_t strtabidx = elf64_getshdr(dynsym_scn)->sh_link;
      Elf64_Sym *sym = reinterpret_cast<Elf64_Sym *>(syms->d_buf) + dynsym_idx;
      rex_dyn_sym dyn_sym = {};
      char *name = elf_strptr(elf.get(), strtabidx, sym->st_name);

      dyn_sym.offset = rela_dyn_data[idx].offset;
      dyn_sym.symbol = reinterpret_cast<__u64>(name);

      dyn_syms.push_back(dyn_sym);
    } else {
      std::cerr << "elf: relocation type not supported" << std::endl;
      return -1;
    }
  }

  if (debug) {
    std::clog << ".rela.dyn: " << std::hex << std::endl;
    for (auto &dyn_rela : dyn_relas) {
      std::clog << "0x" << dyn_rela.offset << ", 0x" << dyn_rela.info << ", 0x"
                << dyn_rela.addend << std::endl;
    }
    for (auto &dyn_sym : dyn_syms) {
      std::clog << "0x" << dyn_sym.offset << ", "
                << reinterpret_cast<char *>(dyn_sym.symbol) << std::endl;
    }
    std::clog << std::dec;
  }

  return 0;
}

int rex_obj::parse_elf() {
  int ret;

  if (!elf) {
    std::cerr << "elf: failed to open object" << std::endl;
    return -1;
  }

  ret = this->parse_scns();
  ret = ret < 0 ? ret : this->parse_maps();
  ret = ret < 0 ? ret : this->parse_progs();
  ret = ret < 0 ? ret : this->parse_rela_dyn();

  return ret;
}

int rex_obj::fix_maps() {
  Elf64_Addr maps_shaddr;
  Elf64_Off maps_shoff;

  if (!this->maps_scn) {
    return 0;
  }

  maps_shaddr = elf64_getshdr(maps_scn)->sh_addr;
  maps_shoff = elf64_getshdr(maps_scn)->sh_offset;

  if (debug) {
    std::clog << ".maps section file offset=0x" << std::hex
              << elf64_getshdr(maps_scn)->sh_offset << std::dec << std::endl;
  }

  for (auto &def : map_defs) {
    size_t kptr_file_off =
        def.first + offsetof(map_def, kptr) - maps_shaddr + maps_shoff;

    if (debug) {
      std::clog << "map_ptr=0x" << std::hex << def.first << std::dec
                << std::endl;
      std::clog << "map_name=\"" << def.second.name << '\"' << std::endl;
    }

    std::optional<int> map_fd = def.second.create();
    if (!map_fd) {
      perror("bpf_map_create");
      return -1;
    }

    if (debug)
      std::clog << "map_fd=" << map_fd.value() << std::endl;

    val_to_buf<uint64_t>(&this->file_map[kptr_file_off], map_fd.value());
  }

  return 0;
}

int rex_obj::load() {
  int fd;
  auto arr = std::make_unique<uint64_t[]>(map_defs.size());
  union bpf_attr attr = {};
  int idx = 0, ret = 0;

  // TODO: Will have race condition if multiple objs loaded at same time
  std::ofstream output("rust.out", std::ios::out | std::ios::binary);

  output.write((char *)this->file_map.get(), this->file_map.get_deleter().size);
  output.close();

  fd = open("rust.out", O_RDONLY);

  for (auto &def : map_defs)
    arr[idx++] = def.first + offsetof(map_def, kptr);

  attr.prog_type = BPF_PROG_TYPE_IU_BASE;
  // progname was zero-initialized so we don't copy the null terminator
  memcpy(attr.prog_name, basename.c_str(),
         std::min(basename.size(), sizeof(attr.prog_name) - 1));
  attr.rustfd = fd;
  attr.license = reinterpret_cast<__u64>("GPL");

  attr.map_offs = reinterpret_cast<__u64>(arr.get());
  attr.map_cnt = map_defs.size();

  attr.dyn_relas = reinterpret_cast<__u64>(dyn_relas.data());
  attr.nr_dyn_relas = dyn_relas.size();

  attr.dyn_syms = reinterpret_cast<__u64>(dyn_syms.data());
  attr.nr_dyn_syms = dyn_syms.size();

  ret = bpf(BPF_PROG_LOAD_IU_BASE, &attr, sizeof(attr));

  if (ret < 0) {
    perror("bpf_prog_load_rex_base");
    return -1;
  }

  this->prog_fd = ret;

  if (debug)
    std::clog << "Base program loaded, fd = " << ret << std::endl;

  if (remove("rust.out") < 0) {
    perror("remove");
    goto close_fds;
  }

  for (auto &prog : progs) {
    int curr_fd;
    attr.prog_type = prog.prog_type;
    strncpy(attr.prog_name, prog.name.c_str(), sizeof(attr.prog_name) - 1);
    attr.base_prog_fd = this->prog_fd.value();
    attr.prog_offset = prog.offset;
    attr.license = (__u64) "GPL";
    curr_fd = bpf(BPF_PROG_LOAD_IU, &attr, sizeof(attr));

    if (curr_fd < 0) {
      perror("bpf_prog_load_rex");
      goto close_fds;
    }

    prog.prog_fd = curr_fd;

    if (debug)
      std::clog << "Program " << prog.name
                << " loaded, fd = " << prog.prog_fd.value_or(-1) << std::endl;
  }

  loaded = true;
  return ret;

close_fds:
  for (auto &prog : progs) {
    prog.prog_fd = prog.prog_fd.and_then([](int fd) -> std::optional<int> {
      close(fd);
      return {};
    });
  }
  prog_fd = prog_fd.and_then([](int fd) -> std::optional<int> {
    close(fd);
    return {};
  });
  return -1;
}

bpf_object *rex_obj::bpf_obj() {
  size_t i;
  // Do not create a bpf_object if the obj has not been loaded
  if (!loaded)
    return nullptr;

  // Return the previously created ptr
  if (bpf_obj_ptr)
    return bpf_obj_ptr.get();

  // Create a new ptr
  decltype(bpf_obj_ptr) ptr(new bpf_object, bpf_obj_del());
  ptr->maps = new bpf_map[map_defs.size()];
  ptr->programs = new bpf_program[progs.size()];

  // Fill in maps
  i = 0;
  for (auto &it : map_defs) {
    if (std::optional<bpf_map> map = it.second.bpfmap())
      ptr->maps[i++] = std::move(map.value());
    else
      return nullptr;
  }
  ptr->nr_maps = i;

  // Fill in programs
  i = 0;
  for (auto &prog : progs) {
    if (std::optional<bpf_program> bpf_prog = prog.bpf_prog()) {
      ptr->programs[i] = std::move(bpf_prog.value());
      ptr->programs[i++].obj = ptr.get();
    } else {
      return nullptr;
    }
  }
  ptr->nr_programs = i;

  // Now transfer the ownership
  bpf_obj_ptr = std::move(ptr);

  return bpf_obj_ptr.get();
}

void rex_set_debug(int val) { debug = val; }

static std::vector<std::unique_ptr<rex_obj>> objs;

rex_obj *rex_obj_load(const char *file_path) {
  int ret;
  if (elf_version(EV_CURRENT) == EV_NONE) {
    std::cerr << "elf: failed to init libelf" << std::endl;
    return nullptr;
  }

  try {
    auto obj = std::make_unique<rex_obj>(file_path);
    ret = obj->parse_elf();
    ret = ret ? ret : obj->fix_maps();
    ret = ret ? ret : obj->load();

    if (ret >= 0) {
      objs.push_back(std::move(obj));
      return objs.back().get();
    } else {
      return nullptr;
    }

  } catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
    return nullptr;
  }
}

bpf_object *rex_obj_get_bpf(rex_obj *obj) { return obj->bpf_obj(); }