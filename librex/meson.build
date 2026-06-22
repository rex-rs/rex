llvm_dep = dependency('llvm', version : '>=18')
elf_dep = dependency('libelf')

subdir('lib')

librex_public_inc = include_directories('include')

librex_sources = [
  'lib/librex.cpp',
  librex_binding
]

librex = library(
  'rex',
  librex_sources,
  cpp_args: ['-Wno-missing-designated-field-initializers'],
  build_rpath: join_paths(meson.project_source_root(), 'linux/tools/lib/bpf'),
  build_by_default: false,
  dependencies: [elf_dep, llvm_dep, kernel_dep, libbpf_dep],
  gnu_symbol_visibility: 'hidden',
  include_directories: librex_public_inc,
  pic: true
)

librex_dep = declare_dependency(
  link_with: librex,
  include_directories: librex_public_inc
)
