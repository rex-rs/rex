binding_script = join_paths(meson.project_source_root(), 'scripts/libbpf-binding.py')

librex_binding = custom_target(
  'bindings.h',
  output: ['bindings.h'],
  command: [
    binding_script, meson.project_source_root(), '@OUTPUT@'
  ],
  depends: kernel_libbpf,
  console: false,
)
