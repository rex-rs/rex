build_dir = run_command(
  realpath,
  '--relative-to',
  meson.current_source_dir(),
  meson.current_build_dir(),
  capture: true,
  check: true
).stdout().strip()

env = environment()
env.prepend('PATH', rust_bin)
env.set('LINUX_OBJ', kbuild_dir)
env.set('LINUX_SRC', join_paths(meson.project_source_root(), './linux'))
env.set('CARGO_TARGET_DIR', join_paths(build_dir, 'target'))

sample_clippy = custom_target(
  'xdp_test-clippy',
  output: ['target'],
  command: [
    cargo_wrapper, rust_bin, '-Z',
    'unstable-options',
    '-C', meson.current_source_dir(),
    'clippy', '-qr'
  ],
  env: env,
  console: false,
  build_by_default: true
)

sample_build = custom_target(
  'xdp_test-build',
  output: ['xdp_test'],
  command: [
    cargo_wrapper, rust_bin, '-Z',
    'unstable-options',
    '-C', meson.current_source_dir(),
    'rustc', '-qr', '--',
    '-Cenable_rex'
  ],
  depends: sample_clippy,
  env: env,
  console: false,
  build_by_default: true
)

xdp_test_entry = executable(
  'entry',
  'entry.c',
  build_by_default: true,
  dependencies: [librex_dep, libbpf_dep, kernel_dep],
  pie: true
)

sanity_test = custom_target(
  'sanity_test',
  output: ['runtest.py'],
  input: join_paths(meson.current_source_dir(), 'tests/runtest.py'),
  command: [
    'cp', '@INPUT@', '@OUTPUT@',
    ]
 )

runtest_deps += [sample_build, xdp_test_entry, sanity_test]

sanity_test_env = environment()
sanity_test_env.set('SAMPLE_PATH', meson.current_build_dir())
sanity_test_env.set('Q_SCRIPT',
  join_paths(meson.project_source_root(), 'scripts/q-script/sanity-test-q')
)
sanity_test_env.set('KERNEL_PATH', kbuild_dir)

test('xdp_test_test', 
  python3_bin, 
  args: [sanity_test_scripts],
  env: sanity_test_env,
  depends: runtest_deps,
  is_parallel: false,
  workdir: meson.current_build_dir()
)
