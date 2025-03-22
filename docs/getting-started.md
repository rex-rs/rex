# Getting started (p20250206)

Building Rex extensions requires modifications to the toolchain (Rust and
LLVM) and running Rex extensions requires modifications to the Linux
kernel.  The steps below describe how to set up both the toolchain and
kernel for running Rex extensions in a VM.

## Nix flake

Using Nix, a package manager, allows you to bypass these dependency
requirements below.

Check out the https://nixos.org/download/ for installation instructions,
the single-user installation should be sufficient.

## Dependencies:

The following tools/libraries are required. Older versions are not
guaranteed to (or guaranteed not to) work. This list does not include
standard kernel build dependencies.
- `clang+LLVM (>= 18.1.0)`
- `cmake`
- `elfutils`
- `libstdc++ (>=13)` for missing `c++23` support in LLVM's `libcxx`
- `meson`
- `mold`
- `ninja`
- `python (>= 3.11)`
- `QEMU`
- `rust-bindgen`

## Repo setup and build

Clone this repo and its submodules:

```bash
git clone https://github.com/rex-rs/rex.git
cd rex-kernel
git submodule update --init --recursive --progress
```

If you are using Nix, the following additional step is required.

```bash
nix develop --extra-experimental-features nix-command --extra-experimental-features flakes
```

It will launch a Nix shell with all necessary dependencies installed.
All subsequent steps should be carried out within this shell.

Rex uses `meson` as its build system, to get started, first set up `meson`
in Rex:

```bash
meson setup --native-file rex-native.ini ./build/
```

Rex requries the modified kernel and its `libbpf` library, which resides in
the `linux` directory after submodule initialization. Rex also uses custom
LLVM passes in the Rust compiler to generate additional code and
instruments the extension programs, therefore,
[bootstraping](https://en.wikipedia.org/wiki/Bootstrapping_(compilers)) the
Rust compiler is required. The Rust toolchain source can be found under the
`rust` directory as another submodule.

Building these dependencies is a one-time effort with the following
command:

```bash
meson compile -C build build_deps
```

This will build the kernel and its `libbpf`. It will also bootstrap the
Rust compiler and build the relevant tools (e.g., `cargo`, `clippy`, etc).

With the linux and Rust setup, all Rex sample programs can then be built
with:

```bash
meson compile -C build
```

## Run `hello` example
First boot the VM:

```bash
cd build/linux
../../scripts/q-script/yifei-q # use ../scripts/q-script/nix-q instead if you are using Nix
```

Inside the VM:

```bash
cd ../samples/hello
./loader &
./event_trigger
```

The following output should be printed out:

```console
<...>-245     [002] d...1    18.417331: bpf_trace_printk: Rust triggered from PID 245.
```

## Troubleshooting

### Building dependencies:

This step includes compiling the Linux kernel which can get quite resource
intensive. In our tests `6GB` is the minimum value for which compiling
Linux is possible, this means you might not be able to use Rex on machines
with 6GB or less RAM. A sign that you ran into Out-Of-Memory (OOM) error is
if you encounter this warning:

```bash
/root/rex/linux/scripts/link-vmlinux.sh: line 113: 55407 Killed                  LLVM_OBJCOPY="${OBJCOPY}" ${PAHOLE} -J ${PAHOLE_FLAGS} ${1}
```

And error:

```bash
FAILED: load BTF from vmlinux: invalid argument
```

Or similar problems.

For WSL users, it is recommended to allocate more RAM to WSL before
starting this step since WSL by default only utilizes half the RAM
available on the host machine:

From a Powershell instance, create and open a `.wslconfig` file in your
home directory:

```bash
notepad $HOME/.wslconfig
```

Add the following lines to the file then save:

```bash
[wsl2]
memory=8GB
swap=8GB
```

You should change the value to how much memory you want to allocate to WSL.

Another issue that may happen is bootstrap failure due to the missing
`libLLVM-19-rex.so`:

```console
  --- stderr
  llvm-config: error: libLLVM-19-rex.so is missing
  thread 'main' panicked at compiler/rustc_llvm/build.rs:264:16:
  command did not execute successfully: "/home/chin39/Documents/rex-kernel/build/rust-build/x86_64-unknown-linux-gnu/llvm/bin/llvm-config" "--link-shared" "--libs" "--system-libs" "asmparser" "bitreader" "bitwriter" "coverage" "instrumentation" "ipo" "linker" "lto" "x86"
  expected success, got: exit status: 1
  stack backtrace:
     0: rust_begin_unwind
               at /rustc/9fc6b43126469e3858e2fe86cafb4f0fd5068869/library/std/src/panicking.rs:665:5
     1: core::panicking::panic_fmt
               at /rustc/9fc6b43126469e3858e2fe86cafb4f0fd5068869/library/core/src/panicking.rs:76:14
     2: build_script_build::output
     3: build_script_build::main
     4: core::ops::function::FnOnce::call_once
  note: Some details are omitted, run with `RUST_BACKTRACE=full` for a verbose backtrace.
Build completed unsuccessfully in 0:00:12
FAILED: cargo rustc
env 'RUSTFLAGS=-Z threads=8 -C target-cpu=native -C codegen-units=1 -C link-arg=-fuse-ld=mold -C link-arg=-Wl,-O1 -C link-arg=-Wl,--as-needed -C link-arg=-flto=thin' /usr/bin/python3 ../rust/x.py install --config=../rust/rex-config.toml --build-dir=./rust-build --set install.prefix=./rust-dist
ninja: build stopped: subcommand failed.
```

Notably this may happen as a result of [`ba85ec815c2f ("rust: enable more
optimizations and features in bootstrap
config")`](https://github.com/rex-rs/rex/commit/ba85ec815c2fc9721e3b466d1c296bd7dd79b1b3),
as it changes the linkage of `libLLVM` from static to dynamic, but rust
bootstrap process does not rebuild `libLLVM.so` following the change.
The issue can be fixed by removing the build directory created by meson and
starting a clean build.

### Building the Rex samples:

There are some caveats before you run this step. By default the `ninja`
build tool uses a quite high level of parallelism, which might again cause
OOM on personal machines. A sign of this happenning is if you try this step
and run into similar errors to:

```bash
error: could not compile `core` (lib)

Caused by:
    process didn't exit successfully:
```

To resolve this problem, try running with fewer commands in parallel using
the `-j` argument, for example to run with 4 commands in parallel:

```bash
meson compile -C build -j 4
```

Our tests indicate a peak memory usage of 12GB with `-j 8`, so if you have
less RAM it's helpful to keep the `-j` argument below 8.

### Booting the QEMU VM:

By default our QEMU VM runs on 8GB of memory. To reduce this, open the qemu
scripts using an editor and locate line 300:

```bash
MEMORY=8192
```

And change this value to the number you want. Rex has been tested to work
with 4GB or `MEMORY=4096`.
