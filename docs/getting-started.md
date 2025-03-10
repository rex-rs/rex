# Getting started (p20250206)

Building Rex extensions requires modifications to the toolchain (Rust and
LLVM) and running Rex extensions requires modifications to the Linux
kernel.  The steps below describe how to set up both the toolchain and
kernel for running Rex extensions in a VM.

Note that this guide assumes a server machine with ample RAM and processors. For those trying to run Rex on Windows Subsystem for Linux (WSL) and/or personal machines, you should look at [the WSL guide](getting-started-wsl.md).

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
