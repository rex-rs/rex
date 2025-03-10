# Getting started - WSL version

This guide is aimed towards those running Rex on Windows Subsystem for Linux and/or personal machines with more limited resources.

## WSL Distro

Rex has been tested to work with the Ubuntu distro, however any WSL distro should work.

## Before starting

The build steps below include compilng the Linux kernel which can get quite resource intensive. Since WSL by default only utilizes half the RAM available on the host machine, if you try to use Rex on your personal machine you may run into Out-Of-Memory (OOM) errors during build steps. Then, it is recommended to allocate more RAM to WSL beforehand.

From a Powershell instance, create and open a `.wslconfig` file in your home directory:
```bash
notepad $HOME/.wslconfig
```

Add the following lines to the file then save:
```bash
[wsl2]
memory=6GB
```

You should change the value to how much memory you want to allocate to WSL. In our tests `6GB` is the minimum value for which compiling Linux is possible, this means you might not be able to use Rex on machines with 6GB or less RAM.

## Building dependencies:

Follow the regular Getting Started guide from start until you build the dependencies:

```bash
meson compile -C build build_deps
```

During this step you might encounter this warning:

```bash
/root/rex/linux/scripts/link-vmlinux.sh: line 113: 55407 Killed                  LLVM_OBJCOPY="${OBJCOPY}" ${PAHOLE} -J ${PAHOLE_FLAGS} ${1}
```

And error:

```bash
FAILED: load BTF from vmlinux: invalid argument
```

Or similar problems. This means you OOM'd while building Linux and you should increase your WSL RAM.

## Building the Rex samples:

There are some caveats before you run the next step, which is building the Rex programs:

```bash
meson compile -C build
```

By default the `ninja` build tool uses a quite high level of parallelism, which might again cause OOM on personal machines. A sign of this happenning is if you try this step and run into similar errors to:

```bash
error: could not compile `core` (lib)

Caused by:
    process didn't exit successfully:
```

To resolve this problem, try running with fewer commands in parallel using the `-j` argument, for example to run with 4 commands in parallel:

```bash
meson compile -C build -j 4
```

Our tests indicate a peak memory usage of 12GB with `-j 8`, so if you have less RAM it's helpful to keep the `-j` argument below 8.

## Running the QEMU VM:

The next step involves booting the QEMU VM:

```bash
cd build/linux
../../scripts/q-script/yifei-q # use ../scripts/q-script/nix-q instead if you are using Nix
```

By default our QEMU VM runs on 8GB of memory. To reduce this, open the qemu scripts using an editor and locate line 300:

```bash
MEMORY=8192
```

And change this value to the number you want. Rex has been tested to work with 4GB or `MEMORY=4096`.

And then follow the rest of the steps in Getting Started.