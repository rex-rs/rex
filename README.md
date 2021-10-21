### Docker build containers

We have a lot of build environments in the form of Docker containers.
While they should get built as a makefile dependency, the build
containers can be built with:

    make docker

### VMM

We are using firecracker as our VMM, which we have obtained via
Firecracker's binary distribution.  

    curl -Lo firecracker https://github.com/firecracker-microvm/firecracker/releases/download/v0.16.0/firecracker-v0.16.0
    curl -Lo firectl https://firectl-release.s3.amazonaws.com/firectl-v0.1.0

### kernel

We are using a small kernel config based off the firecracker microvm
config with `make olddefconfig`.  We have added some kernel features
relevant to eBPF.  Importantly some of the BTF stuff requires really
recent versions of tools (e.g., `pahole`) for the kernel build.  So,
it's easiest to use a container.  Assuming your linux tree is at
`~/linux` run:

    make vmlinux

It will build and copy over the kernel vmlinux file and its config so
that everything matches.

### bpftool

The Linux kernel comes with a tool called bpftool, which can be useful
but should be built from the same kernel source that we are dealing
with.  We have a builder container for that too, so assuming your
linux tree is at `~/linux` run:

    make bpftool

It will put the bpftool into the `rootfs/guest` directory where it
will be used by the guest.

### examples

There's a project called libbpf-bootstrap, which has some minimal bpf
examples.  We have a builder container for that too, so assuming your
libbpf-bootstrap tree is at `~/libbpf-bootstrap` run:

    make examples

It will put the `minimal` example into the `rootfs/guest` directory
where it will be used by the guest.


### rootfs

We are trying to use a very small distro so that everything stays fast
and manageable (e.g., kernel build, building the rootfs, etc.).  The
distro we are using is from some scripts adapted from Lupine Linux.
Lupine's scripts create a rootfs from a Docker image.  We put our
stuff in there (based on ubuntu at this point because we needed a
glibc-based system).  The `rootfs/Dockerfile` contains the build-time
stuff to go in the rootfs.

The root filesystem is best built from the top level with:

    make fs

This can be rerun whenever you want to boot with a new script in the
guest (put it in `rootfs/guest/`).  But you don't have to run it
directly because it's a dependency of `make run`.

### running it

We modified some of the Lupine scripts for a single point of
invocation into a guest shell.

    make run

At this point it gives us a root SSH shell.  To get more shells to do
stuff with, type:

    make shell

### status

So far, we have run the sock_example from the bundled Linux samples.
See `linux/samples/bpf/README.rst`.  Also, the minimal example from
libbpf-bootstrap.

### Next steps

- check out some of the debugging features from https://prototype-kernel.readthedocs.io/en/latest/bpf/troubleshooting.html
