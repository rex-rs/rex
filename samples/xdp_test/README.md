<div style="text-align: justify;">

# Onboarding Task: Rust-based extensions

**Note: You need to be on the x86-64 architecture in order to work on this
MP. We assume the x86-64 architecture and ABI in this writeup.**

**Note2: If you are using aarch64 architecture, you will need to find
another x86-64 computer or run this project in emulation**

**Please make sure you read through this document at least once before
starting.**

# Table of Contents

- [Introduction](#introduction)
- [Problem Description](#problem-description)
  - [eBPF XDP Program](#ebpf-xdp-program)
- [Implementation Overview](#implementation-overview)
  - [Understand the rex repo structure](#understand-the-rex-repo-structure)
    - [Try out the rex xdp sample.](#try-out-the-rex-xdp-sample)
  - [Make the rex version program](#make-the-rex-version-program)
- [Other Requirements](#other-requirements)
- [Resources](#resources)

# Introduction

The emergence of verified eBPF bytecode is ushering in a new era of safe
kernel extensions.  In this paper, we argue that eBPF’s verifier—the source
of its safety guarantees—has become a liability. In addition to the
well-known bugs and vulnerabilities stemming from the complexity and ad hoc
nature of the in-kernel verifier, we highlight a concerning trend in which
escape hatches to unsafe kernel functions (in the form of helper functions)
are being introduced to bypass verifier-imposed limitations on
expressiveness, unfortunately also bypassing its safety guarantees. We
propose safe kernel extension frameworks using a balance of not just static
but also lightweight runtime techniques. We describe a design centered
around kernel extensions in safe Rust that will eliminate the need of the
in-kernel verifier, improve expressiveness, allow for reduced escape
hatches, and ultimately improve the safety of kernel extensions.

The basic ideas are documented in [a workshop
paper](../../docs/rust-kernel-ext.pdf) (no need to read through).

# Problem Description

Your task is to implement an rex program in Rust, equivalent to an eBPF
version. This is conceptually straightforward. However, the real challenge
lies in mastering rex operations and integrating them with your knowledge
of Linux kernel programming, Rust programming, and other essential aspects
like ELF (Executable and Linkable Format). This task will test your
technical skills and ability to quickly adapt to new programming
environments.

To implement a packet filtering mechanism using both eBPF and an rex
program, your objective is to drop incoming network traffic based on
predefined rules for port numbers and protocol types (TCP or UDP). The
steps you need to follow are:

1. Write an eBPF program that employs the XDP hook to inspect and
   potentially drop packets at an early stage in the networking stack.
2. Create a user-space application that interacts with the eBPF program,
   particularly focusing on updating the rules for packet filtering (such
   as which ports to block).
3. Develop an rex program that similarly inspects traffic and creates a
   user-space application for updating the rules for packet filtering.

![xdp_image](../../docs/image/xdp-attach-point.png)

## eBPF XDP Program

The eBPF program will be attached to the XDP hook in the Linux kernel. XDP
provides high-performance packet processing at the earliest point where a
packet is received by the network driver.

The eBPF XDP program will:

1. Inspect each incoming packet's header to determine the port number and
   protocol (TCP/UDP).
2. Check against a set of rules defined in a BPF map (a key-value store
   used by eBPF programs for storing runtime data).
3. Decide whether to drop the packet or allow it to pass based on these
   rules.

# Implementation Overview

## Understand the rex repo structure

The repository contains the following directories:

- `librex`: This is the equivalent of `libbpf` for rex programs. You should
  not modify any files in this directory.
- `rex`: This is the runtime crate for rex programs and contains the
  program type and helper function definitions.
  - You will need to add helper functions to `src/xdp/xdp_impl.rs` but
    should avoid changing any other files.
- `xdp_test`: This is the directory of the program you need to
  implement.
  - Specifically, you should place the rex program code in `src/main.rs`
    and the loader code in `entry.c`.


  ## Utilize Nix
For this task, we encourage to utilize the support of Nix. Using Nix, a
package manager, could allow you to bypass the dependency requirements.
You can find the installation steps [here](../../README.org#nix-flake) All
subsequent steps should be carried out within this shell.

## Make the rex version program

```bash
# assume you are in the rex-kernel
cd xdp_test
# compile the xdp program
make
# bind xdp program to interface lo
./entry 1
```

1. We have provided you with the `samples/xdp_test` directory for
   the rex version of the XDP program. The function `ip_header` in the
   `rex/src/xdp/xdp_impl.rs` file is used to parse the IP header from a
   packet. It is used: `let ip_header = obj.ip_header(ctx);` in
   `samples/xdp_test/src/main.rs`.
2. For loader implementation:
    - One hint is that `rex_obj_load` and `rex_obj_get_bpf` should be used
      for loading and manipulating rex programs.
      ```c
      // load rex obj
      obj = rex_obj_get_bpf(rex_obj_load(EXE));
      ```
    - You need to add additional parameter processing for adding rules,
      besides the existing binding interface part. Implement the new action
      `./entry add_rule <port> <protocol>` to add rules to the eBPF map.
      Adding rules for removal is optional.
3. You can refer to the `samples/map_test` folder to see how to use the map
   in Rust.

## Test your implementation

1. To test your implementation, you can use netcat(nc), a utility tool that
   uses TCP/UDP connections to read/write into the network.
2. On server: nc -l -p port_number (Start a listener at port_number)
3. On client: nc 127.0.0.1 port_number (Starts a client)
4. Note: The above netcat commands are for a TCP connection, for UDP
   connection, "-u" command needs to be added on both server and client.
5. The logs of bpf_printk, can be found at
   "/sys/kernel/debug/tracing/trace_pipe"
6. You can update the map using bpftool: bpftool map update id 1 key hex 35
   00 00 00 value hex 01 00 (Update map with id 1 with hex a value b)

# Other Requirements

- Do not change any other files except the files mentioned above.
- Your Rust code should not have any `unsafe` block in the rex program, but
  can have `unsafe` blocks in the `rex` crate.
- You should not use any other extern crates (i.e. Rust packages) other
  than the provided `rex`.
- You cannot use the Rust `std` library because it is not available in
  standalong mode, but the `core` library remains largely available.
- This research is currently not available to the public. So please do not
  put the rex code on GPT.

# Resources

We recommend you to get your hands dirty directly and check these resources
on demand. In fact, we didn’t know Rust well when we started this project –
you can always learn a language by writing the code.

- eBPF: [ebpf.io](https://ebpf.io/) and [The Illustrated Children’s Guide
  to
  eBPF](https://ebpf.io/books/buzzing-across-space-illustrated-childrens-guide-to-ebpf.pdf)
  and [xdp-tutorial](https://github.com/xdp-project/xdp-tutorial) both are
  good places to start. You can also find the official kernel documentation
  [here](https://elixir.bootlin.com/linux/v5.15.127/source/Documentation/bpf)
  along with the source code. In particular, try answering:
  - What is eBPF?
  - What is XDP?
  - What are some example use cases of eBPF?
  - How are eBPF programs loaded to the kernel and bind XDP program to
    interfaces?
  - How are the execution of eBPF programs triggered?
  - What are eBPF helpers?
- Rust: If you are not familiar with the Rust program language, we have
  some resources for you:
  - [The Rust book](https://doc.rust-lang.org/book/) (Probably the most
    comprehensive guide on Rust programming)
  - [Library API reference](https://doc.rust-lang.org/std/index.html) (for
    searching API specifications)
  - [The Rust playground](https://play.rust-lang.org) (for trying out
    programs)
</div>
