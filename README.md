```
 ____  _______  __  _____      _                 _
|  _ \| ____\ \/ / | ____|_  _| |_ ___ _ __  ___(_) ___  _ __  ___
| |_) |  _|  \  /  |  _| \ \/ / __/ _ \ '_ \/ __| |/ _ \| '_ \/ __|
|  _ <| |___ /  \  | |___ >  <| ||  __/ | | \__ \ | (_) | | | \__ \
|_| \_\_____/_/\_\ |_____/_/\_\\__\___|_| |_|___/_|\___/|_| |_|___/

```

# Rex Kernel Extensions

[![CI](https://img.shields.io/github/actions/workflow/status/rex-rs/rex/.github%2Fworkflows%2Fmeson.yml?label=ci)](https://github.com/rex-rs/rex/actions)
[![Nix](https://img.shields.io/github/actions/workflow/status/rex-rs/rex/.github%2Fworkflows%2Fnix.yml?label=ci-nix)](https://github.com/rex-rs/rex/actions)

[![Gentoo](./docs/image/gentoo-badge3.svg)](https://www.gentoo.org)

#### Table of Contents

- [What is Rex](#what-is-rex)
- [Example program](#example-program)
- [Build and run](#build-and-run)
- [Documentations](#documentations)
- [Why Rex](#why-rex)
- [License](#license)

## What is Rex

Rex is a safe and usable kernel extension framework that allows loading and
executing Rust kernel extension programs in the place of eBPF. Unlike
eBPF-based frameworks such as [Aya](https://aya-rs.dev), Rex programs do
not go through the in-kernel verifier, instead, the programs are
implemented in the safe subset of Rust, on which the Rust compiler performs
the needed safety checks and generates native code directly. This approach
avoids the overly restricted verification requirements (e.g., program
complexity constraints) and the resulting arcane verification errors, while
at the same time potentially provides a better optimization opportunity in
the native compiler backend (i.e., LLVM) than the eBPF backend + in-kernel
JIT approach.

Rex currently supports the following features:

- 5 eBPF program types: `kprobe`, `perf_event`, `tracepoint`, `xdp`, and
  `tc`.
- invocation of eBPF helper functions that are commonly used by these
  programs
- interaction with eBPF maps
- RAII-style management of kernel resources obtainable by programs
- cleanup and in-kernel exception handling of Rust runtime panics with call
  stack traces
- kernel stack (only when CFG cannot be computed statically) and
  termination safety from a thin in-kernel runtime
- bindings and abstractions of kernel data types commonly needed by eBPF
  programs

## Example program

The following example implements a kprobe program that attaches to a
selected system call and injects an error (specified by `errno`) to the
system call on a process (specified by its `pid`). The full example,
including the loader program, can be found under
[samples/error_injector](samples/error_injector).

```Rust
#![no_std]
#![no_main]

use rex::kprobe::kprobe;
use rex::map::RexHashMap;
use rex::pt_regs::PtRegs;
use rex::rex_kprobe;
use rex::rex_map;
use rex::Result;

#[allow(non_upper_case_globals)]
#[rex_map]
static pid_to_errno: RexHashMap<i32, u64> = RexHashMap::new(1, 0);

#[rex_kprobe]
pub fn err_injector(obj: &kprobe, ctx: &mut PtRegs) -> Result {
    obj.bpf_get_current_task()
        .map(|t| t.get_pid())
        .and_then(|p| obj.bpf_map_lookup_elem(&pid_to_errno, &p).cloned())
        .map(|e| obj.bpf_override_return(ctx, e))
        .ok_or(0)
}
```

More sample programs can be found under [samples](samples).

## Build and run

You can find the detailed guide [here](docs/getting-started.md).

## Documentations

Additional design documentations can be found under [docs](docs).

## Why Rex

The existing eBPF extension relies on the in-kernel eBPF verifier to
provide safety guarantees. This unfortunately leads to usability issues
where safe programs are rejected by the verifier, including but not limited
to:

- programs may exceed the inherent complexity contraints of static
  verification
- compilers may not generate verifier-friendly code
- same logic may need to be implemented in a certain way to please the
  verifier

Rex aims to address these issues by directly leveraging the safety
guarantee from _safe Rust_. Developers can implement their programs in any
way that can be written in safe Rust with [few
restrictions](docs/rust_rex_subset.md), and no longer need to worry about
program complexity, the code generator, or finding the (many time
counter-intuitive) way of expressing the same logic to please the verifier.

We demonstrate this with the implementation of the [BPF Memcached Cache
(BMC)](https://github.com/Orange-OpenSource/bmc-cache), a state-of-the-art
extension program for Memcached acceleration. As a complex eBPF program,
BMC is forced to be splitted into several components connected by BPF
tail-calls and use awkward loop/branch implementations to please the
verifier, which are totally not needed in [its Rex
implementation](samples/bmc).

For example, we show the code in cache invalidation logic of the BPF-BMC
that searches for a `SET` command in the packet payload:

```C
// Searches for SET command in payload
for (unsigned int off = 0;
     off < BMC_MAX_PACKET_LENGTH &&  payload + off + 1 <= data_end;
     off++) {
    if (set_found == 0 && payload[off] == 's' &&
        payload + off + 3 <= data_end && payload[off + 1] == 'e' &&
        payload[off + 2] == 't') {
            off += 3;
            set_found = 1;
    }
    ...
}
```

The code not only introduces an extra constraint in the loop (`off <
BMC_MAX_PACKET_LENGTH`) solely for passing the verifier, but also employs
repeated boilerplate code to check packet ends (`data_end`) and cumbersome
logic to match the `"set"` string in the packet.

None of these burdens is needed with the power of safe Rust in Rex, which
has no complexity limits and provides more freedom on the implementation:

```rust
let set_iter = payload.windows(4).enumerate().filter_map(|(i, v)| {
    if v == b"set " {
      Some(i)
    } else {
      None
    }
});

```

The full implementation of BMC in Rex can be found at
[samples/bmc](samples/bmc).

## License

Rex is licensed under the GPLv2 license. The submodules (Linux, Rust, LLVM)
in this repo are licensed under their own terms. Please see the
corresponding license files for more details. Additionally, the memcached
benchmark is licensed under the MIT license.
