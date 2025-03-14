# Entry point code Insertion

## Motivation

To allow Rust extension code to be called from the kernel, an FFI
entry-point function is needed to wrap around the user-defined extension
function. This wrapper function needs to handle certain unsafe operations,
for example, context conversion for XDP and perf event programs. Because of
this, it should never be implemented by the user. For example, interpreting
an XDP context as perf event context and perform the context conversion
specific to perf-event clearly violates memory and type safety and could
result in undefined behavior.

Therefore, we choose to automatically generate the entry point code during
compilation for the Rust extension programs. Since Rust by default uses
LLVM as its code generation backend. We performs the generation of entry
code in the middle-end on LLVM IR.

## Implementation

The entry point insertion is implemented as an LLVM pass
(`RexEntryInsertion`) that operates on the compilation unit that contains
the Rust extension programs. This LLVM pass can be enabled via the
`enable_rex` codegen option in rustc, which sets the corresponding pass for
the LLVM backend.

Take the [error_injector sample](../samples//error_injector/src/main.rs) as
an example:

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

Here, the
[`rex_kprobe`](https://github.com/rex-rs/rex/blob/93777ca3ad238ad3ace1d45614933f277ab587e8/rex-macros/src/lib.rs#L47)
proc-macro defines a kprobe program object  in section (`rex/kprobe/*`)
using the
[`const`](https://doc.rust-lang.org/std/keyword.const.html#compile-time-evaluable-functions)
function `kprobe::new`, which takes the program function `rex_kprobe` is
specified on and its literal name as arguments:

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

pub fn err_injector(obj: &kprobe, ctx: &mut PtRegs) -> Result {
    obj.bpf_get_current_task()
        .map(|t| t.get_pid())
        .and_then(|p| obj.bpf_map_lookup_elem(&pid_to_errno, &p).cloned())
        .map(|e| obj.bpf_override_return(ctx, e))
        .ok_or(0)
}

#[used]
#[link_section = "rex/kprobe"]
static PROG_err_injector: kprobe = kprobe::new(err_injector, "err_injector");
```

Under the hood, the `kprobe` object is defined as the following:

```Rust
#[repr(C)]
pub struct kprobe {
    rtti: u64,
    prog: fn(&Self, &mut PtRegs) -> Result,
    name: &'static str,
}
```

The `rtti` field stores the corresponding
[`bpf_prog_type`](https://elixir.bootlin.com/linux/v5.15.128/source/include/uapi/linux/bpf.h#L919)
enum value (i.e. `BPF_PROG_TYPE_KPROBE` in this case). `prog` is a function
pointer that points to the user-defined extension program function. `name`
holds the user-intended name of the program, in a string literal form (as
mentioned above, the proc-macros in `rex-macros` always set this to the
literal name of the program function).

At LLVM-IR level, the `RexEntryInsertion` will iterate over all global
variables and look for variables with the special `rex/*` sections
generated by proc-macros from `rex-macros`. For the found program objects,
it will then generate the entry point based on the object contents.
Because the `kprobe::new` function is a `const` function. The object is
initialized with a constant expression that can be parsed by the
`RexEntryInsertion` pass. This effectively allows the pass to obtain the
program type (via `rtti`), the actual extension function (via `prog`), and
the intended name (via `name`).

The pass will construct a new `fn (*const()) -> u32` function with the
specified name and eBPF link section, which will be used as the entry point
function the kernel can invoke. This function takes in the context pointer
(as `*mut ()`) and invokes the special program-type-specific entry function
in the `rex` crate. The code of the aforementioned example would be
modified as (the process happens at LLVM-IR stage, but here Rust is used
for clarity):

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

#[inline(always)]
pub fn err_injector(obj: &kprobe, ctx: &mut PtRegs) -> Result {
    obj.bpf_get_current_task()
        .map(|t| t.get_pid())
        .and_then(|p| obj.bpf_map_lookup_elem(&pid_to_errno, &p).cloned())
        .map(|e| obj.bpf_override_return(ctx, e))
        .ok_or(0)
}

#[used]
#[link_section = "rex/kprobe"]
static PROG_err_injector: kprobe = kprobe::new(err_injector, "err_injector"););

#[link_section = "kprobe"]
#[no_mangle]
pub fn err_injector(ctx: *mut ()) -> u32 {
    rex::__rex_entry_kprobe(&PROG_err_injector, ctx)
}
```

`__rex_entry_kprobe` is the tracepoint specific entry function defined in
the `rex` crate (not to be confused with the generated kernel entry point).
The function essentially calls `kprobe::prog_run` that converts the context
to the type specific to the program and invokes the `prog` function. In
this way the program context conversion and other preparation for execution
is safely abstracted away from the users.

### Add new program type support

The only file needs to be updated is
[llvm/include/llvm/Transforms/Rex/RexProgType.def](https://github.com/rex-rs/llvm-project/blob/rex-llvm-rebase/llvm/include/llvm/Transforms/Rex/RexProgType.def).
The basic syntex is:

```C
REX_PROG_TYPE_1(<BPF_PROG_TYPE_ENUM>, <program_type in RT crate>, <sec name>)
```

If the program type has more than 1 section names, use `REX_PROG_TYPE_2`
instead, which will support 2 names.  Therefore, for `tracepoint` this is:

```C
REX_PROG_TYPE_2(BPF_PROG_TYPE_TRACEPOINT, tracepoint, "tracepoint", "tp")
```

Relevant files:
- LLVM pass:
  - [llvm/lib/Transforms/Rex/RexInsertEntry.cpp](https://github.com/rex-rs/llvm-project/blob/rex-llvm-rebase/llvm/lib/Transforms/Rex/RexInsertEntry.cpp)
  - [llvm/include/llvm/Transforms/Rex/RexInsertEntry.h](https://github.com/rex-rs/llvm-project/blob/rex-llvm-rebase/llvm/include/llvm/Transforms/Rex/RexInsertEntry.h)
  - [llvm/include/llvm/Transforms/Rex/RexProgType.def](https://github.com/rex-rs/llvm-project/blob/rex-llvm-rebase/llvm/include/llvm/Transforms/Rex/RexProgType.def)
- Program-type-specific entry function (defined using the
  `define_prog_entry` macro):
  - [rex/src/lib.rs](https://github.com/rex-rs/rex/blob/main/rex/src/lib.rs)
- Kprobe implementation (can be generalized to other programs):
  - [rex/src/kprobe/kprobe_impl.rs](https://github.com/rex-rs/rex/blob/main/rex/src/kprobe/kprobe_impl.rs)
