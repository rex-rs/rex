import os
import re
import subprocess
import sys
import tomllib

# https://github.com/rust-lang/rust-bindgen
bindgen_cmd = '''bindgen $LINUX_OBJ/usr/include/%s --use-core
--with-derive-default --ctypes-prefix core::ffi --no-layout-tests
--no-debug '.*' --no-doc-comments --rust-target=1.85.0 --rust-edition=2024
--translate-enum-integer-types --no-prepend-enum-name --blocklist-type
pt_regs --wrap-unsafe-ops -o %s -- -I$LINUX_OBJ/usr/include'''

k_structs = ['task_struct', 'tk_read_base', 'seqcount_raw_spinlock_t',
             'clocksource', 'seqcount_t', 'seqcount_latch_t', 'timekeeper',
             'kcsan_ctx', 'rnd_state', 'timespec64', 'bpf_spin_lock',
             'bpf_sysctl_kern', 'xdp_buff', 'ethhdr', 'iphdr', 'tcphdr',
             'udphdr', 'sk_buff', 'sock', 'pcpu_hot',
             'bpf_perf_event_data_kern']

bindgen_kernel_cmd = '''bindgen %s --allowlist-type="%s"
--allowlist-var="(___GFP.*|CONFIG_.*|MAX_BPRINTF_BUF)"
--opaque-type xregs_state
--opaque-type desc_struct --opaque-type arch_lbr_state --opaque-type
local_apic --opaque-type alt_instr --opaque-type x86_msi_data --opaque-type
x86_msi_addr_lo --opaque-type kunit_try_catch --opaque-type spinlock
--no-doc-comments --blocklist-function __list_.*_report --use-core
--with-derive-default --ctypes-prefix core::ffi --no-layout-tests
--no-debug '.*' --rust-target=1.85.0 --rust-edition=2024 --wrap-unsafe-ops
-o %s -- -nostdinc -I$LINUX_SRC/arch/x86/include
-I$LINUX_OBJ/arch/x86/include/generated
-I$LINUX_SRC/include -I$LINUX_SRC/arch/x86/include/uapi
-I$LINUX_OBJ/arch/x86/include/generated/uapi -I$LINUX_SRC/include/uapi
-I$LINUX_OBJ/include
-I$LINUX_OBJ/include/generated/uapi -include
$LINUX_SRC/include/linux/compiler-version.h -include
$LINUX_SRC/include/linux/kconfig.h -include
$LINUX_SRC/include/linux/compiler_types.h -D__KERNEL__
--target=x86_64-linux-gnu -fintegrated-as -Werror=unknown-warning-option
-Werror=ignored-optimization-argument -Werror=option-ignored
-Werror=unused-command-line-argument -fmacro-prefix-map=./= -std=gnu11
-fshort-wchar -funsigned-char -fno-common -fno-PIE -fno-strict-aliasing
-mno-sse -mno-mmx -mno-sse2 -mno-3dnow -mno-avx -fcf-protection=branch
-fno-jump-tables -m64 -falign-loops=1 -mno-80387 -mno-fp-ret-in-387
-mstack-alignment=8 -mskip-rax-setup -mtune=generic -mno-red-zone
-mcmodel=kernel -Wno-sign-compare -fno-asynchronous-unwind-tables
-fno-delete-null-pointer-checks -O2 -fstack-protector-strong
-fno-stack-clash-protection -pg -mfentry -DCC_USING_NOP_MCOUNT
-DCC_USING_FENTRY -fno-lto -falign-functions=16 -fstrict-flex-arrays=3
-fno-strict-overflow -fno-stack-check -Wall -Wundef
-Werror=implicit-function-declaration -Werror=implicit-int
-Werror=return-type -Werror=strict-prototypes -Wno-format-security
-Wno-trigraphs -Wno-frame-address -Wno-address-of-packed-member
-Wmissing-declarations -Wmissing-prototypes -Wframe-larger-than=2048
-Wno-gnu -Wvla -Wno-pointer-sign -Wcast-function-type
-Wimplicit-fallthrough -Werror=date-time -Werror=incompatible-pointer-types
-Wenum-conversion -Wextra -Wunused -Wno-unused-but-set-variable
-Wno-unused-const-variable -Wno-format-overflow
-Wno-format-overflow-non-kprintf -Wno-format-truncation-non-kprintf
-Wno-override-init -Wno-pointer-to-enum-cast
-Wno-tautological-constant-out-of-range-compare -Wno-unaligned-access
-Wno-enum-compare-conditional -Wno-enum-enum-conversion
-Wno-missing-field-initializers -Wno-type-limits -Wno-shift-negative-value
-Wno-sign-compare -Wno-unused-parameter -g
-DKBUILD_MODFILE='"rex/rex_generated"' -DKBUILD_BASENAME='"rex_generated"'
-DKBUILD_MODNAME='"rex_generated"' -D__KBUILD_MODNAME=kmod_rex_generated
-D__BINDGEN__ -DMODULE'''


def prep_uapi_headers(linux_path, headers, out_dir):
    for header in headers:
        subdir, hfile = os.path.split(header)
        subdir = os.path.join(out_dir, subdir)
        if not os.path.exists(subdir):
            os.makedirs(subdir)

        out_f = os.path.join(subdir, '%s.rs' % os.path.splitext(hfile)[0])
        cmd = bindgen_cmd.replace('\n', ' ').replace('$LINUX_OBJ', linux_path)
        subprocess.run(cmd % (header, out_f), check=True, shell=True)


def parse_cargo_toml(cargo_toml_path):
    with open(cargo_toml_path, 'rb') as toml_f:
        cargo_toml = tomllib.load(toml_f)

    uheaders = cargo_toml['rex'].get('uheaders', [])
    kheaders = cargo_toml['rex'].get('kheaders', [])
    kconfigs = cargo_toml['rex'].get('kconfigs', [])

    return uheaders, kheaders, kconfigs


def prep_kernel_headers(headers, linux_src, linux_obj, out_dir):
    bindings_h = os.path.join(out_dir, 'bindings.h')
    out_subdir = os.path.join(out_dir, 'linux')
    if not os.path.exists(out_subdir):
        os.makedirs(out_subdir)
    kernel_rs = os.path.join(out_subdir, 'kernel.rs')

    with open(bindings_h, 'w') as bindings:
        for h in headers:
            bindings.write('#include <%s>\n' % h)

    cmd = (
        bindgen_kernel_cmd.replace("\n", " ")
        .replace("$LINUX_SRC", linux_src)
        .replace("$LINUX_OBJ", linux_obj)
    )
    subprocess.run(
        cmd % (bindings_h, "|".join(k_structs), kernel_rs), check=True, shell=True
    )


def parse_kconfigs(dot_config_path, kconfigs):
    if len(kconfigs) == 0:
        return

    with open(dot_config_path) as dot_config:
        dot_config_content = dot_config.readlines()

    ptn = re.compile('(%s)' % '|'.join(kconfigs))

    fmt = 'cargo:rustc-cfg=%s="%s"\n' + \
          'cargo::rustc-check-cfg=cfg(%s, values("%s"))'

    print('\n'.join(map(lambda l: fmt % (l * 2),
                        map(lambda l: tuple(l.strip().split('=')),
                            filter(lambda l: l[0] != '#' and ptn.match(l),
                                   dot_config_content)))))


def main(argv):
    linux_obj = argv[1]
    linux_src = argv[2]
    out_dir = argv[3]
    target_path = os.getcwd()

    result = parse_cargo_toml(os.path.join(target_path, 'Cargo.toml'))
    uheaders, kheaders, kconfigs = result

    u_out_dir = os.path.join(out_dir, 'uapi')
    prep_uapi_headers(linux_obj, uheaders, u_out_dir)
    prep_kernel_headers(kheaders, linux_src, linux_obj, out_dir)
    parse_kconfigs(os.path.join(linux_obj, '.config'), kconfigs)
    return 0


if __name__ == '__main__':
    exit(main(sys.argv))
