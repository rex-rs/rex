#!/usr/bin/env python3
"""Build, profile, and generate flamegraphs for memcached_benchmark.

Usage:
  ./flamegraph.py                     # userspace-only (no sudo needed)
  ./flamegraph.py --kernel            # include kernel stacks (requires sudo)
  ./flamegraph.py -n 1000000          # custom request count
  ./flamegraph.py --no-skip-set       # include the SET phase
  ./flamegraph.py -F 9999             # higher sampling frequency
  ./flamegraph.py --open              # open SVG in browser after generation
  ./flamegraph.py --help
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import socket
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


def _is_executable(p: Path) -> bool:
    return p.is_file() and os.access(p, os.X_OK)


# FlameGraph upstream has no --version flag, so we read it off the path
# (e.g. `FlameGraph-2023-11-06` from a Nix store path).
_FG_VERSION_RX = re.compile(r"FlameGraph-([\w.\-]+)")


def flamegraph_version(fg_bin: Path) -> str | None:
    for part in fg_bin.resolve().parts:
        m = _FG_VERSION_RX.search(part)
        if m:
            return m.group(1)
    return None


def find_flamegraph_bin() -> Path:
    # 0. Env override: FLAMEGRAPH_DIR=/path/to/FlameGraph/bin
    env_dir = os.environ.get("FLAMEGRAPH_DIR")
    if env_dir and _is_executable(Path(env_dir) / "flamegraph.pl"):
        return Path(env_dir)

    # 1. PATH
    path_hit = shutil.which("flamegraph.pl")
    if path_hit:
        return Path(path_hit).parent

    # 2. Nix store (common on NixOS)
    nix_store = Path("/nix/store")
    if nix_store.is_dir():
        for p in nix_store.glob("*/bin/flamegraph.pl"):
            if os.access(p, os.X_OK):
                return p.parent

    # 3. Common checkout locations
    for d in (Path.home() / "FlameGraph", Path("/tmp/FlameGraph"), Path("/opt/FlameGraph")):
        if _is_executable(d / "flamegraph.pl"):
            return d

    raise FileNotFoundError(
        "flamegraph.pl not found.\n"
        "Install: cargo install flamegraph, or clone "
        "https://github.com/brendangregg/FlameGraph"
    )


def _combined_output(proc: subprocess.CompletedProcess) -> str:
    return (proc.stdout or "") + (proc.stderr or "")


def tail_output(cmd: list[str], n: int = 3) -> None:
    proc = subprocess.run(cmd, text=True, capture_output=True)
    for line in _combined_output(proc).rstrip().splitlines()[-n:]:
        print(line)
    if proc.returncode != 0:
        print(
            f"ERROR: {' '.join(cmd)} exited with status {proc.returncode}",
            file=sys.stderr,
        )
        sys.exit(proc.returncode)


def check_memcached_running(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def memcached_start_hint(host: str, port: int) -> str:
    return (
        f"memcached not reachable at {host}:{port}\n"
        f"\nStart it locally with:\n"
        f"  memcached -d -p {port} -U {port} -m 512 -c 1024 -t 4 -l {host}\n"
        f"\nOr point --server / --port at a host that's already running it."
    )


def check_kernel_privs() -> list[str]:
    def read_int(path: str, default: int) -> int:
        try:
            return int(Path(path).read_text().strip())
        except (OSError, ValueError):
            return default

    paranoid = read_int("/proc/sys/kernel/perf_event_paranoid", 2)
    kptr = read_int("/proc/sys/kernel/kptr_restrict", 1)

    if paranoid >= 2 or kptr >= 1:
        print()
        print("Kernel profiling requires elevated privileges.")
        print(f"  perf_event_paranoid={paranoid} (need <=1 for kernel stacks)")
        print(f"  kptr_restrict={kptr} (need 0 for kernel symbols)")
        print()
        print("Using sudo for perf record and perf script.")
        if subprocess.run(["sudo", "-v"], timeout=60).returncode != 0:
            sys.exit("ERROR: sudo authentication failed.")
        return ["sudo"]
    return []


def mk_flamegraph(
    fg_bin: Path,
    input_file: Path,
    output: Path,
    title: str,
    subtitle: str,
    kernel_mode: bool,
) -> None:
    if not input_file.exists() or input_file.stat().st_size == 0:
        print(f"  (skipped {output.name}: no samples)")
        return

    cmd = [
        str(fg_bin / "flamegraph.pl"),
        "--title", title,
        "--subtitle", subtitle,
        "--width", "1800",
        "--hash",
    ]
    if kernel_mode:
        cmd += ["--color", "java"]

    try:
        with input_file.open("rb") as fin, output.open("wb") as fout:
            subprocess.run(cmd, stdin=fin, stdout=fout, check=True)
    except subprocess.CalledProcessError as e:
        output.unlink(missing_ok=True)
        sys.exit(f"ERROR: flamegraph.pl failed for {output.name} (status {e.returncode})")

    size_kb = output.stat().st_size // 1024
    print(f"  {output} ({size_kb}K)")


def _trailing_count(line: str) -> int:
    tail = line.rsplit(" ", 1)[-1]
    try:
        return int(tail)
    except ValueError:
        return 0


def summary(lines: list[str], kernel_mode: bool) -> None:
    total = sum(_trailing_count(line) for line in lines if line)
    if total == 0:
        return

    print()
    print("=== CPU Time Distribution ===")

    def summarize(label: str, pattern: str) -> None:
        rx = re.compile(pattern)
        val = sum(_trailing_count(line) for line in lines if rx.search(line))
        pct = val * 100 / total
        print(f"  {label:<30} {val:>10}  ({pct:5.1f}%)")

    summarize("Zipf sampling (setup)", "generate_test_entries")
    summarize("  ChaCha8Rng", "ChaCha8")
    summarize("  Zipf::sample / floor", r"sample<.*Zipf|exp_unbiased")
    summarize("YAML dict load", "load_test_dict")
    summarize("Bench workers (I/O)", r"^bmc-worker")
    summarize("Arc/HashMap cleanup", "drop_slow")
    if kernel_mode:
        summarize("Kernel functions", r"_\[k\]")
        summarize("  net (udp/ip/sock)", r"udp_|ip_|sock_|skb_|__sys_send|__sys_recv")
        summarize("  scheduler", r"schedule|__switch_to|pick_next")
        summarize("  syscall entry", r"entry_SYSCALL|do_syscall")


@dataclass(frozen=True)
class Variant:
    name: str
    # None means render the folded file as-is; otherwise filter `lines` first.
    predicate: Callable[[str], bool] | None
    title: str
    subtitle: str


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Build, profile, and generate flamegraphs for memcached_benchmark.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Extra args after `--` are forwarded to the benchmark binary.",
    )
    ap.add_argument("-n", "--requests", type=int, default=5_000_000, help="Number of requests")
    ap.add_argument("-F", "--freq", type=int, default=4999, help="Perf sampling frequency in Hz")
    ap.add_argument("-s", "--server", default="127.0.0.1", help="Server address")
    ap.add_argument("-p", "--port", type=int, default=11211, help="Server port")
    ap.add_argument("-t", "--threads", type=int, default=4, help="Worker threads")
    ap.add_argument("-o", "--outdir", type=Path, default=Path("profiles"), help="Output directory")
    ap.add_argument("--kernel", action="store_true", help="Include kernel stacks (requires sudo)")
    ap.add_argument(
        "--no-skip-set", dest="skip_set", action="store_false", help="Include the SET phase"
    )
    ap.add_argument("--open", dest="open_svg", action="store_true", help="Open SVG after generation")
    ap.add_argument("extra", nargs=argparse.REMAINDER, help="Extra args (after --) for the binary")
    args = ap.parse_args()

    # cargo build and the default outdir are resolved relative to this crate.
    os.chdir(Path(__file__).resolve().parent)

    extra_args = args.extra[1:] if args.extra and args.extra[0] == "--" else args.extra

    try:
        fg_bin = find_flamegraph_bin()
    except FileNotFoundError as e:
        sys.exit(f"ERROR: {e}")
    version = flamegraph_version(fg_bin)
    version_label = f" (version {version})" if version else ""
    print(f"FlameGraph scripts: {fg_bin}{version_label}")

    if not shutil.which("perf"):
        sys.exit("ERROR: perf not found. Install linux-perf or perf-tools.")

    if not check_memcached_running(args.server, args.port):
        sys.exit(f"ERROR: {memcached_start_hint(args.server, args.port)}")
    print(f"memcached: reachable at {args.server}:{args.port}")

    sudo: list[str] = []
    if args.kernel:
        sudo = check_kernel_privs()
        print("Kernel mode: ON, kernel stacks will be included")
    else:
        print("Kernel mode: OFF, userspace only (use --kernel for kernel stacks)")

    print()
    print("Building with profiling profile (opt-level=3 + debuginfo + frame-pointers)...")
    tail_output(["cargo", "build", "--profile", "profiling"], n=3)
    bin_path = Path("./target/profiling/memcached_benchmark").resolve()
    if not _is_executable(bin_path):
        sys.exit(f"ERROR: binary not found at {bin_path}")

    args.outdir.mkdir(parents=True, exist_ok=True)
    perf_data = args.outdir / "perf.data"
    for p in (perf_data, args.outdir / "perf.data.old"):
        p.unlink(missing_ok=True)

    bench_args = [
        "bench",
        "-s", args.server,
        "-p", str(args.port),
        "-n", str(args.requests),
        "-t", str(args.threads),
    ]
    if args.skip_set:
        bench_args.append("--skip-set")
    bench_args += extra_args

    # --kernel: dwarf unwinding so we can walk both user and kernel stacks.
    # default: frame-pointer unwinding only, userspace.
    if args.kernel:
        perf_opts = ["-F", str(args.freq), "-e", "cycles", "-g", "--call-graph", "dwarf,16384"]
        mode_label = "cycles, dwarf unwind, user+kernel"
    else:
        perf_opts = ["-F", str(args.freq), "-e", "task-clock", "--call-graph", "fp"]
        mode_label = "task-clock, frame-pointer unwind, userspace only"

    print()
    prefix = "sudo " if sudo else ""
    print(f"Recording: {prefix}perf record {' '.join(perf_opts)} ...")
    print(f"  {bin_path} {' '.join(bench_args)}")
    print(f"  mode: {mode_label}")
    print()

    record_cmd = sudo + ["perf", "record", *perf_opts, "-o", str(perf_data), "--", str(bin_path), *bench_args]
    proc = subprocess.run(record_cmd, capture_output=True, text=True)
    for line in _combined_output(proc).rstrip().splitlines()[-20:]:
        print(line)
    if proc.returncode != 0:
        print(
            f"ERROR: perf record exited with status {proc.returncode}",
            file=sys.stderr,
        )
        return proc.returncode

    if sudo:
        subprocess.run(sudo + ["chown", f"{os.getuid()}:{os.getgid()}", str(perf_data)], check=True)

    print()
    print("Collapsing stacks...")
    folded = args.outdir / "perf.folded"
    script_proc = subprocess.Popen(
        sudo + ["perf", "script", "-i", str(perf_data)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert script_proc.stdout is not None
    with folded.open("wb") as fout:
        collapse = subprocess.Popen(
            [str(fg_bin / "stackcollapse-perf.pl"), "--kernel"],
            stdin=script_proc.stdout,
            stdout=fout,
            stderr=subprocess.PIPE,
        )
        script_proc.stdout.close()
        _, collapse_err = collapse.communicate()
        _, script_err = script_proc.communicate()

    if script_proc.returncode != 0:
        sys.stderr.write(script_err.decode("utf-8", "replace"))
        sys.exit(f"ERROR: perf script exited with status {script_proc.returncode}")
    if collapse.returncode != 0:
        sys.stderr.write(collapse_err.decode("utf-8", "replace"))
        sys.exit(f"ERROR: stackcollapse-perf.pl exited with status {collapse.returncode}")
    if folded.stat().st_size == 0:
        sys.exit(f"ERROR: {folded} is empty (no samples to collapse)")

    lines = folded.read_text().splitlines()
    print(f"  {len(lines)} unique stacks")

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    print()
    print("Generating flamegraphs...")

    variants: list[Variant] = [
        Variant(
            "full", None,
            f"memcached_benchmark: Full Program ({args.requests} reqs, {args.threads} threads)",
            f"{timestamp}, {mode_label}",
        ),
        Variant(
            "setup", lambda l: not l.startswith(("bmc-worker", "perf-exec")),
            "memcached_benchmark: Setup Phase (dict load + Zipf sampling)",
            f"{timestamp}, non-worker threads (main + r2d2 pool)",
        ),
        Variant(
            "workers", lambda l: l.startswith("bmc-worker"),
            "memcached_benchmark: Bench Workers (sendmmsg/recvmmsg)",
            f"{timestamp}, bmc-worker-0..{args.threads - 1}",
        ),
    ]
    if args.kernel:
        variants.append(Variant(
            "kernel", lambda l: "_[k]" in l,
            "memcached_benchmark: Kernel Functions Only",
            f"{timestamp}, kernel frames from all threads",
        ))

    for v in variants:
        if v.predicate is None:
            input_file = folded
        else:
            input_file = args.outdir / f"perf_{v.name}.folded"
            with input_file.open("w") as f:
                f.writelines(line + "\n" for line in lines if v.predicate(line))
        mk_flamegraph(
            fg_bin, input_file, args.outdir / f"flamegraph_{v.name}.svg",
            v.title, v.subtitle, args.kernel,
        )

    summary(lines, args.kernel)

    if args.open_svg:
        svg = args.outdir / "flamegraph_full.svg"
        for opener in ("xdg-open", "open"):
            if shutil.which(opener):
                subprocess.Popen([opener, str(svg)])
                break
        else:
            print(f"Open manually: {svg}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
