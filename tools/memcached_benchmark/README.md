# memcached_benchmark

## Profiling with `flamegraph.py`

`flamegraph.py` builds `memcached_benchmark` under the `profiling` Cargo
profile, runs it under `perf record`, collapses the samples, and writes
flamegraph SVGs into `profiles/`.

### Prerequisites

- `perf`: the Linux `perf` tools.
- [FlameGraph](https://github.com/brendangregg/FlameGraph) scripts
  (`flamegraph.pl`, `stackcollapse-perf.pl`). Any of these work:
  - `nix-shell -p linuxPackages.perf flamegraph`
  - Clone to `~/FlameGraph`, `/tmp/FlameGraph`, or `/opt/FlameGraph`
  - Any other location, with `FLAMEGRAPH_DIR=/path/to/FlameGraph` exported

  Do not `cargo install flamegraph` — that installs flamegraph-rs, which
  bundles the perl scripts internally and does not expose `flamegraph.pl`
  on `PATH`.
- A running `memcached` instance reachable at the configured host/port
  (default `127.0.0.1:11211`). The script probes the port up front and
  bails out if nothing is listening, printing a `memcached -d ...` command
  to start one.

### Basic usage

```bash
# userspace-only profile, no sudo required
./flamegraph.py

# include kernel stacks (network + scheduler paths), requires sudo
./flamegraph.py --kernel

# open the full flamegraph in a browser when done
./flamegraph.py --open
```

Extra args after `--` are forwarded to the benchmark binary:

```bash
./flamegraph.py -n 1000000 -- --verbose
```

### Common flags

| Flag | Default | Notes |
|------|---------|-------|
| `-n`, `--requests` | `5_000_000` | Number of benchmark requests |
| `-F`, `--freq` | `4999` Hz | `perf` sampling frequency |
| `-s`, `--server` | `127.0.0.1` | memcached host |
| `-p`, `--port` | `11211` | memcached port |
| `-t`, `--threads` | `4` | Worker threads |
| `-o`, `--outdir` | `profiles/` | Output directory |
| `--kernel` | off | Include kernel stacks (dwarf unwind, needs sudo) |
| `--no-skip-set` | SET skipped | Include the SET phase in the sampled run |
| `--open` | off | Open `flamegraph_full.svg` after generation |

### Output

All artifacts land in `profiles/` (gitignored):

- `perf.data`: raw `perf record` output
- `perf.folded`: collapsed stacks from `stackcollapse-perf.pl`
- `flamegraph_full.svg`: every sampled thread
- `flamegraph_setup.svg`: main + rayon threads (dict load, Zipf sampling)
- `flamegraph_workers.svg`: `bmc-worker-*` threads only (sendmmsg/recvmmsg)
- `flamegraph_kernel.svg`: kernel frames only (emitted only with `--kernel`)

A `CPU Time Distribution` summary is also printed to stdout (Zipf sampling
share, worker I/O share, kernel-function share when applicable).

### Modes

| Mode | Event | Unwind | Scope |
|------|-------|--------|-------|
| default | `task-clock` | frame pointers | userspace only |
| `--kernel` | `cycles` | `dwarf,16384` | user + kernel |

The `profiling` Cargo profile (`Cargo.toml`) forces
`-Cforce-frame-pointers=yes`, keeps `debug = "full"`, and disables
`split-debuginfo` for kernel-mode unwinding.

### Kernel-mode prerequisites

Kernel stacks need relaxed sysctls; the script checks
`/proc/sys/kernel/perf_event_paranoid` and `/proc/sys/kernel/kptr_restrict` and
prompts for `sudo` if either blocks kernel profiling:

```bash
sudo sysctl -w kernel.perf_event_paranoid=1   # or 0
sudo sysctl -w kernel.kptr_restrict=0
```

`flamegraph.py --kernel` runs `perf record` / `perf script` under `sudo` when
needed and chowns `perf.data` back to the invoking user afterwards.

### Troubleshooting

- **`flamegraph.pl not found`**: install the FlameGraph scripts or set
  `FLAMEGRAPH_DIR`.
- **`perf: command not found`**: install `linux-perf` / `perf` for your
  kernel version.
- **Empty userspace stacks or `[unknown]` frames**: confirm the build was
  produced by the `profiling` profile (automatic when using `flamegraph.py`,
  i.e. `target/profiling/memcached_benchmark`).
- **`memcached not reachable at HOST:PORT`**: the pre-flight TCP probe
  failed. Start `memcached` (the suggested command is printed) or pass
  `-s` / `-p` to match an existing instance.
- **`sudo authentication failed`**: run `sudo -v` once outside the script to
  seed credentials, then retry.
