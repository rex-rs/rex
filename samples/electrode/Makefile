LINUX_INC = ${LINUX}/usr/include
LIBBPF_DIR = $(abspath ${LINUX}/tools/lib/bpf)
LIBREX_DIR := $(abspath ../../librex)

NO_OPT = -C target-feature=-avx,-avx2,-sse,-sse2,-sse3,-sse4.1,-sse4.2,-sse4a,-ssse3

RUST_FLAGS = -Funsafe_code -Finternal_features -Fincomplete_features -Funstable_features -Clink-arg=-nostartfiles -Clink-arg=-fuse-ld=bfd -Cenable_rex

CC = clang

CFLAGS += -O2 -march=native -pipe -std=gnu11
CFLAGS += -ffunction-sections -fdata-sections -fno-semantic-interposition
LDFLAGS += -fuse-ld=mold -Wl,--as-needed -Wl,-O1 -Wl,--gc-sections

LOADER_INC += -I${LINUX_INC} -I${LIBBPF_DIR} -I${LIBREX_DIR}
LOADER_LDFLAGS = -L${LIBBPF_DIR} -L${LIBREX_DIR} -lbpf -lrex -Wl,-rpath=${LIBBPF_DIR} -Wl,-rpath=${LIBREX_DIR}

V ?= 0

ifeq ($(V),1)
CARGO_FLAGS += -v
endif

ifeq ($(V),2)
CARGO_FLAGS += -vv
endif

all: target/x86_64-unknown-linux-gnu/release/electrode entry

clippy: Cargo.toml clippy.toml ./src/*.rs
	cargo clippy -r -- -Fclippy::disallowed-methods -Fclippy::disallowed-types

target/x86_64-unknown-linux-gnu/debug/electrode: clippy Cargo.toml ./src/*.rs
	cargo rustc ${CARGO_FLAGS} -- ${RUST_FLAGS}

target/x86_64-unknown-linux-gnu/release/electrode: clippy Cargo.toml ./src/*.rs
	cargo rustc ${CARGO_FLAGS} --release -- ${RUST_FLAGS}

llvm-ir: Cargo.toml ./src/*.rs
	cargo rustc ${CARGO_FLAGS} --release -- ${RUST_FLAGS} --emit llvm-ir

entry: entry.c
	${CC} ${LOADER_INC} ${CFLAGS} ${LDFLAGS} -o $@ $< ${LOADER_LDFLAGS}

clean:
	cargo clean
	rm -rf entry ./src/linux/*.rs ./src/stub.rs
