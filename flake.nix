{
  description = "A flake for the REX project";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs, ... }:
    let
      system = "x86_64-linux";

      pkgs = import nixpkgs {
        inherit system;
      };

      # Strip -nostdlibinc from an existing nixpkgs clang wrapper
      wrapCC = clangWrapper: clangWrapper.overrideAttrs (old: {
        postFixup = old.postFixup + ''
          sed -i 's|-nostdlibinc||g' "$out/nix-support/cc-cflags"
        '';
      });

      wrappedClang = wrapCC pkgs.llvmPackages_22.clang;

      # The bindgen bakes the flags nix-support/cc-cflags into the wrapper
      # script at build time, so -nostdlibinc needs to be removed with the
      # wrapCC
      cleanBindgen = pkgs.rust-bindgen.override {
        rust-bindgen-unwrapped = pkgs.rust-bindgen-unwrapped.override {
          clang = wrapCC pkgs.clang;
        };
      };

      # Use unwrapped clang & lld to avoid warnings about multi-target usage
      rexPackages = with pkgs; [
        # Kernel builds
        bc
        binutils
        bison
        cmake
        diffutils
        elfutils
        elfutils.dev
        findutils
        flex
        git
        gcc
        gnumake
        ncurses
        openssl
        openssl.dev
        pkg-config
        xz
        xz.dev
        zlib
        zlib.dev
        bpftools

        ninja
        cleanBindgen
        pahole
        zstd
        perf

        mold

        qemu
        file
        util-linux
        hostname
        sysctl


        # Clang kernel builds
        wrappedClang
        llvmPackages_22.llvm
        # for llvm/Demangle/Demangle.h
        llvmPackages_22.libllvm.lib
        llvmPackages_22.libllvm.dev
        llvmPackages_22.libclang.lib
        llvmPackages_22.lld
        libgcc

        # meson deps
        meson
        curl
        perl

        bear # generate compile commands
        rsync # for make headers_install
        gdb

        # bmc deps
        iproute2
        memcached
        # used to auto-generate the libbpf bindings in librex; pinned to LLVM 22
        # (matches llvmPackages_22).
        (python3.withPackages (ps: [
          ((ps.libclang.override { llvmPackages = llvmPackages_22; }).overrideAttrs (old: {
            prePatch = (old.prePatch or "") + "rm -f ./pyproject.toml ./setup.cfg\n";
          }))
        ]))

        # Rex utils
        zoxide # in case host is using zoxide
        openssh # q-script ssh support
        bat
        fd
        eza
        zsh
      ];

      llvmBuildFHSEnv = pkgs.buildFHSEnv.override { stdenv = pkgs.llvmPackages.stdenv; };
      fhsBase =
        {
          name = "rex-env";
          targetPkgs = pkgs: rexPackages ++ [ pkgs.systemd ];

          profile = ''
            export NIX_ENFORCE_NO_NATIVE=0
            export PATH=$(realpath "./build/rust-dist/bin"):$PATH
            export RUST_BACKTRACE=1
          '';
        };

      fhsRex = llvmBuildFHSEnv (fhsBase // {
        runScript = "zsh";
      });

      # FHS environment for running arbitrary commands
      fhsExec = llvmBuildFHSEnv (fhsBase // {
        name = "rex-exec";
        runScript = pkgs.writeScript "fhs-exec-wrapper" ''
          #!${pkgs.bash}/bin/bash
          exec bash "$@"
        '';
      });

    in
    {
      devShells."${system}" = {
        default = fhsRex.env;

        rex = pkgs.mkShell {
          packages = rexPackages;
          # Disable default hardening flags. These are very confusing when doing
          # development and they break builds of packages/systems that don't
          # expect these flags to be on. Automatically enables stuff like
          # FORTIFY_SOURCE, -Werror=format-security, -fPIE, etc. See:
          # - https://nixos.org/manual/nixpkgs/stable/#sec-hardening-in-nixpkgs
          # - https://nixos.wiki/wiki/C#Hardening_flags
          hardeningDisable = [ "all" ];
          LD_LIBRARY_PATH = "${pkgs.stdenv.cc.cc.lib.outPath}/lib:${pkgs.lib.makeLibraryPath rexPackages}:$LD_LIBRARY_PATH";
          shellHook = ''

            export NIX_CC_WRAPPER_SUPPRESS_TARGET_WARNING=1
            export PATH=$(realpath "./build/rust-dist/bin"):$PATH
            # Add required llvm-config
            export PATH=${pkgs.llvmPackages_22.libllvm.out}/bin:$PATH
            export PATH=${pkgs.llvmPackages_22.libllvm.dev}/bin:$PATH
            export RUST_BACKTRACE=1
            export NIX_ENFORCE_NO_NATIVE=0
            export LLVM_SRC_INC="$PWD/rust/src/llvm-project/llvm/include"
            # export LLVM_BUILD_INCLUDE="$PWD/build/rust-build/x86_64-unknown-linux-gnu/llvm/build/include"
            export NIX_CFLAGS_COMPILE_BEFORE="-I$LLVM_SRC_INC"
            echo "loading rex env"
          '';
        };
      };

      packages."${system}" = {
        fhsRex = fhsRex;
        fhsExec = fhsExec;
      };
    };

}
