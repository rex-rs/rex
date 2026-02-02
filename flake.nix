{
  description = "A flake for the REX project";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs, ... }:
    let
      system = "x86_64-linux";

      basePkgs = import nixpkgs {
        inherit system;
      };

      remoteNixpkgsPatches = [
        {
          meta.description = "cc-wrapper: remove -nostdlibinc";
          url = "https://github.com/chinrw/nixpkgs/commit/2a5bd9cecd9ae28d899eb9bf434255a9fa09cbb0.patch";
          sha256 = "sha256-TBmNtH8C5Vp1UArLtXDk+dxEzUR3tohjPMpJc9pIEN8=";
        }
      ];

      patchedNixpkgsSrc = basePkgs.applyPatches {
        name = "nixpkgs-patched";
        src = basePkgs.path;
        patches = map basePkgs.fetchpatch remoteNixpkgsPatches;
      };

      # patchedBindgen =
      #   (self: super: {
      #     rust-bindgen-unwrapped = super.rust-bindgen-unwrapped.overrideAttrs (finalAttrs: oldAttrs: {
      #       src = super.fetchFromGitHub {
      #         owner = "rust-lang";
      #         repo = "rust-bindgen";
      #         rev = "20aa65a0b9edfd5f8ab3e038197da5cb2c52ff18";
      #         sha256 = "sha256-OrwPpXXfbkeS7SAmZDZDUXZV4BfSF3e/58LJjedY1vA=";
      #       };
      #       cargoDeps = pkgs.rustPlatform.fetchCargoVendor {
      #         inherit (finalAttrs) pname src version;
      #         hash = finalAttrs.cargoHash;
      #       };
      #       cargoHash = "sha256-e94pwjeGOv/We6uryQedj7L41dhCUc2wzi/lmKYnEMA=";
      #     });
      #   });

      patchedPkgs = import patchedNixpkgsSrc {
        inherit system;
        # overlays = [ patchedBindgen ];
      };

      pkgs = import nixpkgs {
        inherit system;
        # overlays = [ overrideLLVM ];
      };

      wrapCC = cc: pkgs.wrapCCWith {
        inherit cc;
        extraBuildCommands = ''
          # Remove the line that contains "-nostdlibinc"
          sed -i 's|-nostdlibinc||g' "$out/nix-support/cc-cflags"
          echo " -resource-dir=${pkgs.llvmPackages.clang}/resource-root" >> "$out/nix-support/cc-cflags"
          echo > "$out/nix-support/add-local-cc-cflags-before.sh"
        '';
      };



      # wrappedClang = wrapCC pkgs.llvmPackages.clang.cc;
      # lib = nixpkgs.lib;

      # Use unwrapped clang & lld to avoid warnings about multi-target usage
      rexPackages = with pkgs; [
        # Kernel builds
        autoconf
        bc
        binutils
        bison
        cmake
        diffutils
        elfutils
        elfutils.dev
        fakeroot
        findutils
        flex
        git
        gcc
        getopt
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

        cargo-pgo

        ninja
        patchedPkgs.rust-bindgen
        pahole
        strace
        zstd
        perf-tools
        # linuxKernel.packages.linux_latest.perf

        # Clang kernel builds
        patchedPkgs.llvmPackages.clang
        patchedPkgs.llvmPackages.llvm
        # wrappedClang
        # llvmPackages.libcxxStdenv
        lld
        mold

        qemu
        file
        util-linux
        hostname
        sysctl

        perf-tools

        # for llvm/Demangle/Demangle.h
        libllvm.lib
        libllvm.dev
        libgcc
        libclang.lib
        libclang.dev

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
        python3

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
          targetPkgs = pkgs: rexPackages ++ [ pkgs.systemd pkgs.file ];

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
            export PATH=${patchedPkgs.llvmPackages.libllvm.out}/bin:$PATH
            export PATH=${patchedPkgs.llvmPackages.libllvm.dev}/bin:$PATH
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
