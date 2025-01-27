{
  description = "A flake for the REX project";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs, ... }:
    let
      # overlays = [
      #   (self: super: {
      #     bindgen = super.bindgen.overrideAttrs (oldAttrs: {
      #       src = super.fetchCrate {
      #         pname = "bindgen-cli";
      #         version = "0.68.1";
      #         sha256 = "sha256-5fwJq1WsL3IEcVUjsyqKdQU8VufbbPk6TglwJg3C1Gw=";
      #       };
      #     });
      #   })
      # ];

      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
        # overlays = overlays;
      };
      rexPackages = with pkgs; [
        # build deps
        cmake
        ninja # rust build
        (hiPrio gcc)
        libgcc
        curl
        diffutils
        xz.dev
        llvm_19
        clang_19
        lld_19
        clang-tools
        zlib.dev
        openssl.dev
        flex
        bison
        busybox
        qemu
        mold
        perl
        pkg-config
        elfutils.dev
        ncurses.dev
        rust-bindgen
        pahole
        strace
        zstd
        eza
        zlib

        bear # generate compile commands
        rsync # for make headers_install
        gdb

        # bmc deps
        iproute2
        memcached

        # python3 scripts
        (pkgs.python3.withPackages
          (python-pkgs: (with python-pkgs;  [
            # select Python packages here
            tqdm
          ])))

        zoxide # in case host is using zoxide
        openssh # q-script ssh support
      ];

      fhs = pkgs.buildFHSEnv {
        name = "rex-env";
        targetPkgs = pkgs: rexPackages;
        runScript = "./scripts/start.sh";
        profile = ''
          export LIBCLANG_PATH="${pkgs.llvmPackages_19.libclang.lib}/lib/libclang.so"
        '';
      };
    in
    {
      devShells."${system}" = {
        default = fhs.env;

        rex = pkgs.mkShell {
          inputsFrom = [ pkgs.linux_latest ];
          buildInputs = rexPackages;
          hardeningDisable = [ "strictoverflow" "zerocallusedregs" ];

          shellHook = ''
            echo "loading rex env"
            source ./scripts/env.sh
            export LIBCLANG_PATH="${pkgs.llvmPackages_19.libclang.lib}/lib/libclang.so"
          '';
        };
      };
    };
}

