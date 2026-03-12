{
  description = "Rust development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        # 1. Replicate languages.rust
        rustToolchain = pkgs.rust-bin.nightly.latest.default.override {
          extensions = [
            "rust-src"
            "rustc"
            "clippy"
            "rust-analyzer"
            "rustfmt"
          ];
        };

        # Extract LLVM major version from the Rust toolchain via IFD
        rustcLlvmVersion = pkgs.runCommand "rustc-llvm-version" {
          nativeBuildInputs = [ rustToolchain ];
        } ''
          rustc -vV | sed -n 's/LLVM version: \([0-9]*\).*/\1/p' | tr -d '\n' > $out
        '';
        llvmMajor = builtins.readFile rustcLlvmVersion;
        llvmPackages = pkgs."llvmPackages_${llvmMajor}";
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            pkgs.git
            pkgs.mold
            llvmPackages.clangUseLLVM
            pkgs.memcached
            rustToolchain
          ];

          shellHook = ''
            # enterShell logic
            clang --version
            rustc --version
          '';
        };
      }
    );
}
