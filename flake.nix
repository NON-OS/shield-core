{
  # One command that gives every builder the same tools: the Rust toolchain
  # this tree pins in rust-toolchain.toml, the shell tools the two apps need,
  # and the exact Aeneas and Charon that produced the committed extraction.
  # Aeneas exports the Charon it was built against, so the two cannot drift
  # from each other here, and flake.lock pins everything else by hash.
  #
  #   nix develop                 cargo, charon, aeneas, elan and the app tools
  #   nix build .#extraction      the Lean that verified/src translates to
  #   nix flake check             fails if lean-verified/NoxVerified.lean has drifted
  #
  # The extracted proofs are checked by lake, which fetches mathlib and so
  # cannot run inside a pure build; the verify workflow does that in the shell.
  description = "NOX Shield, the wallet core";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
    aeneas.url = "github:AeneasVerif/aeneas/45061fa1a5b4bad876f17c03d3a5544d818622e6";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, aeneas, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
          config.allowUnfree = true;
          config.android_sdk.accept_license = true;
        };

        # The channel, components and targets are read from the same file
        # rustup reads, so the shell and a bare checkout agree by construction.
        rust = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

        charon = aeneas.packages.${system}.charon;
        aeneasBin = aeneas.packages.${system}.aeneas;
      in
      {
        packages.core = pkgs.rustPlatform.buildRustPackage {
          pname = "nox-shield-core";
          version = "0.1.0";
          src = self;
          cargoLock.lockFile = ./Cargo.lock;
          # The shield stack and the custody crates are path dependencies from
          # sibling checkouts, so a pure build needs them vendored first. See
          # docs/07-reproduce.md for the vendoring step.
          doCheck = false;
        };

        # The translation as a derivation: no network, no host toolchain, the
        # same bytes on every machine that evaluates this flake.
        packages.extraction = pkgs.stdenv.mkDerivation {
          name = "nox-verified-extraction";
          src = ./verified;
          nativeBuildInputs = [ charon aeneasBin ];
          buildPhase = ''
            export HOME=$TMPDIR
            charon cargo --preset=aeneas --dest-file nox_verified.llbc
            mkdir -p $out
            aeneas -backend lean nox_verified.llbc -dest $out -namespace NoxVerified
          '';
          installPhase = "true";
        };

        checks.lean = pkgs.stdenv.mkDerivation {
          name = "nox-shield-lean";
          src = ./lean;
          nativeBuildInputs = [ pkgs.elan ];
          buildPhase = "lake build";
          installPhase = "touch $out";
        };

        # The committed extraction is the one the Rust produces.
        checks.extraction = pkgs.runCommand "nox-verified-extraction-is-committed" {} ''
          if ! diff -u ${./lean-verified/NoxVerified.lean} ${self.packages.${system}.extraction}/NoxVerified.lean; then
            echo "lean-verified/NoxVerified.lean does not match verified/src; run scripts/extract.sh" >&2
            exit 1
          fi
          touch $out
        '';

        devShells.default = pkgs.mkShell {
          packages = [
            rust
            charon
            aeneasBin
            pkgs.cargo-ndk
            pkgs.cargo-deny
            pkgs.cargo-audit
            pkgs.elan
            pkgs.jdk17
            pkgs.xcodegen
          ];

          shellHook = ''
            echo "NOX Shield core."
            echo "  cargo test                     the fast suite"
            echo "  cargo test --release -- --ignored   the proof gates"
            echo "  (cd lean && lake build)        the machine checked proofs"
            echo "  scripts/extract.sh             the Rust to Lean translation"
            echo "  (cd lean-verified && lake build)   the proofs about the Rust"
          '';
        };
      });
}
