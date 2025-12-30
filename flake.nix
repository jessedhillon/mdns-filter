{
  description = "mDNS filter";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    fp.url = "github:hercules-ci/flake-parts";
    devshell = {
      url = "github:numtide/devshell";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
  };

  outputs = inputs:
    let
      project-name = "mdns-filter";
    in
    inputs.fp.lib.mkFlake { inherit inputs; } {
      systems = inputs.nixpkgs.lib.systems.flakeExposed;

      flake = {
        # NixOS module for service configuration
        nixosModules.mdns-filter = import ./nix/module.nix;
        nixosModules.default = inputs.self.nixosModules.mdns-filter;

        # Overlay to add mdns-filter package to pkgs
        overlays.default = final: prev: {
          mdns-filter = inputs.self.packages.${final.stdenv.hostPlatform.system}.default;
        };
      };

      perSystem =
        { system, pkgs, lib, ... }:
        let
          rustToolchain = pkgs.rust-bin.stable.latest.default.override {
            extensions = [ "rust-src" "rust-analyzer" ];
          };
          craneLib = (inputs.crane.mkLib pkgs).overrideToolchain rustToolchain;
        in
        {
          _module.args.pkgs = import inputs.nixpkgs {
            inherit system;
            config.allowUnfree = true;
            overlays = [
              inputs.devshell.overlays.default
              inputs.rust-overlay.overlays.default
            ];
          };

          packages.default = craneLib.buildPackage {
            src = craneLib.cleanCargoSource ./.;
            strictDeps = true;
            meta.mainProgram = "mdns-filter";
          };

          checks = {
            # Verify the package builds
            package = inputs.self.packages.${system}.default;
          } // lib.optionalAttrs pkgs.stdenv.isLinux {
            # Test NixOS module configuration (Linux only)
            nixos-module = (inputs.nixpkgs.lib.nixosSystem {
              inherit system;
              modules = [
                { nixpkgs.overlays = [ inputs.self.overlays.default ]; }
                inputs.self.nixosModules.default
                ./nix/test-config.nix
              ];
            }).config.system.build.toplevel;
          };

          devShells.default = pkgs.devshell.mkShell {
            name = "${project-name}";
            motd = "{32}${project-name} {reset}\n$(type -p menu &>/dev/null && menu)\n";

            env = [
              {
                name = "LD_LIBRARY_PATH" ;
                value = pkgs.lib.makeLibraryPath [
                  pkgs.file
                  pkgs.stdenv.cc.cc.lib
                ];
              }
            ];

            packages = with pkgs; [
              # Rust toolchain
              rustToolchain
              cargo-watch
              cargo-edit
              clang

              # Tools
              claude-code
              file
              gh
              moreutils
              pre-commit
            ];

            commands = [
              {
                name = "format";
                command = ''
                pushd $PRJ_ROOT
                cargo fmt
                popd'';
                help = "format Rust code with rustfmt";
                category = "rust";
              }
              {
                name = "check";
                command = ''
                pushd $PRJ_ROOT
                echo "cargo check" | ts "[cargo]"
                cargo check 2>&1 | ts "[cargo]"
                echo "clippy" | ts "[clippy]"
                cargo clippy -- -D warnings 2>&1 | ts "[clippy]"
                popd'';
                help = "lint Rust code with cargo check and clippy";
                category = "rust";
              }
              {
                name = "test";
                command = ''
                pushd $PRJ_ROOT
                cargo test "$@"
                popd'';
                help = "run Rust tests";
                category = "rust";
              }
              {
                name = "watch";
                command = ''
                pushd $PRJ_ROOT
                cargo watch -x check -x "clippy -- -D warnings" -x test
                popd'';
                help = "watch and rebuild on changes";
                category = "rust";
              }
            ];
          };
        };
    };
}
