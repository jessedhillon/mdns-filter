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

          # Rust package build (for eventual nixpkgs)
          packages.default = craneLib.buildPackage {
            src = craneLib.cleanCargoSource ./.;
            strictDeps = true;
            # buildInputs = [ ]; # add if needed
            # nativeBuildInputs = [ ]; # add if needed
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
              # Python toolchain
              (python312.withPackages (
                pypkgs: with pypkgs; [
                  isort
                  pip
                ]
              ))
              poetry
              pyright
              ruff

              # Rust toolchain
              rustToolchain
              cargo-watch
              cargo-edit

              # Shared tools
              claude-code
              file
              gh
              moreutils
              pre-commit
            ];

            commands = [
              # Python commands
              {
                name = "format-py";
                command = ''
                pushd $PRJ_ROOT
                ruff format -q mdns_filter/ tests/ && isort -q --dt mdns_filter/ tests/
                popd'';
                help = "format Python code with ruff and isort";
                category = "python";
              }
              {
                name = "check-py";
                command = ''
                pushd $PRJ_ROOT
                echo "mdns_filter"
                (ruff check mdns_filter/ || true) | ts "[ruff]"
                pyright mdns_filter/ | ts "[pyright]"

                if [[ -d "tests/" ]]; then
                  echo "tests"
                  (ruff check tests/ || true) | ts "[ruff]"
                  pyright tests/ | ts "[pyright]"
                fi
                popd'';
                help = "lint and type-check Python code";
                category = "python";
              }
              {
                name = "test-py";
                command = ''
                pushd $PRJ_ROOT
                pytest tests/ "$@"
                popd'';
                help = "run Python tests";
                category = "python";
              }

              # Rust commands
              {
                name = "format-rs";
                command = ''
                pushd $PRJ_ROOT
                cargo fmt
                popd'';
                help = "format Rust code with rustfmt";
                category = "rust";
              }
              {
                name = "check-rs";
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
                name = "test-rs";
                command = ''
                pushd $PRJ_ROOT
                cargo test "$@"
                popd'';
                help = "run Rust tests";
                category = "rust";
              }
              {
                name = "watch-rs";
                command = ''
                pushd $PRJ_ROOT
                cargo watch -x check -x "clippy -- -D warnings" -x test
                popd'';
                help = "watch and rebuild Rust on changes";
                category = "rust";
              }

              # Combined/default commands
              {
                name = "format";
                command = "format-py; format-rs";
                help = "format all code";
                category = "all";
              }
              {
                name = "check";
                command = "check-py; check-rs";
                help = "lint all code";
                category = "all";
              }
            ];
          };
        };
    };
}
