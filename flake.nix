{
  description = "mDNS filter";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    fp.url = "github:hercules-ci/flake-parts";
    devshell = {
      url = "github:numtide/devshell";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = inputs:
    let
      project-name = "mdns-filter";
    in
    inputs.fp.lib.mkFlake { inherit inputs; } {
      systems = inputs.nixpkgs.lib.systems.flakeExposed;
      perSystem =
        { system, pkgs, lib, ... }:
        {
          _module.args.pkgs = import inputs.nixpkgs {
            inherit system;
            config.allowUnfree = true;
            overlays = [
              inputs.devshell.overlays.default
            ];
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
              (python312.withPackages (
                pypkgs: with pypkgs; [
                  pip
                ]
              ))
              claude-code
              file
              gh
              moreutils
              poetry
              pre-commit
              pyright
              ruff
            ];

            commands = [
              {
                name = "format";
                command = ''
                pushd $PRJ_ROOT;
                (ruff format -q mdns_filter/ && isort -q --dt mdns_filter/);
                popd'';
                help = "apply ruff, isort, prettier formatting";
              }

              {
                name = "check";
                command = ''
                pushd $PRJ_ROOT;
                echo "mdns_filter"
                (ruff check mdns_filter/ || true) | ts "[ruff]"
                pyright mdns_filter/ | ts "[pyright]"

                if [[ -d "tests/" ]]; then
                  echo "tests"
                  (ruff check tests/ || true) | ts "[ruff]"
                  pyright tests/ | ts "[pyright]"
                fi
                popd'';
                help = "run ruff linter, pyright type checker";
              }
            ];
          };
        };
    };
}
