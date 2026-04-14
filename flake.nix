{
  description = "hopli application";

  inputs = {
    # Core Nix ecosystem dependencies
    flake-utils.url = "github:numtide/flake-utils";
    flake-parts.url = "github:hercules-ci/flake-parts";
    nixpkgs.url = "github:NixOS/nixpkgs/release-25.11";
    nixpkgs-unstable.url = "github:NixOS/nixpkgs/nixos-unstable";

    # HOPR Nix Library (provides flake-utils and reusable build functions)
    nix-lib.url = "github:hoprnet/nix-lib/v1.1.0";

    # Rust build system
    rust-overlay.url = "github:oxalica/rust-overlay/master";

    # Development tools and quality assurance
    foundry.url = "github:hoprnet/foundry.nix/tb/202505-add-xz";
    pre-commit.url = "github:cachix/git-hooks.nix";
    treefmt-nix.url = "github:numtide/treefmt-nix";
    flake-root.url = "github:srid/flake-root";

    # Input dependency optimization
    flake-parts.inputs.nixpkgs-lib.follows = "nixpkgs";
    foundry.inputs.flake-utils.follows = "flake-utils";
    foundry.inputs.nixpkgs.follows = "nixpkgs";
    nix-lib.inputs.nixpkgs.follows = "nixpkgs";
    pre-commit.inputs.nixpkgs.follows = "nixpkgs";
    nix-lib.inputs.rust-overlay.follows = "rust-overlay";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
    treefmt-nix.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      self,
      nixpkgs,
      nixpkgs-unstable,
      flake-utils,
      flake-parts,
      rust-overlay,
      nix-lib,
      foundry,
      pre-commit,
      ...
    }@inputs:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [
        inputs.nix-lib.flakeModules.default
        inputs.flake-root.flakeModule
      ];
      perSystem =
        {
          config,
          lib,
          system,
          ...
        }:
        let
          # Git revision for version tracking
          rev = toString (self.shortRev or self.dirtyShortRev);

          # Filesystem utilities for source filtering
          fs = lib.fileset;

          localSystem = system;

          # Nixpkgs with rust-overlay and foundry overlay
          overlays = [
            (import rust-overlay)
            foundry.overlay
          ];
          pkgs = import nixpkgs { inherit localSystem overlays; };
          pkgsUnstable = import nixpkgs-unstable { inherit localSystem overlays; };

          # Platform information
          buildPlatform = pkgs.stdenv.buildPlatform;

          # Import nix-lib for this system
          nixLib = nix-lib.lib.${system};

          # Use nix-lib to create all rust builders for cross-compilation
          builders = nixLib.mkRustBuilders {
            inherit localSystem;
            rustToolchainFile = ./rust-toolchain.toml;
          };

          # Use nix-lib's source filtering for better rebuild performance
          depsSrc = nixLib.mkDepsSrc {
            root = ./.;
            inherit fs;
            extraFiles = [
              (fs.fileFilter (file: file.hasExt "sh") ./.ci)
              (fs.fileFilter (file: file.hasExt "py") ./.ci)
            ];
          };
          src = nixLib.mkSrc {
            root = ./.;
            inherit fs;
          };
          testSrc = nixLib.mkTestSrc {
            root = ./.;
            inherit fs;
            extraFiles = [ (fs.fileFilter (file: file.hasExt "snap") ./.) ];
          };

          hopliPackages = import ./nix/packages/hopli.nix {
            inherit builders src depsSrc rev buildPlatform nixLib;
          };

          dockerEnv = [
            "ETHERSCAN_API_KEY=placeholder"
            "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
            "SSL_CERT_DIR=${pkgs.cacert}/etc/ssl/certs"
          ];

          profileDeps = with pkgs; [
            gdb
            # FIXME: heaptrack would be useful, but it adds 700MB to the image size (unpacked)
            # lldb
            rust-bin.stable.latest.minimal
            valgrind

            # Networking tools to debug network issues
            tcpdump
            iproute2
            netcat
            iptables
            bind
            curl
            iputils
            nmap
            nethogs
          ];

          # FIXME: the docker image built is not working on macOS arm platforms
          # and will simply lead to a non-working image. Likely, some form of
          # cross-compilation or distributed build is required.
          # Docker images using nix-lib
          hopliDocker = {
            docker-hopli-x86_64-linux = nixLib.mkDockerImage {
              name = "hopli";
              extraContents = [ hopliPackages.binary-hopli-x86_64-linux ];
              Entrypoint = [ "/bin/hopli" ];
              env = dockerEnv;
            };
            docker-hopli-aarch64-linux = nixLib.mkDockerImage {
              name = "hopli";
              extraContents = [ hopliPackages.binary-hopli-aarch64-linux ];
              Entrypoint = [ "/bin/hopli" ];
              env = dockerEnv;
            };
            docker-hopli-x86_64-linux-dev = nixLib.mkDockerImage {
              name = "hopli";
              extraContents = [ hopliPackages.binary-hopli-x86_64-linux-dev ];
              Entrypoint = [ "/bin/hopli" ];
              env = dockerEnv;
            };
            docker-hopli-x86_64-linux-profile = nixLib.mkDockerImage {
              name = "hopli";
              extraContents = [ hopliPackages.binary-hopli-x86_64-linux ] ++ profileDeps;
              Entrypoint = [ "/bin/hopli" ];
              env = dockerEnv;
            };
          };

          pre-commit-check = pre-commit.lib.${system}.run {
            src = ./.;
            hooks = {
              # https://github.com/cachix/git-hooks.nix
              treefmt.enable = false;
              treefmt.package = config.treefmt.build.wrapper;
              check-executables-have-shebangs.enable = true;
              check-shebang-scripts-are-executable.enable = true;
              check-case-conflicts.enable = true;
              check-symlinks.enable = true;
              check-merge-conflicts.enable = true;
              check-added-large-files.enable = true;
              commitizen.enable = true;
              immutable-files = {
                enable = false;
                name = "Immutable files - the files should not change";
                entry = "bash .github/scripts/immutable-files-check.sh";
                files = "";
                language = "system";
              };
            };
            tools = pkgs;
            excludes = [ ".gcloudignore" ];
          };

          # Development shells using nix-lib
          devShell = nixLib.mkDevShell {
            rustToolchainFile = ./rust-toolchain.toml;
            shellName = "Hopli Development";
            treefmtWrapper = config.treefmt.build.wrapper;
            treefmtPrograms = pkgs.lib.attrValues config.treefmt.build.programs;
            extraPackages = with pkgs; [
              cargo-machete
              foundry-bin
              nfpm
              envsubst
              just
            ];
            shellHook = ''
              ${pre-commit-check.shellHook}
            '';
          };

          ciShell = nixLib.mkDevShell {
            rustToolchainFile = ./rust-toolchain.toml;
            shellName = "Hopli CI";
            treefmtWrapper = config.treefmt.build.wrapper;
            treefmtPrograms = pkgs.lib.attrValues config.treefmt.build.programs;
            extraPackages = with pkgs; [
              act
              gh
              google-cloud-sdk
              cargo-machete
              graphviz
              zizmor
              gnupg
              perl
            ];
          };

          docsShell = nixLib.mkDevShell {
            rustToolchainFile = ./rust-toolchain.toml;
            shellName = "Hopli Documentation";
            treefmtWrapper = config.treefmt.build.wrapper;
            treefmtPrograms = pkgs.lib.attrValues config.treefmt.build.programs;
            extraPackages = with pkgs; [
              html-tidy
              pandoc
              sqlite
              cargo-machete
            ];
            shellHook = ''
              ${pre-commit-check.shellHook}
            '';
            rustToolchain = pkgs.rust-bin.selectLatestNightlyWith (toolchain: toolchain.default);
          };

          nightlyShell = nixLib.mkDevShell {
            rustToolchainFile = ./rust-toolchain.toml;
            shellName = "Hopli Nightly";
            treefmtWrapper = config.treefmt.build.wrapper;
            treefmtPrograms = pkgs.lib.attrValues config.treefmt.build.programs;
            extraPackages = with pkgs; [ foundry-bin ];
            shellHook = ''
              ${pre-commit-check.shellHook}
            '';
            rustToolchain = pkgs.rust-bin.selectLatestNightlyWith (toolchain: toolchain.default);
          };
          run-check = flake-utils.lib.mkApp {
            drv = pkgs.writeShellScriptBin "run-check" ''
              set -e
              check=$1
              if [ -z "$check" ]; then
                nix flake show --json 2>/dev/null | \
                  jq -r '.checks."${system}" | to_entries | .[].key' | \
                  xargs -I '{}' nix build ".#checks."${system}".{}"
              else
              	nix build ".#checks."${system}".$check"
              fi
            '';
          };
          run-audit = flake-utils.lib.mkApp {
            drv = pkgs.writeShellApplication {
              name = "audit";
              runtimeInputs = with pkgsUnstable; [
                cargo
                cargo-audit
              ];
              text = ''
                cargo audit
              '';
            };
          };

          update-github-labels = flake-utils.lib.mkApp {
            drv = pkgs.writeShellScriptBin "update-github-labels" ''
              set -eu
              # remove existing crate entries (to remove old crates)
              yq 'with_entries(select(.key != "crate:*"))' .github/labeler.yml > labeler.yml.new
              # add new crate entries for known crates
              for f in `find . -mindepth 2 -name "Cargo.toml" -type f -printf '%P\n'`; do
              	env \
              		name="crate:`yq '.package.name' $f`" \
              		dir="`dirname $f`/**" \
              		yq -n '.[strenv(name)][0]."changed-files"[0]."any-glob-to-any-file" = env(dir)' >> labeler.yml.new
              done
              mv labeler.yml.new .github/labeler.yml
            '';
          };
        in
        {
          treefmt = {
            inherit (config.flake-root) projectRootFile;

            settings.global.excludes = [
              "**/*.id"
              "**/.cargo-ok"
              "**/.gitignore"
              ".actrc"
              ".dockerignore"
              ".editorconfig"
              ".gcloudignore"
              ".gitattributes"
              ".yamlfmt"
              "LICENSE"
              "Makefile"
              "justfile"
              "deploy/nfpm/nfpm.yaml"
              ".github/workflows/build-binaries.yaml"
              "docs/*"
              "nix/setup-hook-darwin.sh"
              "target/*"
            ];

            programs.shfmt.enable = true;
            settings.formatter.shfmt.includes = [ "*.sh" ];

            programs.yamlfmt.enable = true;
            settings.formatter.yamlfmt.includes = [
              ".github/labeler.yml"
              ".github/workflows/*.yaml"
            ];
            # trying setting from https://github.com/google/yamlfmt/blob/main/docs/config-file.md
            settings.formatter.yamlfmt.settings = {
              formatter.type = "basic";
              formatter.max_line_length = 120;
              formatter.trim_trailing_whitespace = true;
              formatter.scan_folded_as_literal = true;
              formatter.include_document_start = true;
            };

            programs.prettier.enable = true;
            settings.formatter.prettier.includes = [
              "*.md"
              "*.json"
            ];
            settings.formatter.prettier.excludes = [
              "*.yml"
              "*.yaml"
            ];
            programs.rustfmt.enable = true;
            # using the official Nixpkgs formatting
            # see https://github.com/NixOS/rfcs/blob/master/rfcs/0166-nix-formatting.md
            programs.nixfmt.enable = true;
            programs.taplo.enable = true;
            programs.ruff-format.enable = true;
          };

          checks = { inherit (hopliPackages) hopli-clippy; };

          apps = {
            inherit update-github-labels;
            check = run-check;
            audit = run-audit;
            coverage-unit = {
              type = "app";
              program = toString (pkgs.writeShellScript "coverage-unit" ''
                nix develop .#coverage -c cargo llvm-cov --workspace --lib --lcov --output-path coverage.lcov
              '');
            };
          };

          packages = hopliPackages // hopliDocker // {
            inherit pre-commit-check;
            default = hopliPackages.hopli;
          };

          devShells.default = devShell;
          devShells.ci = ciShell;
          devShells.docs = docsShell;
          devShells.nightly = nightlyShell;
          devShells.coverage = nixLib.mkDevShell {
            rustToolchainFile = ./rust-toolchain.toml;
            shellName = "Coverage";
            withLlvmTools = true;
            extraPackages = [ pkgs.foundry-bin ];
          };

          formatter = config.treefmt.build.wrapper;
        };
      # platforms which are supported as build environments
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
        "x86_64-darwin"
      ];
    };
}
