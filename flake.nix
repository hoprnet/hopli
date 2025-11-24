{
  description = "hopli application";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    flake-parts.url = "github:hercules-ci/flake-parts";
    nixpkgs.url = "github:NixOS/nixpkgs/release-25.05";
    rust-overlay.url = "github:oxalica/rust-overlay/master";
    crane.url = "github:ipetkov/crane/v0.21.0";
    nix-lib.url = "github:hoprnet/nix-lib";
    # pin it to a version which we are compatible with
    foundry.url = "github:hoprnet/foundry.nix/tb/202505-add-xz";
    pre-commit.url = "github:cachix/git-hooks.nix";
    treefmt-nix.url = "github:numtide/treefmt-nix";
    flake-root.url = "github:srid/flake-root";

    flake-parts.inputs.nixpkgs-lib.follows = "nixpkgs";
    foundry.inputs.flake-utils.follows = "flake-utils";
    foundry.inputs.nixpkgs.follows = "nixpkgs";
    nix-lib.inputs.nixpkgs.follows = "nixpkgs";
    pre-commit.inputs.nixpkgs.follows = "nixpkgs";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
    treefmt-nix.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      flake-parts,
      rust-overlay,
      crane,
      nix-lib,
      foundry,
      pre-commit,
      ...
    }@inputs:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [
        inputs.treefmt-nix.flakeModule
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
          rev = toString (self.shortRev or self.dirtyShortRev);
          fs = lib.fileset;
          localSystem = system;
          overlays = [
            (import rust-overlay)
            foundry.overlay
          ];
          pkgs = import nixpkgs { inherit localSystem overlays; };
          buildPlatform = pkgs.stdenv.buildPlatform;

          # Import nix-lib for shared Nix utilities
          nixLib = nix-lib.lib.${system};

          craneLib = (crane.mkLib pkgs).overrideToolchain (p: p.rust-bin.stable.latest.default);

          # Use nix-lib to create all rust builders for cross-compilation
          builders = nixLib.mkRustBuilders {
            inherit localSystem;
            rustToolchainFile = ./rust-toolchain.toml;
          };

          # Convenience aliases for builders
          rust-builder-local = builders.local;
          rust-builder-x86_64-linux = builders.x86_64-linux;
          rust-builder-x86_64-darwin = builders.x86_64-darwin;
          rust-builder-aarch64-linux = builders.aarch64-linux;
          rust-builder-aarch64-darwin = builders.aarch64-darwin;

          # Nightly builder for docs and specific features
          rust-builder-local-nightly = nixLib.mkRustBuilder {
            inherit localSystem;
            rustToolchainFile = ./rust-toolchain.toml;
            useRustNightly = true;
          };
          # Use nix-lib's source filtering for better rebuild performance
          depsSrc = nixLib.mkDepsSrc {
            root = ./.;
            inherit fs;
          };
          src = nixLib.mkSrc {
            root = ./.;
            inherit fs;
          };
          testSrc = nixLib.mkTestSrc {
            root = ./.;
            inherit fs;
            extraFiles = [
              (fs.fileFilter (file: file.hasExt "snap") ./.)
            ];
          };

          hopliBuildArgs = {
            inherit src depsSrc rev;
            cargoExtraArgs = "-F allocator-jemalloc";
            cargoToml = ./Cargo.toml;
          };

          hopli = rust-builder-local.callPackage nixLib.mkRustPackage hopliBuildArgs;

          # also used for Docker image
          hopli-x86_64-linux = rust-builder-x86_64-linux.callPackage nixLib.mkRustPackage hopliBuildArgs;
          # also used for Docker image
          hopli-x86_64-linux-dev = rust-builder-x86_64-linux.callPackage nixLib.mkRustPackage (
            hopliBuildArgs // { CARGO_PROFILE = "dev"; }
          );
          hopli-aarch64-linux = rust-builder-aarch64-linux.callPackage nixLib.mkRustPackage hopliBuildArgs;
          # CAVEAT: must be built from a darwin system
          hopli-x86_64-darwin = rust-builder-x86_64-darwin.callPackage nixLib.mkRustPackage hopliBuildArgs;
          # CAVEAT: must be built from a darwin system
          hopli-aarch64-darwin = rust-builder-aarch64-darwin.callPackage nixLib.mkRustPackage hopliBuildArgs;

          hopli-clippy = rust-builder-local.callPackage nixLib.mkRustPackage (
            hopliBuildArgs // { runClippy = true; }
          );

          hopli-dev = rust-builder-local.callPackage nixLib.mkRustPackage (
            hopliBuildArgs // { CARGO_PROFILE = "dev"; }
          );
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

          # build candidate binary as static on Linux amd64 to get more test exposure specifically via smoke tests
          hopli-candidate =
            if buildPlatform.isLinux && buildPlatform.isx86_64 then
              rust-builder-x86_64-linux.callPackage nixLib.mkRustPackage (
                hopliBuildArgs // { CARGO_PROFILE = "candidate"; }
              )
            else
              rust-builder-local.callPackage nixLib.mkRustPackage (
                hopliBuildArgs // { CARGO_PROFILE = "candidate"; }
              );

          test-unit = rust-builder-local.callPackage nixLib.mkRustPackage (
            hopliBuildArgs
            // {
              src = testSrc;
              runTests = true;
              cargoExtraArgs = "--lib";

            }
          );

          # Man pages using nix-lib
          hopli-man = nixLib.mkManPage {
            pname = "hopli";
            binary = hopli-dev;
            description = "Hopli CLI helper tool";
          };

          # FIXME: the docker image built is not working on macOS arm platforms
          # and will simply lead to a non-working image. Likely, some form of
          # cross-compilation or distributed build is required.
          # Docker images using nix-lib
          hopli-docker = nixLib.mkDockerImage {
            name = "hopli";
            extraContents = [ hopli-x86_64-linux ];
            Entrypoint = [ "/bin/hopli" ];
            env = [
              "ETHERSCAN_API_KEY=placeholder"
            ];
          };
          hopli-dev-docker = nixLib.mkDockerImage {
            name = "hopli";
            extraContents = [ hopli-x86_64-linux-dev ];
            Entrypoint = [ "/bin/hopli" ];
            env = [
              "ETHERSCAN_API_KEY=placeholder"
            ];
          };
          hopli-profile-docker = nixLib.mkDockerImage {
            name = "hopli";
            extraContents = [ hopli-x86_64-linux ] ++ profileDeps;
            Entrypoint = [ "/bin/hopli" ];
            env = [
              "ETHERSCAN_API_KEY=placeholder"
            ];
          };

          # Docker security scanning and SBOM generation using nix-lib
          hopli-docker-trivy = nixLib.mkTrivyScan {
            image = hopli-docker;
            imageName = "hopli";
          };
          hopli-docker-sbom = nixLib.mkSBOM {
            image = hopli-docker;
            imageName = "hopli";
          };

          # Multi-arch Docker manifests using nix-lib
          # NOTE: These require images for both amd64 and arm64 to be pushed to a registry first
          # hopli-docker-multiarch = nixLib.mkMultiArchManifest {
          #   name = "hopli";
          #   tag = "latest";
          #   images = [
          #     { arch = "amd64"; digest = "sha256:..."; }
          #     { arch = "arm64"; digest = "sha256:..."; }
          #   ];
          # };

          dockerImageUploadScript =
            image:
            pkgs.writeShellScriptBin "docker-image-upload" ''
              set -eu
              OCI_ARCHIVE="$(nix build --no-link --print-out-paths ${image})"
              ${pkgs.skopeo}/bin/skopeo copy --insecure-policy \
                --dest-registry-token="$GOOGLE_ACCESS_TOKEN" \
                "docker-archive:$OCI_ARCHIVE" "docker://$IMAGE_TARGET"
              echo "Uploaded image to $IMAGE_TARGET"
            '';
          hopli-docker-build-and-upload = flake-utils.lib.mkApp {
            drv = dockerImageUploadScript hopli-docker;
          };
          hopli-dev-docker-build-and-upload = flake-utils.lib.mkApp {
            drv = dockerImageUploadScript hopli-dev-docker;
          };
          hopli-profile-docker-build-and-upload = flake-utils.lib.mkApp {
            drv = dockerImageUploadScript hopli-profile-docker;
          };
          docs = rust-builder-local-nightly.callPackage nixLib.mkRustPackage (
            hopliBuildArgs // { buildDocs = true; }
          );
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
            excludes = [
              ".gcloudignore"
            ];
          };

          # Development shells using nix-lib
          devShell = nixLib.mkDevShell {
            rustToolchainFile = ./rust-toolchain.toml;
            shellName = "Hopli Development";
            treefmtWrapper = config.treefmt.build.wrapper;
            treefmtPrograms = pkgs.lib.attrValues config.treefmt.build.programs;
            extraPackages = with pkgs; [
              sqlite
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
              swagger-codegen3
              vacuum-go
              zizmor
              gnupg
              perl
            ];
          };

          testShell = nixLib.mkDevShell {
            rustToolchainFile = ./rust-toolchain.toml;
            shellName = "Hopli Testing";
            treefmtWrapper = config.treefmt.build.wrapper;
            treefmtPrograms = pkgs.lib.attrValues config.treefmt.build.programs;
            extraPackages = with pkgs; [
              uv
              python313
              foundry-bin
            ];
            shellHook = ''
              uv sync --frozen
              unset SOURCE_DATE_EPOCH
              ${pkgs.lib.optionalString pkgs.stdenv.isLinux "autoPatchelf ./.venv"}
            '';
          };

          ciTestDevShell = nixLib.mkDevShell {
            rustToolchainFile = ./rust-toolchain.toml;
            shellName = "Hopli CI Test (Dev)";
            treefmtWrapper = config.treefmt.build.wrapper;
            treefmtPrograms = pkgs.lib.attrValues config.treefmt.build.programs;
            extraPackages = with pkgs; [
              foundry-bin
              hopli-dev
            ];
            shellHook = ''
              unset SOURCE_DATE_EPOCH
            '';
          };

          ciTestShell = nixLib.mkDevShell {
            rustToolchainFile = ./rust-toolchain.toml;
            shellName = "Hopli CI Test (Candidate)";
            treefmtWrapper = config.treefmt.build.wrapper;
            treefmtPrograms = pkgs.lib.attrValues config.treefmt.build.programs;
            extraPackages = with pkgs; [
              foundry-bin
              hopli-candidate
            ];
            shellHook = ''
              unset SOURCE_DATE_EPOCH
            '';
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
            extraPackages = with pkgs; [
              foundry-bin
            ];
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
              runtimeInputs = [
                pkgs.cargo
                pkgs.cargo-audit
              ];
              text = ''
                cargo audit
              '';
            };
          };

          find-port-ci = flake-utils.lib.mkApp {
            drv = pkgs.writeShellApplication {
              name = "find-port";
              text = ''
                ${pkgs.python3}/bin/python ./tests/find_port.py --min-port 3000 --max-port 4000 --skip 30
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
            settings.formatter.shfmt.includes = [
              "*.sh"
            ];

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

            settings.formatter.rustfmt = {
              command = "${pkgs.rust-bin.selectLatestNightlyWith (toolchain: toolchain.default)}/bin/rustfmt";
            };
          };

          checks = {
            inherit hopli-clippy;
          };

          apps = {
            inherit hopli-docker-build-and-upload;
            inherit hopli-dev-docker-build-and-upload;
            inherit hopli-profile-docker-build-and-upload;
            inherit update-github-labels find-port-ci;
            check = run-check;
            audit = run-audit;
          };

          packages = {
            inherit
              hopli
              hopli-dev
              hopli-docker
              hopli-dev-docker
              hopli-profile-docker
              ;
            inherit hopli-candidate;
            inherit test-unit;
            inherit docs;
            inherit pre-commit-check;
            inherit hopli-man;
            # binary packages
            inherit hopli-x86_64-linux hopli-x86_64-linux-dev;
            inherit hopli-aarch64-linux;
            # FIXME: Darwin cross-builds are currently broken.
            # Follow https://github.com/nixos/nixpkgs/pull/256590
            inherit hopli-x86_64-darwin;
            inherit hopli-aarch64-darwin;
            default = hopli;
          };

          devShells.default = devShell;
          devShells.ci = ciShell;
          devShells.test = testShell;
          devShells.citest = ciTestShell;
          devShells.citestdev = ciTestDevShell;
          devShells.docs = docsShell;
          devShells.nightly = nightlyShell;

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
