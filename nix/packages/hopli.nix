{
  builders,
  src,
  depsSrc,
  rev,
  buildPlatform,
  nixLib,
}:
let
  hopliBuildArgs = {
    inherit src depsSrc rev;
    cargoExtraArgs = "-F allocator-jemalloc";
    cargoToml = ./../../Cargo.toml;
  };

  # needed as input for hopli-man
  hopli-dev = builders.local.callPackage nixLib.mkRustPackage (
    hopliBuildArgs // { CARGO_PROFILE = "dev"; }
  );
in
{
  hopli = builders.local.callPackage nixLib.mkRustPackage hopliBuildArgs;
  inherit hopli-dev;

  hopli-clippy = builders.local.callPackage nixLib.mkRustPackage (
    hopliBuildArgs // { runClippy = true; }
  );

  hopli-coverage = builders.localCoverage.callPackage nixLib.mkRustPackage (
    hopliBuildArgs // {
      runCoverage = true;
      cargoLlvmCovExtraArgs = "--lcov --output-path $out --lib";
    }
  );

  # build candidate binary as static on Linux amd64 to get more test exposure specifically via smoke tests
  hopli-candidate =
    if buildPlatform.isLinux && buildPlatform.isx86_64 then
      builders.x86_64-linux.callPackage nixLib.mkRustPackage (
        hopliBuildArgs // { CARGO_PROFILE = "candidate"; }
      )
    else
      builders.local.callPackage nixLib.mkRustPackage (
        hopliBuildArgs // { CARGO_PROFILE = "candidate"; }
      );

  hopli-man = nixLib.mkManPage {
    pname = "hopli";
    binary = hopli-dev;
    description = "Hopli CLI helper tool";
  };

  hopli-docs = builders.local.callPackage nixLib.mkRustPackage (
    hopliBuildArgs // { buildDocs = true; }
  );

  # also used for Docker image
  binary-hopli-x86_64-linux = builders.x86_64-linux.callPackage nixLib.mkRustPackage hopliBuildArgs;
  # also used for Docker image
  binary-hopli-x86_64-linux-dev = builders.x86_64-linux.callPackage nixLib.mkRustPackage (
    hopliBuildArgs // { CARGO_PROFILE = "dev"; }
  );
  binary-hopli-aarch64-linux = builders.aarch64-linux.callPackage nixLib.mkRustPackage hopliBuildArgs;
  # CAVEAT: must be built from a darwin system
  # FIXME: Darwin cross-builds are currently broken.
  # Follow https://github.com/nixos/nixpkgs/pull/256590
  binary-hopli-x86_64-darwin = builders.x86_64-darwin.callPackage nixLib.mkRustPackage hopliBuildArgs;
  # CAVEAT: must be built from a darwin system
  binary-hopli-aarch64-darwin = builders.aarch64-darwin.callPackage nixLib.mkRustPackage hopliBuildArgs;

}
