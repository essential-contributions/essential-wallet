# A derivation for the `essential-wallet` crate.
{ lib
, stdenv
, darwin
, rustPlatform
}:
let
  src = ./.;
  crateDir = "${src}/crates/wallet";
  crateTOML = "${crateDir}/Cargo.toml";
  lockFile = "${src}/Cargo.lock";
in
rustPlatform.buildRustPackage {
  inherit src;
  pname = "essential-rest-server";
  version = (builtins.fromTOML (builtins.readFile crateTOML)).package.version;

  # We run tests separately in CI.
  doCheck = false;

  buildInputs = lib.optionals stdenv.isLinux [
  ] ++ lib.optionals stdenv.isDarwin [
    darwin.apple_sdk.frameworks.SystemConfiguration
  ];

  cargoLock = {
    inherit lockFile;
    # FIXME: This enables using `builtins.fetchGit` which uses the user's local
    # `git` (and hence ssh-agent for ssh support). Once the repos are public,
    # this should be removed.
    allowBuiltinFetchGit = true;
  };
}
