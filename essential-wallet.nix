# A derivation for the `essential-wallet` crate.
{ lib
, stdenv
, darwin
, rustPlatform
, openssl
, pkg-config
}:
let
  src = builtins.path {
    path = ./.;
    filter = path: type:
      let
        keepFiles = [
          "Cargo.lock"
          "Cargo.toml"
          "crates"
        ];
        includeDirs = [
          "crates"
        ];
        isPathInIncludeDirs = dir: lib.strings.hasInfix dir path;
      in
      if lib.lists.any (p: p == (baseNameOf path)) keepFiles then
        true
      else
        lib.lists.any (dir: isPathInIncludeDirs dir) includeDirs
    ;
  };
  crateDir = "${src}/crates/wallet";
  crateTOML = "${crateDir}/Cargo.toml";
  lockFile = "${src}/Cargo.lock";
in
rustPlatform.buildRustPackage {
  inherit src;
  pname = "essential-wallet";
  version = (builtins.fromTOML (builtins.readFile crateTOML)).package.version;

  OPENSSL_NO_VENDOR = 1;

  buildAndTestSubdir = "crates/wallet";

  # We run tests separately in CI.
  doCheck = false;

  nativeBuildInputs = [
    pkg-config
  ];

  buildInputs = [
    openssl
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
