# A dev shell providing the essentials for working on essential-server.
{ cargo-toml-lint
, clippy
, essential-wallet
, mkShell
, rust-analyzer
, rustfmt
, cargo
, rustc
}:
mkShell {
  inputsFrom = [
    essential-wallet
  ];
  buildInputs = [
    cargo-toml-lint
    clippy
    rust-analyzer
    rustfmt
    cargo
    rustc
  ];
}
