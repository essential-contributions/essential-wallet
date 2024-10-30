# A dev shell providing the essentials for working on essential-server.
{ cargo-toml-lint
, clippy
, essential-wallet
, essential-wallet-test
, mkShell
, rust-analyzer
, rustfmt
, cargo
, rustc
}:
mkShell {
  inputsFrom = [
    essential-wallet
    essential-wallet-test
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
