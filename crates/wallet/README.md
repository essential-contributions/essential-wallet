# Essential Wallet
[![Crates.io][crates-badge]][crates-url]
[![Documentation][docs-badge]][docs-url]
[![license][apache-badge]][apache-url]
[![Build Status][actions-badge]][actions-url]

[crates-badge]: https://img.shields.io/crates/v/essential-wallet.svg
[crates-url]: https://crates.io/crates/essential-wallet
[docs-badge]: https://docs.rs/essential-wallet/badge.svg
[docs-url]: https://docs.rs/essential-wallet
[apache-badge]: https://img.shields.io/badge/license-APACHE-blue.svg
[apache-url]: LICENSE

## Warning!
This crate has not been audited for security.
**USE AT YOUR OWN RISK!**
This crate is intended for testing and educational purposes only.
Never use this for production code or to store real funds.

These crate can be used as a library in front ends for testing key management and signing.
The walled crate also provides a binary cli tool that can be used to manage keys and sign data.

The wallet stores keys in your OS's keychain or keyring.
You will be prompted to enter a password when you want to sign data.

## Description
This crates provides a wallet cli and library to use when testing and developing applications on the Essential protocol.