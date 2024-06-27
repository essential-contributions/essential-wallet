# Essential Wallet and Essential Signer

## Warning!
This crate has not been audited for security.
**USE AT YOUR OWN RISK!**
This crate is intended for testing and educational purposes only.
Never use this for production code or to store real funds.

These crate can be used as a library in front ends for testing key management and signing.
The walled crate also provides a binary cli tool that can be used to manage keys and sign data.

The wallet stores keys in your OS's keychain or keyring.
You will be prompted to enter a password when you want to sign data.

## Cli Usage
```
Usage: essential-wallet <COMMAND>

Commands:
  generate         
  delete           
  list             
  sign             
  sign-contract  
  help             Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```
### Sign some hex data
```bash
$ essential-wallet sign my_key data "0011224455667788"
$ ef6e089abc7e23e589b4476819cd4b222dda4dd10d959e8c738141e9207af0bd6fb03e25dea74c77e6dec341a6c5fd0cf5e04937b1e0fa6a6b0e0c6fe4d28b680000000000000001
```
## Nix
The wallet can be run with:
```bash
nix run .#wallet
```
There is a development shell available with:
```bash
nix develop
```
