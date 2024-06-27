use std::path::PathBuf;

use anyhow::ensure;
use clap::{Parser, Subcommand};
use essential_signer::{decode_str, read_file, Encoding, Padding, Signature};
use essential_types::contract::Contract;
use essential_wallet::{Scheme, Wallet};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Select a subcommand to run
    #[command(subcommand)]
    command: Command,
    /// Set the path to the wallet directory.
    /// If not set then a sensible default will be used (like ~/.essential-wallet).
    #[arg(short, long)]
    path: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    Generate {
        /// The name that the key pair will be stored under.
        name: String,
        /// The signature scheme to use.
        #[arg(default_value_t = Scheme::Secp256k1, value_enum)]
        scheme: Scheme,
    },
    Delete {
        /// The name of the key pair to delete.
        name: String,
    },
    List,
    Sign {
        /// The name of the key pair to use for signing.
        name: String,
        /// Require the input to be word aligned [default: true].
        #[arg(short, long, default_value_t = true)]
        require_aligned: bool,
        /// The input to sign.
        #[command(subcommand)]
        input: Input,
        /// auto-pad the input to the nearest Word (8 bytes)
        #[arg(short, long, value_enum)]
        auto_pad: Option<Padding>,
        /// Encoding of the output signature
        #[arg(short, long, default_value_t = Encoding::Hex, value_enum)]
        output: Encoding,
        /// Pad the output signature to the nearest Word (8 bytes) [default: true].
        #[arg(long, default_value_t = true)]
        pad_signature: bool,
    },
    SignContract {
        /// The name of the key pair to use for signing.
        name: String,
        /// Path to the compiled contract.
        path: PathBuf,
        /// Encoding of the output signature
        #[arg(short, long, default_value_t = Encoding::Hex, value_enum)]
        output: Encoding,
    },
}

#[derive(Subcommand)]
enum Input {
    File {
        /// Path to the file to sign.
        path: PathBuf,
    },
    Data {
        /// The encoding of the input
        /// Encoding is ignored if the input is a file.
        #[arg(short, long, default_value_t = Encoding::Hex, value_enum)]
        encoding: Encoding,
        /// The data to sign.
        data: String,
    },
}

const WARNING: &str = "
Essential Wallet

Warning!
This code has not been audited for security.
USE AT YOUR OWN RISK!
This crate is intended for testing and educational purposes only.
Never use this for production code or to store real funds.
";

fn main() {
    let args = Cli::parse();
    if let Err(e) = run(args) {
        eprintln!("Command failed because: {}", e);
    }
}

fn run(args: Cli) -> anyhow::Result<()> {
    eprintln!("{}", WARNING);

    let pass = rpassword::prompt_password("Enter password to unlock wallet: ")?;

    // TODO: Not sure what to do for salt as it would need to be stored anyway
    let mut wallet = args
        .path
        .map(|p| Wallet::new(&pass, p))
        .unwrap_or_else(|| Wallet::with_default_path(&pass))?;
    match args.command {
        Command::Generate { name, scheme } => {
            wallet.new_key_pair(&name, scheme)?;
        }
        Command::Delete { name } => {
            println!(
                "Are you sure you want to delete the key pair {}? (only 'yes' is accepted)",
                name
            );
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            ensure!(input.trim() == "yes", "Aborted");
            wallet.delete_key_pair(&name)?;
        }
        Command::List => {
            let names = wallet.list_names()?;
            println!("Stored Accounts:");
            for name in names {
                println!("{}", name);
            }
        }
        Command::Sign {
            name,
            require_aligned,
            input,
            auto_pad,
            pad_signature,
            output,
        } => {
            let data = match input {
                Input::File { path } => read_file(&path)?,
                Input::Data { data, encoding } => decode_str(data, encoding)?,
            };
            let sig = if require_aligned {
                match auto_pad {
                    Some(padding) => wallet.sign_bytes_with_padding(data, padding, &name)?,
                    None => wallet.sign_aligned_bytes(&data, &name)?,
                }
            } else {
                match auto_pad {
                    Some(padding) => wallet.sign_bytes_with_padding(data, padding, &name)?,
                    None => wallet.sign_bytes_unchecked(&data, &name)?,
                }
            };
            output_signature(&sig, pad_signature, output)?;
        }
        Command::SignContract { name, path, output } => {
            let data = read_file(&path)?;
            let contract: Contract = serde_json::from_slice(&data)?;

            let sig = wallet.sign_contract(contract, &name)?;
            let sig = essential_signer::signed_set_to_bytes(&sig)?;
            let sig = essential_signer::encode_str(sig, output)?;
            println!("{}", sig);
        }
    }
    Ok(())
}

fn output_signature(sig: &Signature, pad_signature: bool, output: Encoding) -> anyhow::Result<()> {
    let sig = if pad_signature {
        essential_signer::signature_to_aligned_bytes(sig)
    } else {
        essential_signer::signature_to_bytes(sig)?
    };
    let sig = essential_signer::encode_str(sig, output)?;
    println!("{}", sig);
    Ok(())
}
