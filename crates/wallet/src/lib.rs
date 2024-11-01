//! # Essential Wallet
//!
//! ## Warning!
//! This crate has not been audited for security.
//! USE AT YOUR OWN RISK!
//! This crate is intended for testing and educational purposes only.
//! Never use this for production code or to store real funds.
//!
//! This crate can be used as a library in front ends for testing key management and signing.
//! This crate also provides a binary cli tool that can be used to manage keys and sign data.

#![deny(missing_docs)]
#![deny(unsafe_code)]

use std::path::PathBuf;
use std::{fmt::Display, str::FromStr};

use clap::ValueEnum;
use essential_signer::Key;
use essential_signer::PublicKey;
use essential_types::contract::Contract;
use essential_types::{Hash, Word};
use rand::SeedableRng;
use serde::Serialize;

pub use essential_signer::ed25519_dalek;
pub use essential_signer::secp256k1;
pub use essential_signer::Padding;
pub use essential_signer::Signature;

mod store;

const NAME: &str = "essential-wallet";

#[derive(ValueEnum, Clone, Copy, Debug)]
/// Which signature scheme to use.
pub enum Scheme {
    /// The secp256k1 signature scheme.
    Secp256k1,
    /// The ed25519 signature scheme.
    Ed25519,
}

/// Essential Wallet
/// **USE AT YOUR OWN RISK!**
/// Stores secret keys in sqlcipher database.
pub struct Wallet {
    store: store::Store,
    #[cfg(feature = "test-utils")]
    dir: Option<tempfile::TempDir>,
}

impl Wallet {
    /// Create a new wallet with a password and directory.
    pub fn new(password: &str, path: PathBuf) -> anyhow::Result<Self> {
        let mut path = db_dir(Some(path.clone()))?;
        path.push("accounts.sqlite3");
        let store = store::Store::new(password, &path)?;

        #[cfg(not(feature = "test-utils"))]
        let r = Ok(Self { store });
        #[cfg(feature = "test-utils")]
        let r = Ok(Self { store, dir: None });
        r
    }

    /// Create a new wallet with a password.
    ///
    /// The wallet will find a suitable directory to store the database.
    pub fn with_default_path(password: &str) -> anyhow::Result<Self> {
        let path = db_dir(None)?;
        Self::new(password, path)
    }

    #[cfg(feature = "test-utils")]
    /// Create a wallet for testing that has an empty password and a temporary directory.
    pub fn temp() -> anyhow::Result<Self> {
        let dir = tempfile::tempdir()?;
        let path = db_dir(Some(dir.path().to_path_buf()))?;
        let mut s = Self::new("password", path)?;
        s.dir = Some(dir);
        Ok(s)
    }

    #[cfg(feature = "test-utils")]
    /// Insert an existing key into the wallet.
    /// Warning this is for testing only.
    pub fn insert_key(&mut self, name: &str, key: Key) -> anyhow::Result<()> {
        match key {
            Key::Secp256k1(private_key) => {
                self.store
                    .set_secret(name, Scheme::Secp256k1, private_key.as_ref().as_slice())
            }
            Key::Ed25519(_) => todo!("Not supported yet"),
        }
    }

    #[cfg(feature = "test-utils")]
    /// Generate a private key.
    /// Warning this is for testing only.
    pub fn generate_private_key(&mut self, scheme: Scheme) -> anyhow::Result<Key> {
        match scheme {
            Scheme::Secp256k1 => {
                let mut rng = rand::rngs::StdRng::from_entropy();
                let (private_key, _) = secp256k1::generate_keypair(&mut rng);
                Ok(Key::Secp256k1(private_key))
            }
            Scheme::Ed25519 => todo!("Not supported yet"),
        }
    }

    /// Create a new key pair.
    /// The key pair will be stored in the OS self.store.
    /// The key will be stored at the name provided.
    /// The scheme determines which signature scheme to use.
    pub fn new_key_pair(&mut self, name: &str, scheme: Scheme) -> anyhow::Result<()> {
        match scheme {
            Scheme::Secp256k1 => {
                let mut rng = rand::rngs::StdRng::from_entropy();
                let (private_key, _) = secp256k1::generate_keypair(&mut rng);
                self.store
                    .set_secret(name, scheme, private_key.as_ref().as_slice())
            }
            Scheme::Ed25519 => todo!("Not supported yet"),
        }
    }

    /// Delete a key pair at this name.
    pub fn delete_key_pair(&mut self, name: &str) -> anyhow::Result<()> {
        self.store.delete_secret(name)
    }

    /// List all names for key pairs stored in the OS self.store for this service.
    pub fn list_names(&mut self) -> anyhow::Result<Vec<String>> {
        Ok(self.list()?.into_iter().map(|(n, _)| n).collect())
    }

    /// Get the public key for this key pair.
    pub fn get_public_key(&mut self, name: &str) -> anyhow::Result<PublicKey> {
        let key = self.name_to_key(name)?;
        Ok(essential_signer::public_key(&key))
    }

    /// Get the private key for this key pair.
    pub fn get_private_key(&mut self, name: &str) -> anyhow::Result<Key> {
        self.name_to_key(name)
    }

    /// Sign an contract.
    ///
    /// Requires the keypair be a secp256k1 key or this will return an error.
    /// No padding is applied to the data before signing.
    /// This is designed to be used for deploying contracts to the api.
    pub fn sign_contract(
        &mut self,
        data: Contract,
        name: &str,
    ) -> anyhow::Result<essential_types::contract::SignedContract> {
        let key = self.name_to_key(name)?;
        match key {
            Key::Secp256k1(key) => Ok(essential_sign::contract::sign(data, &key)),
            Key::Ed25519(_) => Err(anyhow::anyhow!(
                "Ed25519 not supported for signing contracts. Please use a Secp256k1 key"
            ))?,
        }
    }

    /// Create a signature using the key pair stored at this name.
    ///
    /// The data will be serialized as postcard, then hashed and the hash signed.
    /// No padding is applied to the data before signing.
    pub fn sign_postcard<T: Serialize>(
        &mut self,
        data: &T,
        name: &str,
    ) -> anyhow::Result<Signature> {
        let key = self.name_to_key(name)?;
        essential_signer::sign_postcard(data, &key)
    }

    /// Create a signature using the key pair stored at this name.
    ///
    /// The data will be serialized as postcard, then padded to be word aligned,
    /// then hashed and the hash signed.
    pub fn sign_postcard_with_padding<T: Serialize>(
        &mut self,
        data: &T,
        padding: Padding,
        name: &str,
    ) -> anyhow::Result<Signature> {
        let key = self.name_to_key(name)?;
        essential_signer::sign_postcard_with_padding(data, padding, &key)
    }

    /// Create a signature using the key pair stored at this name.
    pub fn sign_hash(&mut self, data: Hash, name: &str) -> anyhow::Result<Signature> {
        let key = self.name_to_key(name)?;
        essential_signer::sign_hash(data, &key)
    }

    /// Create a signature using the key pair stored at this name.
    pub fn sign_words(&mut self, data: &[Word], name: &str) -> anyhow::Result<Signature> {
        let key = self.name_to_key(name)?;
        essential_signer::sign_words(data, &key)
    }

    /// Create a signature using the key pair stored at this name.
    ///
    /// The data will be padded to be word aligned, then hashed and the hash signed.
    pub fn sign_bytes_with_padding(
        &mut self,
        data: Vec<u8>,
        padding: Padding,
        name: &str,
    ) -> anyhow::Result<Signature> {
        let key = self.name_to_key(name)?;
        essential_signer::sign_bytes_with_padding(data, padding, &key)
    }

    /// Create a signature using the key pair stored at this name.
    ///
    /// The data will be hashed and the hash signed.
    /// This will return an error if the data is not word aligned.
    pub fn sign_aligned_bytes(&mut self, data: &[u8], name: &str) -> anyhow::Result<Signature> {
        let key = self.name_to_key(name)?;
        essential_signer::sign_aligned_bytes(data, &key)
    }

    /// Create a signature using the key pair stored at this name.
    ///
    /// The data will be hashed and the hash signed.
    /// Word alignment is not checked.
    pub fn sign_bytes_unchecked(&mut self, data: &[u8], name: &str) -> anyhow::Result<Signature> {
        let key = self.name_to_key(name)?;
        essential_signer::sign_bytes_unchecked(data, &key)
    }

    fn name_to_key(&mut self, name: &str) -> anyhow::Result<Key> {
        let (private_key, scheme) = self.store.get_secret(name)?;
        match scheme {
            Scheme::Secp256k1 => {
                let private_key = secp256k1::SecretKey::from_slice(private_key.as_slice())?;
                Ok(Key::Secp256k1(private_key))
            }
            Scheme::Ed25519 => todo!("Not supported yet"),
        }
    }

    /// List all accounts under this service.
    fn list(&mut self) -> anyhow::Result<Vec<(String, Scheme)>> {
        self.store.list()
    }
}

impl Display for Scheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Scheme::Secp256k1 => write!(f, "secp256k1"),
            Scheme::Ed25519 => write!(f, "ed25519"),
        }
    }
}

impl FromStr for Scheme {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "secp256k1" => Ok(Scheme::Secp256k1),
            "ed25519" => Ok(Scheme::Ed25519),
            _ => Err(anyhow::anyhow!("Unknown scheme: {}", s)),
        }
    }
}

fn db_dir(in_path: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    let path = match in_path {
        None => {
            let mut path = dirs::home_dir().unwrap_or_else(|| {
                dirs::document_dir().unwrap_or_else(|| {
                    dirs::data_local_dir()
                        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR").to_string()))
                })
            });
            path.push(format!(".{}", NAME));
            path
        }
        Some(path) => path,
    };

    if !path.is_dir() {
        std::fs::create_dir_all(&path)?;
    }
    Ok(path)
}
