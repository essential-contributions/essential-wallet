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

use std::{fmt::Display, str::FromStr};

use clap::ValueEnum;
use cryptex::{get_os_keyring, KeyRing, ListKeyRing};
use essential_signer::Key;
use essential_types::intent::Intent;
use essential_types::Word;
use rand::SeedableRng;
use serde::Serialize;

pub use essential_signer::ed25519_dalek;
pub use essential_signer::secp256k1;
pub use essential_signer::Padding;
pub use essential_signer::Signature;

const SERVICE_NAME: &str = "essential-wallet";

#[derive(ValueEnum, Clone, Copy, Debug)]
/// Which signature scheme to use.
pub enum Scheme {
    /// The secp256k1 signature scheme.
    Secp256k1,
    /// The ed25519 signature scheme.
    Ed25519,
}

/// Create a new key pair.
/// The key pair will be stored in the OS keyring.
/// The key will be stored at the name provided.
/// The name must be unique for this service.
/// The scheme determines which signature scheme to use.
pub fn new_key_pair(name: String, scheme: Scheme) -> anyhow::Result<()> {
    if list()?.any(|n| n.contains(&name)) {
        return Err(anyhow::anyhow!("Name already exists: {}", name));
    }
    match scheme {
        Scheme::Secp256k1 => {
            let mut keyring = get_os_keyring(SERVICE_NAME)?;
            let mut rng = rand::rngs::StdRng::from_entropy();
            let (private_key, _) = secp256k1::generate_keypair(&mut rng);
            keyring.set_secret(
                format!("{}:{}", scheme, name),
                private_key.as_ref().as_slice(),
            )?;
        }
        Scheme::Ed25519 => todo!("Not supported yet"),
    }
    Ok(())
}

/// Delete a key pair at this name.
pub fn delete_key_pair(name: String) -> anyhow::Result<()> {
    let (full_name, _) = extract_name_and_scheme(&name)?;
    let mut keyring = get_os_keyring(SERVICE_NAME)?;
    keyring
        .delete_secret(full_name)
        .map_err(|_| anyhow::anyhow!("The name '{}' does not exist", name))?;
    Ok(())
}

/// List all names for key pairs stored in the OS keyring for this service.
pub fn list_names() -> anyhow::Result<Vec<String>> {
    Ok(list()?.collect())
}

/// Sign an intent set.
///
/// Requires the keypair be a secp256k1 key or this will return an error.
/// No padding is applied to the data before signing.
/// This is designed to be used for deploying intent sets to the api.
pub fn sign_intent_set(
    data: Vec<Intent>,
    name: &str,
) -> anyhow::Result<essential_types::intent::SignedSet> {
    let key = name_to_key(name)?;
    match key {
        Key::Secp256k1(key) => Ok(essential_sign::intent_set::sign(data, &key)),
        Key::Ed25519(_) => Err(anyhow::anyhow!(
            "Ed25519 not supported for signing intent sets. Please use a Secp256k1 key"
        ))?,
    }
}

/// Create a signature using the key pair stored at this name.
///
/// The data will be serialized as postcard, then hashed and the hash signed.
/// No padding is applied to the data before signing.
pub fn sign_postcard<T: Serialize>(data: &T, name: &str) -> anyhow::Result<Signature> {
    let key = name_to_key(name)?;
    essential_signer::sign_postcard(data, &key)
}

/// Create a signature using the key pair stored at this name.
///
/// The data will be serialized as postcard, then padded to be word aligned,
/// then hashed and the hash signed.
pub fn sign_postcard_with_padding<T: Serialize>(
    data: &T,
    padding: Padding,
    name: &str,
) -> anyhow::Result<Signature> {
    let key = name_to_key(name)?;
    essential_signer::sign_postcard_with_padding(data, padding, &key)
}

/// Create a signature using the key pair stored at this name.
pub fn sign_words(data: &[Word], name: &str) -> anyhow::Result<Signature> {
    let key = name_to_key(name)?;
    essential_signer::sign_words(data, &key)
}

/// Create a signature using the key pair stored at this name.
///
/// The data will be padded to be word aligned, then hashed and the hash signed.
pub fn sign_bytes_with_padding(
    data: Vec<u8>,
    padding: Padding,
    name: &str,
) -> anyhow::Result<Signature> {
    let key = name_to_key(name)?;
    essential_signer::sign_bytes_with_padding(data, padding, &key)
}

/// Create a signature using the key pair stored at this name.
///
/// The data will be hashed and the hash signed.
/// This will return an error if the data is not word aligned.
pub fn sign_aligned_bytes(data: &[u8], name: &str) -> anyhow::Result<Signature> {
    let key = name_to_key(name)?;
    essential_signer::sign_aligned_bytes(data, &key)
}

/// Create a signature using the key pair stored at this name.
///
/// The data will be hashed and the hash signed.
/// Word alignment is not checked.
pub fn sign_bytes_unchecked(data: &[u8], name: &str) -> anyhow::Result<Signature> {
    let key = name_to_key(name)?;
    essential_signer::sign_bytes_unchecked(data, &key)
}

fn name_to_key(name: &str) -> anyhow::Result<Key> {
    let (full_name, scheme) = extract_name_and_scheme(name)?;

    let mut keyring = get_os_keyring(SERVICE_NAME)?;
    let private_key = keyring.get_secret(full_name)?;
    match scheme {
        Scheme::Secp256k1 => {
            let private_key = secp256k1::SecretKey::from_slice(private_key.as_slice())?;
            Ok(Key::Secp256k1(private_key))
        }
        Scheme::Ed25519 => todo!("Not supported yet"),
    }
}

/// The scheme is stored in the key name.
///
/// This function extracts the scheme and the full name from the name.
/// Note that the cryptex crate adds the computer username when creating the name.
/// So the stored name is actually `username:scheme:account_name`.
/// But when calling any cryptex apis the full name that's used is `scheme:account_name`
/// because the username is added automatically.
fn extract_name_and_scheme(name: &str) -> Result<(String, Scheme), anyhow::Error> {
    let n = list()?
        .find(|n| n.contains(name))
        .ok_or_else(|| anyhow::anyhow!("No key pair found for name: {}", name))?;
    let mut iter = n.split(':').skip(1);
    let scheme = iter
        .next()
        .ok_or_else(|| anyhow::anyhow!("Account name corrupted for {} got {}", name, n))?;
    let full_name = format!("{}:{}", scheme, name);
    let scheme = <Scheme as FromStr>::from_str(scheme)?;
    Ok((full_name, scheme))
}

/// List all accounts under this service.
fn list() -> anyhow::Result<impl Iterator<Item = String>> {
    let list = cryptex::OsKeyRing::list_secrets()?;
    Ok(list
        .into_iter()
        .filter(|map| map.get("service").map_or(false, |s| s == SERVICE_NAME))
        .filter_map(|map| map.get("account").cloned()))
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
