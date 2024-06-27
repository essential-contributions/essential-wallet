//! # Essential Signer
//!
//! This crate provides a simple API for signing data with various cryptographic schemes.
//! It is designed to be used with the Essential protocol.
//! There is functionality to make word aligning data for use in decision variables easy.
//!
//! Note that all hashing in this crate is done with sha256.
//! This may change in the future to allow more types of hashing.
//! You can use `sign_hash` if you wish to hash the data with a different algorithm.

#![deny(missing_docs)]
#![deny(unsafe_code)]

use anyhow::ensure;
use clap::ValueEnum;
use essential_types::{convert::word_4_from_u8_32, Hash, Word};
use serde::{Deserialize, Serialize};
use sha2::Digest;

pub use ed25519_dalek;
pub use secp256k1;

#[derive(ValueEnum, Clone, Copy, Debug)]
/// The encoding to use when decoding or encoding a string.
pub enum Encoding {
    /// The data is encoded as a json sting of bytes.
    /// For example `"[104, 22, 33]"`.
    /// This is not the most efficient encoding but easy to write by hand.
    Bytes,
    /// Hexadecimal encoding.
    Hex,
    /// Standard base64 encoding.
    Base64,
    /// Base64 encoding with URL safe characters and no padding.
    /// Note this means no padding characters are used not
    /// that the data is not word aligned.
    Base64UrlNoPad,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
/// Where to pad the data to make it word aligned.
pub enum Padding {
    /// Pad the start of the data.
    Start,
    /// Pad the end of the data.
    End,
}

#[derive(Clone, Copy)]
/// Different types of private keys that can be used for signing.
pub enum Key {
    /// A secp256k1 key.
    Secp256k1(secp256k1::SecretKey),
    /// An ed25519 key.
    Ed25519(ed25519_dalek::SecretKey),
}

#[derive(Clone, Copy, Debug)]
/// Different types of public keys.
pub enum PublicKey {
    /// A secp256k1 key.
    Secp256k1(secp256k1::PublicKey),
    /// An ed25519 key.
    Ed25519(ed25519_dalek::VerifyingKey),
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Different types of signatures that can be produced.
pub enum Signature {
    /// A secp256k1 signature.
    Secp256k1(secp256k1::ecdsa::RecoverableSignature),
    /// An ed25519 signature.
    Ed25519(ed25519_dalek::Signature),
}

/// Sign data by serializing it using postcard and then hashing and signing the hash.
///
/// This does **not** pad the data to be word aligned.
pub fn sign_postcard<T: Serialize>(data: &T, private_key: &Key) -> anyhow::Result<Signature> {
    let data = postcard_bytes(data)?;
    let hash = hash_bytes(&data)?;
    sign_hash(hash, private_key)
}

/// Sign data by serializing it using postcard and then hashing and signing the hash.
///
/// This pads the data to be word aligned.
pub fn sign_postcard_with_padding<T: Serialize>(
    data: &T,
    padding: Padding,
    private_key: &Key,
) -> anyhow::Result<Signature> {
    let data = postcard_bytes_with_padding(data, padding)?;
    let hash = hash_bytes(&data)?;
    sign_hash(hash, private_key)
}

/// Sign a slice of words by hashing and signing the hash.
pub fn sign_words(data: &[Word], private_key: &Key) -> anyhow::Result<Signature> {
    let hash = hash_words(data);
    sign_hash(hash, private_key)
}

/// Sign the data by padding it to be word aligned and then hashing and signing the hash.
///
/// If the data is already word aligned no padding will occur.
pub fn sign_bytes_with_padding(
    data: Vec<u8>,
    padding: Padding,
    private_key: &Key,
) -> anyhow::Result<Signature> {
    let data = align_to_word(data, padding);
    let hash = hash_bytes(&data)?;
    sign_hash(hash, private_key)
}

/// Sign already word aligned data by hashing and signing the hash.
///
/// If the data is not word aligned an error will be returned.
pub fn sign_aligned_bytes(data: &[u8], private_key: &Key) -> anyhow::Result<Signature> {
    ensure!(is_word_aligned(data), "Data is not word aligned");
    let hash = hash_bytes(data)?;
    sign_hash(hash, private_key)
}

/// Sign the data by hashing and signing the hash.
///
/// This does **not** check if the data is word aligned.
pub fn sign_bytes_unchecked(data: &[u8], private_key: &Key) -> anyhow::Result<Signature> {
    let hash = hash_bytes(data)?;
    sign_hash(hash, private_key)
}

/// Sign a already hashed data.
pub fn sign_hash(hash: Hash, private_key: &Key) -> anyhow::Result<Signature> {
    match private_key {
        Key::Secp256k1(private_key) => {
            let sig = essential_sign::sign_hash(hash, private_key);
            let sig = secp256k1::ecdsa::RecoverableSignature::from_compact(
                &sig.0,
                secp256k1::ecdsa::RecoveryId::from_i32(sig.1 as i32)?,
            )?;
            Ok(Signature::Secp256k1(sig))
        }
        Key::Ed25519(_) => todo!(),
    }
}

/// Read a file into a vector of bytes.
pub fn read_file(path: &std::path::Path) -> anyhow::Result<Vec<u8>> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    Ok(data)
}

#[derive(Deserialize, Serialize)]
struct Bytes(#[serde(with = "serde_bytes")] Vec<u8>);

/// Decode a string into a vector of bytes using the given encoding.
pub fn decode_str(data: String, encoding: Encoding) -> anyhow::Result<Vec<u8>> {
    match encoding {
        Encoding::Bytes => {
            let Bytes(data) = serde_json::from_str(&data)?;
            Ok(data)
        }
        Encoding::Hex => Ok(hex::decode(data)?),
        Encoding::Base64 => {
            use base64::engine::general_purpose::STANDARD;
            use base64::Engine;
            Ok(STANDARD.decode(data.as_bytes())?)
        }
        Encoding::Base64UrlNoPad => {
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            use base64::Engine;
            Ok(URL_SAFE_NO_PAD.decode(data.as_bytes())?)
        }
    }
}

/// Encode a vector of bytes into a string using the given encoding.
pub fn encode_str(data: Vec<u8>, encoding: Encoding) -> anyhow::Result<String> {
    match encoding {
        Encoding::Bytes => Ok(serde_json::to_string(&Bytes(data))?),
        Encoding::Hex => Ok(hex::encode(data)),
        Encoding::Base64 => {
            use base64::engine::general_purpose::STANDARD;
            use base64::Engine;
            Ok(STANDARD.encode(data))
        }
        Encoding::Base64UrlNoPad => {
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            use base64::Engine;
            Ok(URL_SAFE_NO_PAD.encode(data))
        }
    }
}

/// Align and convert the data to words.
pub fn into_words(data: Vec<u8>, padding: Padding) -> Vec<Word> {
    let data = align_to_word(data, padding);
    data.chunks(8)
        .map(|chunk| {
            essential_types::convert::word_from_bytes(
                chunk.try_into().expect("This can't fail because of chunks"),
            )
        })
        .collect::<Vec<Word>>()
}

/// Align the data to be word aligned.
/// This will pad the data with zeros at the start or end depending on the padding.
pub fn align_to_word(data: Vec<u8>, padding: Padding) -> Vec<u8> {
    if is_word_aligned(&data) {
        data
    } else {
        pad_bytes(data, padding)
    }
}

/// Check if the data is word aligned.
pub fn is_word_aligned(data: &[u8]) -> bool {
    data.len() % 8 == 0
}

/// Pad the data to be word aligned.
///
/// Note it's cheaper to use `align_to_word` if the data might already be word aligned.
pub fn pad_bytes(mut data: Vec<u8>, padding: Padding) -> Vec<u8> {
    match padding {
        Padding::Start => {
            let len = data.len();
            let pad = 8 - len % 8;
            let mut padded = vec![0; pad];
            padded.extend(data);
            padded
        }
        Padding::End => {
            let len = data.len();
            let pad = 8 - len % 8;
            data.extend(std::iter::repeat(0).take(pad));
            data
        }
    }
}

/// Hash the data using sha256.
///
/// This does **not** pad or check if the data is word aligned.
pub fn hash_bytes(data: &[u8]) -> anyhow::Result<Hash> {
    let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
    hasher.update(data);
    Ok(hasher.finalize().into())
}

/// Hash the words using sha256.
pub fn hash_words(data: &[Word]) -> Hash {
    essential_hash::hash_words(data)
}

/// Turn a secp256k1 signature into an essential signature.
pub fn to_essential_signature(
    sig: secp256k1::ecdsa::RecoverableSignature,
) -> anyhow::Result<essential_types::Signature> {
    let (rec_id, data) = sig.serialize_compact();
    Ok(essential_types::Signature(
        data,
        rec_id.to_i32().try_into()?,
    ))
}

/// Turn any supported signature into bytes that are padded to be word aligned.
///
/// This is the same layout that the `essential-constraint-vm` expects.
pub fn signature_to_aligned_bytes(sig: &Signature) -> Vec<u8> {
    match sig {
        Signature::Secp256k1(sig) => essential_sign::encode::signature_as_bytes(sig).to_vec(),
        Signature::Ed25519(sig) => sig.to_bytes().to_vec(),
    }
}

/// Turn any supported signature into bytes.
///
/// This is **not** padded to be word aligned.
pub fn signature_to_bytes(sig: &Signature) -> anyhow::Result<Vec<u8>> {
    match sig {
        Signature::Secp256k1(sig) => {
            let (rec_id, data) = sig.serialize_compact();
            let mut bytes = data.to_vec();
            let rec_id = rec_id.to_i32();
            let rec_id: u8 = rec_id.try_into()?;
            bytes.push(rec_id);
            Ok(bytes)
        }
        Signature::Ed25519(sig) => Ok(sig.to_bytes().to_vec()),
    }
}

/// Serialize a signed contract to json bytes.
///
/// This can be directly submitted to the api.
pub fn signed_set_to_bytes(
    signed_set: &essential_types::contract::SignedContract,
) -> anyhow::Result<Vec<u8>> {
    Ok(serde_json::to_vec(signed_set)?)
}

/// Turn any supported signature into words.
pub fn signature_to_words(sig: &Signature) -> Vec<Word> {
    match sig {
        Signature::Secp256k1(sig) => essential_sign::encode::signature(sig).to_vec(),
        Signature::Ed25519(_) => todo!(),
    }
}

/// Turn any supported public key into bytes that are padded to be word aligned.
///
/// This is the same layout that the `essential-constraint-vm` expects.
pub fn public_key_to_words(key: &PublicKey) -> Vec<Word> {
    match key {
        PublicKey::Secp256k1(key) => essential_sign::encode::public_key(key).to_vec(),
        PublicKey::Ed25519(key) => word_4_from_u8_32(key.to_bytes()).to_vec(),
    }
}

/// Serialize data using postcard and then pad it to be word aligned.
pub fn postcard_bytes_with_padding<T: Serialize>(
    data: &T,
    padding: Padding,
) -> anyhow::Result<Vec<u8>> {
    let data = postcard::to_allocvec(data)?;
    Ok(align_to_word(data, padding))
}

/// Serialize data using postcard.
pub fn postcard_bytes<T: Serialize>(data: &T) -> anyhow::Result<Vec<u8>> {
    Ok(postcard::to_allocvec(data)?)
}

/// Get the public key from a private key.
pub fn public_key(private_key: &Key) -> PublicKey {
    match private_key {
        Key::Secp256k1(key) => {
            let secp = secp256k1::Secp256k1::new();
            PublicKey::Secp256k1(key.public_key(&secp))
        }
        Key::Ed25519(key) => {
            let key = ed25519_dalek::SigningKey::from_bytes(key);
            PublicKey::Ed25519(key.verifying_key())
        }
    }
}
