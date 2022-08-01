//! # Bitcoin keys
//! 
//! Types and traits for managing Bitcoin keys.
//! 
//! ## About
//! 
//! The Bitcoin protocol deals with multiple formats and contexts of keys.
//! There are legacy ECDSA keys that may or may not be compressed, X-only (Taproot) keys, private keys, etc.
//! To avoid mixing them, this library provides multiple newtypes and
//! additional infrastructure aiding with conversions, parsing, serializing...
//!
//! The crate is `no_std` and doesn't require an allocator.

#![no_std]

#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod ecdsa;
pub mod bip340;

pub use secp256k1::{self, scalar::Scalar};
pub use bip340::{XOnlyPublicKey, XOnlyPrivateKey, XOnlyKeyPair};

/// Public key that may be serialized as uncompressed, used in legacy addresses only.
///
/// You probably want to use this alias instead of explicitly writing out the type.
pub type LegacyPublicKey = ecdsa::Legacy<secp256k1::PublicKey>;

/// Public key that is always serialized as compressed.
///
/// You probably want to use this alias instead of explicitly writing out the type.
pub type CompressedPublicKey = ecdsa::Compressed<secp256k1::PublicKey>;

/// Private key that may be serialized as uncompressed, used in legacy addresses only.
///
/// You probably want to use this alias instead of explicitly writing out the type.
pub type LegacyPrivateKey = ecdsa::Legacy<secp256k1::SecretKey>;

/// Private key that is always serialized as compressed.
///
/// You probably want to use this alias instead of explicitly writing out the type.
pub type CompressedPrivateKey = ecdsa::Compressed<secp256k1::SecretKey>;

/// Key pair that may be serialized as uncompressed, used in legacy addresses only.
///
/// You probably want to use this alias instead of explicitly writing out the type.
pub type LegacyKeyPair = ecdsa::Legacy<secp256k1::KeyPair>;

/// Key pair that is always serialized as compressed.
///
/// You probably want to use this alias instead of explicitly writing out the type.
pub type CompressedKeyPair = ecdsa::Compressed<secp256k1::KeyPair>;
