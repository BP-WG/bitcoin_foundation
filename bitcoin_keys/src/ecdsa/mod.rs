//! Types handling ECDSA public keys.
//! 
//! While ECDSA keys are expected to be replaced with Taproot or other future upgrades they are
//! still widely used at the time of writing this library. This module contains the types and
//! methods for handling them correctly and easily.
//!
//! Note that if you're writing a modern Bitcoin application from scratch it may be better to use
//! P2TR - see the [`schnorr`](crate::schnorr) module.
//!
//! There are two main key types in this module: [`Compressed`] and [`Legacy`].
//! They are nearly identical in memory and differ in serialization only.
//! [`Legacy`] may be (de)serialized as uncompressed and dynamically remembers the format.
//! [`Compressed`] is statically known to be compressed and can not be serialized as uncompressed.
//! Aside from saving a tiny bit of memory, it can statically prevent problems like panics when
//! constructing SegWit v0 addresses.
//!
//! Note that while these types are generic, it's actually recommended to not use their generic
//! properties and use type aliases in the crate root instead. Them being generic is mainly
//! avoiding code duplication in this crate.

pub mod serialized_public_key;

pub use serialized_public_key::SerializedPublicKey;

use core::convert::TryFrom;
use core::fmt;
use secp256k1::Secp256k1;

/// Distinguishes compressed keys from uncompressed ones (runtime).
///
/// This is a more readable alternative to `bool`.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum KeyFormat {
    /// The public key should be serialized as compressed.
    Compressed,
    /// The public key should be serialized as uncompressed.
    Uncompressed,
}

impl KeyFormat {
    /// Returns `true` if the format is [`Compressed`].
    ///
    /// Shorthand for matching/comparing.
    ///
    /// [`Compressed`]: Self::Compressed
    #[inline]
    pub fn is_compressed(self) -> bool {
        self == KeyFormat::Compressed
    }

    /// Returns `true` if the format is [`Uncompressed`].
    ///
    /// Shorthand for matching/comparing.
    ///
    /// [`Uncompressed`]: Self::Uncompressed
    #[inline]
    pub fn is_uncompressed(self) -> bool {
        self == KeyFormat::Uncompressed
    }
}

/// Turns compressed format to uncompressed and vice versa.
impl core::ops::Not for KeyFormat {
    type Output = Self;

    #[inline]
    fn not(self) -> Self::Output {
        match self {
            KeyFormat::Compressed => KeyFormat::Uncompressed,
            KeyFormat::Uncompressed => KeyFormat::Compressed,
        }
    }
}

mod sealed {
    use secp256k1::Secp256k1;

    pub trait Key: Copy + Eq {}

    impl Key for secp256k1::PublicKey {}
    impl Key for secp256k1::SecretKey {}
    impl Key for secp256k1::KeyPair {}

    pub trait PublicKey: Key {
        fn public_key(&self) -> secp256k1::PublicKey;
    }

    impl PublicKey for secp256k1::PublicKey {
        #[inline]
        fn public_key(&self) -> secp256k1::PublicKey {
            *self
        }
    }

    impl PublicKey for secp256k1::KeyPair {
        #[inline]
        fn public_key(&self) -> secp256k1::PublicKey {
            self.into()
        }
    }


    pub trait PrivateKey: Key {
        fn private_key(&self) -> secp256k1::SecretKey;

        #[inline]
        fn compute_public_key<C: secp256k1::Signing>(&self, context: &Secp256k1<C>) -> secp256k1::PublicKey {
            secp256k1::PublicKey::from_secret_key(context, &self.private_key())
        }
    }

    impl PrivateKey for secp256k1::SecretKey {
        #[inline]
        fn private_key(&self) -> secp256k1::SecretKey {
            *self
        }
    }

    impl PrivateKey for secp256k1::KeyPair {
        #[inline]
        fn private_key(&self) -> secp256k1::SecretKey {
            self.into()
        }

        /// Optimized override skips computing
        #[inline]
        fn compute_public_key<C: secp256k1::Signing>(&self, _context: &Secp256k1<C>) -> secp256k1::PublicKey {
            self.into()
        }
    }
}

/// Restricts key types that may be stored in [`Compressed`] and [`Legacy`]
pub trait Key: sealed::Key {
}

/// Represents key types that are or contain public keys.
pub trait PublicKey: Key + sealed::PublicKey {
}

/// Represents key types that are or contain private keys.
pub trait PrivateKey: Key + sealed::PrivateKey {
}

impl Key for secp256k1::PublicKey {}
impl Key for secp256k1::SecretKey {}
impl Key for secp256k1::KeyPair {}

impl PublicKey for secp256k1::PublicKey {}
impl PrivateKey for secp256k1::SecretKey {}
impl PublicKey for secp256k1::KeyPair {}
impl PrivateKey for secp256k1::KeyPair {}

/// Contains a key that may be uncompressed when serialized as public key.
///
/// Old Bitcoin addresses may have internally used an uncompressed public key. This is discouraged
/// in the new software since it wastes money, among other things, but it may be required to
/// recover old coins.
pub struct Legacy<K: Key> {
    key: K,
    format: KeyFormat,
}

impl<K: Key> Legacy<K> {
    /// Constructs the legacy key from the underlying secp256k1 key and format information.
    ///
    /// **Warning:** make sure to supply the correct key format. Incorrect format may lead to a
    /// different address making spending difficult or even impossible for non-technical people.
    #[inline]
    pub fn from_raw(key: K, format: KeyFormat) -> Self {
        Legacy {
            key,
            format,
        }
    }

    /// Returns the serialization format of this key.
    #[inline]
    pub fn format(&self) -> KeyFormat {
        self.format
    }

    /// Returns the underlying secp256k1 key.
    #[inline]
    pub fn raw_key(&self) -> K {
        self.key
    }

    /// Dangerous: Overrides the format.
    ///
    /// This method may change the format and result in a different address.
    /// As a consequence, improper use can make it harder to spend from the address, even impossible
    /// for non-technical people.
    ///
    /// The method should only be used when this behavior is known to be correct, e.g. in recovery
    /// tools.
    #[inline]
    pub fn force_set_format(&mut self, format: KeyFormat) {
        self.format = format;
    }

    /// Dangerous: Forces the format to be compressed.
    ///
    /// This method may change the format and result in a different address.
    /// As a consequence, improper use can make it harder to spend from the address, even impossible
    /// for non-technical people.
    ///
    /// The method should only be used when this behavior is known to be correct, e.g. in recovery
    /// tools.
    #[inline]
    pub fn force_to_compressed(&self) -> Compressed<K> {
        Compressed::from_raw(self.key)
    }

    /// Returns true if the keys are equal *regardless of the format*.
    ///
    /// The `Eq` trait takes serialization format into account thus same keys with different
    /// formats are considered **not** equal. This method ignores the format when comparing.
    #[inline]
    pub fn eq_key(&self, rhs: Self) -> bool {
        self.key == rhs.key
    }
}

impl<K: PublicKey> Legacy<K> {
    /// Serializes the public key into bytes according to the format.
    ///
    /// This is generally **not** presented to the user, just used to generate Bitcoin script.
    ///
    /// The returned type has API similar to immutable [`Vec<u8>`](alloc::vec::Vec) but as opposed
    /// to `Vec` it uses stack to hold the data. The downside is more costly moves.
    /// To avoid performance issues it's recommended to turn the returned value into a slice or
    /// iterator as soon as possible.
    #[inline]
    pub fn serialize_public_key(&self) -> SerializedPublicKey {
        SerializedPublicKey::new(self.key.public_key(), self.format)
    }
}

impl<K: PrivateKey> Legacy<K> {
    /// Computes a public key from this private key
    pub fn compute_public_key<C: secp256k1::Signing>(&self, context: &Secp256k1<C>) -> Legacy<secp256k1::PublicKey> {
        Legacy::from_raw(self.key.compute_public_key(context), self.format)
    }
}

/// Contains a key that is guaranteed to be compressed when serialized as public key.
///
/// This key may be used in either P2SH or SegWit v0 addresses which are still widely used but are
/// being replaced by P2TR addresses. New software is encouraged to use P2TR implemented ing the
/// [`schnorr`](crate::schnorr) module but this may still be required to recover old coins.
pub struct Compressed<K: Key> {
    key: K,
}

impl<K: Key> Compressed<K> {
    /// Creates compressed key from it's raw form.
    pub fn from_raw(key: K) -> Self {
        Compressed {
            key,
        }
    }

    /// Returns the raw key.
    pub fn raw_key(&self) -> K {
        self.key
    }
}

impl<K: PublicKey> Compressed<K> {
    /// Serializes the public key into bytes in compressed format.
    ///
    ///
    /// This is generally **not** presented to the user, just used to generate Bitcoin script.
    #[inline]
    pub fn serialize_public_key(&self) -> [u8; 33] {
        self.key.public_key().serialize()
    }
}

impl<K: PrivateKey> Compressed<K> {
    /// Computes a public key from this private key
    pub fn compute_public_key<C: secp256k1::Signing>(&self, context: &Secp256k1<C>) -> Compressed<secp256k1::PublicKey> {
        Compressed::from_raw(self.key.compute_public_key(context))
    }
}

impl From<Legacy<secp256k1::KeyPair>> for Legacy<secp256k1::PublicKey> {
    fn from(value: Legacy<secp256k1::KeyPair>) -> Self {
        Legacy::from_raw(value.raw_key().into(), value.format())
    }
}

impl From<Legacy<secp256k1::KeyPair>> for Legacy<secp256k1::SecretKey> {
    fn from(value: Legacy<secp256k1::KeyPair>) -> Self {
        Legacy::from_raw(value.raw_key().into(), value.format())
    }
}

impl From<Compressed<secp256k1::KeyPair>> for Compressed<secp256k1::PublicKey> {
    fn from(value: Compressed<secp256k1::KeyPair>) -> Self {
        Compressed::from_raw(value.raw_key().into())
    }
}

impl From<Compressed<secp256k1::KeyPair>> for Compressed<secp256k1::SecretKey> {
    fn from(value: Compressed<secp256k1::KeyPair>) -> Self {
        Compressed::from_raw(value.raw_key().into())
    }
}

impl<K: Key> From<Compressed<K>> for Legacy<K> {
    fn from(value: Compressed<K>) -> Self {
        Self::from_raw(value.raw_key(), KeyFormat::Compressed)
    }
}

impl<K: Key> TryFrom<Legacy<K>> for Compressed<K> {
    type Error = KeyNotCompressedError;

    fn try_from(value: Legacy<K>) -> Result<Self, Self::Error> {
        match value.format() {
            KeyFormat::Compressed => Ok(Self::from_raw(value.raw_key())),
            KeyFormat::Uncompressed => Err(KeyNotCompressedError {}),
        }
    }
}

/// Returned when attempting to convert legacy key into compressed and the legacy key is in
/// uncompressed format.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct KeyNotCompressedError {
}

impl fmt::Display for KeyNotCompressedError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("the key is not compressed")
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for KeyNotCompressedError {}
