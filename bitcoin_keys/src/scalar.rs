//! Provides [`Scalar`] and related types.
//!
//! In elliptic curve cryptography scalars are non-point values that can be used to multiply
//! points. The most common type of scalars are private keys. However not all scalars are private
//! keys. They can even be public *values*. To make handling them safer and easier this module
//! provides the `Scalar` type and related.

use core::fmt;

/// Positive 256-bit integer guaranteed to be less than the secp256k1 curve order.
///
/// The difference between `PrivateKey` and `Scalar` is that `Scalar` doesn't guarantee being
/// securely usable as a private key.
///
/// **Warning: the operations on this type are NOT constant time!**
/// Using this with secret values is not advised.
// Internal represenation is big endian to match what `libsecp256k1` uses.
// Also easier to implement comparison.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct Scalar([u8; 32]);

const MAX_RAW: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x40
];

impl Scalar {
    /// Scalar representing `0`
    pub const ZERO: Scalar = Scalar([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    /// Scalar representing `1`
    pub const ONE: Scalar = Scalar([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    /// Maximum valid value: `curve_order - 1`
    pub const MAX: Scalar = Scalar(MAX_RAW);

    /// Tries to deserialize from big endian bytes
    ///
    /// **Security warning:** this function is not constant time!
    /// Passing secret data is not recommended.
    ///
    /// # Errors
    ///
    /// Returns error when the value is above the curve order.
    pub fn from_be_bytes(value: [u8; 32]) -> Result<Self, OutOfRangeError> {
        // Lexicographic ordering of arrays of the same length is same as ordering of BE numbers
        if value <= MAX_RAW {
            Ok(Scalar(value))
        } else {
            Err(OutOfRangeError {})
        }
    }

    /// Tries to deserialize from little endian bytes
    ///
    /// **Security warning:** this function is not constant time!
    /// Passing secret data is not recommended.
    ///
    /// # Errors
    ///
    /// Returns error when the value is above the curve order.
    pub fn from_le_bytes(mut value: [u8; 32]) -> Result<Self, OutOfRangeError> {
        value.reverse();
        Self::from_be_bytes(value)
    }

    /// Serializes to big endian bytes
    pub fn to_be_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Serializes to little endian bytes
    pub fn to_le_bytes(self) -> [u8; 32] {
        let mut res = self.0;
        res.reverse();
        res
    }
}

impl From<secp256k1::SecretKey> for Scalar {
    fn from(value: secp256k1::SecretKey) -> Self {
        Scalar(value.secret_bytes())
    }
}


/// Error returned when the value of scalar is invalid - larger than the curve order.
// Intentionally doesn't implement `Copy` to improve forward compatibility.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub struct OutOfRangeError {
}

impl fmt::Display for OutOfRangeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt("the value is not a member of secp256k1 field", f)
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for OutOfRangeError {}
