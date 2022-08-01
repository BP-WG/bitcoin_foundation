//! Keys intended to be used in Schnorr sinatures - in P2TR.

pub use secp256k1::XOnlyPublicKey;

use secp256k1::Secp256k1;
use crate::Scalar;

/// Private key intended for schnorr signatures.
///
/// This type wraps [`secp256k1::SecretKey`] to prevent accidental use in ECDSA signatures.
/// It is mostly used to sign P2TR spends or derive P2TR addresses.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct XOnlyPrivateKey {
    key: secp256k1::SecretKey,
}

impl XOnlyPrivateKey {
    /// Creates the x-only private key from a generic private key
    pub fn from_raw(key: secp256k1::SecretKey) -> Self {
        XOnlyPrivateKey {
            key,
        }
    }

    /// Computes public key from this private key.
    pub fn compute_public_key<C: secp256k1::Signing>(self, context: &Secp256k1<C>) -> secp256k1::XOnlyPublicKey {
        secp256k1::PublicKey::from_secret_key(context, &self.key).into()
    }

    pub fn add_tweak(self, tweak: &Scalar) -> Result<Self, secp256k1::Error> {
        self.key.add_tweak(tweak).map(|key| XOnlyPrivateKey { key })
    }

    pub fn mul_tweak(self, tweak: &Scalar) -> Result<Self, secp256k1::Error> {
        self.key.mul_tweak(tweak).map(|key| XOnlyPrivateKey { key })
    }
}

/// Key pair intended for schnorr signatures.
///
/// This type wraps [`secp256k1::KeyPair`] to prevent accidental use in ECDSA signatures.
/// It is mostly used to sign P2TR spends or derive P2TR addresses.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct XOnlyKeyPair {
    key: secp256k1::KeyPair,
}

impl XOnlyKeyPair {
    /// Creates the x-only key pair from a generic key pair
    pub fn from_raw(key: secp256k1::KeyPair) -> Self {
        XOnlyKeyPair {
            key,
        }
    }

    /// Returns the public key.
    pub fn public_key(self) -> secp256k1::XOnlyPublicKey {
        secp256k1::PublicKey::from(self.key).into()
    }

    /// Returns the private key.
    pub fn private_key(self) -> XOnlyPrivateKey {
        XOnlyPrivateKey::from_raw(self.key.into())
    }

    pub fn add_tweak<C: secp256k1::Signing + secp256k1::Verification>(self, context: &Secp256k1<C>, tweak: &Scalar) -> Result<Self, secp256k1::Error> {
        self.key.add_xonly_tweak(context, tweak).map(|key| XOnlyKeyPair { key })
    }
}
