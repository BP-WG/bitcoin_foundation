//! Types intended for manipulating serialized legacy public keys.
//!
//! Because the serialized keys may have different lengths a simple array can not be used.
//! `Vec<u8>` would've been possible but require allocation (slow, needs allocator).
//! Our special types avoid this problem.

use super::KeyFormat;
use core::convert::TryFrom;
use core::fmt;

/// Serialized ECDSA public key.
///
/// When serialized, the public key may have different length depending on the format.
/// This type holds the owned data of a serialized public key without heap allocation
/// while providing API similar to that of an immutable `Vec`
///
/// Note that this type is a bit large and may be costly to move.
/// Ideally, you should obtain the slice/iterator as soon after it's returned as you can and use it instead.
#[derive(Copy, Clone)] // others must be manual
pub struct SerializedPublicKey {
    // Note: we don't need to store Format because it is stored in zeroth byte.
    data: [u8; 65],
}

impl SerializedPublicKey {
    /// Serializes given public key.
    ///
    /// This function is intentionally private and written here as opposed to being a method on
    /// `Legacy`. This avoids the potential cost of monomorphisation. However we still allow the
    /// compiler to inline this as it may remove branches and just call the appropriate function.
    #[inline]
    pub(super) fn new(key: secp256k1::PublicKey, format: KeyFormat) -> Self {
        let data = match format {
            KeyFormat::Uncompressed => {
                let data = key.serialize_uncompressed();
                debug_assert_eq!(data[0], 4);
                data
            },
            KeyFormat::Compressed => {
                let serialized = key.serialize();
                debug_assert!(serialized[0] == 2 || serialized[0] == 3, "unexpected first byte {}, should've been 2 or 3", serialized[0]);
                let mut data = [0u8; 65];
                data[..33].copy_from_slice(&serialized);
                data
            },
        };

        SerializedPublicKey {
            data,
        }
    }

    /// Returns the length of the slice.
    ///
    /// The returned value will be either 33 or 65, depending on the format of the key this was
    /// created from.
    #[inline]
    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    /// Creates an iterator of bytes.
    #[inline]
    pub fn iter(&self) -> core::slice::Iter<'_, u8> {
        self.as_slice().iter()
    }

    /// Returns the serialized bytes as a slice.
    ///
    /// The length of the returned slice will be either 33 or 65, depending on the format of the
    /// kye this was created from.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        // This produces a beautiful, short, branch-free assembly :)
        //
        // If the key format is uncompressed, the zeroth byte is 4, 2 or 3 otherwise.
        // Thus the single bit is sufficient to decide the length.
        // Multiplying by 8 we get 32 or 0, as needed.

        // Debug check our assumptions.
        debug_assert!(self.data[0] == 4 || self.data[0] == 2 || self.data[0] == 3);

        &self.data[..(33 + (usize::from(self.data[0] & 4) * 8))]
    }
    
    /// Returns raw pointer pointing to the beginning of the serialized bytes.
    ///
    /// To maintain memory safety the memory behind the pointer MUST NOT be accessed after `self`
    /// is dropped or moved or mutably borrowed. You also MUST NOT write to the memory behind the
    /// pointer. The memory is only valid for up to `self.len()` bytes.
    #[inline]
    pub fn as_ptr(&self) -> *const u8 {
        self.as_slice().as_ptr()
    }
}

impl core::ops::Deref for SerializedPublicKey {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl AsRef<[u8]> for SerializedPublicKey {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl core::borrow::Borrow<[u8]> for SerializedPublicKey {
    #[inline]
    fn borrow(&self) -> &[u8] {
        self.as_slice()
    }
}

// For consideration before API 1.0: should we newtype this to get an iterator returning `u8`?
impl<'a> IntoIterator for &'a SerializedPublicKey {
    type IntoIter = core::slice::Iter<'a, u8>;
    type Item = &'a u8;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl IntoIterator for SerializedPublicKey {
    type IntoIter = IntoIter;
    type Item = u8;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        IntoIter {
            key: self,
            pos: 0,
        }
    }
}

impl PartialEq for SerializedPublicKey {
    #[inline]
    fn eq(&self, other: &SerializedPublicKey) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for SerializedPublicKey {
}

impl PartialOrd for SerializedPublicKey {
    #[inline]
    fn partial_cmp(&self, other: &SerializedPublicKey) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SerializedPublicKey {
    #[inline]
    fn cmp(&self, other: &SerializedPublicKey) -> core::cmp::Ordering {
        self.as_slice().cmp(other.as_slice())
    }
}

impl core::hash::Hash for SerializedPublicKey {
    #[inline]
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        <[u8] as core::hash::Hash>::hash(self.as_slice(), state)
    }
}

impl fmt::Debug for SerializedPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for b in self {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}


/// Owned iterator over bytes of the serialized public key.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct IntoIter {
    key: SerializedPublicKey,
    // invariant: pos <= key.len()
    pos: u8,
}

impl IntoIter {
    /// Returns the remaining bytes as a slice.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.key[self.pos()..]
    }

    // usize is more useful in general so this casts too
    // however storing u8 leads to a smaller type
    // I believe the casts will be reasonably optimized.
    fn pos(&self) -> usize {
        self.pos.into()
    }
}

impl Iterator for IntoIter {
    type Item = u8;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let item = *self.key.get(self.pos())?;
        // The invariant is maintained because we start at zero and only add one if `pos` is less
        // than `self.key.len()`. If `pos == self.key.len()` the line above returns.
        // no overflow because key len is at most 65
        self.pos += 1;
        debug_assert!(self.pos() <= self.key.len());
        Some(item)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.key.len() - self.pos();
        (len, Some(len))
    }

    #[inline]
    fn count(self) -> usize {
        // no need to actually produce/drop the items
        self.len()
    }

    #[inline]
    fn last(self) -> Option<Self::Item> {
        // no need to actually produce/drop the items
        if self.pos() < self.key.len() {
            Some(self.key[self.key.len() - 1])
        } else {
            None
        }
    }

    #[inline]
    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        // no need to actually produce/drop the items
        // if n can't be converted to u8 or overflows u8 when added to pos it's certainly above len
        // because len is at most 65.
        let elem_pos = self.pos.saturating_add(u8::try_from(n).unwrap_or(255));
        if usize::from(elem_pos) < self.key.len() {
            // no overflow because key len is at most 65
            self.pos = elem_pos + 1;
            Some(self.key[usize::from(elem_pos)])
        } else {
            None
        }
    }
}

impl ExactSizeIterator for IntoIter {}

// Once `pos` reaches `len()` `get()` is returning `None` without changing the iterator.
impl core::iter::FusedIterator for IntoIter {}

#[cfg(feature = "alloc")]
mod alloc_impls {
    use alloc::borrow::Cow;
    use alloc::vec::Vec;
    use alloc::boxed::Box;
    use alloc::rc::Rc;
    use alloc::sync::Arc;
    use super::SerializedPublicKey;

    /// This conversion allocates
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    impl From<SerializedPublicKey> for Vec<u8> {
        #[inline]
        fn from(value: SerializedPublicKey) -> Self {
            value.as_slice().into()
        }
    }

    /// This conversion allocates
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    impl From<SerializedPublicKey> for Box<[u8]> {
        #[inline]
        fn from(value: SerializedPublicKey) -> Self {
            value.as_slice().into()
        }
    }

    /// This conversion allocates
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    impl From<SerializedPublicKey> for Rc<[u8]> {
        #[inline]
        fn from(value: SerializedPublicKey) -> Self {
            value.as_slice().into()
        }
    }

    /// This conversion allocates
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    impl From<SerializedPublicKey> for Arc<[u8]> {
        #[inline]
        fn from(value: SerializedPublicKey) -> Self {
            value.as_slice().into()
        }
    }

    /// This conversion always produces the [`Owned`](Cow::Owned) variant - allocates.
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    impl<'a> From<SerializedPublicKey> for Cow<'a, [u8]> {
        #[inline]
        fn from(value: SerializedPublicKey) -> Self {
            Cow::Owned(value.into())
        }
    }
}
