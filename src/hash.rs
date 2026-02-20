//! Hash types used throughout the blockchain data structures.

use core::fmt;

/// A 32-byte hash (SHA-256d / double-SHA-256) stored as a zero-copy reference.
///
/// The inner reference borrows from the original parse buffer, so no heap
/// allocation is required.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Hash32<'a>(pub &'a [u8; 32]);

impl<'a> Hash32<'a> {
    /// View the hash as a raw byte slice.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Return the inner fixed-size reference.
    #[inline]
    pub fn as_array(&self) -> &[u8; 32] {
        self.0
    }

    /// Verify that this hash matches an owned array.
    #[inline]
    pub fn eq_array(&self, other: &[u8; 32]) -> bool {
        self.0 == other
    }
}

impl fmt::Debug for Hash32<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash32(")?;
        // Bitcoin convention: display bytes in reverse (little-endian txid)
        for b in self.0.iter().rev() {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

impl fmt::Display for Hash32<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0.iter().rev() {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// A 20-byte hash (RIPEMD-160 of SHA-256, used in P2PKH / P2SH addresses).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Hash20<'a>(pub &'a [u8; 20]);

impl fmt::Debug for Hash20<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash20(")?;
        for b in self.0.iter() {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

/// Compute double-SHA-256 of `data` and return a newly allocated `[u8; 32]`.
///
/// This is the only place where allocation (stack frame) is required; the
/// result is typically compared against a zero-copy reference hash and then
/// discarded.
#[cfg(feature = "std")]
pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let first = Sha256::digest(data);
    Sha256::digest(first).into()
}
