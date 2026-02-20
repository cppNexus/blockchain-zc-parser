//! Zero-copy cursor over a byte slice.
//!
//! The [`Cursor`] type advances a shared reference into the input buffer without
//! ever copying bytes. All returned slices have the lifetime of the original
//! input data.

use crate::error::{ParseError, ParseResult};

/// Stateful, zero-copy cursor over an immutable byte slice.
///
/// All methods advance the cursor in-place and return sub-slices that borrow
/// from the **original** input — no allocation, no memcpy.
#[derive(Debug, Clone)]
pub struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    /// Create a new cursor starting at position 0.
    #[inline]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Current byte offset from the start.
    #[inline]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Number of bytes remaining in the buffer.
    #[inline]
    pub const fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    /// `true` if there are no more bytes to read.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    /// Return the unread portion as a slice without advancing.
    #[inline]
    pub fn as_slice(&self) -> &'a [u8] {
        debug_assert!(self.pos <= self.data.len());
        &self.data[self.pos..]
    }

    /// Borrow exactly `n` bytes and advance the cursor.
    ///
    /// This is the core primitive — O(1), zero-copy.
    #[inline]
    pub fn read_bytes(&mut self, n: usize) -> ParseResult<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(ParseError::UnexpectedEof {
            needed: n,
            available: self.remaining(),
        })?;
        if end > self.data.len() {
            return Err(ParseError::UnexpectedEof {
                needed: n,
                available: self.remaining(),
            });
        }
        // SAFETY: bounds checked above
        let slice = unsafe { self.data.get_unchecked(self.pos..end) };
        self.pos = end;
        Ok(slice)
    }

    /// Read a single byte.
    #[inline]
    pub fn read_u8(&mut self) -> ParseResult<u8> {
        if self.pos >= self.data.len() {
            return Err(ParseError::UnexpectedEof {
                needed: 1,
                available: 0,
            });
        }
        // SAFETY: bounds checked above
        let b = unsafe { *self.data.get_unchecked(self.pos) };
        self.pos += 1;
        Ok(b)
    }

    /// Read a little-endian `u16`.
    #[inline]
    pub fn read_u16_le(&mut self) -> ParseResult<u16> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    /// Read a little-endian `u32`.
    #[inline]
    pub fn read_u32_le(&mut self) -> ParseResult<u32> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Read a little-endian `i32`.
    #[inline]
    pub fn read_i32_le(&mut self) -> ParseResult<i32> {
        let bytes = self.read_bytes(4)?;
        Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Read a little-endian `u64`.
    #[inline]
    pub fn read_u64_le(&mut self) -> ParseResult<u64> {
        let bytes = self.read_bytes(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Read a little-endian `i64`.
    #[inline]
    pub fn read_i64_le(&mut self) -> ParseResult<i64> {
        let bytes = self.read_bytes(8)?;
        Ok(i64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Parse a Bitcoin-style variable-length integer (1, 3, 5, or 9 bytes).
    ///
    /// Returns the decoded value as `u64`.
    #[inline]
    pub fn read_varint(&mut self) -> ParseResult<u64> {
        match self.read_u8()? {
            v @ 0x00..=0xfc => Ok(v as u64),
            0xfd => self.read_u16_le().map(|v| v as u64),
            0xfe => self.read_u32_le().map(|v| v as u64),
            0xff => self.read_u64_le(),
        }
    }

    /// Read a length-prefixed byte slice (varint + raw bytes).
    ///
    /// Returns a zero-copy sub-slice of the original input.
    #[inline]
    pub fn read_var_bytes(&mut self, max: usize) -> ParseResult<&'a [u8]> {
        let len_u64 = self.read_varint()?;
        let len: usize = len_u64
            .try_into()
            .map_err(|_| ParseError::IntegerTooLarge { value: len_u64 })?;

        if len > max {
            return Err(ParseError::OversizedData { size: len, max });
        }
        self.read_bytes(len)
    }

    /// Borrow a fixed-size array from the current position.
    ///
    /// Panics at compile-time if `N == 0`.
    #[inline]
    pub fn read_array<const N: usize>(&mut self) -> ParseResult<&'a [u8; N]> {
        let bytes = self.read_bytes(N)?;
        // SAFETY: read_bytes guarantees exactly N bytes
        Ok(unsafe { &*(bytes.as_ptr() as *const [u8; N]) })
    }

    /// Skip `n` bytes without returning them.
    #[inline]
    pub fn skip(&mut self, n: usize) -> ParseResult<()> {
        let _ = self.read_bytes(n)?;
        Ok(())
    }

    /// Create a sub-cursor for exactly `n` bytes and advance the outer cursor.
    ///
    /// Useful for reading a known-size payload and ensuring it is fully consumed.
    #[inline]
    pub fn split(&mut self, n: usize) -> ParseResult<Cursor<'a>> {
        let slice = self.read_bytes(n)?;
        Ok(Cursor::new(slice))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_bytes_zero_copy() {
        let data = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut c = Cursor::new(&data);
        let slice = c.read_bytes(4).unwrap();
        // Pointer equality — no copy happened
        assert_eq!(slice.as_ptr(), data.as_ptr());
        assert_eq!(slice, &[1, 2, 3, 4]);
        assert_eq!(c.remaining(), 4);
    }

    #[test]
    fn varint_single_byte() {
        let data = [0xfc];
        let mut c = Cursor::new(&data);
        assert_eq!(c.read_varint().unwrap(), 0xfc);
    }

    #[test]
    fn varint_two_bytes() {
        let data = [0xfd, 0x01, 0x00];
        let mut c = Cursor::new(&data);
        assert_eq!(c.read_varint().unwrap(), 1);
    }

    #[test]
    fn varint_nine_bytes() {
        let mut data = [0u8; 9];
        data[0] = 0xff;
        data[1..].copy_from_slice(&u64::MAX.to_le_bytes());
        let mut c = Cursor::new(&data);
        assert_eq!(c.read_varint().unwrap(), u64::MAX);
    }

    #[test]
    fn eof_error() {
        let data = [1u8, 2];
        let mut c = Cursor::new(&data);
        assert!(matches!(
            c.read_bytes(3),
            Err(ParseError::UnexpectedEof {
                needed: 3,
                available: 2
            })
        ));
    }
}
