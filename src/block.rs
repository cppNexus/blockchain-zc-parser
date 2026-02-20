//! Bitcoin block header and full block parsing — zero-copy.

use crate::{
    cursor::Cursor,
    error::{ParseError, ParseResult},
    hash::Hash32,
    transaction::TransactionParser,
};

/// Bitcoin mainnet magic bytes.
pub const MAINNET_MAGIC: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];
/// Bitcoin testnet3 magic bytes.
pub const TESTNET_MAGIC: [u8; 4] = [0x0b, 0x11, 0x09, 0x07];
/// Bitcoin signet magic bytes.
pub const SIGNET_MAGIC: [u8; 4] = [0x0a, 0x03, 0xcf, 0x40];

/// Maximum number of transactions per block (sanity cap for iteration).
pub const MAX_BLOCK_TXN: usize = 1_000_000;

/// Maximum raw block payload size we will accept from a `.dat` file entry (sanity cap).
///
/// Bitcoin Core uses 4,000,000 weight units, but raw serialized blocks can still be large.
/// This is a defensive cap for parsing file blobs.
pub const MAX_BLOCK_BYTES: usize = 8_000_000;

// ---------------------------------------------------------------------------
// Block header
// ---------------------------------------------------------------------------

/// An 80-byte Bitcoin block header — zero-copy.
///
/// All hash fields borrow directly from the parse buffer.
#[derive(Debug, Clone, Copy)]
pub struct BlockHeader<'a> {
    /// Protocol version.
    pub version: i32,
    /// Hash of the previous block header.
    pub prev_block: Hash32<'a>,
    /// Merkle root of all transactions.
    pub merkle_root: Hash32<'a>,
    /// Unix timestamp (seconds since epoch).
    pub timestamp: u32,
    /// Compact difficulty target.
    pub bits: u32,
    /// Nonce.
    pub nonce: u32,
    /// Raw 80-byte header (for hashing / comparison).
    pub raw: &'a [u8; 80],
}

impl<'a> BlockHeader<'a> {
    /// Parse exactly 80 bytes as a block header.
    pub fn parse(c: &mut Cursor<'a>) -> ParseResult<Self> {
        let raw: &'a [u8; 80] = c.read_array::<80>()?;
        // Parse fields from a sub-cursor over the same bytes (zero-copy).
        let mut sub = Cursor::new(raw.as_slice());
        let version = sub.read_i32_le()?;
        let prev_block = Hash32(sub.read_array::<32>()?);
        let merkle_root = Hash32(sub.read_array::<32>()?);
        let timestamp = sub.read_u32_le()?;
        let bits = sub.read_u32_le()?;
        let nonce = sub.read_u32_le()?;
        Ok(Self {
            version,
            prev_block,
            merkle_root,
            timestamp,
            bits,
            nonce,
            raw,
        })
    }

    /// Compute the block hash (double-SHA-256 of the 80-byte header).
    ///
    /// Returns a stack-allocated `[u8; 32]` in Bitcoin display byte order.
    #[cfg(feature = "std")]
    pub fn block_hash(&self) -> [u8; 32] {
        crate::hash::double_sha256(self.raw.as_slice())
    }

    /// Decode the compact difficulty `bits` to a 256-bit target.
    ///
    /// Returns `(mantissa, exponent)` such that `target = mantissa << (8 * (exponent - 3))`.
    #[inline]
    pub fn difficulty_target(&self) -> (u32, u8) {
        let exp = (self.bits >> 24) as u8;
        let mantissa = self.bits & 0x00ff_ffff;
        (mantissa, exp)
    }
}

// ---------------------------------------------------------------------------
// Block iterator
// ---------------------------------------------------------------------------

/// A streaming iterator over the transactions in a raw block.
///
/// No allocation is performed. Each call to [`BlockTxIter::next_tx`] advances
/// the cursor and calls a user-supplied closure.
pub struct BlockTxIter<'a> {
    cursor: Cursor<'a>,
    total: usize,
    consumed: usize,
}

impl<'a> BlockTxIter<'a> {
    /// Position the iterator just after the block header.
    pub fn new(data: &'a [u8]) -> ParseResult<(BlockHeader<'a>, Self)> {
        let mut c = Cursor::new(data);
        let header = BlockHeader::parse(&mut c)?;
        let tx_count_u64 = c.read_varint()?;
        let tx_count: usize = tx_count_u64
            .try_into()
            .map_err(|_| ParseError::IntegerTooLarge {
                value: tx_count_u64,
            })?;
        if tx_count > MAX_BLOCK_TXN {
            return Err(ParseError::OversizedData {
                size: tx_count,
                max: MAX_BLOCK_TXN,
            });
        }
        Ok((
            header,
            Self {
                cursor: c,
                total: tx_count,
                consumed: 0,
            },
        ))
    }

    /// Total number of transactions in this block.
    #[inline]
    pub fn total(&self) -> usize {
        self.total
    }

    /// Number of transactions already consumed.
    #[inline]
    pub fn consumed(&self) -> usize {
        self.consumed
    }

    /// Number of bytes remaining in the underlying cursor (unparsed portion of the block payload).
    #[inline]
    pub fn bytes_remaining(&self) -> usize {
        self.cursor.remaining()
    }

    /// Number of bytes consumed so far from the underlying block payload.
    ///
    /// This is useful for instrumentation / debugging: after parsing `n` transactions,
    /// you can see how many bytes of the block were actually consumed.
    #[inline]
    pub fn bytes_consumed(&self) -> usize {
        self.cursor.position()
    }

    /// Parse the next transaction and pass it to `f`.
    ///
    /// Returns `Ok(true)` if a transaction was parsed, `Ok(false)` at end of block.
    pub fn next_tx<FI, FO>(&mut self, on_input: FI, on_output: FO) -> ParseResult<bool>
    where
        FI: FnMut(crate::transaction::TxInput<'a>) -> ParseResult<()>,
        FO: FnMut(crate::transaction::TxOutput<'a>) -> ParseResult<()>,
    {
        if self.consumed >= self.total {
            return Ok(false);
        }
        // Create a parser over the remaining (unread) buffer.
        // `as_slice()` returns a `&'a [u8]` zero-copy sub-slice.
        let remaining: &'a [u8] = self.cursor.as_slice();
        let mut parser = TransactionParser::new(remaining);
        parser.parse_with(on_input, on_output)?;
        // Advance the outer cursor by exactly the bytes the tx consumed.
        let tx_len = parser.bytes_consumed();
        self.cursor.skip(tx_len)?;
        self.consumed += 1;
        Ok(true)
    }

    /// Skip all remaining transactions (fast path — just advance the cursor).
    pub fn skip_remaining(&mut self) -> ParseResult<()> {
        while self.consumed < self.total {
            self.next_tx(|_| Ok(()), |_| Ok(()))?;
        }
        Ok(())
    }

    /// In strict mode, ensure we've parsed exactly `total` transactions and consumed the buffer.
    ///
    /// Call this after iterating all transactions. If there are unread bytes remaining,
    /// this returns an error to surface offset / format bugs early.
    pub fn finish_strict(&self) -> ParseResult<()> {
        if self.consumed != self.total {
            return Err(ParseError::IncompleteTransactions {
                expected: self.total,
                parsed: self.consumed,
            });
        }
        let rem = self.cursor.remaining();
        if rem != 0 {
            return Err(ParseError::TrailingBytes { remaining: rem });
        }
        Ok(())
    }

    /// Convenience helper: iterate all transactions and enforce strict completion.
    pub fn consume_all_strict<FI, FO>(
        mut self,
        mut on_input: FI,
        mut on_output: FO,
    ) -> ParseResult<()>
    where
        FI: FnMut(crate::transaction::TxInput<'a>) -> ParseResult<()>,
        FO: FnMut(crate::transaction::TxOutput<'a>) -> ParseResult<()>,
    {
        let mut coinbase_txs: usize = 0;

        while self.consumed < self.total {
            let tx_index = self.consumed;
            let mut saw_first_input = false;
            let mut is_coinbase_tx = false;

            // Wrap the user callback to detect coinbase on the first input.
            let mut wrapped_on_input = |input: crate::transaction::TxInput<'a>| -> ParseResult<()> {
                if !saw_first_input {
                    saw_first_input = true;
                    // Coinbase is identified by an all-zero prevout txid and vout=0xffff_ffff.
                    // Coinbase if prevout txid is all-zero and vout is 0xffff_ffff.
                    is_coinbase_tx = input.previous_output.is_coinbase();
                    if is_coinbase_tx {
                        coinbase_txs += 1;
                        // In strict mode, coinbase must be the first transaction.
                        if tx_index != 0 {
                            return Err(ParseError::InvalidCoinbaseCount {
                                count: coinbase_txs,
                            });
                        }
                    }
                }
                on_input(input)
            };

            let mut wrapped_on_output =
                |output: crate::transaction::TxOutput<'a>| -> ParseResult<()> { on_output(output) };

            // Parse exactly one transaction.
            let _ = self.next_tx(&mut wrapped_on_input, &mut wrapped_on_output)?;
        }

        // Enforce strict completion.
        self.finish_strict()?;

        // Enforce exactly one coinbase transaction per block.
        if coinbase_txs != 1 {
            return Err(ParseError::InvalidCoinbaseCount {
                count: coinbase_txs,
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Raw block file parser (blkNNNNN.dat format)
// ---------------------------------------------------------------------------

/// Iterator over raw block messages in a Bitcoin Core `blkNNNNN.dat` file.
///
/// Each entry in these files is: `[magic: 4] [size: u32-le] [block: size bytes]`.
pub struct BlkFileIter<'a> {
    cursor: Cursor<'a>,
    magic: [u8; 4],
}

impl<'a> BlkFileIter<'a> {
    /// Create an iterator over a raw `.dat` file buffer with the given magic.
    pub fn new(data: &'a [u8], magic: [u8; 4]) -> Self {
        Self {
            cursor: Cursor::new(data),
            magic,
        }
    }

    /// Return the next raw block bytes (zero-copy sub-slice), or `None` at EOF.
    pub fn next_block(&mut self) -> ParseResult<Option<&'a [u8]>> {
        if self.cursor.is_empty() {
            return Ok(None);
        }
        let magic: &[u8; 4] = self.cursor.read_array::<4>()?;
        if *magic != self.magic {
            return Err(ParseError::MagicMismatch {
                expected: self.magic,
                got: *magic,
            });
        }
        let size = self.cursor.read_u32_le()? as usize;
        if size > MAX_BLOCK_BYTES {
            return Err(ParseError::OversizedData {
                size,
                max: MAX_BLOCK_BYTES,
            });
        }
        let block_bytes = self.cursor.read_bytes(size)?;
        Ok(Some(block_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn genesis_header_raw() -> [u8; 80] {
        // Bitcoin genesis block header (mainnet)
        hex_literal::hex!(
            "01000000"                                                         // version
            "0000000000000000000000000000000000000000000000000000000000000000" // prev_block
            "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a" // merkle_root
            "29ab5f49"                                                         // timestamp
            "ffff001d"                                                         // bits
            "1dac2b7c"                                                         // nonce
        )
    }

    #[test]
    fn parse_genesis_header() {
        let raw = genesis_header_raw();
        let mut cursor = Cursor::new(&raw);
        let header = BlockHeader::parse(&mut cursor).unwrap();
        assert_eq!(header.version, 1);
        assert_eq!(header.nonce, 0x7c2bac1d);
        assert!(header.prev_block.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn header_is_zero_copy() {
        let raw = genesis_header_raw();
        let raw_ptr = raw.as_ptr();
        let mut cursor = Cursor::new(&raw);
        let header = BlockHeader::parse(&mut cursor).unwrap();
        // prev_block bytes should point into the original buffer
        assert_eq!(header.prev_block.as_bytes().as_ptr(), unsafe {
            raw_ptr.add(4)
        });
    }
}
