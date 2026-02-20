//! Bitcoin transaction parsing — zero-copy, no alloc.
//!
//! All structures borrow from the original input buffer via lifetime `'a`.

use crate::{
    cursor::Cursor,
    error::{ParseError, ParseResult},
    hash::Hash32,
    script::Script,
};

/// Maximum number of inputs / outputs per transaction (protocol sanity limit).
pub const MAX_IO_COUNT: usize = 100_000;
/// Maximum witness items per input.
pub const MAX_WITNESS_ITEMS: usize = 500;
/// Maximum witness item size.
pub const MAX_WITNESS_ITEM_SIZE: usize = 520;

// ---------------------------------------------------------------------------
// Outpoint
// ---------------------------------------------------------------------------

/// Reference to a specific output of a previous transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutPoint<'a> {
    /// TXID of the referenced transaction (32 bytes, zero-copy).
    pub txid: Hash32<'a>,
    /// Index of the output in that transaction.
    pub vout: u32,
}

impl<'a> OutPoint<'a> {
    /// Parse from cursor (36 bytes total).
    #[inline]
    pub fn parse(c: &mut Cursor<'a>) -> ParseResult<Self> {
        let txid = Hash32(c.read_array::<32>()?);
        let vout = c.read_u32_le()?;
        Ok(Self { txid, vout })
    }

    /// `true` for a coinbase input (all-zero txid, vout = 0xffffffff).
    #[inline]
    pub fn is_coinbase(&self) -> bool {
        self.txid.as_bytes().iter().all(|&b| b == 0) && self.vout == 0xffff_ffff
    }
}

// ---------------------------------------------------------------------------
// TxInput
// ---------------------------------------------------------------------------

/// A transaction input, borrowing from the original buffer.
#[derive(Debug, Clone, Copy)]
pub struct TxInput<'a> {
    /// Previous output being spent.
    pub previous_output: OutPoint<'a>,
    /// Unlocking script (scriptSig). Empty for SegWit inputs.
    pub script_sig: Script<'a>,
    /// Sequence number.
    pub sequence: u32,
}

impl<'a> TxInput<'a> {
    /// Parse one input from the cursor.
    #[inline]
    pub fn parse(c: &mut Cursor<'a>) -> ParseResult<Self> {
        let previous_output = OutPoint::parse(c)?;
        let script_sig = Script::parse(c)?;
        let sequence = c.read_u32_le()?;
        Ok(Self {
            previous_output,
            script_sig,
            sequence,
        })
    }

    /// `true` if this is a coinbase input.
    #[inline]
    pub fn is_coinbase(&self) -> bool {
        self.previous_output.is_coinbase()
    }

    /// `true` if this input opts into Replace-By-Fee (BIP 125).
    #[inline]
    pub fn is_rbf(&self) -> bool {
        self.sequence <= 0xffff_fffd
    }
}

// ---------------------------------------------------------------------------
// TxOutput
// ---------------------------------------------------------------------------

/// A transaction output.
#[derive(Debug, Clone, Copy)]
pub struct TxOutput<'a> {
    /// Satoshi value (unsigned).
    pub value: u64,
    /// Locking script (scriptPubKey).
    pub script_pubkey: Script<'a>,
}

impl<'a> TxOutput<'a> {
    /// Parse one output from the cursor.
    #[inline]
    pub fn parse(c: &mut Cursor<'a>) -> ParseResult<Self> {
        let value = c.read_u64_le()?;
        let script_pubkey = Script::parse(c)?;
        Ok(Self {
            value,
            script_pubkey,
        })
    }
}

// ---------------------------------------------------------------------------
// Witness
// ---------------------------------------------------------------------------

/// SegWit witness data for a single input — a sequence of byte-string items.
///
/// Stores a zero-copy slice covering the entire witness field (item count
/// varint + all items), so items can be iterated on demand.
#[derive(Debug, Clone, Copy)]
pub struct Witness<'a> {
    /// Raw witness bytes starting at the item-count varint.
    pub raw: &'a [u8],
    /// Number of items decoded from the item-count varint.
    pub item_count: usize,
}

impl<'a> Witness<'a> {
    /// Parse one witness from `data` (which should start at the item-count varint).
    ///
    /// Returns the parsed [`Witness`] and the number of bytes consumed, so the
    /// caller can advance its cursor by exactly that amount.
    pub(crate) fn parse(data: &'a [u8]) -> ParseResult<(Self, usize)> {
        let mut c = Cursor::new(data);
        let item_count_u64 = c.read_varint()?;
        let item_count: usize =
            item_count_u64
                .try_into()
                .map_err(|_| ParseError::IntegerTooLarge {
                    value: item_count_u64,
                })?;
        if item_count > MAX_WITNESS_ITEMS {
            return Err(ParseError::OversizedData {
                size: item_count,
                max: MAX_WITNESS_ITEMS,
            });
        }
        for _ in 0..item_count {
            c.read_var_bytes(MAX_WITNESS_ITEM_SIZE)?;
        }
        let consumed = c.position();
        // SAFETY: `consumed` bytes were validated by the reads above,
        // so `data[..consumed]` is a valid sub-slice.
        let raw = unsafe { data.get_unchecked(..consumed) };
        Ok((Witness { raw, item_count }, consumed))
    }

    /// Iterate over items in this witness.
    pub fn items(&self) -> WitnessIter<'a> {
        // Skip the item_count varint at the start of `raw`.
        let mut skip_cursor = Cursor::new(self.raw);
        let _ = skip_cursor.read_varint(); // can't fail — we validated on parse
        WitnessIter {
            cursor: Cursor::new(&self.raw[skip_cursor.position()..]),
            remaining: self.item_count,
        }
    }
}

/// Iterator over witness items.
pub struct WitnessIter<'a> {
    cursor: Cursor<'a>,
    remaining: usize,
}

impl<'a> Iterator for WitnessIter<'a> {
    type Item = ParseResult<&'a [u8]>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        Some(self.cursor.read_var_bytes(MAX_WITNESS_ITEM_SIZE))
    }
}

// ---------------------------------------------------------------------------
// Transaction
// ---------------------------------------------------------------------------

/// A fully parsed Bitcoin transaction.
///
/// **Note:** This struct requires the caller to provide backing storage for the
/// `inputs`, `outputs`, and `witnesses` slices (e.g. stack arrays or arena
/// buffers). For allocation-free use, prefer [`TransactionParser`] with its
/// closure API.
///
/// All fields borrow from the original parse buffer — zero allocations in the
/// parser itself.
#[allow(dead_code)]
pub struct Transaction<'a> {
    /// Serialised version (1 or 2).
    pub version: i32,
    /// Whether this transaction uses the SegWit format (BIP 141).
    pub is_segwit: bool,
    /// Transaction inputs.
    pub inputs: &'a [TxInput<'a>],
    /// Transaction outputs.
    pub outputs: &'a [TxOutput<'a>],
    /// Witness data, one per input (empty slice for non-segwit).
    pub witnesses: &'a [Witness<'a>],
    /// Lock time.
    pub locktime: u32,
    /// Zero-copy reference to the raw bytes of this transaction.
    pub raw: &'a [u8],
}

impl core::fmt::Debug for Transaction<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Transaction")
            .field("version", &self.version)
            .field("is_segwit", &self.is_segwit)
            .field("input_count", &self.inputs.len())
            .field("output_count", &self.outputs.len())
            .field("locktime", &self.locktime)
            .field("raw_len", &self.raw.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Streaming parser (no alloc)
// ---------------------------------------------------------------------------

/// Streaming, callback-based transaction parser for `no_std` / zero-alloc use.
///
/// Instead of collecting inputs/outputs into a slice, this parser calls user-
/// supplied closures for each element, allowing the caller to decide how to
/// store or discard them.
///
/// ```rust
/// # use blockchain_zc_parser::transaction::TransactionParser;
/// # let raw = &[0u8; 0]; // placeholder
/// let mut parser = TransactionParser::new(raw);
/// // parser.parse_with(|input| { ... }, |output| { ... });
/// ```
pub struct TransactionParser<'a> {
    cursor: Cursor<'a>,
}

impl<'a> TransactionParser<'a> {
    /// Create a new parser positioned at the start of a raw transaction.
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            cursor: Cursor::new(data),
        }
    }

    /// How many bytes have been consumed so far.
    ///
    /// Call this after [`parse_with`](Self::parse_with) to advance an outer
    /// cursor by exactly the number of bytes this transaction occupied.
    #[inline]
    pub fn bytes_consumed(&self) -> usize {
        self.cursor.position()
    }

    /// Parse the transaction, calling `on_input` for each input and
    /// `on_output` for each output.
    ///
    /// Witness data is skipped unless you need it (saves work for indexers).
    ///
    /// Returns `(version, locktime, input_count, output_count)`.
    pub fn parse_with<FI, FO>(
        &mut self,
        mut on_input: FI,
        mut on_output: FO,
    ) -> ParseResult<(i32, u32, usize, usize)>
    where
        FI: FnMut(TxInput<'a>) -> ParseResult<()>,
        FO: FnMut(TxOutput<'a>) -> ParseResult<()>,
    {
        let c = &mut self.cursor;
        let version = c.read_i32_le()?;

        // Local helper for varint parsing from first byte
        #[inline]
        fn varint_from_first<'a>(c: &mut Cursor<'a>, first: u8) -> ParseResult<u64> {
            Ok(match first {
                0x00..=0xfc => first as u64,
                0xfd => c.read_u16_le()? as u64,
                0xfe => c.read_u32_le()? as u64,
                0xff => c.read_u64_le()?,
            })
        }

        // Detect SegWit marker and read input count
        let first_byte = c.read_u8()?;
        let is_segwit = if first_byte == 0x00 {
            // Potential SegWit marker. In legacy format this would mean 0 inputs,
            // which is invalid; we treat 0x00 0x01 as SegWit, otherwise error.
            let flag = c.read_u8()?;
            if flag != 0x01 {
                return Err(ParseError::InvalidSegwitFlag(flag));
            }
            true
        } else {
            false
        };

        let input_count_u64 = if is_segwit {
            c.read_varint()?
        } else {
            // `first_byte` is the first byte of the input-count varint.
            varint_from_first(c, first_byte)?
        };

        let input_count: usize =
            input_count_u64
                .try_into()
                .map_err(|_| ParseError::IntegerTooLarge {
                    value: input_count_u64,
                })?;

        if input_count == 0 {
            return Err(ParseError::InvalidInputCount);
        }

        if input_count > MAX_IO_COUNT {
            return Err(ParseError::OversizedData {
                size: input_count,
                max: MAX_IO_COUNT,
            });
        }

        for _ in 0..input_count {
            let input = TxInput::parse(c)?;
            on_input(input)?;
        }

        let output_count_u64 = c.read_varint()?;
        let output_count: usize =
            output_count_u64
                .try_into()
                .map_err(|_| ParseError::IntegerTooLarge {
                    value: output_count_u64,
                })?;
        if output_count > MAX_IO_COUNT {
            return Err(ParseError::OversizedData {
                size: output_count,
                max: MAX_IO_COUNT,
            });
        }

        for _ in 0..output_count {
            let output = TxOutput::parse(c)?;
            on_output(output)?;
        }

        // Parse (and discard) witness data, using Witness::parse so the logic
        // lives in one place.  Callers that need witness access can use the
        // returned Witness values by adding an `on_witness` callback in future.
        if is_segwit {
            for _ in 0..input_count {
                let (_, consumed) = Witness::parse(c.as_slice())?;
                c.skip(consumed)?;
            }
        }

        let locktime = c.read_u32_le()?;
        Ok((version, locktime, input_count, output_count))
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// Minimal valid non-segwit coinbase transaction.
    fn coinbase_tx_raw() -> Vec<u8> {
        let mut tx = Vec::new();
        // version
        tx.extend_from_slice(&1i32.to_le_bytes());
        // input count: 1
        tx.push(1);
        // outpoint: 32 zero bytes + 0xffffffff
        tx.extend_from_slice(&[0u8; 32]);
        tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        // scriptSig length (4 bytes) + arbitrary data
        tx.push(4);
        tx.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        // sequence
        tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        // output count: 1
        tx.push(1);
        // value: 50 BTC in satoshis
        tx.extend_from_slice(&(50u64 * 100_000_000).to_le_bytes());
        // scriptPubKey: empty (non-standard, ok for test)
        tx.push(0);
        // locktime
        tx.extend_from_slice(&0u32.to_le_bytes());
        tx
    }

    #[test]
    fn parse_coinbase_streaming() {
        let raw = coinbase_tx_raw();
        let mut parser = TransactionParser::new(&raw);
        let mut inputs = 0usize;
        let mut outputs = 0usize;
        let mut saw_coinbase = false;

        let (version, locktime, in_count, out_count) = parser
            .parse_with(
                |inp| {
                    inputs += 1;
                    if inp.is_coinbase() {
                        saw_coinbase = true;
                    }
                    Ok(())
                },
                |_out| {
                    outputs += 1;
                    Ok(())
                },
            )
            .unwrap();

        assert_eq!(version, 1);
        assert_eq!(locktime, 0);
        assert_eq!(in_count, 1);
        assert_eq!(out_count, 1);
        assert_eq!(inputs, 1);
        assert_eq!(outputs, 1);
        assert!(saw_coinbase);
    }

    #[test]
    fn outpoint_coinbase_detection() {
        let raw = [0u8; 36];
        let mut raw = raw.to_vec();
        raw[32..].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
        let mut c = Cursor::new(&raw);
        let op = OutPoint::parse(&mut c).unwrap();
        assert!(op.is_coinbase());
    }
}
