//! Bitcoin script parsing — zero-copy, no alloc.

use crate::{
    cursor::Cursor,
    error::{ParseError, ParseResult},
};

/// Maximum standard script size (Bitcoin Core limit).
pub const MAX_SCRIPT_SIZE: usize = 10_000;

/// A raw locking or unlocking script.
///
/// All bytes borrow from the original parse buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Script<'a> {
    /// The raw opcodes + push-data bytes.
    pub bytes: &'a [u8],
}

impl<'a> Script<'a> {
    /// Parse a length-prefixed script from `cursor`.
    #[inline]
    pub fn parse(cursor: &mut Cursor<'a>) -> ParseResult<Self> {
        let bytes = cursor.read_var_bytes(MAX_SCRIPT_SIZE)?;
        Ok(Self { bytes })
    }

    /// Classify the script into a well-known output type.
    #[inline]
    pub fn script_type(&self) -> ScriptType<'a> {
        ScriptType::classify(self.bytes)
    }

    /// Length of the script in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// `true` for an empty (OP_0 / bare) script.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Iterate over parsed opcodes / push-data in this script.
    pub fn instructions(&self) -> Instructions<'a> {
        Instructions {
            data: self.bytes,
            pos: 0,
            errored: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Script classification
// ---------------------------------------------------------------------------

/// Known standard output script types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptType<'a> {
    /// Pay-to-Public-Key-Hash: OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
    P2PKH {
        /// RIPEMD-160(SHA-256(pubkey)) hash embedded in the script.
        pubkey_hash: &'a [u8; 20],
    },
    /// Pay-to-Script-Hash: OP_HASH160 <20-byte hash> OP_EQUAL
    P2SH {
        /// RIPEMD-160(SHA-256(redeem_script)) hash embedded in the script.
        script_hash: &'a [u8; 20],
    },
    /// Pay-to-Witness-Public-Key-Hash: OP_0 <20-byte hash>
    P2WPKH {
        /// Witness program: RIPEMD-160(SHA-256(pubkey)).
        pubkey_hash: &'a [u8; 20],
    },
    /// Pay-to-Witness-Script-Hash: OP_0 <32-byte hash>
    P2WSH {
        /// Witness program: SHA-256(witness_script).
        script_hash: &'a [u8; 32],
    },
    /// Pay-to-Taproot: OP_1 <32-byte x-only pubkey>
    P2TR {
        /// Taproot output key (x-only, 32 bytes).
        x_only_pubkey: &'a [u8; 32],
    },
    /// Pay-to-Public-Key: <compressed/uncompressed pubkey> OP_CHECKSIG
    P2PK {
        /// Raw public key bytes (33 bytes compressed or 65 bytes uncompressed).
        pubkey: &'a [u8],
    },
    /// OP_RETURN / provably unspendable
    OpReturn {
        /// Arbitrary data payload following the OP_RETURN opcode.
        data: &'a [u8],
    },
    /// Multisig: OP_m <pubkeys…> OP_n OP_CHECKMULTISIG
    Multisig {
        /// Minimum number of signatures required to spend.
        required: u8,
        /// Total number of public keys listed.
        total: u8,
    },
    /// Anything else (non-standard / complex).
    Unknown,
}

impl<'a> ScriptType<'a> {
    fn classify(b: &'a [u8]) -> Self {
        match b {
            // P2PKH  25 bytes
            [0x76, 0xa9, 0x14, hash @ .., 0x88, 0xac] if hash.len() == 20 => ScriptType::P2PKH {
                pubkey_hash: hash.try_into().unwrap(),
            },
            // P2SH  23 bytes
            [0xa9, 0x14, hash @ .., 0x87] if hash.len() == 20 => ScriptType::P2SH {
                script_hash: hash.try_into().unwrap(),
            },
            // P2WPKH  22 bytes
            [0x00, 0x14, hash @ ..] if hash.len() == 20 => ScriptType::P2WPKH {
                pubkey_hash: hash.try_into().unwrap(),
            },
            // P2WSH  34 bytes
            [0x00, 0x20, hash @ ..] if hash.len() == 32 => ScriptType::P2WSH {
                script_hash: hash.try_into().unwrap(),
            },
            // P2TR  34 bytes  (OP_1 = 0x51, push 32 = 0x20)
            [0x51, 0x20, pk @ ..] if pk.len() == 32 => ScriptType::P2TR {
                x_only_pubkey: pk.try_into().unwrap(),
            },
            // P2PK compressed  35 bytes
            [0x21, pk @ .., 0xac] if pk.len() == 33 => ScriptType::P2PK { pubkey: pk },
            // P2PK uncompressed  67 bytes
            [0x41, pk @ .., 0xac] if pk.len() == 65 => ScriptType::P2PK { pubkey: pk },
            // OP_RETURN
            [0x6a, rest @ ..] => ScriptType::OpReturn { data: rest },
            _ => ScriptType::Unknown,
        }
    }
}

// ---------------------------------------------------------------------------
// Instruction iterator
// ---------------------------------------------------------------------------

/// A single decoded script instruction.
///
/// This type is `Copy` — parse errors are surfaced as `Err(ParseError)` in
/// the [`Instructions`] iterator rather than being embedded in the enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Instruction<'a> {
    /// A push-data instruction with the pushed bytes (may be empty for OP_0).
    PushBytes(&'a [u8]),
    /// A non-data opcode.
    Op(u8),
}

/// Iterator over instructions in a [`Script`].
///
/// Yields `Ok(Instruction)` for each valid opcode/push-data and
/// `Err(ParseError)` on the first malformed byte, after which it stops.
pub struct Instructions<'a> {
    data: &'a [u8],
    pos: usize,
    /// Becomes `true` after the first error so the iterator stops cleanly.
    errored: bool,
}

impl<'a> Iterator for Instructions<'a> {
    type Item = ParseResult<Instruction<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.errored || self.pos >= self.data.len() {
            return None;
        }

        let op = self.data[self.pos];
        self.pos += 1;

        // Resolve the number of push-data bytes that follow, or None for a
        // plain opcode.  Returns Err if the length prefix itself is truncated.
        let push_len: Option<Result<usize, ParseError>> = match op {
            0x00 => Some(Ok(0)),
            n @ 0x01..=0x4b => Some(Ok(n as usize)),
            0x4c => {
                // OP_PUSHDATA1: 1-byte length
                let avail = self.data.len() - self.pos;
                if avail < 1 {
                    Some(Err(ParseError::UnexpectedEof {
                        needed: 1,
                        available: avail,
                    }))
                } else {
                    let n = self.data[self.pos] as usize;
                    self.pos += 1;
                    Some(Ok(n))
                }
            }
            0x4d => {
                // OP_PUSHDATA2: 2-byte LE length
                let avail = self.data.len() - self.pos;
                if avail < 2 {
                    Some(Err(ParseError::UnexpectedEof {
                        needed: 2,
                        available: avail,
                    }))
                } else {
                    let n =
                        u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]) as usize;
                    self.pos += 2;
                    Some(Ok(n))
                }
            }
            0x4e => {
                // OP_PUSHDATA4: 4-byte LE length
                let avail = self.data.len() - self.pos;
                if avail < 4 {
                    Some(Err(ParseError::UnexpectedEof {
                        needed: 4,
                        available: avail,
                    }))
                } else {
                    let n = u32::from_le_bytes([
                        self.data[self.pos],
                        self.data[self.pos + 1],
                        self.data[self.pos + 2],
                        self.data[self.pos + 3],
                    ]) as usize;
                    self.pos += 4;
                    Some(Ok(n))
                }
            }
            _ => None, // plain non-push opcode
        };

        match push_len {
            None => Some(Ok(Instruction::Op(op))),
            Some(Err(e)) => {
                self.errored = true;
                Some(Err(e))
            }
            Some(Ok(n)) => {
                let avail = self.data.len() - self.pos;
                if n > avail {
                    self.errored = true;
                    Some(Err(ParseError::UnexpectedEof {
                        needed: n,
                        available: avail,
                    }))
                } else {
                    let bytes = &self.data[self.pos..self.pos + n];
                    self.pos += n;
                    Some(Ok(Instruction::PushBytes(bytes)))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::cursor::Cursor;
    use std::vec::Vec;

    #[test]
    fn p2pkh_classification() {
        // 25-byte P2PKH script
        let script_bytes: &[u8] = &[
            0x76, 0xa9, 0x14, 0x89, 0xab, 0xcd, 0xef, 0xab, 0xba, 0xab, 0xba, 0xab, 0xba, 0xab,
            0xba, 0xab, 0xba, 0xab, 0xba, 0xab, 0xba, 0xab, 0xba, 0x88, 0xac,
        ];
        let mut raw = Vec::new();
        // varint length prefix
        raw.push(script_bytes.len() as u8);
        raw.extend_from_slice(script_bytes);

        let mut cursor = Cursor::new(&raw);
        let script = Script::parse(&mut cursor).unwrap();
        assert!(matches!(script.script_type(), ScriptType::P2PKH { .. }));
    }

    #[test]
    fn op_return_classification() {
        let script_bytes: &[u8] = &[0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef];
        let mut raw = Vec::new();
        raw.push(script_bytes.len() as u8);
        raw.extend_from_slice(script_bytes);
        let mut cursor = Cursor::new(&raw);
        let script = Script::parse(&mut cursor).unwrap();
        assert!(matches!(script.script_type(), ScriptType::OpReturn { .. }));
    }
}
