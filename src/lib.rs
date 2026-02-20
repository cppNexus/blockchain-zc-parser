//! # blockchain-zc-parser
//!
//! A **zero-copy**, allocation-free parser for Bitcoin blockchain binary data.
//!
//! ## Design goals
//!
//! | Goal | How |
//! |------|-----|
//! | **Zero-copy** | All parsed structures borrow `&'a [u8]` from the input — no `memcpy`. |
//! | **No alloc** | Compatible with `#![no_std]` — no heap allocations required. |
//! | **Streaming** | [`block::BlockTxIter`] and [`transaction::TransactionParser`] parse lazily via callbacks. |
//! | **Safe** | `unsafe` only for pointer-arithmetic inside [`cursor`] after bounds checks. |
//! | **Fast** | A single block header parse requires only ~10 integer reads from a contiguous buffer. |
//!
//! ## Supported formats
//!
//! - Bitcoin block headers (80 bytes)
//! - Legacy and SegWit (BIP 141) transactions
//! - Bitcoin script (`scriptPubKey` / `scriptSig`), including pattern matching for
//!   P2PKH, P2SH, P2WPKH, P2WSH, P2TR, P2PK, OP_RETURN
//! - Raw block files (`blkNNNNN.dat`) written by Bitcoin Core
//!
//! ## Quick start
//!
//! ```rust
//! use blockchain_zc_parser::{
//!     block::BlockHeader,
//!     cursor::Cursor,
//! };
//!
//! // Any &[u8] — memory-mapped file, network buffer, test fixture, …
//! let raw: &[u8] = &[0u8; 80]; // placeholder
//! let mut cursor = Cursor::new(raw);
//! // let header = BlockHeader::parse(&mut cursor)?;
//! ```
//!
//! ## Safety
//!
//! The crate contains a small amount of `unsafe` code inside [`cursor`].
//! Every `unsafe` block is immediately preceded by a comment explaining the
//! invariant that makes it sound.  The invariant is always a prior bounds-
//! check performed by safe Rust code.

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]
#![warn(clippy::undocumented_unsafe_blocks)]
#![deny(clippy::panic)]

pub mod block;
pub mod cursor;
pub mod error;
pub mod hash;
pub mod script;
pub mod transaction;

// Re-export the most commonly used types at the crate root.
pub use block::{BlkFileIter, BlockHeader, BlockTxIter};
pub use cursor::Cursor;
pub use error::{ParseError, ParseResult};
pub use hash::{Hash20, Hash32};
pub use script::{Instruction, Instructions, Script, ScriptType};
pub use transaction::{OutPoint, TransactionParser, TxInput, TxOutput};
