//! Parse error types.

#[cfg(feature = "std")]
extern crate std;

/// All errors that can occur during parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// Input ended before the structure was complete.
    UnexpectedEof {
        /// How many bytes were needed.
        needed: usize,
        /// How many were available.
        available: usize,
    },
    /// A variable-length integer had an invalid encoding.
    InvalidVarInt,
    /// A length/value was valid as a u64 but does not fit into the platform usize.
    IntegerTooLarge {
        /// The original integer value that could not fit into `usize`.
        value: u64,
    },
    /// A script or data field exceeded the allowed maximum size.
    OversizedData {
        /// Actual size that was encountered.
        size: usize,
        /// Maximum size allowed by the parser.
        max: usize,
    },
    /// The block / transaction version is not supported by this parser.
    UnsupportedVersion(i32),
    /// The magic bytes at the start of a raw block did not match.
    MagicMismatch {
        /// The magic bytes this parser was configured to expect.
        expected: [u8; 4],
        /// The magic bytes that were actually found in the input.
        got: [u8; 4],
    },
    /// Segwit marker / flag bytes are invalid.
    InvalidSegwitFlag(
        /// The invalid flag byte.
        u8,
    ),
    /// Transaction input count was invalid (e.g., zero in legacy format).
    InvalidInputCount,
    /// Extra bytes remained after parsing a structure in strict mode.
    TrailingBytes {
        /// Number of bytes left unread.
        remaining: usize,
    },
    /// Not all transactions declared in the block were parsed.
    IncompleteTransactions {
        /// Number of transactions declared in the block header.
        expected: usize,
        /// Number of transactions that were actually parsed.
        parsed: usize,
    },
    /// Coinbase transaction had a non-empty `txid` reference (must be all-zero).
    InvalidCoinbase,
    /// A block contained an unexpected number of coinbase transactions.
    InvalidCoinbaseCount {
        /// Number of coinbase transactions observed while parsing.
        count: usize,
    },
    /// An underlying I/O error occurred (only available with the `std` feature).
    #[cfg(feature = "std")]
    Io {
        /// Human-readable I/O error message.
        message: std::string::String,
    },
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ParseError::UnexpectedEof { needed, available } => write!(
                f,
                "unexpected end of input: needed {needed} bytes but only {available} available"
            ),
            ParseError::InvalidVarInt => write!(f, "invalid variable-length integer encoding"),
            ParseError::IntegerTooLarge { value } => {
                write!(f, "integer too large to fit into usize: {value}")
            }
            ParseError::OversizedData { size, max } => {
                write!(f, "data size {size} exceeds maximum allowed {max}")
            }
            ParseError::UnsupportedVersion(v) => {
                write!(f, "unsupported version: {v}")
            }
            ParseError::MagicMismatch { expected, got } => {
                write!(f, "magic mismatch: expected {expected:02x?} got {got:02x?}")
            }
            ParseError::InvalidSegwitFlag(b) => {
                write!(f, "invalid segwit flag byte: {b:#x}")
            }
            ParseError::InvalidInputCount => {
                write!(f, "invalid transaction input count")
            }
            ParseError::TrailingBytes { remaining } => {
                write!(f, "trailing bytes after parse: {remaining}")
            }
            ParseError::IncompleteTransactions { expected, parsed } => {
                write!(
                    f,
                    "incomplete transaction parsing: expected {expected}, parsed {parsed}"
                )
            }
            ParseError::InvalidCoinbase => {
                write!(f, "coinbase txid reference must be all-zero bytes")
            }
            ParseError::InvalidCoinbaseCount { count } => {
                write!(f, "invalid coinbase tx count in block: {count}")
            }
            #[cfg(feature = "std")]
            ParseError::Io { message } => {
                write!(f, "io error: {message}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {}

/// Convenience alias.
pub type ParseResult<T> = Result<T, ParseError>;

#[cfg(feature = "std")]
impl From<std::io::Error> for ParseError {
    fn from(e: std::io::Error) -> Self {
        ParseError::Io {
            message: e.to_string(),
        }
    }
}
