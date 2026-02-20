# blockchain-zc-parser

[![Crates.io](https://img.shields.io/crates/v/blockchain-zc-parser.svg)](https://crates.io/crates/blockchain-zc-parser)
[![Docs.rs](https://docs.rs/blockchain-zc-parser/badge.svg)](https://docs.rs/blockchain-zc-parser)
[![Apache-2.0](https://img.shields.io/badge/license-20Apache--2.0-blue.svg)](#license)

A **zero-copy**, allocation-free parser for Bitcoin blockchain binary data written in Rust.

---
https://github.com/cppNexus/blockchain-zc-parser.git
## Features

| | |
|---|---|
| **Zero-copy** | All parsed structures borrow `&'a [u8]` directly from the input — no `memcpy`, no `String`, no `Vec`. |
| **No alloc** | Compatible with `#![no_std]` targets. Use in embedded devices, WASM, kernel modules. |
| **Streaming** | `BlockTxIter` and `TransactionParser` process transactions lazily via closures — never load an entire block into structured memory. |
| **Fast** | Parsing an 80-byte block header requires only ~10 integer reads from a contiguous buffer. Block file iteration is a tight loop over magic bytes and size fields. |
| **Safe** | `unsafe` is used only inside `cursor.rs` for pointer arithmetic **after** explicit bounds checks. Every `unsafe` block is annotated. |

## Supported formats

- **Block headers** (80 bytes, Bitcoin protocol)
- **Legacy and SegWit** (BIP 141) **transactions**
- **Bitcoin script** pattern matching:
  - `P2PKH`, `P2SH`, `P2WPKH`, `P2WSH`, `P2TR`, `P2PK`, `OP_RETURN`, bare multisig
- **`blkNNNNN.dat`** raw block files written by Bitcoin Core

---

## Quick start

```toml
[dependencies]
blockchain-zc-parser = "0.1"
```

### Parse a block header

```rust
use blockchain_zc_parser::{Cursor, BlockHeader};

fn parse(raw_80_bytes: &[u8]) -> blockchain_zc_parser::ParseResult<()> {
    let mut cursor = Cursor::new(raw_80_bytes);
    let header = BlockHeader::parse(&mut cursor)?;

    println!("version   = {}", header.version);
    println!("timestamp = {}", header.timestamp);
    println!("nonce     = {:#010x}", header.nonce);
    println!("prev_hash = {}", header.prev_block);   // Display impl, no alloc

    // header.prev_block is a &[u8;32] pointing into raw_80_bytes — no copy.
    Ok(())
}
```

## Example: parse a raw block file

Download a raw block (example: Bitcoin genesis block):

```sh
curl -L \
"https://mempool.space/api/block/000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f/raw" \
-o genesis.bin
```

Run the example parser:

```sh
cargo run --example parse_block -- genesis.bin
```

Summary-only mode (no per-transaction printing):

```sh
cargo run --example parse_block -- --summary genesis.bin
```

Limit printed transactions:

```sh
cargo run --example parse_block -- --limit-tx 5 genesis.bin
```

Print a specific transaction index:

```sh
cargo run --example parse_block -- --tx 100 genesis.bin
```


## Raw block vs `blkNNNNN.dat`

There are **two different binary formats** you may encounter:

### 1️⃣ Raw block (`.bin`, RPC, mempool API)

This is the pure Bitcoin block payload:

```
[80-byte header]
[varint tx_count]
[transactions...]
```

It contains **no magic bytes and no size prefix**.

You typically obtain it via:

```sh
curl -L \
"https://mempool.space/api/block/<blockhash>/raw" \
-o block.bin
```

This format can be parsed directly with:

```rust
let (header, iter) = BlockTxIter::new(raw_block_bytes)?;
```

---

### 2️⃣ Bitcoin Core `blkNNNNN.dat`

Files in your local Bitcoin Core data directory:

```
~/.bitcoin/blocks/blk00000.dat
```

Each file contains **multiple blocks**, each prefixed by:

```
[4-byte magic][4-byte little-endian size][raw block]
```

To parse these files, use `BlkFileIter`:

```rust
use blockchain_zc_parser::block::{BlkFileIter, MAINNET_MAGIC};

let mut it = BlkFileIter::new(file_bytes, MAINNET_MAGIC);
while let Some(raw_block) = it.next_block()? {
    let (_header, mut tx_iter) = BlockTxIter::new(raw_block)?;
    // process block...
}
```

---

### 🔍 Important

If you pass a `blkNNNNN.dat` file directly to `BlockTxIter::new`, parsing will fail
because the file contains magic bytes and size prefixes.

The `parse_block` example automatically detects and unwraps the first block
from a `blkNNNNN.dat` file if necessary.

---

## Why zero-copy matters

Bitcoin blocks can exceed 1–2 MB and may contain thousands of transactions.

A traditional parser typically:

- Allocates `Vec`s for inputs and outputs
- Copies script bytes into owned buffers
- Builds full in-memory representations

`blockchain-zc-parser` avoids all of this.

Every parsed structure borrows directly from the original `&[u8]` buffer.
No heap allocations. No memcpy. No string building.

This has several practical consequences:

- High throughput (hundreds of MB/s on modern CPUs)
- Very low memory usage
- Suitable for streaming, indexers, and embedded environments
- Works naturally with memory-mapped files (`mmap`)

For indexers and blockchain analytics pipelines, this allows processing
entire block files with near-linear memory access patterns.

---

### Stream transactions from a block

```rust
use blockchain_zc_parser::{BlockTxIter, script::ScriptType};

fn scan_block(raw_block: &[u8]) -> blockchain_zc_parser::ParseResult<u64> {
    let (_header, mut iter) = BlockTxIter::new(raw_block)?;
    let mut total_satoshis: u64 = 0;

    while iter.next_tx(
        |_input| Ok(()),              // called for every TxInput
        |output| {                    // called for every TxOutput
            total_satoshis += output.value as u64;
            if let ScriptType::P2WPKH { pubkey_hash } = output.script_pubkey.script_type() {
                // pubkey_hash: &[u8; 20] — zero-copy pointer into raw_block
                println!("  P2WPKH output to {:?}", pubkey_hash);
            }
            Ok(())
        },
    )? {}

    Ok(total_satoshis)
}
```

### Iterate over a Bitcoin Core `blkNNNNN.dat` file

```rust
use blockchain_zc_parser::block::{BlkFileIter, MAINNET_MAGIC};

fn count_blocks(file_bytes: &[u8]) -> usize {
    let mut iter = BlkFileIter::new(file_bytes, MAINNET_MAGIC);
    let mut count = 0;
    while let Ok(Some(_raw_block)) = iter.next_block() {
        count += 1;
    }
    count
}
```

---

## Architecture

```
src/
├── lib.rs          — crate root, re-exports
├── cursor.rs       — zero-copy Cursor<'a> over &[u8]  ← start here
├── error.rs        — ParseError enum, no_std compatible
├── hash.rs         — Hash32<'a> / Hash20<'a> wrappers
├── script.rs       — Script<'a>, ScriptType, instruction iterator
├── transaction.rs  — TxInput, TxOutput, OutPoint, TransactionParser
└── block.rs        — BlockHeader, BlockTxIter, BlkFileIter
```

The [`Cursor`](src/cursor.rs) type is the single entry point for all parsing.
It advances a `usize` offset into a `&'a [u8]` and returns sub-slices with
lifetime `'a` — identical to the original input.  No unsafe code exists outside
this file.

---

## Benchmarks

Run on an Apple M2 Pro (single-core, Rust 1.88, `--release`):

| Benchmark | Throughput |
|---|---|
| `block_header/parse_80_bytes` | **~1.1 GB/s** |
| `transaction/parse/coinbase` | ~860 MB/s |
| `transaction/parse/p2pkh_2out` | ~740 MB/s |
| `block/streaming_iter/tx_count=1000` | ~695 MB/s |

Run yourself:

```sh
cargo bench
# HTML report: target/criterion/report/index.html
```

---

## `no_std` usage

Disable the default feature set (which enables `std`):

```toml
[dependencies]
blockchain-zc-parser = { version = "0.1", default-features = false }
```

With `default-features = false`:
- All `std::error::Error` impls are removed.
- `BlockHeader::block_hash()` (requires SHA-256) is removed — call `sha2::Sha256` directly on `header.raw`.
- Everything else works identically.

---

## Minimum supported Rust version (MSRV)

**Rust 1.74+** (edition 2021). The crate uses only stable Rust features.

---

## Safety

The only `unsafe` code lives in [`src/cursor.rs`](src/cursor.rs):

```rust
// SAFETY: `end` was checked to be ≤ data.len() on the line above.
let slice = unsafe { self.data.get_unchecked(self.pos..end) };
```

All other code is safe Rust.  The crate passes `cargo miri test` (run it yourself with `cargo +nightly miri test`).

---

## Contributing

Pull requests are welcome. Please:

1. Run:

```
   cargo test
   cargo clippy --all-targets -- -D warnings
```
2. Add a unit test for any new parsing logic.
3. Keep `unsafe` blocks minimal and documented.

---

## License

Licensed under either of:

- **Apache-2.0** ([LICENSE-APACHE](LICENSE-APACHE))

at your option.

---