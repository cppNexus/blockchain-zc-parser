//! Example: parse a raw Bitcoin block and print a summary.
//!
//! Usage:
//!   cargo run --example parse_block
//!   cargo run --example parse_block -- <path>
//!
//! Flags:
//!   --summary           Only print header + stats + total output value
//!   --limit-tx N        Print only first N transactions (default: all)
//!   --tx IDX            Print only a specific transaction by index
//!   --no-outputs        Don't print per-output lines
//!   --no-opreturn       Suppress OP_RETURN outputs (still counted in totals)
//!   -h, --help          Show this help

use blockchain_zc_parser::{
    block::{BlkFileIter, BlockTxIter, MAINNET_MAGIC, SIGNET_MAGIC, TESTNET_MAGIC},
    error::{ParseError, ParseResult},
    script::ScriptType,
};

const USAGE: &str = "Usage:\n  cargo run --example parse_block\n  cargo run --example parse_block -- <path>\n\nFlags:\n  --summary           Only print header + stats + total output value\n  --limit-tx N        Print only first N transactions (default: all)\n  --tx IDX            Print only a specific transaction by index\n  --no-outputs        Don't print per-output lines\n  --no-opreturn       Suppress OP_RETURN outputs (still counted in totals)\n  -h, --help          Show this help\n\nExamples:\n  cargo run --example parse_block -- --summary genesis.bin\n  cargo run --example parse_block -- --limit-tx 3 tip.bin\n";

#[derive(Debug, Clone, Copy, Default)]
struct Opts {
    summary: bool,
    limit_tx: Option<usize>,
    only_tx: Option<usize>,
    no_outputs: bool,
    no_opreturn: bool,
    help: bool,
}

fn parse_opts(args: &[String]) -> Result<(Opts, Option<String>), String> {
    let mut opts = Opts::default();
    let mut path: Option<String> = None;

    let mut i = 0usize;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "--summary" => {
                opts.summary = true;
                i += 1;
            }
            "--no-outputs" => {
                opts.no_outputs = true;
                i += 1;
            }
            "--no-opreturn" => {
                opts.no_opreturn = true;
                i += 1;
            }
            "--limit-tx" => {
                let n = args.get(i + 1).and_then(|s| s.parse::<usize>().ok());
                if let Some(n) = n {
                    opts.limit_tx = Some(n);
                    i += 2;
                } else {
                    return Err("expected number after --limit-tx".to_string());
                }
            }
            "--tx" => {
                let n = args.get(i + 1).and_then(|s| s.parse::<usize>().ok());
                if let Some(n) = n {
                    opts.only_tx = Some(n);
                    i += 2;
                } else {
                    return Err("expected number after --tx".to_string());
                }
            }
            "--help" | "-h" => {
                opts.help = true;
                return Ok((opts, path));
            }
            _ => {
                if a.starts_with("--") {
                    return Err(format!("unknown flag: {a}"));
                }
                if path.is_none() {
                    path = Some(a.clone());
                }
                i += 1;
            }
        }
    }

    Ok((opts, path))
}

fn main() -> ParseResult<()> {
    let argv: Vec<String> = std::env::args().collect();
    let (opts, path_arg) = match parse_opts(&argv[1..]) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("error: {msg}\n\n{USAGE}");
            return Ok(());
        }
    };

    if opts.help {
        eprintln!("{USAGE}");
        return Ok(());
    }

    let block_bytes: Vec<u8> = if let Some(path) = path_arg.as_deref() {
        let bytes = std::fs::read(path)?;
        if let Ok(Some(first)) = try_first_dat_entry(&bytes) {
            first.to_vec()
        } else {
            bytes
        }
    } else {
        build_synthetic_block()
    };

    let (header, mut iter) = BlockTxIter::new(&block_bytes)?;

    println!("=== Block Summary ===");
    println!("Version   : {}", header.version);
    println!("Timestamp : {}", header.timestamp);
    println!("Nonce     : {:#010x}", header.nonce);
    println!("Tx count  : {}", iter.total());
    println!();

    let mut tx_idx: usize = 0;
    let mut coinbase_txs: usize = 0;
    let mut saw_first_input_in_tx: bool = false;

    let mut total_value: u64 = 0;

    let should_print_tx = |idx: usize| -> bool {
        if opts.summary {
            return false;
        }
        if let Some(only) = opts.only_tx {
            return idx == only;
        }
        if let Some(limit) = opts.limit_tx {
            return idx < limit;
        }
        true
    };

    let should_print_outputs_for_tx = |idx: usize| -> bool {
        if opts.no_outputs {
            return false;
        }
        should_print_tx(idx)
    };

    while iter.next_tx(
        |input| {
            if !saw_first_input_in_tx {
                saw_first_input_in_tx = true;
                if input.is_coinbase() {
                    coinbase_txs += 1;
                    if should_print_tx(tx_idx) {
                        println!("  [tx {tx_idx}] coinbase");
                    }
                } else if should_print_tx(tx_idx) {
                    println!("  [tx {tx_idx}] normal");
                }
            }
            Ok(())
        },
        |output| {
            total_value = total_value.saturating_add(output.value);

            // Fast-path: in summary mode (or when outputs are disabled), don't classify scripts.
            if opts.summary || opts.no_outputs {
                return Ok(());
            }

            let kind = match output.script_pubkey.script_type() {
                ScriptType::P2PKH { .. } => "P2PKH",
                ScriptType::P2SH { .. } => "P2SH",
                ScriptType::P2WPKH { .. } => "P2WPKH",
                ScriptType::P2WSH { .. } => "P2WSH",
                ScriptType::P2TR { .. } => "P2TR",
                ScriptType::P2PK { .. } => "P2PK",
                ScriptType::OpReturn { .. } => "OP_RETURN",
                ScriptType::Multisig { required, total } => {
                    if should_print_outputs_for_tx(tx_idx) {
                        println!(
                            "    output {} sat  script-type=MULTISIG ({}-of-{})  script-len={}",
                            output.value,
                            required,
                            total,
                            output.script_pubkey.len()
                        );
                    }
                    return Ok(());
                }
                ScriptType::Unknown => "unknown",
            };

            if opts.no_opreturn && kind == "OP_RETURN" {
                return Ok(());
            }

            if !should_print_outputs_for_tx(tx_idx) {
                return Ok(());
            }

            println!(
                "    output {} sat  script-type={}  script-len={}",
                output.value,
                kind,
                output.script_pubkey.len()
            );
            Ok(())
        },
    )? {
        tx_idx += 1;
        saw_first_input_in_tx = false;
    }

    if let Some(only) = opts.only_tx {
        if only >= tx_idx {
            eprintln!("requested --tx {only}, but block has only {tx_idx} transactions");
        }
    }

    println!("\n--- Parse Stats ---");
    println!("Declared tx count : {}", iter.total());
    println!("Parsed tx count   : {tx_idx}");
    println!("Block size (bytes): {}", block_bytes.len());

    println!(
        "Before strict-check : tx_idx={} / total={}  bytes_consumed={}  bytes_remaining={}",
        tx_idx,
        iter.total(),
        iter.bytes_consumed(),
        iter.bytes_remaining()
    );

    iter.finish_strict()?;

    println!(
        "After strict-check  : bytes_consumed={}  bytes_remaining={}",
        iter.bytes_consumed(),
        iter.bytes_remaining()
    );

    if coinbase_txs != 1 {
        return Err(ParseError::InvalidCoinbaseCount {
            count: coinbase_txs,
        });
    }

    if opts.summary {
        println!("Coinbase txs      : {coinbase_txs}");
        println!("Total txs parsed  : {tx_idx}");
    }

    println!();
    println!(
        "Total output value : {} sat ({:.8} BTC)",
        total_value,
        total_value as f64 / 1e8
    );

    Ok(())
}

fn try_first_dat_entry(bytes: &[u8]) -> ParseResult<Option<&[u8]>> {
    for magic in [MAINNET_MAGIC, TESTNET_MAGIC, SIGNET_MAGIC] {
        let mut it = BlkFileIter::new(bytes, magic);
        if let Some(first) = it.next_block()? {
            return Ok(Some(first));
        }
    }
    Ok(None)
}

fn build_synthetic_block() -> Vec<u8> {
    let header = hex_literal::hex!(
        "01000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
        "29ab5f49"
        "ffff001d"
        "1dac2b7c"
    );

    let tx = coinbase_tx();

    let mut block = Vec::with_capacity(80 + 9 + tx.len());
    block.extend_from_slice(&header);
    block.extend_from_slice(&encode_varint(1));
    block.extend_from_slice(&tx);
    block
}

fn encode_varint(v: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(9);
    match v {
        0..=0xfc => out.push(v as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(v as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(v as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&v.to_le_bytes());
        }
    }
    out
}

fn coinbase_tx() -> Vec<u8> {
    let mut tx = Vec::new();
    tx.extend_from_slice(&1i32.to_le_bytes());

    tx.push(1);

    tx.extend_from_slice(&[0u8; 32]);
    tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes());

    tx.push(4);
    tx.extend_from_slice(&[0x03, 0x4b, 0x6e, 0x0b]);

    tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes());

    tx.push(1);

    tx.extend_from_slice(&(625_000_000u64).to_le_bytes());

    tx.push(22);
    tx.extend_from_slice(&[
        0x00, 0x14, 0x89, 0xab, 0xcd, 0xef, 0xab, 0xba, 0xab, 0xba, 0xab, 0xba, 0xab, 0xba, 0xab,
        0xba, 0xab, 0xba, 0xab, 0xba, 0xab, 0xba,
    ]);

    tx.extend_from_slice(&0u32.to_le_bytes());
    tx
}
