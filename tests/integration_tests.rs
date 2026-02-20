use blockchain_zc_parser::{
    block::{BlkFileIter, BlockHeader, BlockTxIter, MAINNET_MAGIC},
    cursor::Cursor,
    error::ParseError,
    script::ScriptType,
    transaction::{OutPoint, TransactionParser},
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn genesis_header() -> [u8; 80] {
    hex_literal::hex!(
        "01000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
        "29ab5f49"
        "ffff001d"
        "1dac2b7c"
    )
}

fn build_block_message(block_body: &[u8], magic: [u8; 4]) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&magic);
    msg.extend_from_slice(&(block_body.len() as u32).to_le_bytes());
    msg.extend_from_slice(block_body);
    msg
}

fn minimal_block(tx_count: u8) -> Vec<u8> {
    let header = genesis_header();
    let coinbase = build_coinbase_bytes();
    let mut block = Vec::new();
    block.extend_from_slice(&header);
    block.push(tx_count);
    for _ in 0..tx_count {
        block.extend_from_slice(&coinbase);
    }
    block
}

fn build_coinbase_bytes() -> Vec<u8> {
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

// ---------------------------------------------------------------------------
// Block header tests
// ---------------------------------------------------------------------------

#[test]
fn genesis_header_fields() {
    let raw = genesis_header();
    let mut c = Cursor::new(&raw);
    let h = BlockHeader::parse(&mut c).unwrap();

    assert_eq!(h.version, 1);
    assert_eq!(h.timestamp, 0x495f_ab29); // 1231006505
    assert_eq!(h.nonce, 0x7c2b_ac1d);
    assert!(h.prev_block.as_bytes().iter().all(|&b| b == 0));
}

#[test]
fn genesis_header_zero_copy_pointers() {
    let raw = genesis_header();
    let base = raw.as_ptr();
    let mut c = Cursor::new(&raw);
    let h = BlockHeader::parse(&mut c).unwrap();

    // version is at byte 0..4, prev_block starts at byte 4
    assert_eq!(h.prev_block.as_bytes().as_ptr(), unsafe { base.add(4) });
    // merkle_root starts at byte 36
    assert_eq!(h.merkle_root.as_bytes().as_ptr(), unsafe { base.add(36) });
}

#[test]
fn header_eof_error() {
    let raw = [0u8; 79]; // one byte short
    let mut c = Cursor::new(&raw);
    let err = BlockHeader::parse(&mut c).unwrap_err();
    assert!(matches!(
        err,
        ParseError::UnexpectedEof {
            needed: 80,
            available: 79
        }
    ));
}

// ---------------------------------------------------------------------------
// Block iteration tests
// ---------------------------------------------------------------------------

#[test]
fn block_tx_iter_coinbase_only() {
    let block = minimal_block(1);
    let (_header, mut iter) = BlockTxIter::new(&block).unwrap();
    assert_eq!(iter.total(), 1);

    let mut input_count = 0usize;
    let mut output_count = 0usize;
    let found = iter
        .next_tx(
            |_| {
                input_count += 1;
                Ok(())
            },
            |_| {
                output_count += 1;
                Ok(())
            },
        )
        .unwrap();

    assert!(found);
    assert_eq!(input_count, 1);
    assert_eq!(output_count, 1);
    assert!(iter.next_tx(|_| Ok(()), |_| Ok(())).unwrap() == false);
}

#[test]
fn block_tx_iter_multiple() {
    let block = minimal_block(5);
    let (_header, mut iter) = BlockTxIter::new(&block).unwrap();
    assert_eq!(iter.total(), 5);

    let mut count = 0;
    while iter.next_tx(|_| Ok(()), |_| Ok(())).unwrap() {
        count += 1;
    }
    assert_eq!(count, 5);
    assert_eq!(iter.consumed(), 5);
}

// ---------------------------------------------------------------------------
// BlkFileIter tests
// ---------------------------------------------------------------------------

#[test]
fn blk_file_iter_single_block() {
    let block = minimal_block(1);
    let file = build_block_message(&block, MAINNET_MAGIC);

    let mut iter = BlkFileIter::new(&file, MAINNET_MAGIC);
    let raw = iter.next_block().unwrap().expect("expected one block");
    assert_eq!(raw, block.as_slice());
    assert!(iter.next_block().unwrap().is_none());
}

#[test]
fn blk_file_iter_magic_mismatch() {
    let block = minimal_block(1);
    let file = build_block_message(&block, [0x00, 0x01, 0x02, 0x03]);

    let mut iter = BlkFileIter::new(&file, MAINNET_MAGIC);
    assert!(matches!(
        iter.next_block().unwrap_err(),
        ParseError::MagicMismatch { .. }
    ));
}

#[test]
fn blk_file_iter_multiple_blocks() {
    let b1 = minimal_block(1);
    let b2 = minimal_block(2);
    let mut file = build_block_message(&b1, MAINNET_MAGIC);
    file.extend_from_slice(&build_block_message(&b2, MAINNET_MAGIC));

    let mut iter = BlkFileIter::new(&file, MAINNET_MAGIC);
    assert_eq!(iter.next_block().unwrap().unwrap(), b1.as_slice());
    assert_eq!(iter.next_block().unwrap().unwrap(), b2.as_slice());
    assert!(iter.next_block().unwrap().is_none());
}

// ---------------------------------------------------------------------------
// Script classification tests
// ---------------------------------------------------------------------------

#[test]
fn classify_p2wpkh() {
    let script_bytes: &[u8] = &[
        0x00, 0x14, 0x89, 0xab, 0xcd, 0xef, 0xab, 0xba, 0xab, 0xba, 0xab, 0xba, 0xab, 0xba, 0xab,
        0xba, 0xab, 0xba, 0xab, 0xba, 0xab, 0xba,
    ];
    let mut raw = vec![script_bytes.len() as u8];
    raw.extend_from_slice(script_bytes);
    let mut c = Cursor::new(&raw);
    let script = blockchain_zc_parser::Script::parse(&mut c).unwrap();
    assert!(matches!(script.script_type(), ScriptType::P2WPKH { .. }));
}

#[test]
fn classify_p2tr() {
    let mut script_bytes = vec![0x51u8, 0x20]; // OP_1 push32
    script_bytes.extend_from_slice(&[0xab; 32]);
    let mut raw = vec![script_bytes.len() as u8];
    raw.extend_from_slice(&script_bytes);
    let mut c = Cursor::new(&raw);
    let script = blockchain_zc_parser::Script::parse(&mut c).unwrap();
    assert!(matches!(script.script_type(), ScriptType::P2TR { .. }));
}

// ---------------------------------------------------------------------------
// OutPoint tests
// ---------------------------------------------------------------------------

#[test]
fn outpoint_not_coinbase() {
    let mut raw = [0xabu8; 36];
    raw[32..].copy_from_slice(&0u32.to_le_bytes());
    let mut c = Cursor::new(&raw);
    let op = OutPoint::parse(&mut c).unwrap();
    assert!(!op.is_coinbase());
}

// ---------------------------------------------------------------------------
// Streaming transaction parser
// ---------------------------------------------------------------------------

#[test]
fn tx_parser_collects_values() {
    let raw = build_coinbase_bytes();
    let mut parser = TransactionParser::new(&raw);
    let mut total_out = 0u64;
    parser
        .parse_with(
            |_| Ok(()),
            |out| {
                total_out += out.value as u64;
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(total_out, 625_000_000);
}

#[test]
fn tx_parser_is_zero_copy() {
    let raw = build_coinbase_bytes();
    let raw_ptr = raw.as_ptr();
    let mut parser = TransactionParser::new(&raw);
    parser
        .parse_with(
            |inp| {
                // txid should point into `raw`
                let txid_ptr = inp.previous_output.txid.as_bytes().as_ptr();
                assert!(txid_ptr >= raw_ptr);
                assert!(txid_ptr < unsafe { raw_ptr.add(raw.len()) });
                Ok(())
            },
            |_| Ok(()),
        )
        .unwrap();
}
