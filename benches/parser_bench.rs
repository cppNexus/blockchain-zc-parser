use blockchain_zc_parser::{
    block::{BlockHeader, BlockTxIter},
    cursor::Cursor,
    transaction::TransactionParser,
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

// ---------------------------------------------------------------------------
// Helper: build a realistic synthetic block in memory
// ---------------------------------------------------------------------------

fn build_coinbase_tx() -> Vec<u8> {
    let mut tx = Vec::with_capacity(100);
    tx.extend_from_slice(&1i32.to_le_bytes()); // version
    tx.push(1); // 1 input
    tx.extend_from_slice(&[0u8; 32]); // outpoint txid (zeros)
    tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // outpoint vout
    tx.push(4); // scriptSig len
    tx.extend_from_slice(&[0x03, 0x4b, 0x6e, 0x0b]); // scriptSig
    tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // sequence
    tx.push(1); // 1 output
    tx.extend_from_slice(&(625_000_000u64).to_le_bytes()); // 6.25 BTC
                                                           // P2WPKH scriptPubKey (22 bytes)
    tx.push(22);
    tx.extend_from_slice(&[
        0x00, 0x14, 0x89, 0xab, 0xcd, 0xef, 0xab, 0xba, 0xab, 0xba, 0xab, 0xba, 0xab, 0xba, 0xab,
        0xba, 0xab, 0xba, 0xab, 0xba, 0xab, 0xba,
    ]);
    tx.extend_from_slice(&0u32.to_le_bytes()); // locktime
    tx
}

fn build_p2pkh_tx() -> Vec<u8> {
    let mut tx = Vec::with_capacity(200);
    tx.extend_from_slice(&2i32.to_le_bytes()); // version 2
    tx.push(1); // 1 input
                // outpoint: arbitrary txid + vout
    tx.extend_from_slice(&[0xab; 32]);
    tx.extend_from_slice(&0u32.to_le_bytes());
    // scriptSig: compressed pubkey push + sig push (roughly)
    let script_sig: &[u8] = &[
        0x47, // push 71 bytes
        0x30, 0x44, 0x02, 0x20, // DER sig header
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe,
        0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad,
        0xbe, 0xef, 0x02, 0x20, 0xca, 0xfe, 0xba, 0xbe, 0xca, 0xfe, 0xba, 0xbe, 0xca, 0xfe, 0xba,
        0xbe, 0xca, 0xfe, 0xba, 0xbe, 0xca, 0xfe, 0xba, 0xbe, 0xca, 0xfe, 0xba, 0xbe, 0xca, 0xfe,
        0xba, 0xbe, 0xca, 0xfe, 0xba, 0xbe, 0x01, // SIGHASH_ALL
        0x21, // push 33 bytes (compressed pubkey)
        0x02, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad,
        0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde,
        0xad, 0xbe, 0xef, 0x01,
    ];
    tx.push(script_sig.len() as u8);
    tx.extend_from_slice(script_sig);
    tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // sequence

    tx.push(2); // 2 outputs
    for _ in 0..2 {
        tx.extend_from_slice(&(1_000_000u64).to_le_bytes());
        // P2PKH scriptPubKey
        tx.extend_from_slice(&[
            25, 0x76, 0xa9, 0x14, 0x89, 0xab, 0xcd, 0xef, 0xab, 0xba, 0xab, 0xba, 0xab, 0xba, 0xab,
            0xba, 0xab, 0xba, 0xab, 0xba, 0xab, 0xba, 0xab, 0xba, 0x88, 0xac,
        ]);
    }
    tx.extend_from_slice(&0u32.to_le_bytes()); // locktime
    tx
}

fn build_block(tx_count: usize) -> Vec<u8> {
    // 80-byte header (genesis values, good enough for benchmarking)
    let header: &[u8] = &hex_literal::hex!(
        "01000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
        "29ab5f49"
        "ffff001d"
        "1dac2b7c"
    );

    let coinbase = build_coinbase_tx();
    let regular = build_p2pkh_tx();

    let mut block = Vec::with_capacity(80 + 9 + tx_count * regular.len());
    block.extend_from_slice(header);
    // tx count varint
    block.push(tx_count as u8);
    block.extend_from_slice(&coinbase);
    for _ in 1..tx_count {
        block.extend_from_slice(&regular);
    }
    block
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

fn bench_block_header(c: &mut Criterion) {
    let header_raw = hex_literal::hex!(
        "01000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
        "29ab5f49"
        "ffff001d"
        "1dac2b7c"
    );

    c.bench_function("block_header/parse_80_bytes", |b| {
        b.iter(|| {
            let mut cursor = Cursor::new(black_box(&header_raw));
            black_box(BlockHeader::parse(&mut cursor).unwrap())
        })
    });
}

fn bench_transaction(c: &mut Criterion) {
    let coinbase = build_coinbase_tx();
    let p2pkh = build_p2pkh_tx();

    let mut group = c.benchmark_group("transaction");
    for (name, raw) in [("coinbase", &coinbase), ("p2pkh_2out", &p2pkh)] {
        group.throughput(Throughput::Bytes(raw.len() as u64));
        group.bench_with_input(BenchmarkId::new("parse", name), raw, |b, raw| {
            b.iter(|| {
                let mut parser = TransactionParser::new(black_box(raw));
                parser
                    .parse_with(
                        |inp| {
                            black_box(inp);
                            Ok(())
                        },
                        |out| {
                            black_box(out);
                            Ok(())
                        },
                    )
                    .unwrap()
            })
        });
    }
    group.finish();
}

fn bench_block_streaming(c: &mut Criterion) {
    let tx_counts = [10usize, 100, 1_000];
    let mut group = c.benchmark_group("block/streaming_iter");

    for &n in &tx_counts {
        let block = build_block(n);
        group.throughput(Throughput::Bytes(block.len() as u64));
        group.bench_with_input(BenchmarkId::new("tx_count", n), &block, |b, block| {
            b.iter(|| {
                let (_header, mut iter) = BlockTxIter::new(black_box(block)).unwrap();
                while iter
                    .next_tx(
                        |i| {
                            black_box(i);
                            Ok(())
                        },
                        |o| {
                            black_box(o);
                            Ok(())
                        },
                    )
                    .unwrap()
                {}
            })
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_block_header,
    bench_transaction,
    bench_block_streaming,
);
criterion_main!(benches);
