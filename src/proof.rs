// SPDX-License-Identifier: MIT

//! Parsing for WASM smart rollup outbox proofs.
//!
//! An outbox proof is the `output_proof` field of an
//! `Sc_rollup_execute_outbox_message` L1 operation.  It is a hex-encoded
//! Data_encoding binary blob with the following layout:
//!
//! ```text
//! [Irmin compact proof — variable, self-delimiting, NO length prefix]
//! [output_proof_output — concatenated directly after:]
//!   [outbox_level:  4 bytes BE int32]
//!   [message_index: LEB128 unsigned varint, 1–N bytes]
//!   [message union:]
//!     tag 0x00 AtomicTransactionBatch:
//!       [4-byte Dynamic_size list length L][L bytes transactions]
//!     tag 0x01 AtomicTransactionBatchTyped:
//!       [4-byte Dynamic_size list length L][L bytes typed transactions]
//!     tag 0x02 WhitelistUpdate:
//!       [0xFF][4-byte L][L bytes pkh list]   (Some)
//!       [0x00]                                (None)
//! ```
//!
//! ## Finding the split point
//!
//! The Irmin proof has no framing, so we cannot tell directly where it ends.
//! Instead we use two signals:
//!
//! 1. **Structural**: find position `pos` where `bytes[pos]` is a valid union
//!    tag and the `Dynamic_size` list-length field is consistent with the
//!    remaining bytes (i.e. `pos + header + L == total_len`).
//!
//! 2. **Irmin confirmation**: the WASM Irmin proof embeds the outbox message
//!    bytes verbatim as a leaf-node value (it proves the message exists in
//!    durable storage). So `bytes[pos..end]` should appear again somewhere
//!    inside `bytes[0..pos]` (the Irmin proof section). False positives
//!    inside the transaction data do not have this property.
//!
//! We scan right-to-left, collecting structural candidates, then prefer the
//! rightmost one confirmed by the Irmin-section echo. If no echo is found we
//! fall back to the rightmost structural candidate that has a valid LEB128
//! terminator (MSB=0) in the byte immediately before it.

use std::fmt;

use tezos_data_encoding::nom::NomReader;
use tezos_data_encoding::types::Narith;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageType {
    AtomicTransactionBatch,
    AtomicTransactionBatchTyped,
    WhitelistUpdate,
    Unknown(u8),
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AtomicTransactionBatch => write!(f, "AtomicTransactionBatch"),
            Self::AtomicTransactionBatchTyped => write!(f, "AtomicTransactionBatchTyped"),
            Self::WhitelistUpdate => write!(f, "WhitelistUpdate"),
            Self::Unknown(t) => write!(f, "Unknown({t})"),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct OutputMetadata {
    pub outbox_level: u32,
    pub message_index: u64,
    pub message_type: MessageType,
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum ParseError {
    Hex(hex::FromHexError),
    TooShort,
    MessageNotFound,
    NarithDecode(String),
    NarithOverflow,
    LevelNotFound,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hex(e) => write!(f, "hex decode error: {e}"),
            Self::TooShort => write!(f, "input too short"),
            Self::MessageNotFound => write!(f, "could not locate outbox message — no consistent tag+length anchor found"),
            Self::NarithDecode(msg) => write!(f, "message_index LEB128 decode: {msg}"),
            Self::NarithOverflow => write!(f, "message_index too large for u64"),
            Self::LevelNotFound => write!(f, "insufficient bytes before message_index for outbox_level"),
        }
    }
}

impl From<hex::FromHexError> for ParseError {
    fn from(e: hex::FromHexError) -> Self {
        Self::Hex(e)
    }
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

pub fn parse(hex_str: &str) -> Result<OutputMetadata, ParseError> {
    let bytes = hex::decode(hex_str)?;
    parse_bytes(&bytes)
}

pub fn parse_bytes(bytes: &[u8]) -> Result<OutputMetadata, ParseError> {
    if bytes.len() < 8 {
        return Err(ParseError::TooShort);
    }
    let (msg_start, message_type) = find_message_start(bytes)?;
    let (leb_start, message_index) = find_leb128_before(bytes, msg_start)?;
    if leb_start < 4 {
        return Err(ParseError::LevelNotFound);
    }
    let level_slice: [u8; 4] = bytes[leb_start - 4..leb_start].try_into().unwrap();
    let outbox_level = i32::from_be_bytes(level_slice) as u32;
    Ok(OutputMetadata { outbox_level, message_index, message_type })
}

// ---------------------------------------------------------------------------
// Core scan
// ---------------------------------------------------------------------------

/// Return the start position of the outbox message union and its type.
///
/// Scans left-to-right (longest possible suffix first). For each position:
///
/// 1. **Irmin echo**: check that `bytes[pos..n]` appears verbatim somewhere in
///    `bytes[0..pos]`. The Irmin proof stores the outbox message as a leaf-node
///    value, so the true msg_start produces a long match; false positives from
///    coincidental byte patterns produce only short matches.
///
/// 2. **Structure**: check that the suffix starts with a valid union tag and
///    that the `Dynamic_size` list-length field (or the `0x00` None sentinel)
///    is consistent with the remaining bytes.
///
/// Both signals must hold. If either fails we shrink the candidate by one byte
/// (increment pos) and try again, naturally converging on the true split point.
fn find_message_start(bytes: &[u8]) -> Result<(usize, MessageType), ParseError> {
    let n = bytes.len();

    // pos >= 5: minimum room for 4-byte level + 1-byte LEB128 before the tag.
    for pos in 5..n {
        let msg = &bytes[pos..n];

        // Echo check: suffix must fit inside the prefix and appear there.
        if msg.len() > pos {
            continue;
        }
        if !bytes[..pos].windows(msg.len()).any(|w| w == msg) {
            continue;
        }

        // Structure check: must start with a valid tag and have consistent framing.
        if let Some(kind) = message_kind(msg) {
            return Ok((pos, kind));
        }
    }

    // Fallback for proofs where the Irmin section doesn't embed the message
    // verbatim (e.g. blinded/hashed leaf nodes). Revert to the structural scan
    // with the LEB128 MSB-0 filter.
    for pos in (5..n).rev() {
        if bytes[pos - 1] & 0x80 != 0 {
            continue;
        }
        let msg = &bytes[pos..n];
        if let Some(kind) = message_kind(msg) {
            return Ok((pos, kind));
        }
    }

    Err(ParseError::MessageNotFound)
}

/// Check whether `msg` is a structurally valid serialised outbox message and
/// return its type, or `None` if it fails the structural constraints.
fn message_kind(msg: &[u8]) -> Option<MessageType> {
    match *msg.first()? {
        // AtomicTransactionBatch / AtomicTransactionBatchTyped:
        //   [tag][4-byte list length L][L bytes]
        t @ (0 | 1) => {
            let list_len = u32::from_be_bytes(msg.get(1..5)?.try_into().ok()?) as usize;
            if 5 + list_len == msg.len() {
                Some(if t == 0 {
                    MessageType::AtomicTransactionBatch
                } else {
                    MessageType::AtomicTransactionBatchTyped
                })
            } else {
                None
            }
        }
        // WhitelistUpdate:
        //   Some(list): [0x02][0xFF][4-byte L][L bytes]
        //   None:       [0x02][0x00]
        2 => match *msg.get(1)? {
            0xFF => {
                let list_len =
                    u32::from_be_bytes(msg.get(2..6)?.try_into().ok()?) as usize;
                if 6 + list_len == msg.len() {
                    Some(MessageType::WhitelistUpdate)
                } else {
                    None
                }
            }
            0x00 if msg.len() == 2 => Some(MessageType::WhitelistUpdate),
            _ => None,
        },
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// LEB128 backwards resolution
// ---------------------------------------------------------------------------

/// Given that a LEB128 varint ends at byte `end` (exclusive), find where it
/// starts and decode its value.
///
/// Tries lengths 1..=9. A valid LEB128 of length L has:
/// - bytes[end-L .. end-1]: MSB=1 (continuation bytes)
/// - bytes[end-1]:           MSB=0 (terminal byte)
fn find_leb128_before(bytes: &[u8], end: usize) -> Result<(usize, u64), ParseError> {
    for leb_len in 1usize..=9 {
        if end < leb_len + 4 {
            break;
        }
        let start = end - leb_len;
        let leb = &bytes[start..end];
        let valid = leb[leb_len - 1] & 0x80 == 0
            && (0..leb_len - 1).all(|i| leb[i] & 0x80 != 0);
        if !valid {
            continue;
        }
        let (_, narith) = Narith::nom_read(leb)
            .map_err(|e| ParseError::NarithDecode(format!("{e:?}")))?;
        return Ok((start, narith_to_u64(narith)?));
    }
    Err(ParseError::NarithDecode(
        "no valid LEB128 terminator before message".into(),
    ))
}

fn narith_to_u64(n: Narith) -> Result<u64, ParseError> {
    let big: num_bigint::BigUint = n.into();
    big.try_into().map_err(|_| ParseError::NarithOverflow)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic outbox proof in the REAL binary format:
    ///   [irmin][outbox_level: 4 BE][leb128_index][tag][message_body]
    ///
    /// For the Irmin-echo confirmation to work on these synthetic tests, the
    /// `irmin` slice must contain the message bytes (`[tag][message_body]`).
    fn build_proof(irmin: &[u8], level: u32, idx: &[u8], tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(irmin);
        out.extend_from_slice(&level.to_be_bytes());
        out.extend_from_slice(idx);
        out.push(tag);
        out.extend_from_slice(body);
        out
    }

    fn leb128(mut n: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (n & 0x7f) as u8;
            n >>= 7;
            if n == 0 {
                out.push(byte);
                break;
            } else {
                out.push(byte | 0x80);
            }
        }
        out
    }

    fn list_body(data: &[u8]) -> Vec<u8> {
        let mut b = (data.len() as u32).to_be_bytes().to_vec();
        b.extend_from_slice(data);
        b
    }

    // ── Test 1 ────────────────────────────────────────────────────────────────
    // level=100000, index=5, AtomicTransactionBatch, empty list.
    // Irmin placeholder echoes the message bytes so the confirmation fires.
    #[test]
    fn test_atomic_transaction_batch() {
        let tag: u8 = 0;
        let body = list_body(&[]);
        // Irmin placeholder contains the echo of [tag][body]
        let mut irmin = vec![0xAB, 0xCD];
        irmin.push(tag);
        irmin.extend_from_slice(&body);
        irmin.extend_from_slice(&[0xEF]);

        let proof = build_proof(&irmin, 100_000, &leb128(5), tag, &body);
        // 2(pad) + 1(tag) + 4(list_len=0) + 1(pad) = 8 irmin bytes
        // + 4 level + 1 idx + 1 tag + 4 list_len = 10 payload bytes
        assert_eq!(proof.len(), 18);

        let meta = parse_bytes(&proof).expect("parse failed");
        assert_eq!(meta, OutputMetadata {
            outbox_level: 100_000,
            message_index: 5,
            message_type: MessageType::AtomicTransactionBatch,
        });
    }

    // ── Test 2 ────────────────────────────────────────────────────────────────
    // level=50_000_000 (lower bytes have MSB=1 — tricky LEB128 boundary),
    // index=0, AtomicTransactionBatch with 4 transaction bytes.
    #[test]
    fn test_high_level_index_zero() {
        let tag: u8 = 0;
        let tx = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let body = list_body(&tx);
        let mut irmin = vec![0x03, 0x00, 0x02]; // realistic compact proof prefix
        irmin.push(tag);
        irmin.extend_from_slice(&body);

        let proof = build_proof(&irmin, 50_000_000, &leb128(0), tag, &body);
        let meta = parse_bytes(&proof).expect("parse failed");
        assert_eq!(meta.outbox_level, 50_000_000);
        assert_eq!(meta.message_index, 0);
        assert_eq!(meta.message_type, MessageType::AtomicTransactionBatch);
    }

    // ── Test 3 ────────────────────────────────────────────────────────────────
    // Typed batch (tag 1).
    #[test]
    fn test_typed_batch() {
        let tag: u8 = 1;
        let body = list_body(&[]);
        let mut irmin = vec![0xFF];
        irmin.push(tag);
        irmin.extend_from_slice(&body);

        let proof = build_proof(&irmin, 42, &leb128(0), tag, &body);
        let meta = parse_bytes(&proof).expect("parse failed");
        assert_eq!(meta.message_type, MessageType::AtomicTransactionBatchTyped);
    }

    // ── Test 4: mainnet example ───────────────────────────────────────────────
    #[test]
    fn test_example_mainnet_0() {
        let message = "030002251b0b76de272d9cd56a9008a6901388df316536c94fae84fa9c61c76946f5f3251b0b76de272d9cd56a9008a6901388df316536c94fae84fa9c61c76946f5f30005820764757261626c65d068dbc4ca9fb400180432b2aaed5850c00f27aed96bc599aca49f0593c2ab819f03746167c00800000004536f6d650003c02c7224c8ea964d400cd8adaffd70ada88613d072daa61b8d6f2c912ad72603f1820576616c7565810370766d8107627566666572738205696e707574820468656164c00100066c656e677468c00100066f75747075740004820132810a6c6173745f6c6576656cc00400bf470f0133810f76616c69646974795f706572696f64c0040003b10082013181086f7574626f786573020003b100c033262ed02860ca5a10aeea24f924b76ad54c4560b60341eb81a221d30308b69e020001d829c085db0ac9a2b156f41f43fd69e9d95a3935b844d3f0784ef0378240acb9c8940d01ecfcc011adb1bd16a329d7017c2c91a3710f306859b61ec53c20e900db5a9630939ee5017677013bd9011ddac0255c1835a539598fe0b7908a59fc2cd0593fe0707b155ab1cebe741da3264b1e010f13c0ed819c4a32839e06643e9df685e7ac31c1ff7f7fb2317dc30fe863623d366c870107990103a2c028877b6fb6cf0aa0900e090be990d3dfd61ee29248d0905116b1e7d8cb63cb150101d3c0c2dd26678b80f5033a77f083cfb593c439630f7e7415a23281989fa64e83d8d200f90083c0ffa95ea5d81213e924482e5171a1081d9bc721f3641920d35477c9a02fcd82f20039c0cec4c4e974ab46c106ae35db40aecd6c2892bbfad4be18cdb68cdc9e8506075e001fc086ef8a2af008eaf3c340ccb8d9ed5e2d7bd4b76f3d6da4589f134cd27c7fb7c80011c0fa6dc2a8b78f4331a4dbacb002f322f240eb603ff9cd8ddc313cb76834b1ba840008000482083132333036393135820468656164c00100066c656e677468c001008208636f6e74656e7473810130c0a5000000a1000000009c070700bcf802070707070a00000016012c895aa0a61697411ffc877120556a6c2b83ca510007070707000003060080897a07070098a4c09c0d07070a000000160000cf35399ff651c74f3c3cd55eb3b8feb089e767b007070a000000050500b0e9790a00000014f9e0f0a650716e7d626c66ed13459cb92491ac05011d8993318173e5a41c48b9a5121494dd982785f8000000000764656661756c74066c656e677468c00101c022e909631a08efda34cef6d26809251b6ac1a1b606421ee7ffd1745a38fb9088c03aa0746ae26f1babc8f2ffd29fede842804bff6c2cac228f473eb1adb8f280f5c05bd77fe183dd949d9624cc375f99fde7253b3677be4189cbc7aadcf7ee63bc01c0def8b615ea610b083395daeee39eb468f038466d8ceef4e4929b3464446d4b09c0c3569f101dd5ccb4910eafc66f8f92c51ce52732ebde962f0a89255c268e33cfc0112e6424536156492723426c7a7acdd378cb04c0b2d4c8e296b94ac81937a6f20134810d6d6573736167655f6c696d6974c002a401047761736dd0efad883f86e154819326ebf628d26c1de173f649c401c7514a8a6e9aa320f2cc00bf469100000000009c070700bcf802070707070a00000016012c895aa0a61697411ffc877120556a6c2b83ca510007070707000003060080897a07070098a4c09c0d07070a000000160000cf35399ff651c74f3c3cd55eb3b8feb089e767b007070a000000050500b0e9790a00000014f9e0f0a650716e7d626c66ed13459cb92491ac05011d8993318173e5a41c48b9a5121494dd982785f8000000000764656661756c74";

        let meta = parse(message).expect("parse failed");
        // Confirmed AtomicTransactionBatch: ends with "default" entrypoint bytes.
        assert_eq!(meta.message_type, MessageType::AtomicTransactionBatch);
        assert!(
            meta.outbox_level > 0 && meta.outbox_level < 100_000_000,
            "unexpected level {}",
            meta.outbox_level
        );
        println!("Mainnet: level={}, index={}, type={}", meta.outbox_level, meta.message_index, meta.message_type);
    }

    // ── Test 5: mainnet whitelist update ─────────────────────────────────────
    // A real whitelist-update proof from mainnet. Ends with tag 0x02 + 0x00
    // (WhitelistUpdate None — removing all stakers from the whitelist).
    #[test]
    fn test_example_mainnet_1() {
        let proof = "030002f185a00dbcc3506d084a06b405dcbe7f456342311b44f333eac0898308b2cfa8f185a00dbcc3506d084a06b405dcbe7f456342311b44f333eac0898308b2cfa80005820764757261626c65d04b3ff4f2b5ae336d34f45dc081bcee9c1e2a4765cad23c2c106e8aa5563f7c2f03746167c00800000004536f6d650003c0fd3ca96fd4f3ec5376d44c353e5278c3155bed43f67b2ad646a0ab0ec53264fd820576616c7565810370766d8107627566666572738205696e707574820468656164c00100066c656e677468c00100066f75747075740004820132810a6c6173745f6c6576656cc004005434e70133810f76616c69646974795f706572696f64c00400013b0082013181086f7574626f786573003cc0af264e7838bd1e31a7892833f12e7b221eb9d53f054fc6db71a98b2185d566160021000e0009c09d3a14989b215e5925c5cb582e780752224dbddc5b0d143068e6f438526866d200058207353531383530380003810468656164c001008208636f6e74656e7473810130c006000000020200066c656e677468c001010735353138353331820468656164c00100066c656e677468c00100c013f7d3c265c2d70c324622de8ea047f234a615c07f21dcd6279f9a3f409e173ac07823161845e978482c271391d940f857ad0ad523f632d534f2e198556d53f31dc0eb4f13dcee0a82fd914ed8094b6d10713f6de68305d6b0866c1f39b7c6c8b93e0134810d6d6573736167655f6c696d6974c002a401047761736dd0b26dc0862ffb2e48f0c695c8df9f4aece087b68f2a16550969a2676a35f0c7c0005434ac000200";

        let meta = parse(proof).expect("parse failed");
        assert_eq!(meta.message_type, MessageType::WhitelistUpdate);
        assert_eq!(meta.outbox_level, 5_518_508);
        assert_eq!(meta.message_index, 0);
    }

    // ── Error cases ───────────────────────────────────────────────────────────
    #[test]
    fn test_too_short() {
        assert!(parse("").is_err());
        assert!(parse("deadbeef").is_err());
    }

    #[test]
    fn test_bad_hex() {
        assert!(parse("zzzz").is_err());
    }
}
