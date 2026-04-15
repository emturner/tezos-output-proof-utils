# outbox-proof-utils

CLI for inspecting Tezos smart rollup outbox proofs — the `output_proof` field
of an `Sc_rollup_execute_outbox_message` L1 operation.

## Usage

```
outbox-proof-utils extract-metadata --type wasm --hex <HEX>
```

`--hex` takes the raw hex-encoded proof as it appears in the operation (e.g.
from a block explorer or the `octez-client` output).

Example output:

```
Outbox level:  12535441
Message index: 0
Message type:  AtomicTransactionBatch
```

## Supported PVM types

| `--type` | Description |
|----------|-------------|
| `wasm`   | WASM 2.0 PVM (Irmin-backed durable storage) |

## How it works

An outbox proof is a binary blob containing an Irmin Merkle tree proof followed
by the output metadata (`outbox_level`, `message_index`, and the serialised
outbox message). The two sections are concatenated with no delimiter.

The tool locates the split point by scanning for the longest suffix of the proof
that:
1. Starts with a known outbox message union tag (0 = `AtomicTransactionBatch`,
   1 = `AtomicTransactionBatchTyped`, 2 = `WhitelistUpdate`) and has consistent
   internal framing.
2. Appears verbatim as a `Dynamic_size` leaf node (`[4-byte length][message
   bytes]`) inside the Irmin proof section — the WASM Irmin proof embeds the
   outbox message as a storage leaf, so this is a strong structural confirmation
   rather than a coincidental byte match.

## Building

```
cargo build --release
```
