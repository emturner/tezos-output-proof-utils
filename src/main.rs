// SPDX-FileCopyrightText: 2026 Trilitech <contact@trili.tech>
//
// SPDX-License-Identifier: MIT

mod proof;

use clap::{Parser, Subcommand, ValueEnum};

use proof::parse;

#[derive(Parser)]
#[command(name = "outbox-proof-utils", about = "Tools for inspecting Tezos smart rollup outbox proofs")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Extract metadata from an outbox proof
    ExtractMetadata {
        /// PVM type that produced the proof
        #[arg(long, value_enum)]
        r#type: PvmType,

        /// Hex-encoded outbox proof (the `output_proof` field from an
        /// Sc_rollup_execute_outbox_message operation)
        #[arg(long)]
        hex: String,
    },
}

#[derive(Clone, ValueEnum)]
enum PvmType {
    /// WASM 2.0 PVM (Irmin-backed durable storage)
    Wasm,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::ExtractMetadata { r#type, hex } => {
            let result = match r#type {
                PvmType::Wasm => parse(&hex),
            };
            match result {
                Ok(meta) => {
                    println!("Outbox level:  {}", meta.outbox_level);
                    println!("Message index: {}", meta.message_index);
                    println!("Message type:  {}", meta.message_type);
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}
