// SPDX-License-Identifier: MIT

mod proof;

use clap::{Parser, Subcommand};

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
        #[command(subcommand)]
        target: ExtractMetadataTarget,
    },
}

#[derive(Subcommand)]
enum ExtractMetadataTarget {
    /// Parse a raw outbox proof (the `output_proof` hex field from an Sc_rollup_execute_outbox_message operation)
    Proof {
        /// Hex-encoded outbox proof
        hex: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::ExtractMetadata {
            target: ExtractMetadataTarget::Proof { hex },
        } => match parse(&hex) {
            Ok(meta) => {
                println!("Outbox level:  {}", meta.outbox_level);
                println!("Message index: {}", meta.message_index);
                println!("Message type:  {}", meta.message_type);
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        },
    }
}
