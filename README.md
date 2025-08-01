# KeyForge-BTC
KeyForge BTC is a powerful, multi-threaded Bitcoin private key scanner that can search for addresses matching a predefined target list. It supports multiple key generation modes, including random, sequential, and BIP39 mnemonic-based searches.

KeyForge BTC provides a fast and efficient way to scan vast ranges of private keys.
📌 Features

✅ Multi-Threaded Scanning – Utilizes all CPU cores for maximum speed
✅ Multiple Key Generation Modes

    Random – Brute-force random private keys

    Sequential – Iterate through keys in order (useful for range scanning)

    BIP39 Mnemonics – Generate keys from BIP39 seed phrases (requires wordlist)
    ✅ Supports Multiple Address Types

    P2PKH (Compressed & Uncompressed)

    P2SH (SegWit wrapped in P2SH)

    Bech32 (Native SegWit)

    Taproot (P2TR)

    P2PK (Raw Public Key)
    ✅ Custom Range Support – Define start and end ranges in hex
    ✅ Real-Time Status Updates – Monitor progress per thread
    ✅ Match Logging – Automatically saves found keys to a file

📂 Project Structure & Function Overview
1. Core Components
🔹 main()

    Handles user input (search mode, address types, key range)

    Spawns worker threads for parallel scanning

    Manages Ctrl+C graceful shutdown

🔹 scan_loop()

    The main scanning logic for each thread

    Generates private keys based on the selected mode

    Derives Bitcoin addresses and checks against target list

    Logs matches to a file

🔹 Key Generation Functions

    generate_keypair_random() – Creates random private keys within a range

    generate_keypair_sequential() – Increments keys sequentially

    generate_bip39_keypair() – Derives keys from BIP39 mnemonics

🔹 Address Derivation (generate_addresses())

    Converts private keys into multiple Bitcoin address formats

    Supports legacy, SegWit, and Taproot addresses

🔹 Helper Functions

    load_targets_to_memory() – Reads target addresses from a file

    load_bip39_wordlist() – Loads BIP39 words for mnemonic generation

    wif_from_sk() – Converts a private key to WIF format

🚀 Getting Started
Prerequisites

    Rust (Install via rustup.rs)

    Bitcoin development libraries (bitcoin, secp256k1, bip39)

Installation

    Clone the repo:
    sh

git clone https://github.com/[your-username]/keyforge-btc.git
cd keyforge-btc

Build the project:
sh

    cargo build --release

Usage

    Prepare a target file (targets.txt) with Bitcoin addresses (one per line).

    Run the scanner:
    sh

    cargo run --release

    Follow the prompts to select:

        Search mode (Random/Sequential/BIP39)

        Address types to check

        Key range (for sequential mode)

        Path to BIP39 wordlist (if using mnemonics)

Example Output
text

*** MATCH FOUND! (Thread 3) ***
  Address Type: P2PKH Compressed
  Address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
  Private (WIF): 5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf

📜 License

MIT License – Free for personal and research use.
