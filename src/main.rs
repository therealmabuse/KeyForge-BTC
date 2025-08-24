use bitcoin::{Address, Network, PrivateKey, PublicKey};
use bitcoin::secp256k1::{Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::hashes::Hash;
use rand::RngCore;
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::time::{Instant, Duration};
use num_bigint::BigUint;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::sync::Mutex;
use std::thread;
use rand::Rng;
use ctrlc;
use bitcoin::bip32::{Xpriv, DerivationPath};
use std::str::FromStr;
use bip39::Mnemonic;

#[derive(Clone, Copy, Debug, PartialEq)]
enum SearchPattern {
    Random,
    Sequential,
    Bip39,
}

#[derive(Clone, Debug)]
struct AddressOptions {
    p2pkh_compressed: bool,
    p2pkh_uncompressed: bool,
    p2sh: bool,
    bech32: bool,
    taproot: bool,
    p2pk_compressed: bool,
    p2pk_uncompressed: bool,
    all: bool,
}

impl Default for AddressOptions {
    fn default() -> Self {
        Self {
            p2pkh_compressed: true,
            p2pkh_uncompressed: false,
            p2sh: false,
            bech32: false,
            taproot: false,
            p2pk_compressed: false,
            p2pk_uncompressed: false,
            all: false,
        }
    }
}

fn prompt_search_pattern() -> SearchPattern {
    println!("Select search pattern:");
    println!("  [1] ⚡Random (without range restriction)");
    println!("  [2] 🔢Sequential");
    println!("  [3] 📝BIP39 (mnemonics)");
    print!("Enter your choice [1-3]: ");
    io::stdout().flush().expect("Failed to flush stdout");

    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read input");
    match input.trim() {
        "2" => SearchPattern::Sequential,
        "3" => SearchPattern::Bip39,
        _ => SearchPattern::Random,
    }
}

fn prompt_address_options() -> AddressOptions {
    let mut options = AddressOptions::default();
    
    println!("Select address types to generate (comma separated):");
    println!("  [1] 🔑P2PKH Compressed");
    println!("  [2] 🔑P2PKH Uncompressed");
    println!("  [3] 🦖P2SH");
    println!("  [4] 🔐Bech32");
    println!("  [5] 🌱Taproot");
    println!("  [6] 🧿P2PK Compressed");
    println!("  [7] 🧿P2PK Uncompressed");
    println!("  [8] 💯ALL (including WIF)");
    print!("Your choices (e.g. 1,2,4): ");
    io::stdout().flush().expect("Failed to flush stdout");

    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read input");
    
    let selections: Vec<&str> = input.trim().split(',').collect();
    
    for selection in selections {
        match selection.trim() {
            "1" => options.p2pkh_compressed = true,
            "2" => options.p2pkh_uncompressed = true,
            "3" => options.p2sh = true,
            "4" => options.bech32 = true,
            "5" => options.taproot = true,
            "6" => options.p2pk_compressed = true,
            "7" => options.p2pk_uncompressed = true,
            "8" => {
                options = AddressOptions {
                    p2pkh_compressed: true,
                    p2pkh_uncompressed: true,
                    p2sh: true,
                    bech32: true,
                    taproot: true,
                    p2pk_compressed: true,
                    p2pk_uncompressed: true,
                    all: true,
                };
                break;
            }
            _ => continue,
        }
    }
    
    options
}

fn prompt_hex_range() -> ([u8; 32], [u8; 32]) {
    let mut start_bytes = [0u8; 32];
    start_bytes[31] = 1; // Default start: 0x1
    let mut end_bytes = [0xff; 32]; // Default end: max 32-byte value

    println!("Enter start range (32-byte hex, or leave blank for 0x1):");
    let mut start_input = String::new();
    if io::stdin().read_line(&mut start_input).is_ok() {
        let start_input = start_input.trim();
        if !start_input.is_empty() {
            if start_input.len() <= 64 && start_input.chars().all(|c| c.is_ascii_hexdigit()) {
                let hex = if start_input.len() % 2 == 1 {
                    format!("0{}", start_input)
                } else {
                    start_input.to_string()
                };
                if let Ok(bytes) = hex::decode(&hex) {
                    let start = 32 - bytes.len();
                    start_bytes[start..].copy_from_slice(&bytes);
                }
            }
        }
    }

    println!("Enter end range (32-byte hex, or leave blank for max):");
    let mut end_input = String::new();
    if io::stdin().read_line(&mut end_input).is_ok() {
        let end_input = end_input.trim();
        if !end_input.is_empty() {
            if end_input.len() <= 64 && end_input.chars().all(|c| c.is_ascii_hexdigit()) {
                let hex = if end_input.len() % 2 == 1 {
                    format!("0{}", end_input)
                } else {
                    end_input.to_string()
                };
                if let Ok(bytes) = hex::decode(&hex) {
                    let start = 32 - bytes.len();
                    end_bytes[start..].copy_from_slice(&bytes);
                }
            }
        }
    }

    // Ensure start <= end
    let start_val = BigUint::from_bytes_be(&start_bytes);
    let end_val = BigUint::from_bytes_be(&end_bytes);
    if start_val > end_val {
        println!("Start range exceeds end range. Swapping values.");
        (end_bytes, start_bytes)
    } else {
        (start_bytes, end_bytes)
    }
}

fn load_targets_to_memory<P: AsRef<Path>>(path: P) -> io::Result<HashSet<String>> {
    let content = std::fs::read_to_string(path)?;
    Ok(content.lines().map(|s| s.trim().to_string()).collect())
}

fn load_bip39_wordlist<P: AsRef<Path>>(path: P) -> Vec<String> {
    match File::open(&path) {
        Ok(file) => {
            let reader = io::BufReader::new(file);
            reader
                .lines()
                .filter_map(|l| l.ok())
                .map(|s| s.trim().to_string())
                .collect()
        }
        Err(e) => {
            println!("Failed to open BIP39 wordlist file: {}. Using empty list.", e);
            vec![]
        }
    }
}

fn increment_seq_bytes(bytes: &mut [u8; 32], step: &BigUint, max: &BigUint) -> bool {
    let mut val = BigUint::from_bytes_be(bytes);
    val += step;
    if val > *max {
        return false;
    }
    let new = val.to_bytes_be();
    let start = 32 - new.len();
    for i in 0..32 {
        bytes[i] = if i < start { 0 } else { new[i - start] };
    }
    true
}

fn generate_keypair_random(min: &[u8; 32], max: &[u8; 32]) -> SecretKey {
    let min_val = BigUint::from_bytes_be(min);
    let max_val = BigUint::from_bytes_be(max);
    let range = &max_val - &min_val;
    let mut rng = rand::thread_rng();
    loop {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let val = BigUint::from_bytes_be(&bytes);
        if val <= range {
            let key_val = &min_val + val;
            if key_val <= max_val {
                let key_bytes = key_val.to_bytes_be();
                let mut arr = [0u8; 32];
                let start = 32 - key_bytes.len();
                arr[start..].copy_from_slice(&key_bytes);
                if let Ok(sk) = SecretKey::from_slice(&arr) {
                    return sk;
                }
            }
        }
    }
}

fn generate_keypair_sequential(seq_bytes: &[u8; 32]) -> Result<SecretKey, &'static str> {
    use bitcoin::secp256k1::constants::CURVE_ORDER;
    let curve_order = BigUint::from_bytes_be(&CURVE_ORDER);
    let val = BigUint::from_bytes_be(seq_bytes);
    if val > BigUint::from(0u32) && val < curve_order {
        SecretKey::from_slice(seq_bytes).map_err(|_| "Invalid private key")
    } else {
        Err("Private key out of valid range")
    }
}

fn generate_bip39_keypair(
    wordlist: &[String],
    secp: &Secp256k1<bitcoin::secp256k1::All>,
) -> (SecretKey, String) {
    let mut rng = rand::thread_rng();
    let mut entropy = [0u8; 16];
    rng.fill_bytes(&mut entropy);
    let hash = bitcoin::hashes::sha256::Hash::hash(&entropy);
    let checksum = hash.to_byte_array()[0] >> 4;
    let mut bits = Vec::with_capacity(132);
    for byte in entropy.iter() {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1 == 1);
        }
    }
    for i in (0..4).rev() {
        bits.push((checksum >> i) & 1 == 1);
    }
    let words: Vec<&str> = bits
        .chunks(11)
        .map(|chunk| {
            let mut index = 0;
            for (i, bit) in chunk.iter().enumerate() {
                if *bit {
                    index |= 1 << (10 - i);
                }
            }
            wordlist[index].as_str()
        })
        .collect();

    let mnemonic_phrase = words.join(" ");
    let mnemonic = Mnemonic::from_str(&mnemonic_phrase).expect("Valid mnemonic");
    let seed = mnemonic.to_seed("");
    let master_key = Xpriv::new_master(Network::Bitcoin, &seed).expect("Valid master key");
    let path = DerivationPath::from_str("m/44'/0'/0'/0/0").expect("Valid derivation path");
    let derived_key = master_key.derive_priv(secp, &path).expect("Valid derived key");
    let secret_key = derived_key.private_key;
    (secret_key, mnemonic_phrase)
}

fn generate_addresses(
    sk: &SecretKey,
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    options: &AddressOptions,
) -> Vec<(String, String)> {
    let mut addresses = Vec::new();
    let secp_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(secp, sk);
    let network = Network::Bitcoin;

    if options.p2pkh_compressed || options.all {
        let pubkey = PublicKey {
            compressed: true,
            inner: secp_pubkey,
        };
        let addr = Address::p2pkh(&pubkey, network).to_string();
        addresses.push(("P2PKH Compressed".to_string(), addr));
    }

    if options.p2pkh_uncompressed || options.all {
        let pubkey = PublicKey {
            compressed: false,
            inner: secp_pubkey,
        };
        let addr = Address::p2pkh(&pubkey, network).to_string();
        addresses.push(("P2PKH Uncompressed".to_string(), addr));
    }

    if options.p2sh || options.all {
        let pubkey = PublicKey {
            compressed: true,
            inner: secp_pubkey,
        };
        match pubkey.wpubkey_hash() {
            Ok(wpkh) => {
                let redeem_script = bitcoin::blockdata::script::ScriptBuf::new_p2wpkh(&wpkh);
                match Address::p2sh(&redeem_script, network) {
                    Ok(addr) => addresses.push(("P2SH".to_string(), addr.to_string())),
                    Err(_) => (),
                }
            }
            Err(_) => (),
        }
    }

    if options.bech32 || options.all {
        if let Ok(compressed) = bitcoin::key::CompressedPublicKey::from_slice(&secp_pubkey.serialize()) {
            let addr = Address::p2wpkh(&compressed, network).to_string();
            addresses.push(("Bech32".to_string(), addr));
        }
    }

    if options.taproot || options.all {
        if let Ok(xonly) = XOnlyPublicKey::from_slice(&secp_pubkey.serialize()[1..33]) {
            let addr = Address::p2tr(secp, xonly, None, network).to_string();
            addresses.push(("Taproot".to_string(), addr));
        }
    }

    if options.p2pk_compressed || options.all {
        let pubkey = PublicKey {
            compressed: true,
            inner: secp_pubkey,
        };
        let script = bitcoin::blockdata::script::ScriptBuf::new_p2pk(&pubkey);
        addresses.push(("P2PK Compressed".to_string(), script.to_string()));
    }

    if options.p2pk_uncompressed || options.all {
        let pubkey = PublicKey {
            compressed: false,
            inner: secp_pubkey,
        };
        let script = bitcoin::blockdata::script::ScriptBuf::new_p2pk(&pubkey);
        addresses.push(("P2PK Uncompressed".to_string(), script.to_string()));
    }

    addresses
}

fn wif_from_sk(sk: &SecretKey) -> String {
    let pk = PrivateKey::new(sk.clone(), Network::Bitcoin);
    pk.to_wif()
}

struct WorkerStatus {
    privkey: String,
    wif: String,
    addresses: Vec<(String, String)>,
    speed: f64,
    mnemonic: Option<String>,
}

fn scan_loop(
    pattern: SearchPattern,
    mut seq_bytes: [u8; 32],
    step: BigUint,
    min_bytes: [u8; 32],
    max_bytes: [u8; 32],
    targets: Arc<HashSet<String>>,
    secp: Arc<Secp256k1<bitcoin::secp256k1::All>>,
    total_keys: Arc<AtomicU64>,
    thread_id: usize,
    worker_status: Arc<Vec<Mutex<WorkerStatus>>>,
    running: Arc<AtomicBool>,
    _debug: bool,
    bip39_words: Arc<Vec<String>>,
    address_options: AddressOptions,
) {
    let _rng = rand::thread_rng();
    let start_time = Instant::now();
    let mut n_keys = 0u64;
    let _min_val = BigUint::from_bytes_be(&min_bytes);
    let max_val = BigUint::from_bytes_be(&max_bytes);

    while running.load(Ordering::SeqCst) {
        let (sk, mnemonic) = match pattern {
            SearchPattern::Random => (generate_keypair_random(&min_bytes, &max_bytes), None),
            SearchPattern::Sequential => {
                match generate_keypair_sequential(&seq_bytes) {
                    Ok(sk) => {
                        if !increment_seq_bytes(&mut seq_bytes, &step, &max_val) {
                            break;
                        }
                        (sk, None)
                    }
                    Err(_) => (generate_keypair_random(&min_bytes, &max_bytes), None),
                }
            }
            SearchPattern::Bip39 => {
                if bip39_words.is_empty() {
                    (generate_keypair_random(&min_bytes, &max_bytes), None)
                } else {
                    let (sk, mnemonic) = generate_bip39_keypair(&bip39_words, &secp);
                    (sk, Some(mnemonic))
                }
            }
        };

        let wif = wif_from_sk(&sk);
        let addresses = generate_addresses(&sk, &secp, &address_options);

        // Update worker status periodically
        if n_keys % 1000 == 0 {
            let elapsed = start_time.elapsed().as_secs_f64();
            let speed = if elapsed > 0.0 { n_keys as f64 / elapsed } else { 0.0 };
            let mut ws = worker_status[thread_id].lock().unwrap();
            ws.privkey = hex::encode(sk.secret_bytes());
            ws.wif = wif.clone();
            ws.addresses = addresses.clone();
            ws.speed = speed;
            ws.mnemonic = mnemonic.clone();
        }

        // Check all generated addresses against targets
        for (addr_type, addr) in &addresses {
            if !targets.is_empty() && targets.contains(addr) {
                println!("*** MATCH FOUND! (Thread {}) ***", thread_id);
                println!("  Address Type: {}\n  Address: {}\n  Private (WIF): {}", addr_type, addr, wif);
                if let Some(mn) = &mnemonic {
                    println!("  Mnemonic: {}", mn);
                }
                let mut file = File::create(format!("match_thread_{}.txt", thread_id)).unwrap();
                writeln!(file, "Address Type: {}\nAddress: {}\nWIF: {}", addr_type, addr, wif).unwrap();
                if let Some(mn) = &mnemonic {
                    writeln!(file, "Mnemonic: {}", mn).unwrap();
                }
            }
        }

        n_keys += 1;
        total_keys.fetch_add(1, Ordering::Relaxed);
    }
}

fn main() {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        println!("Shutting down...");
        r.store(false, Ordering::SeqCst);
    }).expect("Error setting Ctrl+C handler");

    let pattern = prompt_search_pattern();
    let address_options = prompt_address_options();

    let (min_bytes, max_bytes) = if pattern != SearchPattern::Bip39 {
        prompt_hex_range()
    } else {
        ([0u8; 32], [0xff; 32])
    };

    // Use all available CPU cores
    let thread_count = num_cpus::get();
    println!("Using {} threads (all available cores)", thread_count);

    println!("Enter path to target addresses file:");
    let mut addr_path = String::new();
    let targets: HashSet<String> = if io::stdin().read_line(&mut addr_path).is_ok() {
        let addr_path = addr_path.trim();
        match load_targets_to_memory(addr_path) {
            Ok(set) => set,
            Err(e) => {
                println!("Failed to load targets file: {}. Using empty set.", e);
                HashSet::new()
            }
        }
    } else {
        HashSet::new()
    };

    let bip39_words = if pattern == SearchPattern::Bip39 {
        println!("Enter path to BIP39 wordlist:");
        let mut bip39_path = String::new();
        if io::stdin().read_line(&mut bip39_path).is_ok() {
            let path = bip39_path.trim();
            Arc::new(load_bip39_wordlist(path))
        } else {
            Arc::new(Vec::new())
        }
    } else {
        Arc::new(Vec::new())
    };

    println!("Loaded {} targets.", targets.len());

    let secp = Arc::new(Secp256k1::new());
    let targets = Arc::new(targets);
    let total_keys = Arc::new(AtomicU64::new(0));
    let worker_status: Arc<Vec<Mutex<WorkerStatus>>> = Arc::new(
        (0..thread_count)
            .map(|_| Mutex::new(WorkerStatus {
                privkey: String::new(),
                wif: String::new(),
                addresses: Vec::new(),
                speed: 0.0,
                mnemonic: None,
            }))
            .collect()
    );

    // Calculate sub-ranges for each thread
    let min_val = BigUint::from_bytes_be(&min_bytes);
    let max_val = BigUint::from_bytes_be(&max_bytes);
    let range_size = &max_val - &min_val + BigUint::from(1u32);
    let subrange_size = &range_size / BigUint::from(thread_count as u64);

    for thread_id in 0..thread_count {
        let targets = Arc::clone(&targets);
        let secp = Arc::clone(&secp);
        let total_keys = Arc::clone(&total_keys);
        let worker_status = Arc::clone(&worker_status);
        let running = Arc::clone(&running);
        let step = BigUint::from(1u32);
        let bip39_words = Arc::clone(&bip39_words);
        let address_options = address_options.clone();

        let thread_min_val = &min_val + (&subrange_size * BigUint::from(thread_id as u64));
        let thread_max_val = if thread_id == thread_count - 1 {
            max_val.clone()
        } else {
            &min_val + (&subrange_size * BigUint::from((thread_id + 1) as u64)) - BigUint::from(1u32)
        };

        let thread_min_bytes = {
            let bytes = thread_min_val.to_bytes_be();
            let mut arr = [0u8; 32];
            let start = 32 - bytes.len();
            arr[start..].copy_from_slice(&bytes);
            arr
        };

        let thread_max_bytes = {
            let bytes = thread_max_val.to_bytes_be();
            let mut arr = [0u8; 32];
            let start = 32 - bytes.len();
            arr[start..].copy_from_slice(&bytes);
            arr
        };

        let thread_seq_bytes = thread_min_bytes;

        thread::spawn(move || {
            scan_loop(
                pattern,
                thread_seq_bytes,
                step,
                thread_min_bytes,
                thread_max_bytes,
                targets,
                secp,
                total_keys,
                thread_id,
                worker_status,
                running,
                false,
                bip39_words,
                address_options,
            );
        });
    }

    // Status output thread
    let worker_status = Arc::clone(&worker_status);
    let running_main = Arc::clone(&running);
    thread::spawn(move || {
        while running.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_secs(60));
            let mut rng = rand::thread_rng();
            let idx = rng.gen_range(0..worker_status.len());
            let status = worker_status[idx].lock().unwrap();

            println!("\n🟢 [Random Thread Status - Thread {}]", idx);
            println!("🔑  PrivKey: {}", status.privkey);
            println!("🪙  WIF: {}", status.wif);
            
            for (addr_type, addr) in &status.addresses {
                println!("📍  {}: {}", addr_type, addr);
            }
            
            if let Some(ref mnemonic) = status.mnemonic {
                println!("📝  Mnemonic: {}", mnemonic);
            }
            
            println!("⚡  Speed: {:.2} keys/sec", status.speed);
            println!("🔢  Total Keys: {}", total_keys.load(Ordering::Relaxed));
        }
    });

    while running_main.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_secs(1));
    }
    println!("All threads stopped.");

}
