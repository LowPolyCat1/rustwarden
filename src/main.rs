use anyhow::{anyhow, bail, Context, Result};
use argon2::{Argon2, Params, Version};
use arboard::Clipboard;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use clap::{Parser, Subcommand};
use rand::{rngs::OsRng, RngCore};
use secrecy::{ExposeSecret, SecretString, SecretVec};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;
use zeroize::Zeroize;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32; // 256-bit key
const DEFAULT_DB: &str = "pwdb.enc";
const DEFAULT_CLEAR_SECONDS: u64 = 15;

#[derive(Parser)]
#[command(author, version, about = "Simple local password manager (encrypted DB)")]
struct Cli {
    /// Path to database file
    #[arg(short, long, default_value = DEFAULT_DB)]
    db: PathBuf,
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Add { service: String, username: String },
    Get { service: String, #[arg(short, long)] clear: Option<u64> },
    Delete { service: String },
    List,
    New {
        name: String,
        #[arg(short, long, default_value_t = 12)]
        length: usize,
        #[arg(long, default_value_t = true)]
        lowercase: bool,
        #[arg(long, default_value_t = true)]
        uppercase: bool,
        #[arg(long, default_value_t = true)]
        digits: bool,
        #[arg(long, default_value_t = true)]
        symbols: bool,
        #[arg(long, default_value_t = true)]
        require_lowercase: bool,
        #[arg(long, default_value_t = true)]
        require_uppercase: bool,
        #[arg(long, default_value_t = true)]
        require_digits: bool,
        #[arg(long, default_value_t = true)]
        require_symbols: bool,
        #[arg(short, long, default_value_t = DEFAULT_CLEAR_SECONDS)]
        clear: u64,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Entry {
    service: String,
    username: String,
    password: String,
}

fn read_password(prompt: &str) -> Result<SecretString> {
    let pw = rpassword::prompt_password(prompt).context("failed to read password")?;
    Ok(SecretString::new(pw))
}

fn derive_key(password: &SecretString, salt: &[u8]) -> Result<SecretVec<u8>> {
    let mem_kib: u32 = 64 * 1024;
    let iterations: u32 = 3;
    let parallelism: u32 = 1;
    let params = Params::new(mem_kib, iterations, parallelism, None)
        .map_err(|e| anyhow!("failed to create Argon2 params: {:?}", e))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);
    let mut out = vec![0u8; KEY_LEN];
    argon2
        .hash_password_into(password.expose_secret().as_bytes(), salt, &mut out)
        .map_err(|e| anyhow!("argon2 key derivation failed: {:?}", e))?;
    Ok(SecretVec::new(out))
}

fn encrypt_blob(plaintext: &[u8], password: &SecretString) -> Result<Vec<u8>> {
    let mut salt = vec![0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let key_secret = derive_key(password, &salt)?;
    let key = Key::from_slice(key_secret.expose_secret());
    let cipher = ChaCha20Poly1305::new(key);
    let mut nonce_bytes = vec![0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow!("encryption failed: {:?}", e))?;
    drop(key_secret);
    let mut out = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn decrypt_blob(filedata: &[u8], password: &SecretString) -> Result<Vec<u8>> {
    if filedata.len() < SALT_LEN + NONCE_LEN {
        bail!("file too small to be valid");
    }
    let salt = &filedata[0..SALT_LEN];
    let nonce_bytes = &filedata[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ciphertext = &filedata[SALT_LEN + NONCE_LEN..];
    let key_secret = derive_key(password, salt)?;
    let key = Key::from_slice(key_secret.expose_secret());
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| anyhow!("decryption failed (bad password or corrupted file): {:?}", e))?;
    drop(key_secret);
    Ok(plaintext)
}

fn load_db(db_path: &PathBuf, master: &SecretString) -> Result<Vec<Entry>> {
    if !db_path.exists() {
        return Ok(Vec::new());
    }
    let mut f = File::open(db_path).with_context(|| format!("opening {:?}", db_path))?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).with_context(|| format!("reading {:?}", db_path))?;
    let plain = decrypt_blob(&buf, master)?;
    let entries: Vec<Entry> = serde_json::from_slice(&plain).context("failed to parse DB JSON")?;
    let mut plain_owned = plain;
    plain_owned.zeroize();
    Ok(entries)
}

fn save_db(db_path: &PathBuf, entries: &[Entry], master: &SecretString) -> Result<()> {
    let json = serde_json::to_vec(entries).context("failed to serialize DB")?;
    let encrypted = encrypt_blob(&json, master)?;
    let mut json_owned = json;
    json_owned.zeroize();
    let tmp = db_path.with_extension("enc.tmp");
    {
        let mut f = File::create(&tmp).with_context(|| format!("creating {:?}", &tmp))?;
        f.write_all(&encrypted).with_context(|| format!("writing {:?}", &tmp))?;
        f.sync_all().with_context(|| format!("syncing {:?}", &tmp))?;
    }
    std::fs::rename(&tmp, db_path).with_context(|| format!("atomic rename to {:?}", db_path))?;
    Ok(())
}

fn copy_to_clipboard_with_clear(secret: &str, secs: u64) -> Result<()> {
    let mut cb = Clipboard::new().map_err(|e| anyhow!("failed to open clipboard: {:?}", e))?;
    cb.set_text(secret.to_string())
        .map_err(|e| anyhow!("failed to set clipboard: {:?}", e))?;
    let secret_owned = secret.to_string();
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(secs));
        if let Ok(mut cb2) = Clipboard::new() {
            let dummy = " ".repeat(secret_owned.len().max(8));
            let _ = cb2.set_text(dummy);
            let _ = cb2.set_text(String::new());
        }
    });
    Ok(())
}

fn generate_password(
    length: usize,
    lowercase: bool,
    uppercase: bool,
    digits: bool,
    symbols: bool,
    req_lower: bool,
    req_upper: bool,
    req_digits: bool,
    req_symbols: bool,
) -> Result<String> {
    use rand::seq::SliceRandom;
    use rand::thread_rng;

    const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const DIGITS: &[u8] = b"0123456789";
    const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.<>?/";

    let mut categories: Vec<(&[u8], bool)> = Vec::new();
    if lowercase { categories.push((LOWER, req_lower)); }
    if uppercase { categories.push((UPPER, req_upper)); }
    if digits { categories.push((DIGITS, req_digits)); }
    if symbols { categories.push((SYMBOLS, req_symbols)); }

    if categories.is_empty() { bail!("No character sets enabled"); }
    if length < categories.iter().filter(|(_, req)| *req).count() {
        bail!("Password length too short to satisfy requirements");
    }

    let mut rng = thread_rng();
    let mut password: Vec<u8> = Vec::new();

    for (set, required) in &categories {
        if *required { password.push(*set.choose(&mut rng).unwrap()); }
    }

    let all: Vec<u8> = categories.iter().flat_map(|(set, _)| *set).cloned().collect();
    while password.len() < length { password.push(*all.choose(&mut rng).unwrap()); }
    password.shuffle(&mut rng);
    Ok(String::from_utf8(password).unwrap())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let master = read_password("Master password: ")?;
    let mut entries = load_db(&cli.db, &master)?;

    match cli.cmd {
        Commands::Add { service, username } => {
            let pass = rpassword::prompt_password("Entry password: ").context("failed to read entry password")?;
            if entries.iter().any(|e| e.service == service) {
                bail!("service already exists; delete first if you want to replace");
            }
            entries.push(Entry { service, username, password: pass });
            save_db(&cli.db, &entries, &master).context("failed to save DB")?;
            println!("Added entry and saved DB.");
        }
        Commands::Get { service, clear } => {
            if let Some(e) = entries.iter().find(|e| e.service == service) {
                let secs = clear.unwrap_or(DEFAULT_CLEAR_SECONDS);
                copy_to_clipboard_with_clear(&e.password, secs)?;
                println!("Password for '{}' copied to clipboard; will clear in {}s", e.service, secs);
            } else { bail!("No such service"); }
        }
        Commands::Delete { service } => {
            let orig_len = entries.len();
            entries.retain(|e| e.service != service);
            if entries.len() == orig_len { bail!("No such service"); }
            save_db(&cli.db, &entries, &master)?;
            println!("Deleted entry and saved DB.");
        }
        Commands::List => {
            for e in &entries { println!("{} ({})", e.service, e.username); }
        }
        Commands::New { name, length, lowercase, uppercase, digits, symbols, require_lowercase, require_uppercase, require_digits, require_symbols, clear } => {
            if entries.iter().any(|e| e.service == name) {
                bail!("Service '{}' already exists; delete first if you want to replace", name);
            }
            let pw = generate_password(length, lowercase, uppercase, digits, symbols, require_lowercase, require_uppercase, require_digits, require_symbols)?;
            entries.push(Entry { service: name.clone(), username: "".to_string(), password: pw.clone() });
            save_db(&cli.db, &entries, &master)?;
            copy_to_clipboard_with_clear(&pw, clear)?;
            println!("Password for '{}' generated, stored in DB, and copied to clipboard (will clear in {}s)", name, clear);
        }
    }

    for e in entries.iter_mut() { e.password.zeroize(); }
    Ok(())
}
