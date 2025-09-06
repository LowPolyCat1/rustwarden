//! A simple local password manager with encrypted database storage.
//!
//! This library provides secure password storage using ChaCha20Poly1305 encryption
//! and Argon2 key derivation. It supports adding, retrieving, deleting, and listing
//! password entries, as well as generating secure passwords.

use anyhow::{anyhow, bail, Context, Result};
use argon2::{Argon2, Params, Version};
use arboard::Clipboard;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use secrecy::{ExposeSecret, SecretString, SecretVec};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;
use zeroize::Zeroize;

/// Length of the salt used for key derivation (128 bits)
pub const SALT_LEN: usize = 16;
/// Length of the nonce used for encryption (96 bits for ChaCha20Poly1305)
pub const NONCE_LEN: usize = 12;
/// Length of the encryption key (256 bits)
pub const KEY_LEN: usize = 32;
/// Default database filename
pub const DEFAULT_DB: &str = "pwdb.enc";
/// Default time in seconds before clearing clipboard
pub const DEFAULT_CLEAR_SECONDS: u64 = 15;

/// Represents a password entry in the database
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Entry {
    /// Name of the service (e.g., "gmail", "github")
    pub service: String,
    /// Username or email for the service
    pub username: String,
    /// Password for the service
    pub password: String,
}

/// Securely reads a password from the terminal without echoing
///
/// # Arguments
/// * `prompt` - The prompt message to display to the user
///
/// # Returns
/// * `Result<SecretString>` - The password wrapped in a SecretString for secure handling
///
/// # Errors
/// Returns an error if reading from the terminal fails
pub fn read_password(prompt: &str) -> Result<SecretString> {
    let pw = rpassword::prompt_password(prompt).context("failed to read password")?;
    Ok(SecretString::new(pw))
}

/// Derives a cryptographic key from a password using Argon2id
///
/// Uses Argon2id with 64MB memory, 3 iterations, and 1 thread for key derivation.
/// This provides strong protection against brute-force and rainbow table attacks.
///
/// # Arguments
/// * `password` - The master password to derive the key from
/// * `salt` - Random salt bytes to prevent rainbow table attacks
///
/// # Returns
/// * `Result<SecretVec<u8>>` - A 256-bit derived key wrapped in SecretVec
///
/// # Errors
/// Returns an error if Argon2 parameter creation or key derivation fails
pub fn derive_key(password: &SecretString, salt: &[u8]) -> Result<SecretVec<u8>> {
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

/// Encrypts data using ChaCha20Poly1305 with a password-derived key
///
/// The encryption process:
/// 1. Generates a random salt for key derivation
/// 2. Derives a key using Argon2id with the salt
/// 3. Generates a random nonce for encryption
/// 4. Encrypts the plaintext using ChaCha20Poly1305
/// 5. Returns salt + nonce + ciphertext concatenated
///
/// # Arguments
/// * `plaintext` - The data to encrypt
/// * `password` - The password to derive the encryption key from
///
/// # Returns
/// * `Result<Vec<u8>>` - Encrypted blob containing salt, nonce, and ciphertext
///
/// # Errors
/// Returns an error if key derivation or encryption fails
pub fn encrypt_blob(plaintext: &[u8], password: &SecretString) -> Result<Vec<u8>> {
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

/// Decrypts data that was encrypted with encrypt_blob
///
/// The decryption process:
/// 1. Extracts salt, nonce, and ciphertext from the input
/// 2. Derives the key using Argon2id with the extracted salt
/// 3. Decrypts the ciphertext using ChaCha20Poly1305
///
/// # Arguments
/// * `filedata` - Encrypted blob containing salt + nonce + ciphertext
/// * `password` - The password to derive the decryption key from
///
/// # Returns
/// * `Result<Vec<u8>>` - The decrypted plaintext data
///
/// # Errors
/// Returns an error if:
/// - The input data is too small to contain salt and nonce
/// - Key derivation fails
/// - Decryption fails (wrong password or corrupted data)
pub fn decrypt_blob(filedata: &[u8], password: &SecretString) -> Result<Vec<u8>> {
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

/// Loads and decrypts the password database from disk
///
/// If the database file doesn't exist, returns an empty vector.
/// Otherwise, reads the encrypted file, decrypts it, and deserializes
/// the JSON data into a vector of Entry structs.
///
/// # Arguments
/// * `db_path` - Path to the encrypted database file
/// * `master` - Master password for decryption
///
/// # Returns
/// * `Result<Vec<Entry>>` - Vector of password entries from the database
///
/// # Errors
/// Returns an error if:
/// - File cannot be opened or read
/// - Decryption fails (wrong password or corrupted file)
/// - JSON deserialization fails
pub fn load_db(db_path: &PathBuf, master: &SecretString) -> Result<Vec<Entry>> {
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

/// Encrypts and saves the password database to disk
///
/// Serializes the entries to JSON, encrypts the data, and writes it to disk
/// using an atomic write operation (write to temp file, then rename).
/// This ensures the database is never left in a corrupted state.
///
/// # Arguments
/// * `db_path` - Path where the encrypted database should be saved
/// * `entries` - Vector of password entries to save
/// * `master` - Master password for encryption
///
/// # Returns
/// * `Result<()>` - Success or error
///
/// # Errors
/// Returns an error if:
/// - JSON serialization fails
/// - Encryption fails
/// - File creation, writing, or syncing fails
/// - Atomic rename operation fails
pub fn save_db(db_path: &PathBuf, entries: &[Entry], master: &SecretString) -> Result<()> {
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

/// Copies a secret to the clipboard and automatically clears it after a timeout
///
/// The secret is immediately copied to the clipboard, then a background thread
/// is spawned to clear the clipboard after the specified number of seconds.
/// The clearing process overwrites the clipboard with spaces, then with an empty string.
///
/// # Arguments
/// * `secret` - The secret text to copy to clipboard
/// * `secs` - Number of seconds to wait before clearing the clipboard
///
/// # Returns
/// * `Result<()>` - Success or error
///
/// # Errors
/// Returns an error if:
/// - Clipboard cannot be accessed
/// - Setting clipboard text fails
pub fn copy_to_clipboard_with_clear(secret: &str, secs: u64) -> Result<()> {
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

/// Generates a secure random password with customizable character sets and requirements
///
/// The password generation process:
/// 1. Validates that at least one character set is enabled
/// 2. Ensures the password length can satisfy all requirements
/// 3. Adds required characters from each required character set
/// 4. Fills remaining positions with random characters from all enabled sets
/// 5. Shuffles the password to randomize character positions
///
/// # Arguments
/// * `length` - Desired password length
/// * `lowercase` - Include lowercase letters (a-z)
/// * `uppercase` - Include uppercase letters (A-Z)
/// * `digits` - Include digits (0-9)
/// * `symbols` - Include symbols (!@#$%^&*()-_=+[]{};:,.<>?/)
/// * `req_lower` - Require at least one lowercase letter
/// * `req_upper` - Require at least one uppercase letter
/// * `req_digits` - Require at least one digit
/// * `req_symbols` - Require at least one symbol
///
/// # Returns
/// * `Result<String>` - The generated password
///
/// # Errors
/// Returns an error if:
/// - No character sets are enabled
/// - Password length is too short to satisfy all requirements
pub fn generate_password(
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

#[cfg(test)]
mod test;

pub mod setup;