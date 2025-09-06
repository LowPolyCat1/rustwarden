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

pub mod setup {
    use anyhow::{Context, Result};
    use console::style;
    use std::fs;
    use std::io::{self, Write};
    use std::path::PathBuf;

    /// Configuration structure for the password manager
    #[derive(Debug, Clone)]
    pub struct Config {
        pub db_path: PathBuf,
        pub default_clear_seconds: u64,
        pub auto_backup: bool,
        pub backup_path: Option<PathBuf>,
    }

    impl Default for Config {
        fn default() -> Self {
            Self {
                db_path: PathBuf::from("pwdb.enc"),
                default_clear_seconds: 15,
                auto_backup: false,
                backup_path: None,
            }
        }
    }

    /// Checks if this is the first run by looking for a config file
    pub fn is_first_run() -> bool {
        !get_config_path().exists()
    }

    /// Gets the path to the configuration file
    pub fn get_config_path() -> PathBuf {
        if let Some(config_dir) = dirs::config_dir() {
            config_dir.join("rustwarden").join("config.toml")
        } else {
            PathBuf::from(".rustwarden_config.toml")
        }
    }

    /// Clears the terminal screen
    fn clear_screen() -> Result<()> {
        clearscreen::clear().context("failed to clear screen")?;
        Ok(())
    }

    /// Displays a clean welcome header with colors
    fn display_welcome_banner() -> Result<()> {
        clear_screen()?;
        println!("{}", style("rustwarden").cyan().bold());
        println!("{}", style("encrypted password manager - first time setup").dim());
        println!();
        Ok(())
    }

    /// Shows a tooltip/hint for the current field
    fn show_tooltip(text: &str) {
        println!("  {}", style(format!("hint: {}", text)).dim().italic());
    }

    /// Prompts user for input with a default value and tooltip
    fn prompt_with_default(prompt: &str, default: &str, tooltip: Option<&str>) -> Result<String> {
        if let Some(tip) = tooltip {
            show_tooltip(tip);
        }

        print!("{} {}: ",
               style(prompt).green(),
               style(format!("[{}]", default)).dim());
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();

        if input.is_empty() {
            Ok(default.to_string())
        } else {
            Ok(input.to_string())
        }
    }

    /// Prompts user for yes/no input with tooltip
    fn prompt_yes_no(prompt: &str, default: bool, tooltip: Option<&str>) -> Result<bool> {
        if let Some(tip) = tooltip {
            show_tooltip(tip);
        }

        let default_str = if default { "Y/n" } else { "y/N" };
        print!("{} {}: ",
               style(prompt).green(),
               style(format!("[{}]", default_str)).dim());
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim().to_lowercase();

        match input.as_str() {
            "" => Ok(default),
            "y" | "yes" => Ok(true),
            "n" | "no" => Ok(false),
            _ => {
                println!("{}", style("error: please enter 'y' for yes or 'n' for no").red());
                prompt_yes_no(prompt, default, None)
            }
        }
    }

    /// Interactive menu selection
    fn select_option(prompt: &str, options: &[(&str, &str)], default: usize) -> Result<usize> {
        println!("{}", style(prompt).green().bold());

        for (i, (option, desc)) in options.iter().enumerate() {
            let marker = if i == default { ">" } else { " " };
            println!("  {}{} {} {}",
                     style(marker).cyan().bold(),
                     style(format!("{}", i + 1)).cyan(),
                     style(option).white(),
                     style(format!("({})", desc)).dim());
        }

        show_tooltip("use numbers 1-{} or press enter for default");
        print!("{} {}: ",
               style("choice").green(),
               style(format!("[{}]", default + 1)).dim());
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();

        if input.is_empty() {
            Ok(default)
        } else if let Ok(choice) = input.parse::<usize>() {
            if choice > 0 && choice <= options.len() {
                Ok(choice - 1)
            } else {
                println!("{}", style("error: invalid choice").red());
                select_option(prompt, options, default)
            }
        } else {
            println!("{}", style("error: please enter a number").red());
            select_option(prompt, options, default)
        }
    }

    /// Runs the interactive setup wizard
    pub fn run_setup_wizard() -> Result<Config> {
        display_welcome_banner()?;

        // Database location
        println!("{}", style("database configuration").yellow().bold());
        let db_path = prompt_with_default(
            "  path",
            "pwdb.enc",
            Some("where to store your encrypted password database")
        )?;

        println!();

        // Security settings
        println!("{}", style("security configuration").yellow().bold());
        let clear_seconds_str = prompt_with_default(
            "  clipboard timeout",
            "15",
            Some("seconds before passwords are cleared from clipboard")
        )?;
        let clear_seconds: u64 = clear_seconds_str.parse()
            .context("invalid number for clipboard timeout")?;

        println!();

        // Backup settings
        println!("{}", style("backup configuration").yellow().bold());
        let auto_backup = prompt_yes_no(
            "  enable backups",
            false,
            Some("automatically backup database on changes")
        )?;

        let backup_path = if auto_backup {
            let path = prompt_with_default(
                "  backup directory",
                "backups",
                Some("directory to store backup files")
            )?;
            Some(PathBuf::from(path))
        } else {
            None
        };

        println!();

        // Configuration summary
        let config = Config {
            db_path: PathBuf::from(db_path),
            default_clear_seconds: clear_seconds,
            auto_backup,
            backup_path,
        };

        println!("{}", style("configuration summary").yellow().bold());
        println!("  {}: {}", style("database").cyan(), config.db_path.display());
        println!("  {}: {}s", style("clipboard timeout").cyan(), config.default_clear_seconds);
        println!("  {}: {}", style("backups").cyan(),
                 if config.auto_backup {
                     style("enabled").green()
                 } else {
                     style("disabled").red()
                 });
        if let Some(ref backup_path) = config.backup_path {
            println!("  {}: {}", style("backup path").cyan(), backup_path.display());
        }

        println!();
        if prompt_yes_no("save configuration", true, None)? {
            save_config(&config)?;

            // Create backup directory if needed
            if let Some(ref backup_path) = config.backup_path {
                fs::create_dir_all(backup_path)
                    .context("failed to create backup directory")?;
            }

            clear_screen()?;
            println!("{}", style("✓ setup complete").green().bold());
            println!();
            println!("{}: {}", style("config").dim(), get_config_path().display());
            println!("{}: {}", style("database").dim(), config.db_path.display());
            println!();
            println!("{}", style("security notice").red().bold());
            println!("  • your master password is never stored");
            println!("  • if forgotten, data cannot be recovered");
            println!("  • choose a strong, memorable password");
            println!();

            Ok(config)
        } else {
            clear_screen()?;
            println!("{}", style("setup cancelled").yellow());
            std::process::exit(0);
        }
    }

    /// Saves configuration to file
    pub fn save_config(config: &Config) -> Result<()> {
        let config_path = get_config_path();

        // Create config directory if it doesn't exist
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)
                .context("Failed to create config directory")?;
        }

        let toml_content = format!(
            r#"# RustWarden Configuration File
# This file was automatically generated during setup

[database]
path = "{}"

[security]
default_clear_seconds = {}

[backup]
enabled = {}
{}"#,
            config.db_path.display(),
            config.default_clear_seconds,
            config.auto_backup,
            if let Some(ref path) = config.backup_path {
                format!("path = \"{}\"", path.display())
            } else {
                "# path = \"backups\"".to_string()
            }
        );

        fs::write(&config_path, toml_content)
            .context("Failed to write configuration file")?;

        Ok(())
    }

    /// Loads configuration from file
    pub fn load_config() -> Result<Config> {
        let config_path = get_config_path();

        if !config_path.exists() {
            return Ok(Config::default());
        }

        let content = fs::read_to_string(&config_path)
            .context("Failed to read configuration file")?;

        // Simple TOML parsing (you could use the `toml` crate for more robust parsing)
        let mut config = Config::default();

        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }

            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim().trim_matches('"');

                match key {
                    "path" => config.db_path = PathBuf::from(value),
                    "default_clear_seconds" => {
                        config.default_clear_seconds = value.parse()
                            .context("Invalid default_clear_seconds in config")?;
                    }
                    "enabled" => {
                        config.auto_backup = value.parse()
                            .context("Invalid backup enabled setting in config")?;
                    }
                    _ => {} // Ignore unknown keys
                }
            }
        }

        Ok(config)
    }

    /// Displays a minimal setup prompt for non-interactive environments
    pub fn quick_setup() -> Result<Config> {
        clear_screen()?;
        println!("{}", style("rustwarden").cyan().bold());
        println!("{}", style("using default configuration").dim());

        let config = Config::default();
        save_config(&config)?;

        println!();
        println!("{}: {}", style("config").green(), get_config_path().display());
        println!("{}: {}", style("database").green(), config.db_path.display());

        Ok(config)
    }
}