use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use rustwarden::*;
use std::path::PathBuf;
use zeroize::Zeroize;

/// Command-line interface structure for the password manager
#[derive(Parser)]
#[command(author, version, about = "Simple local password manager (encrypted DB)")]
struct Cli {
    /// Path to database file
    #[arg(short, long, default_value = DEFAULT_DB)]
    db: PathBuf,
    #[command(subcommand)]
    cmd: Commands,
}

/// Available commands for the password manager
#[derive(Subcommand)]
enum Commands {
    /// Add a new password entry for a service
    Add {
        /// Name of the service
        service: String,
        /// Username for the service
        username: String,
    },
    /// Retrieve a password and copy it to clipboard
    Get {
        /// Name of the service to retrieve
        service: String,
        /// Seconds before clearing clipboard (default: 15)
        #[arg(short, long)]
        clear: Option<u64>,
    },
    /// Delete a password entry
    Delete {
        /// Name of the service to delete
        service: String,
    },
    /// List all stored services and usernames
    List,
    /// Generate a new password and store it
    New {
        /// Name of the service for the new password
        name: String,
        /// Length of the generated password
        #[arg(short, long, default_value_t = 12)]
        length: usize,
        /// Include lowercase letters
        #[arg(long, default_value_t = true)]
        lowercase: bool,
        /// Include uppercase letters
        #[arg(long, default_value_t = true)]
        uppercase: bool,
        /// Include digits
        #[arg(long, default_value_t = true)]
        digits: bool,
        /// Include symbols
        #[arg(long, default_value_t = true)]
        symbols: bool,
        /// Require at least one lowercase letter
        #[arg(long, default_value_t = true)]
        require_lowercase: bool,
        /// Require at least one uppercase letter
        #[arg(long, default_value_t = true)]
        require_uppercase: bool,
        /// Require at least one digit
        #[arg(long, default_value_t = true)]
        require_digits: bool,
        /// Require at least one symbol
        #[arg(long, default_value_t = true)]
        require_symbols: bool,
        /// Seconds before clearing clipboard
        #[arg(short, long, default_value_t = DEFAULT_CLEAR_SECONDS)]
        clear: u64,
    },
}

/// Main entry point for the password manager application
///
/// Parses command-line arguments, prompts for the master password,
/// loads the database, executes the requested command, and saves
/// any changes back to the database.
///
/// # Returns
/// * `Result<()>` - Success or error
///
/// # Errors
/// Returns an error if any operation fails (password reading, database
/// operations, command execution, etc.)
fn main() -> Result<()> {
    let cli = Cli::parse();
    let master = read_password("Master password: ")?;
    let mut entries = load_db(&cli.db, &master)?;

    match cli.cmd {
        Commands::Add { service, username } => {
            let pass = rpassword::prompt_password("Entry password: ")
                .context("failed to read entry password")?;
            if entries.iter().any(|e| e.service == service) {
                bail!("service already exists; delete first if you want to replace");
            }
            entries.push(Entry {
                service,
                username,
                password: pass,
            });
            save_db(&cli.db, &entries, &master).context("failed to save DB")?;
            println!("Added entry and saved DB.");
        }
        Commands::Get { service, clear } => {
            if let Some(e) = entries.iter().find(|e| e.service == service) {
                let secs = clear.unwrap_or(DEFAULT_CLEAR_SECONDS);
                copy_to_clipboard_with_clear(&e.password, secs)?;
                println!(
                    "Password for '{}' copied to clipboard; will clear in {}s",
                    e.service, secs
                );
            } else {
                bail!("No such service");
            }
        }
        Commands::Delete { service } => {
            let orig_len = entries.len();
            entries.retain(|e| e.service != service);
            if entries.len() == orig_len {
                bail!("No such service");
            }
            save_db(&cli.db, &entries, &master)?;
            println!("Deleted entry and saved DB.");
        }
        Commands::List => {
            for e in &entries {
                println!("{} ({})", e.service, e.username);
            }
        }
        Commands::New {
            name,
            length,
            lowercase,
            uppercase,
            digits,
            symbols,
            require_lowercase,
            require_uppercase,
            require_digits,
            require_symbols,
            clear,
        } => {
            if entries.iter().any(|e| e.service == name) {
                bail!(
                    "Service '{}' already exists; delete first if you want to replace",
                    name
                );
            }
            let pw = generate_password(
                length,
                lowercase,
                uppercase,
                digits,
                symbols,
                require_lowercase,
                require_uppercase,
                require_digits,
                require_symbols,
            )?;
            entries.push(Entry {
                service: name.clone(),
                username: "".to_string(),
                password: pw.clone(),
            });
            save_db(&cli.db, &entries, &master)?;
            copy_to_clipboard_with_clear(&pw, clear)?;
            println!(
                "Password for '{}' generated, stored in DB, and copied to clipboard (will clear in {}s)",
                name, clear
            );
        }
    }

    for e in entries.iter_mut() {
        e.password.zeroize();
    }
    Ok(())
}