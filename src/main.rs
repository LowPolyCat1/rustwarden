use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use console::style;
use rustwarden::*;
use std::io::{self, Write};
use std::path::PathBuf;
use zeroize::Zeroize;

/// Command-line interface structure for the password manager
#[derive(Parser)]
#[command(author, version, about = "encrypted password manager")]
struct Cli {
    /// Path to database file (overrides config file setting)
    #[arg(short, long)]
    db: Option<PathBuf>,

    /// Skip interactive setup and use defaults
    #[arg(long)]
    quick_setup: bool,

    /// Force run setup wizard even if already configured
    #[arg(long)]
    setup: bool,

    #[command(subcommand)]
    cmd: Option<Commands>,
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
    /// Load a backup file and restore it
    LoadBackup {
        /// Path to the backup file to restore
        backup_path: PathBuf,
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

    // Handle setup scenarios
    if cli.setup || setup::is_first_run() {
        if cli.quick_setup {
            setup::quick_setup()?;
        } else {
            setup::run_setup_wizard()?;
        }

        // If this was just a setup run, exit
        if cli.setup && cli.cmd.is_none() {
            return Ok(());
        }

        // Clear screen after setup before continuing
        clearscreen::clear().ok();
    }

    // Load configuration
    let config = setup::load_config()?;

    // Determine database path (CLI arg overrides config)
    let db_path = cli.db.unwrap_or(config.db_path);

    // If no command provided, show help
    let Some(cmd) = cli.cmd else {
        clearscreen::clear().ok();
        println!("{}", style("rustwarden").cyan().bold());
        println!("{}", style("encrypted password manager").dim());
        println!();
        println!("{}", style("usage:").yellow().bold());
        println!("  {} {} {}",
                 style("rustwarden").cyan(),
                 style("<command>").green(),
                 style("[args]").dim());
        println!();
        println!("{}", style("commands:").yellow().bold());
        println!("  {} {}    {}",
                 style("add").green(),
                 style("<service> <username>").dim(),
                 style("add password entry").white());
        println!("  {} {}               {}",
                 style("get").green(),
                 style("<service>").dim(),
                 style("retrieve password").white());
        println!("  {} {}               {}",
                 style("new").green(),
                 style("<service>").dim(),
                 style("generate new password").white());
        println!("  {}                        {}",
                 style("list").green(),
                 style("list all services").white());
        println!("  {} {}            {}",
                 style("delete").green(),
                 style("<service>").dim(),
                 style("remove entry").white());
        println!("  {} {}        {}",
                 style("load-backup").green(),
                 style("<file>").dim(),
                 style("restore from backup").white());
        println!();
        println!("{}", style("options:").yellow().bold());
        println!("  {}                     {}",
                 style("--setup").cyan(),
                 style("run configuration wizard").white());
        println!("  {}                      {}",
                 style("--help").cyan(),
                 style("show detailed help").white());
        return Ok(());
    };

    clearscreen::clear().ok();
    print!("{}: ", style("master password").green());
    io::stdout().flush().unwrap();
    let master = read_password("")?;
    let mut entries = load_db(&db_path, &master)?;

    match cmd {
        Commands::Add { service, username } => {
            print!("{}: ", style("password").green());
            io::stdout().flush().unwrap();
            let pass = rpassword::prompt_password("")
                .context("failed to read password")?;
            if entries.iter().any(|e| e.service == service) {
                println!("{}", style(format!("error: service '{}' already exists", service)).red());
                std::process::exit(1);
            }
            entries.push(Entry {
                service: service.clone(),
                username,
                password: pass,
            });
            save_db(&db_path, &entries, &master).context("failed to save database")?;
            println!("{} {}", style("✓ added:").green(), style(&service).cyan());
        }
        Commands::Get { service, clear } => {
            if let Some(e) = entries.iter().find(|e| e.service == service) {
                let secs = clear.unwrap_or(config.default_clear_seconds);
                copy_to_clipboard_with_clear(&e.password, secs)?;
                println!("{} {} {}",
                         style("✓ copied to clipboard").green(),
                         style(format!("({}s", secs)).dim(),
                         style("timeout)").dim());
            } else {
                println!("{}", style(format!("error: service '{}' not found", service)).red());
                std::process::exit(1);
            }
        }
        Commands::Delete { service } => {
            let orig_len = entries.len();
            entries.retain(|e| e.service != service);
            if entries.len() == orig_len {
                println!("{}", style(format!("error: service '{}' not found", service)).red());
                std::process::exit(1);
            }
            save_db(&db_path, &entries, &master)?;
            println!("{} {}", style("✓ deleted:").red(), style(&service).cyan());
        }
        Commands::List => {
            if entries.is_empty() {
                println!("{}", style("no entries found").dim());
            } else {
                println!("{}", style("stored passwords:").yellow().bold());
                for e in &entries {
                    if e.username.is_empty() {
                        println!("  {}", style(&e.service).cyan());
                    } else {
                        println!("  {} {}",
                                 style(&e.service).cyan(),
                                 style(format!("({})", e.username)).dim());
                    }
                }
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
                println!("{}", style(format!("error: service '{}' already exists", name)).red());
                std::process::exit(1);
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
            save_db(&db_path, &entries, &master)?;
            copy_to_clipboard_with_clear(&pw, clear)?;
            println!("{} {} {} {}",
                     style("✓ generated:").green(),
                     style(&name).cyan(),
                     style(format!("({}s", clear)).dim(),
                     style("timeout)").dim());
        }
        Commands::LoadBackup { backup_path } => {
            setup::load_backup(&backup_path, &master)?;
            return Ok(()); // Exit after backup restore
        }
    }

    for e in entries.iter_mut() {
        e.password.zeroize();
    }
    Ok(())
}