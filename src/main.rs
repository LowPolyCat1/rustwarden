use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use console::style;
use rustwarden::*;
use std::io::{self, Write};
use std::path::PathBuf;
use zeroize::Zeroize;

/// Helper function to perform auto-sync after database changes
fn perform_auto_sync(config: &mut setup::Config, db_path: &PathBuf) -> Result<()> {
    if let Some(ref mut gh) = config.github_config {
        if gh.auto_sync {
            println!("{}", style("  syncing to GitHub...").dim());

            if let Ok(db_bytes) = std::fs::read(&db_path) {
                // Create gist if it doesn't exist yet
                if gh.gist_id == "new" {
                    let sync = github_sync::GitHubSync::new(gh.token.clone(), "new".to_string());
                    match sync.create_gist(&db_bytes, "pwdb.enc") {
                        Ok(gist_id) => {
                            gh.gist_id = gist_id.clone();
                            println!("{} created gist: {}", style("✓").green(), gist_id);
                            // Save config with new gist ID
                            setup::save_config(&config)?;
                        }
                        Err(e) => {
                            println!(
                                "{} {}",
                                style("  ⚠ sync failed to create gist:").yellow(),
                                e
                            );
                            return Ok(()); // Don't fail, just skip sync
                        }
                    }
                } else {
                    let sync = github_sync::GitHubSync::new(gh.token.clone(), gh.gist_id.clone());
                    match sync.push_db(&db_bytes, "pwdb.enc") {
                        Ok(updated_at) => {
                            gh.last_sync = updated_at;
                            setup::save_config(&config)?;
                            println!("{}", style("  ✓ synced").green());
                        }
                        Err(e) => println!("{} {}", style("  ⚠ sync failed:").yellow(), e),
                    }
                }
            }
        }
    }
    Ok(())
}

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
        username: Option<String>,
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
    /// Sync database with GitHub Gist
    Sync {
        /// Push database to GitHub
        #[arg(long)]
        push: bool,
        /// Pull database from GitHub
        #[arg(long)]
        pull: bool,
        /// Check sync status
        #[arg(long)]
        status: bool,
        /// Force pull even if remote isn't newer
        #[arg(long)]
        force: bool,
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
    let db_path = cli
        .db
        .as_ref()
        .map(|p| p.clone())
        .unwrap_or_else(|| config.db_path.clone());

    // If no command provided, show help
    let Some(cmd) = cli.cmd else {
        clearscreen::clear().ok();
        println!("{}", style("rustwarden").cyan().bold());
        println!("{}", style("encrypted password manager").dim());
        println!();
        println!("{}", style("usage:").yellow().bold());
        println!(
            "  {} {} {}",
            style("rustwarden").cyan(),
            style("<command>").green(),
            style("[args]").dim()
        );
        println!();
        println!("{}", style("commands:").yellow().bold());
        println!(
            "  {} {}    {}",
            style("add").green(),
            style("<service> <username>").dim(),
            style("add password entry").white()
        );
        println!(
            "  {} {}               {}",
            style("get").green(),
            style("<service>").dim(),
            style("retrieve password").white()
        );
        println!(
            "  {} {}               {}",
            style("new").green(),
            style("<service>").dim(),
            style("generate new password").white()
        );
        println!(
            "  {}                        {}",
            style("list").green(),
            style("list all services").white()
        );
        println!(
            "  {} {}            {}",
            style("delete").green(),
            style("<service>").dim(),
            style("remove entry").white()
        );
        println!(
            "  {} {}        {}",
            style("load-backup").green(),
            style("<file>").dim(),
            style("restore from backup").white()
        );
        println!(
            "  {}                     {}",
            style("sync").green(),
            style("manage GitHub sync").white()
        );
        println!();
        println!("{}", style("options:").yellow().bold());
        println!(
            "  {}                     {}",
            style("--setup").cyan(),
            style("run configuration wizard").white()
        );
        println!(
            "  {}                      {}",
            style("--help").cyan(),
            style("show detailed help").white()
        );
        return Ok(());
    };

    clearscreen::clear().ok();
    print!("{}: ", style("master password").green());
    io::stdout().flush().unwrap();
    let master = read_password("")?;
    let mut entries = load_db(&db_path, &master)?;
    let mut config = config; // Make config mutable for auto-sync

    match cmd {
        Commands::Sync { push, pull, status, force } => {
            // Sync command doesn't need master password to be read yet for status
            if status {
                if let Some(ref gh) = config.github_config {
                    let sync = github_sync::GitHubSync::new(gh.token.clone(), gh.gist_id.clone());
                    match sync.check_gist_status() {
                        Ok((exists, size)) => {
                            if exists {
                                println!("{} Gist is accessible", style("✓").green());
                                println!("  {} {} bytes", style("size:").dim(), size);
                                if let Some(timestamp) = &gh.last_sync {
                                    println!("  {} {}", style("last sync:").dim(), timestamp);
                                }
                            } else {
                                println!("{} Gist not found or not accessible", style("✗").red());
                            }
                        }
                        Err(e) => {
                            println!("{} Error checking gist: {}", style("✗").red(), e);
                        }
                    }
                } else {
                    println!("{}", style("error: GitHub sync not configured").red());
                    println!("  run 'rustwarden --setup' to enable it");
                }
                return Ok(());
            }

            // Push and pull need master password
            if !push && !pull {
                println!("{}", style("error: specify --push or --pull").red());
                return Err(anyhow::anyhow!("no sync action specified"));
            }

            if let Some(ref gh) = config.github_config {
                let sync = github_sync::GitHubSync::new(gh.token.clone(), gh.gist_id.clone());

                if push {
                    // Read encrypted database to push
                    let db_bytes =
                        std::fs::read(&db_path).context("failed to read database file")?;

                    println!("{}", style("pushing database to GitHub...").cyan());

                    // Handle new gist creation
                    let mut config_updated = config.clone();

                    let gist_id = if gh.gist_id == "new" {
                        match sync.create_gist(&db_bytes, "pwdb.enc") {
                            Ok(id) => {
                                println!("{} created new gist: {}", style("✓").green(), id);
                                // Update config with new gist ID
                                if let Some(ref mut gh_config) = config_updated.github_config {
                                    gh_config.gist_id = id.clone();
                                }
                                id
                            }
                            Err(e) => {
                                println!("{} failed to create gist: {}", style("✗").red(), e);
                                return Err(e);
                            }
                        }
                    } else {
                        gh.gist_id.clone()
                    };

                    // Create sync handler with actual gist ID
                    let sync_final =
                        github_sync::GitHubSync::new(gh.token.clone(), gist_id.clone());

                    match sync_final.push_db(&db_bytes, "pwdb.enc") {
                        Ok(updated_at) => {
                            println!("{} database pushed successfully", style("✓").green());
                            println!("  {} {}", style("gist:").dim(), gist_id);

                            // Update last_sync timestamp
                            if let Some(ref mut gh_config) = config_updated.github_config {
                                gh_config.last_sync = updated_at;
                            }

                            // Save updated config (either with new gist ID or updated timestamp)
                            setup::save_config(&config_updated)?;
                            if gh.gist_id == "new" {
                                println!("{} config updated with gist ID", style("✓").green());
                            }
                        }
                        Err(e) => {
                            println!("{} failed to push database: {}", style("✗").red(), e);
                            return Err(e);
                        }
                    }
                }

                if pull {
                    if gh.gist_id == "new" {
                        println!("{}", style("error: no gist configured yet").red());
                        println!("  run 'rustwarden sync --push' to create one");
                        return Err(anyhow::anyhow!("no gist configured"));
                    }

                    println!("{}", style("pulling database from GitHub...").cyan());

                    match sync.pull_db("pwdb.enc", force, &gh.last_sync) {
                        Ok((encrypted_data, updated_at)) => {
                            // Backup current database before pulling
                            if db_path.exists() {
                                let backup_name = format!(
                                    "backup_before_sync_{}.enc",
                                    chrono::Utc::now().format("%Y%m%d_%H%M%S")
                                );
                                let safety_backup = db_path.with_file_name(backup_name);
                                std::fs::copy(&db_path, &safety_backup)
                                    .context("failed to create safety backup")?;
                                println!(
                                    "  {} {}",
                                    style("safety backup:").dim(),
                                    safety_backup.display()
                                );
                            }

                            // Write pulled data
                            std::fs::write(&db_path, encrypted_data)
                                .context("failed to write synced database")?;

                            // Update last_sync timestamp
                            if let Some(ref mut gh_config) = config.github_config {
                                gh_config.last_sync = updated_at;
                                setup::save_config(&config)?;
                            }

                            println!("{} database pulled successfully", style("✓").green());
                            println!(
                                "  {} entries updated",
                                style("reload entries with 'get' or 'list'").dim()
                            );
                        }
                        Err(e) => {
                            println!("{} failed to pull database: {}", style("✗").red(), e);
                            return Err(e);
                        }
                    }
                }
            } else {
                println!("{}", style("error: GitHub sync not configured").red());
                println!("  run 'rustwarden --setup' to enable it");
                return Err(anyhow::anyhow!("GitHub sync not configured"));
            }
            return Ok(());
        }
        Commands::Add { service, username } => {
            print!("{}: ", style("password").green());
            io::stdout().flush().unwrap();
            let pass = rpassword::prompt_password("").context("failed to read password")?;
            if entries.iter().any(|e| e.service == service) {
                println!(
                    "{}",
                    style(format!("error: service '{}' already exists", service)).red()
                );
                std::process::exit(1);
            }
            entries.push(Entry {
                service: service.clone(),
                username: username.unwrap_or("".to_string()),
                password: pass,
            });
            save_db(&db_path, &entries, &master).context("failed to save database")?;
            println!("{} {}", style("✓ added:").green(), style(&service).cyan());

            // Auto-sync if enabled
            let _ = perform_auto_sync(&mut config, &db_path);
        }
        Commands::Get { service, clear } => {
            if let Some(e) = entries.iter().find(|e| e.service == service) {
                let secs = clear.unwrap_or(config.default_clear_seconds);
                copy_to_clipboard_with_clear(&e.password, secs)?;
                println!(
                    "{} {} {}",
                    style("✓ copied to clipboard").green(),
                    style(format!("({}s", secs)).dim(),
                    style("timeout)").dim()
                );
            } else {
                println!(
                    "{}",
                    style(format!("error: service '{}' not found", service)).red()
                );
                std::process::exit(1);
            }
        }
        Commands::Delete { service } => {
            let orig_len = entries.len();
            entries.retain(|e| e.service != service);
            if entries.len() == orig_len {
                println!(
                    "{}",
                    style(format!("error: service '{}' not found", service)).red()
                );
                std::process::exit(1);
            }
            save_db(&db_path, &entries, &master)?;
            println!("{} {}", style("✓ deleted:").red(), style(&service).cyan());

            // Auto-sync if enabled
            let _ = perform_auto_sync(&mut config, &db_path);
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
                        println!(
                            "  {} {}",
                            style(&e.service).cyan(),
                            style(format!("({})", e.username)).dim()
                        );
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
                println!(
                    "{}",
                    style(format!("error: service '{}' already exists", name)).red()
                );
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
            println!(
                "{} {} {} {}",
                style("✓ generated:").green(),
                style(&name).cyan(),
                style(format!("({}s", clear)).dim(),
                style("timeout)").dim()
            );

            // Auto-sync if enabled
            let _ = perform_auto_sync(&mut config, &db_path);
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
