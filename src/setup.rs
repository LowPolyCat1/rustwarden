use anyhow::{Context, Result};
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

/// Displays a nice welcome banner
fn display_welcome_banner() {
    println!("\n{}", "═".repeat(70));
    println!(
        "{}🔐 Welcome to RustWarden - Secure Password Manager 🔐{}",
        " ".repeat(10),
        " ".repeat(10)
    );
    println!("{}", "═".repeat(70));
    println!();
    println!("  Thank you for choosing RustWarden! This setup wizard will help");
    println!("  you configure your password manager for optimal security and");
    println!("  convenience.");
    println!();
    println!("  Features:");
    println!("  • Military-grade ChaCha20Poly1305 encryption");
    println!("  • Argon2id key derivation (64MB memory, 3 iterations)");
    println!("  • Automatic clipboard clearing");
    println!("  • Secure password generation");
    println!("  • Local storage (no cloud, maximum privacy)");
    println!();
    println!("{}", "═".repeat(70));
    println!();
}

/// Prompts user for input with a default value
fn prompt_with_default(prompt: &str, default: &str) -> Result<String> {
    print!("  {} [{}]: ", prompt, default);
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

/// Prompts user for yes/no input
fn prompt_yes_no(prompt: &str, default: bool) -> Result<bool> {
    let default_str = if default { "Y/n" } else { "y/N" };
    print!("  {} [{}]: ", prompt, default_str);
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim().to_lowercase();

    match input.as_str() {
        "" => Ok(default),
        "y" | "yes" => Ok(true),
        "n" | "no" => Ok(false),
        _ => {
            println!("    Please enter 'y' for yes or 'n' for no.");
            prompt_yes_no(prompt, default)
        }
    }
}

/// Runs the interactive setup wizard
pub fn run_setup_wizard() -> Result<Config> {
    display_welcome_banner();

    println!("📋 Configuration Setup");
    println!("{}", "─".repeat(25));
    println!();

    // Database location
    println!("1. Database Location");
    println!("   Where would you like to store your encrypted password database?");
    let db_path = prompt_with_default("Database file path", "pwdb.enc")?;
    println!();

    // Clipboard clear time
    println!("2. Security Settings");
    println!("   How long should passwords stay in your clipboard before auto-clearing?");
    let clear_seconds_str = prompt_with_default("Clipboard clear time (seconds)", "15")?;
    let clear_seconds: u64 = clear_seconds_str
        .parse()
        .context("Invalid number for clipboard clear time")?;
    println!();

    // Backup settings
    println!("3. Backup Configuration");
    println!("   Would you like to enable automatic backups of your database?");
    let auto_backup = prompt_yes_no("Enable automatic backups", false)?;

    let backup_path = if auto_backup {
        println!("   Where would you like to store backup files?");
        let path = prompt_with_default("Backup directory", "backups")?;
        Some(PathBuf::from(path))
    } else {
        None
    };
    println!();

    // Security notice
    println!("🔒 Security Notice");
    println!("{}", "─".repeat(20));
    println!("   • Your master password is NEVER stored anywhere");
    println!("   • All data is encrypted with your master password");
    println!("   • If you forget your master password, your data cannot be recovered");
    println!("   • Choose a strong, memorable master password");
    println!();

    // Final confirmation
    let config = Config {
        db_path: PathBuf::from(db_path),
        default_clear_seconds: clear_seconds,
        auto_backup,
        backup_path,
    };

    println!("📝 Configuration Summary");
    println!("{}", "─".repeat(28));
    println!("   Database file: {}", config.db_path.display());
    println!(
        "   Clipboard clear time: {} seconds",
        config.default_clear_seconds
    );
    println!(
        "   Auto backup: {}",
        if config.auto_backup {
            "Enabled"
        } else {
            "Disabled"
        }
    );
    if let Some(ref backup_path) = config.backup_path {
        println!("   Backup location: {}", backup_path.display());
    }
    println!();

    if prompt_yes_no("Save this configuration", true)? {
        save_config(&config)?;

        // Create backup directory if needed
        if let Some(ref backup_path) = config.backup_path {
            fs::create_dir_all(backup_path).context("Failed to create backup directory")?;
        }

        println!();
        println!("✅ Setup completed successfully!");
        println!();
        println!("🚀 Quick Start Guide");
        println!("{}", "─".repeat(22));
        println!("   • Add a password:     rustwarden add <service> <username>");
        println!("   • Get a password:     rustwarden get <service>");
        println!("   • Generate password:  rustwarden new <service>");
        println!("   • List all services:  rustwarden list");
        println!("   • Delete a password:  rustwarden delete <service>");
        println!();
        println!("   For more options, run: rustwarden --help");
        println!();
        println!("{}", "═".repeat(70));
        println!("  🎉 Welcome to secure password management with RustWarden! 🎉");
        println!("{}", "═".repeat(70));
        println!();

        Ok(config)
    } else {
        println!("Setup cancelled. You can run setup again anytime.");
        std::process::exit(0);
    }
}

/// Saves configuration to file
pub fn save_config(config: &Config) -> Result<()> {
    let config_path = get_config_path();

    // Create config directory if it doesn't exist
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent).context("Failed to create config directory")?;
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

    fs::write(&config_path, toml_content).context("Failed to write configuration file")?;

    Ok(())
}

/// Loads configuration from file
pub fn load_config() -> Result<Config> {
    let config_path = get_config_path();

    if !config_path.exists() {
        return Ok(Config::default());
    }

    let content = fs::read_to_string(&config_path).context("Failed to read configuration file")?;

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
                    config.default_clear_seconds = value
                        .parse()
                        .context("Invalid default_clear_seconds in config")?;
                }
                "enabled" => {
                    config.auto_backup = value
                        .parse()
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
    println!("🔐 RustWarden - First Time Setup");
    println!("Using default configuration...");

    let config = Config::default();
    save_config(&config)?;

    println!(
        "✅ Setup complete! Database will be stored as: {}",
        config.db_path.display()
    );
    println!("Run with --help to see all available commands.");

    Ok(config)
}
