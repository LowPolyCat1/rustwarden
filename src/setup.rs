use anyhow::{Context, Result, bail};
use console::style;
use secrecy::ExposeSecret;
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
        let config_dir = get_config_dir();
        Self {
            db_path: config_dir.join("pwdb.enc"),
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

/// Gets the configuration directory
pub fn get_config_dir() -> PathBuf {
    if let Some(config_dir) = dirs::config_dir() {
        config_dir.join("rustwarden")
    } else {
        PathBuf::from(".rustwarden")
    }
}

/// Gets the path to the configuration file
pub fn get_config_path() -> PathBuf {
    get_config_dir().join("config.toml")
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
    println!(
        "{}",
        style("encrypted password manager - first time setup").dim()
    );
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

    print!(
        "{} {}: ",
        style(prompt).green(),
        style(format!("[{}]", default)).dim()
    );
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
    print!(
        "{} {}: ",
        style(prompt).green(),
        style(format!("[{}]", default_str)).dim()
    );
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim().to_lowercase();

    match input.as_str() {
        "" => Ok(default),
        "y" | "yes" => Ok(true),
        "n" | "no" => Ok(false),
        _ => {
            println!(
                "{}",
                style("error: please enter 'y' for yes or 'n' for no").red()
            );
            prompt_yes_no(prompt, default, None)
        }
    }
}

/// Runs the interactive setup wizard
pub fn run_setup_wizard() -> Result<Config> {
    display_welcome_banner()?;

    // Database location
    println!("{}", style("database configuration").yellow().bold());
    let default_db_path = get_config_dir().join("pwdb.enc");
    let db_path = prompt_with_default(
        "  path",
        &default_db_path.to_string_lossy(),
        Some("where to store your encrypted password database"),
    )?;

    println!();

    // Security settings
    println!("{}", style("security configuration").yellow().bold());
    let clear_seconds_str = prompt_with_default(
        "  clipboard timeout",
        "15",
        Some("seconds before passwords are cleared from clipboard"),
    )?;
    let clear_seconds: u64 = clear_seconds_str
        .parse()
        .context("invalid number for clipboard timeout")?;

    println!();

    // Backup settings
    println!("{}", style("backup configuration").yellow().bold());
    let auto_backup = prompt_yes_no(
        "  enable backups",
        false,
        Some("automatically backup database on changes"),
    )?;

    let backup_path = if auto_backup {
        let default_backup_path = get_config_dir().join("backups");
        let path = prompt_with_default(
            "  backup directory",
            &default_backup_path.to_string_lossy(),
            Some("directory to store backup files"),
        )?;
        Some(PathBuf::from(path))
    } else {
        None
    };

    println!();

    // PATH shortcut configuration
    println!("{}", style("system integration").yellow().bold());
    let add_to_path = prompt_yes_no(
        "  add to PATH",
        true,
        Some("allows running 'rustwarden' from anywhere in terminal"),
    )?;

    println!();

    // Master password setup
    println!("{}", style("master password setup").yellow().bold());
    println!(
        "  {}",
        style("your master password encrypts all stored data").dim()
    );
    println!("  {}", style("choose something strong but memorable").dim());
    println!();

    let master_password = loop {
        print!("  {}: ", style("master password").green());
        io::stdout().flush()?;
        let password1 = crate::read_password("")?;

        print!("  {}: ", style("confirm password").green());
        io::stdout().flush()?;
        let password2 = crate::read_password("")?;

        if password1.expose_secret() == password2.expose_secret() {
            if password1.expose_secret().len() < 8 {
                println!(
                    "  {}",
                    style("warning: password should be at least 8 characters").yellow()
                );
                if !prompt_yes_no("  use anyway", false, None)? {
                    continue;
                }
            }
            break password1;
        } else {
            println!("  {}", style("error: passwords do not match").red());
        }
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
    println!(
        "  {}: {}",
        style("database").cyan(),
        config.db_path.display()
    );
    println!(
        "  {}: {}s",
        style("clipboard timeout").cyan(),
        config.default_clear_seconds
    );
    println!(
        "  {}: {}",
        style("backups").cyan(),
        if config.auto_backup {
            style("enabled").green()
        } else {
            style("disabled").red()
        }
    );
    if let Some(ref backup_path) = config.backup_path {
        println!(
            "  {}: {}",
            style("backup path").cyan(),
            backup_path.display()
        );
    }
    println!(
        "  {}: {}",
        style("PATH integration").cyan(),
        if add_to_path {
            style("enabled").green()
        } else {
            style("disabled").red()
        }
    );

    println!();
    if prompt_yes_no("save configuration", true, None)? {
        save_config(&config)?;

        // Create backup directory only if backups are enabled
        if config.auto_backup {
            if let Some(ref backup_path) = config.backup_path {
                fs::create_dir_all(backup_path).context("failed to create backup directory")?;
            }
        }

        // Add to PATH if requested
        if add_to_path {
            setup_path_integration()?;
        }

        // Create initial empty database with master password
        let db_path_full = config.db_path.clone();

        let empty_entries: Vec<crate::Entry> = vec![];
        crate::save_db(&db_path_full, &empty_entries, &master_password)?;

        clear_screen()?;
        println!("{}", style("✓ setup complete").green().bold());
        println!();
        println!("{}: {}", style("config").dim(), get_config_path().display());
        println!("{}: {}", style("database").dim(), config.db_path.display());
        if add_to_path {
            println!("{}: {}", style("PATH").dim(), style("integrated").green());
        }
        println!();
        println!("{}", style("security notice").red().bold());
        println!("  • your master password is never stored");
        println!("  • if forgotten, data cannot be recovered");
        println!("  • database has been initialized and encrypted");
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
    clear_screen()?;
    println!("{}", style("rustwarden").cyan().bold());
    println!("{}", style("using default configuration").dim());

    let config = Config::default();
    save_config(&config)?;

    println!();
    println!(
        "{}: {}",
        style("config").green(),
        get_config_path().display()
    );
    println!(
        "{}: {}",
        style("database").green(),
        config.db_path.display()
    );

    Ok(config)
}

/// Sets up PATH integration for the current executable
fn setup_path_integration() -> Result<()> {
    let exe_path = std::env::current_exe().context("failed to get current executable path")?;

    let exe_dir = exe_path
        .parent()
        .context("failed to get executable directory")?;

    #[cfg(windows)]
    {
        // On Windows, try to add to user PATH via registry
        use std::process::Command;

        let output = Command::new("powershell")
            .args(&[
                "-Command",
                &format!(
                    "$env:PATH += ';{}'; [Environment]::SetEnvironmentVariable('PATH', $env:PATH, 'User')",
                    exe_dir.display()
                )
            ])
            .output();

        match output {
            Ok(_) => {
                println!(
                    "  {}",
                    style("✓ added to Windows PATH (restart terminal to use)").green()
                );
            }
            Err(_) => {
                println!("  {}", style("⚠ manual PATH setup required").yellow());
                println!("    add this directory to your PATH: {}", exe_dir.display());
            }
        }
    }

    #[cfg(not(windows))]
    {
        // On Unix-like systems, suggest adding to shell profile
        let shell_profile = if let Ok(shell) = std::env::var("SHELL") {
            if shell.contains("zsh") {
                "~/.zshrc"
            } else if shell.contains("fish") {
                "~/.config/fish/config.fish"
            } else {
                "~/.bashrc"
            }
        } else {
            "~/.bashrc"
        };

        println!("  {}", style("manual PATH setup required").yellow());
        println!("    add this line to {}:", shell_profile);
        println!("    export PATH=\"{}:$PATH\"", exe_dir.display());
    }

    Ok(())
}

/// Loads a backup file and restores it as the main database
pub fn load_backup(backup_path: &PathBuf, master_password: &secrecy::SecretString) -> Result<()> {
    if !backup_path.exists() {
        bail!("backup file not found: {}", backup_path.display());
    }

    // Load and verify the backup
    let backup_entries =
        crate::load_db(backup_path, master_password).context("failed to load backup file")?;

    println!("{}", style("backup contents:").yellow().bold());
    if backup_entries.is_empty() {
        println!("  {}", style("no entries found").dim());
    } else {
        for entry in &backup_entries {
            if entry.username.is_empty() {
                println!("  {}", style(&entry.service).cyan());
            } else {
                println!(
                    "  {} {}",
                    style(&entry.service).cyan(),
                    style(format!("({})", entry.username)).dim()
                );
            }
        }
    }

    println!();
    if !prompt_yes_no(
        "restore this backup",
        false,
        Some("this will overwrite your current database"),
    )? {
        println!("{}", style("backup restore cancelled").yellow());
        return Ok(());
    }

    // Get current config to find main database path
    let config = load_config()?;
    let main_db_path = config.db_path;

    // Create backup of current database before restoring
    if main_db_path.exists() {
        let backup_name = format!(
            "backup_before_restore_{}.enc",
            chrono::Utc::now().format("%Y%m%d_%H%M%S")
        );
        let safety_backup = main_db_path.with_file_name(backup_name);

        fs::copy(&main_db_path, &safety_backup).context("failed to create safety backup")?;

        println!(
            "  {}: {}",
            style("safety backup created").green(),
            safety_backup.display()
        );
    }

    // Restore the backup
    crate::save_db(&main_db_path, &backup_entries, master_password)
        .context("failed to restore backup")?;

    println!("{}", style("✓ backup restored successfully").green().bold());
    println!("  {} entries restored", backup_entries.len());

    Ok(())
}
