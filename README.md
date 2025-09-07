# RustWarden

A secure, local password manager built in Rust.

## Features

- **Strong Security**: ChaCha20Poly1305 encryption with Argon2id key derivation
- **Local Storage**: Your passwords never leave your device
- **Clipboard Integration**: Automatic password copying with configurable auto-clear
- **Password Generation**: Customizable password generation with character set requirements
- **Backup System**: Optional automatic backups with restore functionality
- **Clean CLI**: Colorful terminal interface with interactive setup
- **Cross-Platform**: Works on Windows, macOS, and Linux

## Security

RustWarden uses industry-standard cryptographic primitives:

- **Encryption**: ChaCha20Poly1305 (AEAD cipher)
- **Key Derivation**: Argon2id with 64MB memory, 3 iterations
- **Random Generation**: OS-provided cryptographically secure random number generator
- **Memory Safety**: Automatic zeroing of sensitive data using `zeroize`
- **Master Password**: Never stored, required for every database access

## Installation

### From Source

```bash
git clone https://github.com/yourusername/rustwarden.git
cd rustwarden
cargo build --release
```

The binary will be available at `target/release/rustwarden` (or `rustwarden.exe` on Windows).

### System Integration

During first-time setup, RustWarden can automatically integrate with your system PATH, allowing you to run `rustwarden` from anywhere in your terminal.

## Quick Start

1. **First Run**: RustWarden will automatically launch the setup wizard
   ```bash
   ./rustwarden list
   ```

2. **Add a Password**: Store a new password entry
   ```bash
   rustwarden add github myusername
   ```

3. **Generate a Password**: Create and store a new secure password
   ```bash
   rustwarden new gmail --length 16 --require-symbols
   ```

4. **Retrieve a Password**: Copy password to clipboard
   ```bash
   rustwarden get github
   ```

5. **List All Entries**: View all stored services
   ```bash
   rustwarden list
   ```

## Commands

### Core Operations

```bash
# Add a new password entry
rustwarden add <service> <username>

# Retrieve a password (copies to clipboard)
rustwarden get <service> [--clear <seconds>]

# Delete a password entry
rustwarden delete <service>

# List all stored services
rustwarden list
```

### Password Generation

```bash
# Generate a new password with defaults
rustwarden new <service>

# Customize password generation
rustwarden new <service> \
  --length 20 \
  --no-symbols \
  --require-uppercase \
  --require-digits
```

#### Generation Options

- `--length <n>`: Password length (default: 12)
- `--[no-]lowercase`: Include/exclude lowercase letters
- `--[no-]uppercase`: Include/exclude uppercase letters
- `--[no-]digits`: Include/exclude numbers
- `--[no-]symbols`: Include/exclude special characters
- `--require-*`: Ensure at least one character from each enabled set
- `--clear <seconds>`: Clipboard auto-clear timeout (default: 15)

### Database Management

```bash
# Use custom database file
rustwarden --db /path/to/custom.enc list

# Load from backup
rustwarden load-backup /path/to/backup.enc
```

## Configuration

RustWarden stores its configuration in OS-standard directories:

- **Linux/macOS**: `~/.config/rustwarden/`
- **Windows**: `%APPDATA%\rustwarden\`

### Configuration Structure

```
~/.config/rustwarden/
├── config.toml          # Main configuration
├── pwdb.enc            # Encrypted password database
└── backups/            # Automatic backups (if enabled)
    ├── backup_20241201_143022.enc
    └── backup_20241201_150315.enc
```

### Configuration File

```toml
[database]
path = "/home/user/.config/rustwarden/pwdb.enc"

[security]
default_clear_seconds = 15

[backup]
enabled = true
path = "/home/user/.config/rustwarden/backups"
```

## Security Best Practices

### Master Password

- **Choose a strong, memorable passphrase**: Use 4+ random words or a long sentence
- **Never reuse**: Don't use your master password anywhere else
- **No recovery**: If forgotten, your data cannot be recovered
- **Not stored**: Your master password is never saved to disk

### General Security

- **Regular backups**: Enable automatic backups or manually export regularly
- **Secure storage**: Keep backup files in encrypted storage
- **Clean environment**: Use RustWarden on trusted devices only
- **Clipboard hygiene**: Passwords auto-clear from clipboard after timeout

## Backup and Recovery

### Automatic Backups

Enable during setup or manually configure:

```toml
[backup]
enabled = true
path = "/path/to/backup/directory"
```

Backups are created automatically when:
- Adding new entries
- Modifying existing entries
- Deleting entries

### Manual Backup

```bash
# Copy your database file
cp ~/.config/rustwarden/pwdb.enc /secure/backup/location/
```

### Restore from Backup

```bash
rustwarden load-backup /path/to/backup.enc
```

The restore process:
1. Shows backup contents for verification
2. Creates a safety backup of current database
3. Replaces current database with backup data

## Development

### Building

```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release

# Run tests
cargo test

# Run benchmarks
cargo bench
```

### Project Structure

```
src/
├── lib.rs           # Core cryptographic functions
├── main.rs          # CLI application and command handling
├── setup.rs         # Interactive setup wizard and configuration
└── test.rs          # Unit tests

benches/
└── bench.rs         # Performance benchmarks
```

### Dependencies

- **Cryptography**: `chacha20poly1305`, `argon2`, `rand`
- **CLI**: `clap`, `console`, `rpassword`
- **Utilities**: `anyhow`, `serde`, `dirs`, `arboard`
- **Security**: `secrecy`, `zeroize`

## Performance

Performance characteristics:

- **Key derivation**: ~100ms on modern hardware
- **Encryption/Decryption**: <1ms for typical databases
- **Memory usage**: <10MB typical, 64MB during key derivation
- **Database size**: ~100 bytes per entry + encryption overhead

Run benchmarks: `cargo bench`

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes with tests
4. Run the test suite: `cargo test`
5. Submit a pull request

### Code Style

- Follow Rust standard formatting: `cargo fmt`
- Pass all lints: `cargo clippy`
- Add tests for new functionality
- Document public APIs with examples

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [Rust](https://www.rust-lang.org/)
- Cryptography by [RustCrypto](https://github.com/RustCrypto)
- CLI framework by [clap](https://github.com/clap-rs/clap)

---

**Important**: This software handles sensitive data. While built with security best practices, use at your own risk. Always maintain secure backups of your password database.
