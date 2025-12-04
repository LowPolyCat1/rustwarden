#[cfg(test)]
mod tests {
    use crate::*;
    use secrecy::SecretString;
    use std::path::PathBuf;
    use tempfile::NamedTempFile;

    #[test]
    fn test_key_derivation() {
        let password = SecretString::new("test_password".to_string().into());
        let salt = [0u8; 16];

        let key1 = derive_key(&password, &salt).unwrap();
        let key2 = derive_key(&password, &salt).unwrap();

        // Same password and salt should produce same key
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), KEY_LEN);
    }

    #[test]
    fn test_key_derivation_different_salts() {
        let password = SecretString::new("test_password".to_string().into());
        let salt1 = [0u8; 16];
        let salt2 = [1u8; 16];

        let key1 = derive_key(&password, &salt1).unwrap();
        let key2 = derive_key(&password, &salt2).unwrap();

        // Different salts should produce different keys
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_encryption_decryption() {
        let password = SecretString::new("test_password".to_string().into());
        let plaintext = b"Hello, World! This is a test message.";

        let encrypted = encrypt_blob(plaintext, &password).unwrap();
        let decrypted = decrypt_blob(&encrypted, &password).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_encryption_different_each_time() {
        let password = SecretString::new("test_password".to_string().into());
        let plaintext = b"Hello, World!";

        let encrypted1 = encrypt_blob(plaintext, &password).unwrap();
        let encrypted2 = encrypt_blob(plaintext, &password).unwrap();

        // Should be different due to random salt and nonce
        assert_ne!(encrypted1, encrypted2);

        // But both should decrypt to same plaintext
        let decrypted1 = decrypt_blob(&encrypted1, &password).unwrap();
        let decrypted2 = decrypt_blob(&encrypted2, &password).unwrap();
        assert_eq!(decrypted1, decrypted2);
        assert_eq!(plaintext, decrypted1.as_slice());
    }

    #[test]
    fn test_decryption_wrong_password() {
        let password1 = SecretString::new("correct_password".to_string().into());
        let password2 = SecretString::new("wrong_password".to_string().into());
        let plaintext = b"Secret message";

        let encrypted = encrypt_blob(plaintext, &password1).unwrap();
        let result = decrypt_blob(&encrypted, &password2);

        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_invalid_data() {
        let password = SecretString::new("test_password".to_string().into());
        let invalid_data = b"not encrypted data";

        let result = decrypt_blob(invalid_data, &password);
        assert!(result.is_err());
    }

    #[test]
    fn test_password_generation_basic() {
        let password =
            generate_password(12, true, true, true, true, true, true, true, true).unwrap();

        assert_eq!(password.len(), 12);
        assert!(password.chars().any(|c| c.is_ascii_lowercase()));
        assert!(password.chars().any(|c| c.is_ascii_uppercase()));
        assert!(password.chars().any(|c| c.is_ascii_digit()));
        assert!(
            password
                .chars()
                .any(|c| "!@#$%^&*()-_=+[]{};:,.<>?/".contains(c))
        );
    }

    #[test]
    fn test_password_generation_no_requirements() {
        let password =
            generate_password(8, true, true, true, true, false, false, false, false).unwrap();
        assert_eq!(password.len(), 8);
    }

    #[test]
    fn test_password_generation_length_too_short() {
        let result = generate_password(2, true, true, true, true, true, true, true, true);
        assert!(result.is_err());
    }

    #[test]
    fn test_password_generation_no_character_sets() {
        let result = generate_password(8, false, false, false, false, false, false, false, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_password_generation_only_lowercase() {
        let password =
            generate_password(10, true, false, false, false, true, false, false, false).unwrap();

        assert_eq!(password.len(), 10);
        assert!(password.chars().all(|c| c.is_ascii_lowercase()));
    }

    #[test]
    fn test_db_save_load_empty() {
        let temp_file = NamedTempFile::new().unwrap();
        let db_path = PathBuf::from(temp_file.path());
        let password = SecretString::new("test_password".to_string().into());
        let entries: Vec<Entry> = vec![];

        save_db(&db_path, &entries, &password).unwrap();
        let loaded = load_db(&db_path, &password).unwrap();

        assert_eq!(loaded.len(), 0);
    }

    #[test]
    fn test_db_save_load_with_entries() {
        let temp_file = NamedTempFile::new().unwrap();
        let db_path = PathBuf::from(temp_file.path());
        let password = SecretString::new("test_password".to_string().into());

        let entries = vec![
            Entry {
                service: "gmail".to_string(),
                username: "user@gmail.com".to_string(),
                password: "secret123".to_string(),
            },
            Entry {
                service: "github".to_string(),
                username: "developer".to_string(),
                password: "github_token".to_string(),
            },
        ];

        save_db(&db_path, &entries, &password).unwrap();
        let loaded = load_db(&db_path, &password).unwrap();

        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].service, "gmail");
        assert_eq!(loaded[0].username, "user@gmail.com");
        assert_eq!(loaded[0].password, "secret123");
        assert_eq!(loaded[1].service, "github");
        assert_eq!(loaded[1].username, "developer");
        assert_eq!(loaded[1].password, "github_token");
    }

    #[test]
    fn test_db_load_nonexistent() {
        let db_path = PathBuf::from("nonexistent_file.enc");
        let password = SecretString::new("test_password".to_string().into());

        let loaded = load_db(&db_path, &password).unwrap();
        assert_eq!(loaded.len(), 0);
    }

    #[test]
    fn test_db_load_wrong_password() {
        let temp_file = NamedTempFile::new().unwrap();
        let db_path = PathBuf::from(temp_file.path());
        let password1 = SecretString::new("correct_password".to_string().into());
        let password2 = SecretString::new("wrong_password".to_string().into());

        let entries = vec![Entry {
            service: "test".to_string(),
            username: "user".to_string(),
            password: "pass".to_string(),
        }];

        save_db(&db_path, &entries, &password1).unwrap();
        let result = load_db(&db_path, &password2);

        assert!(result.is_err());
    }

    #[test]
    fn test_entry_serialization() {
        let entry = Entry {
            service: "test_service".to_string(),
            username: "test_user".to_string(),
            password: "test_password".to_string(),
        };

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: Entry = serde_json::from_str(&json).unwrap();

        assert_eq!(entry.service, deserialized.service);
        assert_eq!(entry.username, deserialized.username);
        assert_eq!(entry.password, deserialized.password);
    }
}
