use criterion::{Criterion, black_box, criterion_group, criterion_main};
use rustwarden::*;
use secrecy::SecretString;
use std::path::PathBuf;
use tempfile::NamedTempFile;

fn bench_key_derivation(c: &mut Criterion) {
    let password = SecretString::new("test_password".to_string());
    let salt = [0u8; 16];

    c.bench_function("derive_key", |b| {
        b.iter(|| derive_key(black_box(&password), black_box(&salt)).unwrap())
    });
}

fn bench_encryption(c: &mut Criterion) {
    let password = SecretString::new("test_password".to_string());
    let data = b"Hello, World! This is test data for encryption benchmarking.";

    c.bench_function("encrypt_blob", |b| {
        b.iter(|| encrypt_blob(black_box(data), black_box(&password)).unwrap())
    });
}

fn bench_decryption(c: &mut Criterion) {
    let password = SecretString::new("test_password".to_string());
    let data = b"Hello, World! This is test data for encryption benchmarking.";
    let encrypted = encrypt_blob(data, &password).unwrap();

    c.bench_function("decrypt_blob", |b| {
        b.iter(|| decrypt_blob(black_box(&encrypted), black_box(&password)).unwrap())
    });
}

fn bench_password_generation(c: &mut Criterion) {
    c.bench_function("generate_password", |b| {
        b.iter(|| {
            generate_password(
                black_box(16),
                black_box(true),
                black_box(true),
                black_box(true),
                black_box(true),
                black_box(true),
                black_box(true),
                black_box(true),
                black_box(true),
            )
            .unwrap()
        })
    });
}

fn bench_db_operations(c: &mut Criterion) {
    let password = SecretString::new("test_password".to_string());
    let entries = vec![
        Entry {
            service: "test1".to_string(),
            username: "user1".to_string(),
            password: "pass1".to_string(),
        },
        Entry {
            service: "test2".to_string(),
            username: "user2".to_string(),
            password: "pass2".to_string(),
        },
    ];

    c.bench_function("save_and_load_db", |b| {
        b.iter(|| {
            let temp_file = NamedTempFile::new().unwrap();
            let db_path = PathBuf::from(temp_file.path());

            save_db(
                black_box(&db_path),
                black_box(&entries),
                black_box(&password),
            )
            .unwrap();
            load_db(black_box(&db_path), black_box(&password)).unwrap()
        })
    });
}

criterion_group!(
    benches,
    bench_key_derivation,
    bench_encryption,
    bench_decryption,
    bench_password_generation,
    bench_db_operations
);
criterion_main!(benches);
