//! GitHub Gist integration for encrypted database cloud storage
//!
//! This module provides functionality to sync the encrypted password database
//! with a private GitHub Gist. The database remains encrypted throughout transmission.

use anyhow::{Context, Result, anyhow, bail};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;

/// Configuration for GitHub sync
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubConfig {
    /// Personal access token (stored encrypted in config)
    pub token: String,
    /// GitHub Gist ID where database is stored
    pub gist_id: String,
    /// Whether to auto-sync after each change
    pub auto_sync: bool,
    /// Last successful sync timestamp
    pub last_sync: Option<String>,
}

impl GitHubConfig {
    pub fn new(token: String, gist_id: String) -> Self {
        Self {
            token,
            gist_id,
            auto_sync: false,
            last_sync: None,
        }
    }
}

/// GitHub API response for gist details
#[derive(Debug, Deserialize)]
struct GistResponse {
    id: String,
    url: String,
    files: HashMap<String, GistFile>,
}

/// Individual file in a gist
#[derive(Debug, Deserialize, Serialize)]
struct GistFile {
    filename: Option<String>,
    #[serde(default)]
    content: String,
    #[serde(default)]
    size: usize,
}

/// Main struct for GitHub Gist synchronization
pub struct GitHubSync {
    token: SecretString,
    gist_id: String,
}

impl GitHubSync {
    /// Creates a new GitHub sync handler
    pub fn new(token: String, gist_id: String) -> Self {
        Self {
            token: SecretString::new(token),
            gist_id,
        }
    }

    /// Gets the GitHub API base URL for this gist
    fn gist_url(&self) -> String {
        format!("https://api.github.com/gists/{}", self.gist_id)
    }

    /// Pushes encrypted database to GitHub Gist
    ///
    /// # Arguments
    /// * `encrypted_data` - The encrypted database bytes
    /// * `filename` - Name of the file in the gist (e.g., "pwdb.enc")
    ///
    /// # Returns
    /// * `Result<()>` - Success or error
    pub fn push_db(&self, encrypted_data: &[u8], filename: &str) -> Result<()> {
        // Encode encrypted data as base64 for safe JSON transmission
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        let encoded = engine.encode(encrypted_data);

        let client = reqwest::blocking::Client::new();

        // Get current gist to preserve other files
        let response = client
            .get(&self.gist_url())
            .header(
                "Authorization",
                format!("token {}", self.token.expose_secret()),
            )
            .header("Accept", "application/vnd.github.v3+json")
            .header("User-Agent", "rustwarden")
            .send()
            .context("failed to connect to GitHub API")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            bail!("GitHub API error ({}): {}", status, body);
        }

        let gist: GistResponse = response.json().context("failed to parse gist response")?;

        // Build updated files map
        let mut files = HashMap::new();
        for (name, file) in gist.files.iter() {
            if name != filename {
                files.insert(
                    name.clone(),
                    json!({
                        "content": file.content
                    }),
                );
            }
        }

        // Add/update the database file
        files.insert(
            filename.to_string(),
            json!({
                "content": encoded
            }),
        );

        // Update gist with new file
        let body = json!({
            "files": files
        });

        let response = client
            .patch(&self.gist_url())
            .header(
                "Authorization",
                format!("token {}", self.token.expose_secret()),
            )
            .header("Accept", "application/vnd.github.v3+json")
            .header("User-Agent", "rustwarden")
            .json(&body)
            .send()
            .context("failed to update gist")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            bail!("GitHub API error ({}): {}", status, body);
        }

        Ok(())
    }

    /// Pulls encrypted database from GitHub Gist
    ///
    /// # Arguments
    /// * `filename` - Name of the file in the gist (e.g., "pwdb.enc")
    ///
    /// # Returns
    /// * `Result<Vec<u8>>` - The decrypted database content
    pub fn pull_db(&self, filename: &str) -> Result<Vec<u8>> {
        let client = reqwest::blocking::Client::new();

        let response = client
            .get(&self.gist_url())
            .header(
                "Authorization",
                format!("token {}", self.token.expose_secret()),
            )
            .header("Accept", "application/vnd.github.v3+json")
            .header("User-Agent", "rustwarden")
            .send()
            .context("failed to connect to GitHub API")?;

        if !response.status().is_success() {
            let status = response.status();
            bail!("GitHub API error ({})", status);
        }

        let gist: GistResponse = response.json().context("failed to parse gist response")?;

        // Find the database file
        let file = gist
            .files
            .get(filename)
            .ok_or_else(|| anyhow!("file '{}' not found in gist", filename))?;

        // Decode base64 to get binary data
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        let decoded = engine
            .decode(&file.content)
            .context("failed to decode base64 from gist")?;

        Ok(decoded)
    }

    /// Creates a new private gist with the encrypted database
    ///
    /// # Arguments
    /// * `encrypted_data` - The encrypted database bytes
    /// * `filename` - Name of the file in the gist
    ///
    /// # Returns
    /// * `Result<String>` - The gist ID
    pub fn create_gist(&self, encrypted_data: &[u8], filename: &str) -> Result<String> {
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        let encoded = engine.encode(encrypted_data);

        let mut files = HashMap::new();
        files.insert(
            filename.to_string(),
            json!({
                "content": encoded
            }),
        );

        let body = json!({
            "public": false,
            "description": "rustwarden encrypted password database",
            "files": files
        });

        let client = reqwest::blocking::Client::new();

        let response = client
            .post("https://api.github.com/gists")
            .header(
                "Authorization",
                format!("token {}", self.token.expose_secret()),
            )
            .header("Accept", "application/vnd.github.v3+json")
            .header("User-Agent", "rustwarden")
            .json(&body)
            .send()
            .context("failed to create gist")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            bail!("GitHub API error ({}): {}", status, body);
        }

        let gist: GistResponse = response.json().context("failed to parse gist response")?;

        Ok(gist.id)
    }

    /// Validates the GitHub token by testing API access
    pub fn validate_token(&self) -> Result<String> {
        let client = reqwest::blocking::Client::new();

        let response = client
            .get("https://api.github.com/user")
            .header(
                "Authorization",
                format!("token {}", self.token.expose_secret()),
            )
            .header("Accept", "application/vnd.github.v3+json")
            .header("User-Agent", "rustwarden")
            .send()
            .context("failed to connect to GitHub API")?;

        if !response.status().is_success() {
            bail!("invalid GitHub token (HTTP {})", response.status());
        }

        let user_data: Value = response.json()?;
        let username = user_data
            .get("login")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        Ok(username.to_string())
    }

    /// Gets the status of the gist (checks if it exists and is accessible)
    pub fn check_gist_status(&self) -> Result<(bool, usize)> {
        let client = reqwest::blocking::Client::new();

        let response = client
            .get(&self.gist_url())
            .header(
                "Authorization",
                format!("token {}", self.token.expose_secret()),
            )
            .header("Accept", "application/vnd.github.v3+json")
            .header("User-Agent", "rustwarden")
            .send();

        match response {
            Ok(r) if r.status().is_success() => {
                if let Ok(gist) = r.json::<GistResponse>() {
                    let total_size: usize = gist.files.values().map(|f| f.size).sum();
                    Ok((true, total_size))
                } else {
                    Ok((false, 0))
                }
            }
            _ => Ok((false, 0)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_github_config_new() {
        let config = GitHubConfig::new("token123".to_string(), "gist123".to_string());
        assert_eq!(config.token, "token123");
        assert_eq!(config.gist_id, "gist123");
        assert!(!config.auto_sync);
        assert!(config.last_sync.is_none());
    }
}
