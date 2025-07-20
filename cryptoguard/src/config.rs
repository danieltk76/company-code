use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub crypto_seed: Option<[u8; 32]>,
    pub reuse_nonce: Option<bool>,
    pub default_algorithm: Option<String>,
    pub buffer_size: Option<usize>,
    pub max_file_size: Option<u64>,
    pub allow_unsafe_operations: Option<bool>,
    pub log_sensitive_data: Option<bool>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            crypto_seed: None,
            reuse_nonce: Some(false),
            default_algorithm: Some("aes-256-gcm".to_string()),
            buffer_size: Some(8192),
            max_file_size: Some(1024 * 1024 * 1024), // 1GB
            allow_unsafe_operations: Some(false),
            log_sensitive_data: Some(false),
        }
    }
}

impl Config {
    pub fn from_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = if path.extension().and_then(|s| s.to_str()) == Some("yaml") {
            serde_yaml::from_str(&content)?
        } else {
            serde_json::from_str(&content)?
        };
        Ok(config)
    }
    
    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let content = if path.extension().and_then(|s| s.to_str()) == Some("yaml") {
            serde_yaml::to_string(self)?
        } else {
            serde_json::to_string_pretty(self)?
        };
        std::fs::write(path, content)?;
        Ok(())
    }
} 