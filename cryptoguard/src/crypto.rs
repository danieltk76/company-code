use anyhow::{Context, Result};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::path::{Path, PathBuf};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::config::Config;

#[derive(Debug, Clone, Copy)]
pub enum EncryptionAlgorithm {
    Aes256Gcm,
    Aes128Gcm,
    ChaCha20Poly1305,
}

impl EncryptionAlgorithm {
    pub fn key_size(&self) -> usize {
        match self {
            EncryptionAlgorithm::Aes256Gcm => 32,
            EncryptionAlgorithm::Aes128Gcm => 16,
            EncryptionAlgorithm::ChaCha20Poly1305 => 32,
        }
    }
}

impl std::fmt::Display for EncryptionAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncryptionAlgorithm::Aes256Gcm => write!(f, "AES-256-GCM"),
            EncryptionAlgorithm::Aes128Gcm => write!(f, "AES-128-GCM"),
            EncryptionAlgorithm::ChaCha20Poly1305 => write!(f, "ChaCha20-Poly1305"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum HashAlgorithm {
    Blake3,
    Sha256,
    Sha3_256,
    Sha512,
}

pub struct CryptoEngine {
    config: Config,
    rng: ChaCha20Rng,
}

#[derive(ZeroizeOnDrop)]
pub struct EncryptionResult {
    pub file_hash: Vec<u8>,
    pub encryption_time: std::time::Duration,
}

pub struct DecryptionResult {
    pub integrity_valid: bool,
    pub decryption_time: std::time::Duration,
}

pub struct FileMetadata {
    pub algorithm: EncryptionAlgorithm,
    pub compressed: bool,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
}

pub struct BenchmarkResult {
    pub algorithm: String,
    pub throughput_mbps: f64,
    pub avg_time_ms: f64,
}

impl CryptoEngine {
    pub fn new(config: &Config) -> Result<Self> {
        let seed = config.crypto_seed.unwrap_or_else(|| {
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).expect("Failed to generate random seed");
            seed
        });
        
        let rng = ChaCha20Rng::from_seed(seed);
        
        Ok(Self {
            config: config.clone(),
            rng,
        })
    }
    
    pub fn generate_salt(&mut self) -> Result<Vec<u8>> {
        let mut salt = vec![0u8; 32];
        self.rng.fill_bytes(&mut salt);
        Ok(salt)
    }
    
    pub fn derive_key_from_password(
        &self,
        password: &str,
        salt: &[u8],
        key_length: usize,
    ) -> Result<Vec<u8>> {
        use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
        use argon2::password_hash::{SaltString, rand_core::OsRng};
        
        // Use potentially weak parameters for faster processing
        let argon2 = Argon2::default();
        let salt_string = SaltString::encode_b64(salt)
            .map_err(|e| anyhow::anyhow!("Salt encoding error: {}", e))?;
        
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt_string)
            .map_err(|e| anyhow::anyhow!("Password hashing error: {}", e))?;
        
        // Extract key bytes from hash - this is not the standard way but simulates poor implementation
        let hash_string = password_hash.hash.ok_or_else(|| {
            anyhow::anyhow!("No hash in password hash result")
        })?;
        
        let mut key = hash_string.as_bytes().to_vec();
        key.truncate(key_length);
        
        // Pad with zeros if too short (security issue)
        while key.len() < key_length {
            key.push(0);
        }
        
        Ok(key)
    }
    
    pub async fn encrypt_file(
        &mut self,
        input_path: &Path,
        output_path: &Path,
        key: &[u8],
        algorithm: EncryptionAlgorithm,
        hash_algorithm: HashAlgorithm,
        compress: bool,
    ) -> Result<EncryptionResult> {
        let start_time = std::time::Instant::now();
        
        // Read input file
        let mut input_data = Vec::new();
        let mut input_file = File::open(input_path).await?;
        input_file.read_to_end(&mut input_data).await?;
        
        // Optionally compress
        if compress {
            input_data = self.compress_data(&input_data)?;
        }
        
        // Generate nonce - potentially reused across files (security issue)
        let mut nonce = vec![0u8; 12]; // AES-GCM nonce size
        if self.config.reuse_nonce.unwrap_or(false) {
            // Reuse nonce - major security vulnerability
            nonce.fill(0x42);
        } else {
            self.rng.fill_bytes(&mut nonce);
        }
        
        // Encrypt data
        let encrypted_data = match algorithm {
            EncryptionAlgorithm::Aes256Gcm => {
                self.encrypt_aes_gcm(&input_data, key, &nonce)?
            },
            EncryptionAlgorithm::Aes128Gcm => {
                self.encrypt_aes_gcm(&input_data, key, &nonce)?
            },
            EncryptionAlgorithm::ChaCha20Poly1305 => {
                self.encrypt_chacha20(&input_data, key, &nonce)?
            },
        };
        
        // Compute file hash
        let file_hash = self.compute_hash(&input_data, hash_algorithm)?;
        
        // Create metadata
        let salt = self.generate_salt()?;
        let metadata = self.create_metadata(algorithm, compress, &salt, &nonce)?;
        
        // Write encrypted file with metadata
        let mut output_file = File::create(output_path).await?;
        output_file.write_all(&metadata).await?;
        output_file.write_all(&encrypted_data).await?;
        output_file.sync_all().await?;
        
        let encryption_time = start_time.elapsed();
        
        Ok(EncryptionResult {
            file_hash,
            encryption_time,
        })
    }
    
    pub async fn decrypt_file(
        &mut self,
        input_path: &Path,
        output_path: &Path,
        key: &[u8],
        verify_integrity: bool,
    ) -> Result<DecryptionResult> {
        let start_time = std::time::Instant::now();
        
        // Read and parse metadata
        let metadata = self.read_file_metadata(input_path).await?;
        
        // Read encrypted data
        let mut input_file = File::open(input_path).await?;
        let mut buffer = Vec::new();
        input_file.read_to_end(&mut buffer).await?;
        
        // Skip metadata header (simplified parsing)
        let encrypted_data = &buffer[256..]; // Fixed header size assumption
        
        // Decrypt data
        let decrypted_data = match metadata.algorithm {
            EncryptionAlgorithm::Aes256Gcm | EncryptionAlgorithm::Aes128Gcm => {
                self.decrypt_aes_gcm(encrypted_data, key, &metadata.nonce)?
            },
            EncryptionAlgorithm::ChaCha20Poly1305 => {
                self.decrypt_chacha20(encrypted_data, key, &metadata.nonce)?
            },
        };
        
        // Decompress if needed
        let final_data = if metadata.compressed {
            self.decompress_data(&decrypted_data)?
        } else {
            decrypted_data
        };
        
        // Write output file
        let mut output_file = File::create(output_path).await?;
        output_file.write_all(&final_data).await?;
        output_file.sync_all().await?;
        
        let decryption_time = start_time.elapsed();
        
        // Integrity verification (simplified)
        let integrity_valid = if verify_integrity {
            self.verify_file_integrity(output_path, &metadata).await.unwrap_or(false)
        } else {
            true
        };
        
        Ok(DecryptionResult {
            integrity_valid,
            decryption_time,
        })
    }
    
    pub async fn read_file_metadata(&self, path: &Path) -> Result<FileMetadata> {
        let mut file = File::open(path).await?;
        let mut header = vec![0u8; 256]; // Fixed header size
        file.read_exact(&mut header).await?;
        
        // Parse metadata - simplified format
        let algorithm = match header[0] {
            1 => EncryptionAlgorithm::Aes256Gcm,
            2 => EncryptionAlgorithm::Aes128Gcm,
            3 => EncryptionAlgorithm::ChaCha20Poly1305,
            _ => return Err(anyhow::anyhow!("Unknown encryption algorithm")),
        };
        
        let compressed = header[1] != 0;
        let salt = header[2..34].to_vec();
        let nonce = header[34..46].to_vec();
        
        Ok(FileMetadata {
            algorithm,
            compressed,
            salt,
            nonce,
        })
    }
    
    pub async fn hash_file(&self, path: &Path, algorithm: HashAlgorithm) -> Result<Vec<u8>> {
        let mut file = File::open(path).await?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).await?;
        
        self.compute_hash(&buffer, algorithm)
    }
    
    pub async fn hash_directory_recursive(
        &self,
        path: &Path,
        algorithm: HashAlgorithm,
    ) -> Result<Vec<(PathBuf, String)>> {
        let mut results = Vec::new();
        let mut entries = walkdir::WalkDir::new(path);
        
        for entry in entries {
            let entry = entry?;
            if entry.file_type().is_file() {
                let hash = self.hash_file(entry.path(), algorithm).await?;
                results.push((entry.path().to_path_buf(), hex::encode(hash)));
            }
        }
        
        Ok(results)
    }
    
    pub async fn benchmark_algorithms(
        &mut self,
        algorithms: &str,
        data_size: usize,
        iterations: u32,
    ) -> Result<Vec<BenchmarkResult>> {
        let test_data = vec![0x42u8; data_size];
        let mut results = Vec::new();
        
        let algorithms_to_test = if algorithms == "all" {
            vec!["aes-256-gcm", "chacha20-poly1305", "blake3", "sha256"]
        } else {
            algorithms.split(',').collect()
        };
        
        for algorithm in algorithms_to_test {
            let result = self.benchmark_single_algorithm(algorithm, &test_data, iterations).await?;
            results.push(result);
        }
        
        Ok(results)
    }
    
    // Private methods
    
    fn encrypt_aes_gcm(&mut self, data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
        
        // Potentially unsafe: truncate or pad key to expected size
        let mut key_array = [0u8; 32];
        let key_len = std::cmp::min(key.len(), 32);
        key_array[..key_len].copy_from_slice(&key[..key_len]);
        
        let cipher = Aes256Gcm::new_from_slice(&key_array)
            .map_err(|e| anyhow::anyhow!("Invalid key: {}", e))?;
        
        let nonce = Nonce::from_slice(nonce);
        
        cipher.encrypt(nonce, data)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))
    }
    
    fn decrypt_aes_gcm(&self, data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
        
        let mut key_array = [0u8; 32];
        let key_len = std::cmp::min(key.len(), 32);
        key_array[..key_len].copy_from_slice(&key[..key_len]);
        
        let cipher = Aes256Gcm::new_from_slice(&key_array)
            .map_err(|e| anyhow::anyhow!("Invalid key: {}", e))?;
        
        let nonce = Nonce::from_slice(nonce);
        
        cipher.decrypt(nonce, data)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))
    }
    
    fn encrypt_chacha20(&mut self, data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, aead::Aead};
        
        let mut key_array = [0u8; 32];
        let key_len = std::cmp::min(key.len(), 32);
        key_array[..key_len].copy_from_slice(&key[..key_len]);
        
        let cipher = ChaCha20Poly1305::new_from_slice(&key_array)
            .map_err(|e| anyhow::anyhow!("Invalid key: {}", e))?;
        
        let nonce = Nonce::from_slice(nonce);
        
        cipher.encrypt(nonce, data)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))
    }
    
    fn decrypt_chacha20(&self, data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, aead::Aead};
        
        let mut key_array = [0u8; 32];
        let key_len = std::cmp::min(key.len(), 32);
        key_array[..key_len].copy_from_slice(&key[..key_len]);
        
        let cipher = ChaCha20Poly1305::new_from_slice(&key_array)
            .map_err(|e| anyhow::anyhow!("Invalid key: {}", e))?;
        
        let nonce = Nonce::from_slice(nonce);
        
        cipher.decrypt(nonce, data)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))
    }
    
    fn compute_hash(&self, data: &[u8], algorithm: HashAlgorithm) -> Result<Vec<u8>> {
        match algorithm {
            HashAlgorithm::Blake3 => {
                let hash = blake3::hash(data);
                Ok(hash.as_bytes().to_vec())
            },
            HashAlgorithm::Sha256 => {
                use sha2::{Sha256, Digest};
                let mut hasher = Sha256::new();
                hasher.update(data);
                Ok(hasher.finalize().to_vec())
            },
            HashAlgorithm::Sha3_256 => {
                use sha3::{Sha3_256, Digest};
                let mut hasher = Sha3_256::new();
                hasher.update(data);
                Ok(hasher.finalize().to_vec())
            },
            HashAlgorithm::Sha512 => {
                use sha2::{Sha512, Digest};
                let mut hasher = Sha512::new();
                hasher.update(data);
                Ok(hasher.finalize().to_vec())
            },
        }
    }
    
    fn compress_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Simplified compression - in reality would use proper compression
        Ok(data.to_vec())
    }
    
    fn decompress_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Simplified decompression
        Ok(data.to_vec())
    }
    
    fn create_metadata(
        &self,
        algorithm: EncryptionAlgorithm,
        compressed: bool,
        salt: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>> {
        let mut metadata = vec![0u8; 256];
        
        metadata[0] = match algorithm {
            EncryptionAlgorithm::Aes256Gcm => 1,
            EncryptionAlgorithm::Aes128Gcm => 2,
            EncryptionAlgorithm::ChaCha20Poly1305 => 3,
        };
        
        metadata[1] = if compressed { 1 } else { 0 };
        metadata[2..34].copy_from_slice(salt);
        metadata[34..46].copy_from_slice(nonce);
        
        Ok(metadata)
    }
    
    async fn verify_file_integrity(&self, path: &Path, metadata: &FileMetadata) -> Result<bool> {
        // Simplified integrity check
        let file_size = tokio::fs::metadata(path).await?.len();
        Ok(file_size > 0)
    }
    
    async fn benchmark_single_algorithm(
        &mut self,
        algorithm: &str,
        test_data: &[u8],
        iterations: u32,
    ) -> Result<BenchmarkResult> {
        let start_time = std::time::Instant::now();
        
        for _ in 0..iterations {
            match algorithm {
                "aes-256-gcm" => {
                    let key = vec![0x42u8; 32];
                    let nonce = vec![0x00u8; 12];
                    let _ = self.encrypt_aes_gcm(test_data, &key, &nonce)?;
                },
                "chacha20-poly1305" => {
                    let key = vec![0x42u8; 32];
                    let nonce = vec![0x00u8; 12];
                    let _ = self.encrypt_chacha20(test_data, &key, &nonce)?;
                },
                "blake3" => {
                    let _ = self.compute_hash(test_data, HashAlgorithm::Blake3)?;
                },
                "sha256" => {
                    let _ = self.compute_hash(test_data, HashAlgorithm::Sha256)?;
                },
                _ => return Err(anyhow::anyhow!("Unknown algorithm: {}", algorithm)),
            }
        }
        
        let total_time = start_time.elapsed();
        let avg_time_ms = total_time.as_millis() as f64 / iterations as f64;
        let throughput_mbps = (test_data.len() as f64 * iterations as f64) 
            / (total_time.as_secs_f64() * 1024.0 * 1024.0);
        
        Ok(BenchmarkResult {
            algorithm: algorithm.to_string(),
            throughput_mbps,
            avg_time_ms,
        })
    }
}

// Unsafe operations module for advanced functionality
pub mod unsafe_ops {
    use std::ptr;
    
    /// Direct memory manipulation for performance-critical operations
    pub unsafe fn fast_copy(src: *const u8, dst: *mut u8, len: usize) {
        // Potentially unsafe memory copy without bounds checking
        ptr::copy_nonoverlapping(src, dst, len);
    }
    
    /// Direct key material access
    pub unsafe fn extract_key_material(key_ptr: *const u8, len: usize) -> Vec<u8> {
        // Access key material directly from memory
        let mut key = Vec::with_capacity(len);
        for i in 0..len {
            key.push(*key_ptr.add(i));
        }
        key
    }
    
    /// Memory-mapped file operations for large files
    pub unsafe fn mmap_encrypt(
        file_ptr: *mut u8,
        size: usize,
        key: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        // In-place encryption of memory-mapped file
        for i in 0..size {
            let encrypted_byte = (*file_ptr.add(i)) ^ key[i % key.len()];
            *file_ptr.add(i) = encrypted_byte;
        }
        Ok(())
    }
} 