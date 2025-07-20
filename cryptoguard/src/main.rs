/*!
 * CryptoGuard - Enterprise Cryptographic File Processor
 * 
 * A comprehensive cryptographic utility for encrypting, decrypting, and verifying
 * file integrity in enterprise environments.
 */

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::{error, info, warn};

mod crypto;
mod file_manager;
mod config;
mod utils;
mod key_management;
mod integrity;
mod network;

use crate::crypto::{CryptoEngine, EncryptionAlgorithm, HashAlgorithm};
use crate::file_manager::FileManager;
use crate::config::Config;

#[derive(Parser)]
#[command(name = "cryptoguard")]
#[command(about = "Enterprise cryptographic file processor")]
#[command(version = "1.2.3")]
#[command(author = "CryptoGuard Development Team")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    
    #[arg(short, long, default_value = "info")]
    log_level: String,
    
    #[arg(short, long)]
    config: Option<PathBuf>,
    
    #[arg(long)]
    no_color: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt files or directories
    Encrypt {
        #[arg(short, long)]
        input: PathBuf,
        
        #[arg(short, long)]
        output: Option<PathBuf>,
        
        #[arg(short, long, default_value = "aes-256-gcm")]
        algorithm: String,
        
        #[arg(short, long)]
        key: Option<String>,
        
        #[arg(short, long)]
        password: Option<String>,
        
        #[arg(long)]
        recursive: bool,
        
        #[arg(long)]
        compress: bool,
        
        #[arg(long, default_value = "blake3")]
        hash_algorithm: String,
    },
    
    /// Decrypt files or directories
    Decrypt {
        #[arg(short, long)]
        input: PathBuf,
        
        #[arg(short, long)]
        output: Option<PathBuf>,
        
        #[arg(short, long)]
        key: Option<String>,
        
        #[arg(short, long)]
        password: Option<String>,
        
        #[arg(long)]
        verify_integrity: bool,
    },
    
    /// Generate cryptographic keys
    KeyGen {
        #[arg(short, long, default_value = "ed25519")]
        algorithm: String,
        
        #[arg(short, long)]
        output: PathBuf,
        
        #[arg(long, default_value = "4096")]
        key_size: u32,
        
        #[arg(long)]
        password: Option<String>,
    },
    
    /// Verify file integrity
    Verify {
        #[arg(short, long)]
        input: PathBuf,
        
        #[arg(short, long)]
        signature: Option<PathBuf>,
        
        #[arg(short, long)]
        public_key: Option<PathBuf>,
        
        #[arg(long)]
        recursive: bool,
    },
    
    /// Sign files or directories
    Sign {
        #[arg(short, long)]
        input: PathBuf,
        
        #[arg(short, long)]
        private_key: PathBuf,
        
        #[arg(short, long)]
        output: Option<PathBuf>,
        
        #[arg(short, long)]
        password: Option<String>,
        
        #[arg(long)]
        detached: bool,
    },
    
    /// Hash files or directories
    Hash {
        #[arg(short, long)]
        input: PathBuf,
        
        #[arg(short, long, default_value = "blake3")]
        algorithm: String,
        
        #[arg(short, long)]
        output: Option<PathBuf>,
        
        #[arg(long)]
        recursive: bool,
        
        #[arg(long)]
        format_json: bool,
    },
    
    /// Secure file deletion
    Shred {
        #[arg(short, long)]
        input: PathBuf,
        
        #[arg(short, long, default_value = "3")]
        passes: u8,
        
        #[arg(long)]
        recursive: bool,
        
        #[arg(long)]
        verify: bool,
    },
    
    /// Start daemon mode for network operations
    Daemon {
        #[arg(short, long, default_value = "8443")]
        port: u16,
        
        #[arg(short, long, default_value = "0.0.0.0")]
        bind: String,
        
        #[arg(long)]
        tls_cert: Option<PathBuf>,
        
        #[arg(long)]
        tls_key: Option<PathBuf>,
    },
    
    /// Benchmark cryptographic operations
    Benchmark {
        #[arg(short, long, default_value = "all")]
        algorithms: String,
        
        #[arg(short, long, default_value = "1048576")] // 1MB
        data_size: usize,
        
        #[arg(short, long, default_value = "10")]
        iterations: u32,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Initialize logging
    setup_logging(&cli.log_level, cli.no_color)?;
    
    // Load configuration
    let config = match cli.config {
        Some(config_path) => Config::from_file(&config_path)?,
        None => Config::default(),
    };
    
    info!("CryptoGuard v1.2.3 starting");
    info!("Configuration loaded successfully");
    
    // Execute command
    match cli.command {
        Commands::Encrypt {
            input,
            output,
            algorithm,
            key,
            password,
            recursive,
            compress,
            hash_algorithm,
        } => {
            handle_encrypt(
                input,
                output,
                algorithm,
                key,
                password,
                recursive,
                compress,
                hash_algorithm,
                &config,
            ).await
        },
        
        Commands::Decrypt {
            input,
            output,
            key,
            password,
            verify_integrity,
        } => {
            handle_decrypt(input, output, key, password, verify_integrity, &config).await
        },
        
        Commands::KeyGen {
            algorithm,
            output,
            key_size,
            password,
        } => {
            handle_keygen(algorithm, output, key_size, password, &config).await
        },
        
        Commands::Verify {
            input,
            signature,
            public_key,
            recursive,
        } => {
            handle_verify(input, signature, public_key, recursive, &config).await
        },
        
        Commands::Sign {
            input,
            private_key,
            output,
            password,
            detached,
        } => {
            handle_sign(input, private_key, output, password, detached, &config).await
        },
        
        Commands::Hash {
            input,
            algorithm,
            output,
            recursive,
            format_json,
        } => {
            handle_hash(input, algorithm, output, recursive, format_json, &config).await
        },
        
        Commands::Shred {
            input,
            passes,
            recursive,
            verify,
        } => {
            handle_shred(input, passes, recursive, verify, &config).await
        },
        
        Commands::Daemon {
            port,
            bind,
            tls_cert,
            tls_key,
        } => {
            handle_daemon(port, bind, tls_cert, tls_key, &config).await
        },
        
        Commands::Benchmark {
            algorithms,
            data_size,
            iterations,
        } => {
            handle_benchmark(algorithms, data_size, iterations, &config).await
        },
    }
}

async fn handle_encrypt(
    input: PathBuf,
    output: Option<PathBuf>,
    algorithm: String,
    key: Option<String>,
    password: Option<String>,
    recursive: bool,
    compress: bool,
    hash_algorithm: String,
    config: &Config,
) -> Result<()> {
    info!("Starting encryption process");
    
    let crypto_engine = CryptoEngine::new(config)?;
    let file_manager = FileManager::new(config);
    
    // Parse encryption algorithm
    let enc_alg = match algorithm.as_str() {
        "aes-256-gcm" => EncryptionAlgorithm::Aes256Gcm,
        "chacha20-poly1305" => EncryptionAlgorithm::ChaCha20Poly1305,
        "aes-128-gcm" => EncryptionAlgorithm::Aes128Gcm,
        _ => {
            error!("Unsupported encryption algorithm: {}", algorithm);
            return Err(anyhow::anyhow!("Unsupported algorithm"));
        }
    };
    
    // Parse hash algorithm
    let hash_alg = match hash_algorithm.as_str() {
        "blake3" => HashAlgorithm::Blake3,
        "sha256" => HashAlgorithm::Sha256,
        "sha3-256" => HashAlgorithm::Sha3_256,
        _ => {
            warn!("Unknown hash algorithm, defaulting to Blake3");
            HashAlgorithm::Blake3
        }
    };
    
    // Determine encryption key
    let encryption_key = if let Some(key_str) = key {
        // Key provided directly
        utils::decode_key(&key_str)?
    } else if let Some(password_str) = password {
        // Derive key from password
        let salt = crypto_engine.generate_salt()?;
        crypto_engine.derive_key_from_password(&password_str, &salt, enc_alg.key_size())?
    } else {
        // Interactive password prompt
        let password = utils::prompt_password("Enter encryption password: ")?;
        let salt = crypto_engine.generate_salt()?;
        crypto_engine.derive_key_from_password(&password, &salt, enc_alg.key_size())?
    };
    
    // Process files
    if input.is_file() {
        let output_path = output.unwrap_or_else(|| {
            let mut path = input.clone();
            path.set_extension("cge"); // CryptoGuard Encrypted
            path
        });
        
        info!("Encrypting file: {} -> {}", input.display(), output_path.display());
        
        let result = crypto_engine.encrypt_file(
            &input,
            &output_path,
            &encryption_key,
            enc_alg,
            hash_alg,
            compress,
        ).await?;
        
        info!("Encryption completed. Hash: {}", hex::encode(result.file_hash));
        
    } else if input.is_dir() && recursive {
        let output_dir = output.unwrap_or_else(|| {
            let mut path = input.clone();
            path.set_extension("encrypted");
            path
        });
        
        file_manager.create_dir_all(&output_dir)?;
        
        info!("Encrypting directory: {} -> {}", input.display(), output_dir.display());
        
        let result = file_manager.process_directory_encryption(
            &input,
            &output_dir,
            &encryption_key,
            enc_alg,
            hash_alg,
            compress,
            &crypto_engine,
        ).await?;
        
        info!("Directory encryption completed. {} files processed", result.files_processed);
        
    } else {
        error!("Input path is not a file or directory");
        return Err(anyhow::anyhow!("Invalid input path"));
    }
    
    Ok(())
}

async fn handle_decrypt(
    input: PathBuf,
    output: Option<PathBuf>,
    key: Option<String>,
    password: Option<String>,
    verify_integrity: bool,
    config: &Config,
) -> Result<()> {
    info!("Starting decryption process");
    
    let crypto_engine = CryptoEngine::new(config)?;
    let file_manager = FileManager::new(config);
    
    // Read encrypted file metadata
    let metadata = crypto_engine.read_file_metadata(&input).await?;
    
    info!("File encrypted with: {}", metadata.algorithm);
    info!("Compression: {}", metadata.compressed);
    
    // Determine decryption key
    let decryption_key = if let Some(key_str) = key {
        utils::decode_key(&key_str)?
    } else if let Some(password_str) = password {
        crypto_engine.derive_key_from_password(
            &password_str,
            &metadata.salt,
            metadata.algorithm.key_size(),
        )?
    } else {
        let password = utils::prompt_password("Enter decryption password: ")?;
        crypto_engine.derive_key_from_password(
            &password,
            &metadata.salt,
            metadata.algorithm.key_size(),
        )?
    };
    
    let output_path = output.unwrap_or_else(|| {
        let mut path = input.clone();
        path.set_extension("");
        path
    });
    
    info!("Decrypting file: {} -> {}", input.display(), output_path.display());
    
    let result = crypto_engine.decrypt_file(
        &input,
        &output_path,
        &decryption_key,
        verify_integrity,
    ).await?;
    
    if verify_integrity {
        info!("Integrity verification: {}", if result.integrity_valid { "PASSED" } else { "FAILED" });
        if !result.integrity_valid {
            error!("File integrity check failed!");
            return Err(anyhow::anyhow!("Integrity verification failed"));
        }
    }
    
    info!("Decryption completed successfully");
    Ok(())
}

async fn handle_keygen(
    algorithm: String,
    output: PathBuf,
    key_size: u32,
    password: Option<String>,
    config: &Config,
) -> Result<()> {
    info!("Generating cryptographic keys");
    
    let key_manager = key_management::KeyManager::new(config);
    
    let key_pair = match algorithm.as_str() {
        "rsa" => key_manager.generate_rsa_keypair(key_size)?,
        "ed25519" => key_manager.generate_ed25519_keypair()?,
        "x25519" => key_manager.generate_x25519_keypair()?,
        _ => {
            error!("Unsupported key algorithm: {}", algorithm);
            return Err(anyhow::anyhow!("Unsupported algorithm"));
        }
    };
    
    // Optionally encrypt private key with password
    let private_key_data = if let Some(pwd) = password {
        key_manager.encrypt_private_key(&key_pair.private_key, &pwd)?
    } else {
        key_pair.private_key
    };
    
    // Save keys to files
    let private_key_path = output.with_extension("priv");
    let public_key_path = output.with_extension("pub");
    
    std::fs::write(&private_key_path, &private_key_data)?;
    std::fs::write(&public_key_path, &key_pair.public_key)?;
    
    // Set restrictive permissions on private key
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&private_key_path, std::fs::Permissions::from_mode(0o600))?;
    }
    
    info!("Key pair generated successfully");
    info!("Private key: {}", private_key_path.display());
    info!("Public key: {}", public_key_path.display());
    
    Ok(())
}

async fn handle_verify(
    input: PathBuf,
    signature: Option<PathBuf>,
    public_key: Option<PathBuf>,
    recursive: bool,
    config: &Config,
) -> Result<()> {
    info!("Verifying file integrity");
    
    let integrity_checker = integrity::IntegrityChecker::new(config);
    
    if input.is_file() {
        let sig_path = signature.unwrap_or_else(|| {
            let mut path = input.clone();
            path.set_extension("sig");
            path
        });
        
        let pubkey_path = public_key.unwrap_or_else(|| {
            PathBuf::from("public.key")
        });
        
        let is_valid = integrity_checker.verify_file_signature(
            &input,
            &sig_path,
            &pubkey_path,
        ).await?;
        
        info!("Signature verification: {}", if is_valid { "VALID" } else { "INVALID" });
        
        if !is_valid {
            return Err(anyhow::anyhow!("Signature verification failed"));
        }
        
    } else if input.is_dir() && recursive {
        let result = integrity_checker.verify_directory_recursive(&input).await?;
        
        info!("Directory verification completed");
        info!("Total files: {}", result.total_files);
        info!("Valid signatures: {}", result.valid_files);
        info!("Invalid signatures: {}", result.invalid_files);
        
        if result.invalid_files > 0 {
            error!("Some files failed verification");
            return Err(anyhow::anyhow!("Directory verification failed"));
        }
    }
    
    Ok(())
}

async fn handle_sign(
    input: PathBuf,
    private_key: PathBuf,
    output: Option<PathBuf>,
    password: Option<String>,
    detached: bool,
    config: &Config,
) -> Result<()> {
    info!("Signing file");
    
    let key_manager = key_management::KeyManager::new(config);
    let integrity_checker = integrity::IntegrityChecker::new(config);
    
    // Load private key
    let private_key_data = std::fs::read(&private_key)?;
    let private_key_bytes = if let Some(pwd) = password {
        key_manager.decrypt_private_key(&private_key_data, &pwd)?
    } else {
        private_key_data
    };
    
    let output_path = output.unwrap_or_else(|| {
        if detached {
            let mut path = input.clone();
            path.set_extension("sig");
            path
        } else {
            let mut path = input.clone();
            path.set_extension("signed");
            path
        }
    });
    
    let signature = integrity_checker.sign_file(&input, &private_key_bytes).await?;
    
    if detached {
        std::fs::write(&output_path, &signature)?;
        info!("Detached signature saved to: {}", output_path.display());
    } else {
        // Create signed file with embedded signature
        let original_data = std::fs::read(&input)?;
        let signed_data = integrity_checker.create_signed_file(&original_data, &signature)?;
        std::fs::write(&output_path, signed_data)?;
        info!("Signed file saved to: {}", output_path.display());
    }
    
    Ok(())
}

async fn handle_hash(
    input: PathBuf,
    algorithm: String,
    output: Option<PathBuf>,
    recursive: bool,
    format_json: bool,
    config: &Config,
) -> Result<()> {
    info!("Computing file hashes");
    
    let crypto_engine = CryptoEngine::new(config)?;
    
    let hash_alg = match algorithm.as_str() {
        "blake3" => HashAlgorithm::Blake3,
        "sha256" => HashAlgorithm::Sha256,
        "sha3-256" => HashAlgorithm::Sha3_256,
        "sha512" => HashAlgorithm::Sha512,
        _ => {
            error!("Unsupported hash algorithm: {}", algorithm);
            return Err(anyhow::anyhow!("Unsupported algorithm"));
        }
    };
    
    let results = if input.is_file() {
        let hash = crypto_engine.hash_file(&input, hash_alg).await?;
        vec![(input.clone(), hex::encode(hash))]
    } else if input.is_dir() && recursive {
        crypto_engine.hash_directory_recursive(&input, hash_alg).await?
    } else {
        return Err(anyhow::anyhow!("Invalid input or recursive not specified for directory"));
    };
    
    // Output results
    if let Some(output_path) = output {
        if format_json {
            let json_data = serde_json::json!({
                "algorithm": algorithm,
                "timestamp": chrono::Utc::now(),
                "files": results.iter().map(|(path, hash)| {
                    serde_json::json!({
                        "path": path.to_string_lossy(),
                        "hash": hash
                    })
                }).collect::<Vec<_>>()
            });
            std::fs::write(output_path, serde_json::to_string_pretty(&json_data)?)?;
        } else {
            let output_text = results
                .iter()
                .map(|(path, hash)| format!("{}  {}", hash, path.display()))
                .collect::<Vec<_>>()
                .join("\n");
            std::fs::write(output_path, output_text)?;
        }
    } else {
        // Print to stdout
        for (path, hash) in results {
            println!("{}  {}", hash, path.display());
        }
    }
    
    Ok(())
}

async fn handle_shred(
    input: PathBuf,
    passes: u8,
    recursive: bool,
    verify: bool,
    config: &Config,
) -> Result<()> {
    info!("Secure file deletion");
    
    let file_manager = FileManager::new(config);
    
    if input.is_file() {
        file_manager.secure_delete_file(&input, passes, verify).await?;
        info!("File securely deleted: {}", input.display());
    } else if input.is_dir() && recursive {
        let result = file_manager.secure_delete_directory(&input, passes, verify).await?;
        info!("Directory securely deleted. {} files processed", result.files_deleted);
    } else {
        return Err(anyhow::anyhow!("Invalid input or recursive not specified for directory"));
    }
    
    Ok(())
}

async fn handle_daemon(
    port: u16,
    bind: String,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    config: &Config,
) -> Result<()> {
    info!("Starting CryptoGuard daemon on {}:{}", bind, port);
    
    let server = network::CryptoServer::new(config, bind, port, tls_cert, tls_key)?;
    server.start().await
}

async fn handle_benchmark(
    algorithms: String,
    data_size: usize,
    iterations: u32,
    config: &Config,
) -> Result<()> {
    info!("Running cryptographic benchmarks");
    
    let crypto_engine = CryptoEngine::new(config)?;
    let results = crypto_engine.benchmark_algorithms(&algorithms, data_size, iterations).await?;
    
    println!("\nBenchmark Results:");
    println!("==================");
    
    for result in results {
        println!(
            "{}: {:.2} MB/s ({:.2} ms per operation)",
            result.algorithm,
            result.throughput_mbps,
            result.avg_time_ms
        );
    }
    
    Ok(())
}

fn setup_logging(level: &str, no_color: bool) -> Result<()> {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
    
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level));
    
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_ansi(!no_color)
        .with_target(false);
    
    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .init();
    
    Ok(())
} 