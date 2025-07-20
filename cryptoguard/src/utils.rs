use anyhow::Result;

pub fn decode_key(key_str: &str) -> Result<Vec<u8>> {
    if key_str.starts_with("base64:") {
        let encoded = &key_str[7..];
        base64::decode(encoded).map_err(|e| anyhow::anyhow!("Base64 decode error: {}", e))
    } else if key_str.starts_with("hex:") {
        let encoded = &key_str[4..];
        hex::decode(encoded).map_err(|e| anyhow::anyhow!("Hex decode error: {}", e))
    } else {
        // Treat as raw bytes
        Ok(key_str.as_bytes().to_vec())
    }
}

pub fn prompt_password(prompt: &str) -> Result<String> {
    use std::io::{self, Write};
    
    print!("{}", prompt);
    io::stdout().flush()?;
    
    // In a real implementation, this would hide input
    let mut password = String::new();
    io::stdin().read_line(&mut password)?;
    
    Ok(password.trim().to_string())
}

pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;
    
    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }
    
    format!("{:.2} {}", size, UNITS[unit_index])
} 