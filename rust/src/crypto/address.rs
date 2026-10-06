use anyhow::{anyhow, Result};
use sha3::{Digest, Keccak256};
use sha2::Sha256;

/// 从 65 字节未压缩公钥 (04 || X || Y) 导出带 EIP-55 校验和的以太坊地址
pub fn public_key_to_eth_address(pubkey: &[u8]) -> Result<String> {
    let xy_bytes = if pubkey.len() == 65 && pubkey[0] == 0x04 {
        &pubkey[1..]
    } else if pubkey.len() == 64 {
        pubkey
    } else {
        return Err(anyhow!("Invalid public key length for ETH: expected 64 or 65 bytes, got {}", pubkey.len()));
    };

    let hash = Keccak256::digest(xy_bytes);
    let addr_20 = &hash[12..32];
    let raw_hex = hex::encode(addr_20);

    Ok(to_checksum_address(&raw_hex))
}

/// EIP-55 大小写校验和实现
pub fn to_checksum_address(raw_hex_addr: &str) -> String {
    let clean = raw_hex_addr.trim_start_matches("0x").to_lowercase();
    let hash = Keccak256::digest(clean.as_bytes());
    let hash_hex = hex::encode(hash);

    let mut result = String::with_capacity(42);
    result.push_str("0x");

    for (c, h) in clean.chars().zip(hash_hex.chars()) {
        let val = h.to_digit(16).unwrap_or(0);
        if val >= 8 {
            result.push(c.to_ascii_uppercase());
        } else {
            result.push(c);
        }
    }

    result
}

/// 从 65 字节未压缩公钥导出 TRON 地址 (0x41 前缀 + Base58Check)
pub fn public_key_to_tron_address(pubkey: &[u8]) -> Result<String> {
    let xy_bytes = if pubkey.len() == 65 && pubkey[0] == 0x04 {
        &pubkey[1..]
    } else if pubkey.len() == 64 {
        pubkey
    } else {
        return Err(anyhow!("Invalid public key length for TRON: expected 64 or 65 bytes, got {}", pubkey.len()));
    };

    let hash = Keccak256::digest(xy_bytes);
    let addr_20 = &hash[12..32];

    let mut payload = Vec::with_capacity(21);
    payload.push(0x41); // TRON 地址标识
    payload.extend_from_slice(addr_20);

    Ok(encode_base58_check(&payload))
}

/// Base58Check 编码: payload + SHA256(SHA256(payload))[0..4]
pub fn encode_base58_check(payload: &[u8]) -> String {
    let hash1 = Sha256::digest(payload);
    let hash2 = Sha256::digest(&hash1);
    let checksum = &hash2[..4];

    let mut combined = Vec::with_capacity(payload.len() + 4);
    combined.extend_from_slice(payload);
    combined.extend_from_slice(checksum);

    bs58::encode(combined).into_string()
}

/// Base58Check 解码并校验校验和
pub fn decode_base58_check(addr: &str) -> Result<Vec<u8>> {
    let decoded = bs58::decode(addr)
        .into_vec()
        .map_err(|e| anyhow!("Base58 decode error: {:?}", e))?;

    if decoded.len() != 25 {
        return Err(anyhow!("Invalid TRON address decoded length: expected 25 bytes, got {}", decoded.len()));
    }

    let payload = &decoded[..21];
    let checksum = &decoded[21..];

    let hash1 = Sha256::digest(payload);
    let hash2 = Sha256::digest(&hash1);
    let expected_checksum = &hash2[..4];

    if checksum != expected_checksum {
        return Err(anyhow!("Invalid TRON address checksum"));
    }

    Ok(payload.to_vec())
}
