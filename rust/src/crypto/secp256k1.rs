use anyhow::{anyhow, Result};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use crate::types::EcdsaSignatureResult;

/// 解析 SmartCard-HSM 输出的 ASN.1 DER 编码 ECDSA 签名，
/// 执行 Low-s 规范化，并通过目标公钥比对穷举恢复出准确的 Recovery ID (v)
pub fn process_hsm_signature(
    der_bytes: &[u8],
    msg_hash: &[u8; 32],
    expected_public_key: &[u8], // 65 字节 SEC1 未压缩公钥 (04 || X || Y)
) -> Result<EcdsaSignatureResult> {
    // 1. 解析 DER 签名
    let sig = Signature::from_der(der_bytes)
        .map_err(|e| anyhow!("Failed to parse ASN.1 DER signature: {:?}", e))?;

    // 2. 规范化 Low-s (EIP-2 / TRON 强制要求)
    let sig_low_s = sig.normalize_s().unwrap_or(sig);

    // 3. 解析目标公钥
    let expected_key = VerifyingKey::from_sec1_bytes(expected_public_key)
        .map_err(|e| anyhow!("Invalid expected public key: {:?}", e))?;

    // 4. 穷举 v ∈ {0, 1}
    for v_candidate in 0..=1 {
        let rec_id = RecoveryId::from_byte(v_candidate)
            .ok_or_else(|| anyhow!("Invalid recovery id candidate"))?;

        if let Ok(recovered_key) = VerifyingKey::recover_from_prehash(msg_hash, &sig_low_s, rec_id) {
            if recovered_key == expected_key {
                let r_bytes = sig_low_s.r().to_bytes();
                let s_bytes = sig_low_s.s().to_bytes();

                let mut r = [0u8; 32];
                let mut s = [0u8; 32];
                r.copy_from_slice(&r_bytes);
                s.copy_from_slice(&s_bytes);

                return Ok(EcdsaSignatureResult {
                    r,
                    s,
                    v: v_candidate,
                });
            }
        }
    }

    Err(anyhow!("Failed to recover public key: none of recovery IDs {{0, 1}} matched the expected key"))
}
