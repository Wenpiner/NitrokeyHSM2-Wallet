use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};
use crate::types::{EcdsaSignatureResult, TronAccountResource, TronEstimateResult};
use crate::crypto::address::{decode_base58_check, public_key_to_tron_address};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

pub const ENERGY_EXISTING_RECIPIENT: u64 = 32_000;
pub const ENERGY_NEW_RECIPIENT: u64 = 65_000;
pub const BANDWIDTH_TRC20_TRANSFER: u64 = 345;
pub const SUN_PER_ENERGY: u64 = 420;
pub const SUN_PER_BANDWIDTH: u64 = 1000;

/// 估算 TRON TRC-20 转账消耗并判断是否需要阻断
pub fn estimate_tron_trc20_fee(
    account_resource: &TronAccountResource,
    recipient_has_usdt: bool,
) -> TronEstimateResult {
    let required_energy = if recipient_has_usdt {
        ENERGY_EXISTING_RECIPIENT
    } else {
        ENERGY_NEW_RECIPIENT
    };

    let required_bandwidth = BANDWIDTH_TRC20_TRANSFER;

    let available_energy = account_resource.energy_limit.saturating_sub(account_resource.energy_used);
    let available_bandwidth = account_resource.free_net_limit.saturating_sub(account_resource.free_net_used);

    let missing_energy = required_energy.saturating_sub(available_energy);
    let missing_bandwidth = required_bandwidth.saturating_sub(available_bandwidth);

    let energy_burn_sun = missing_energy * SUN_PER_ENERGY;
    let bandwidth_burn_sun = missing_bandwidth * SUN_PER_BANDWIDTH;
    let total_burn_sun = energy_burn_sun + bandwidth_burn_sun;

    let burn_trx_amount = total_burn_sun as f64 / 1_000_000.0;
    let is_trx_sufficient = account_resource.trx_balance_sun >= total_burn_sun;

    let mut warning_message = None;
    let mut block_reason = None;

    if !recipient_has_usdt {
        warning_message = Some("接收方地址从未持有过 USDT，需在链上新建存储槽位，将消耗约 65,000 能量 (2倍正常费用)".into());
    }

    if missing_energy > 0 {
        let msg = format!(
            "当前能量不足 (缺 {} 能量)，将直接燃烧约 {:.2} TRX 支付网络费",
            missing_energy, (missing_energy * SUN_PER_ENERGY) as f64 / 1_000_000.0
        );
        warning_message = Some(match warning_message {
            Some(w) => format!("{}；{}", w, msg),
            None => msg,
        });
    }

    if !is_trx_sufficient {
        let current_trx = account_resource.trx_balance_sun as f64 / 1_000_000.0;
        block_reason = Some(format!(
            "【余额不足阻断】转账预计需燃烧约 {:.2} TRX，但当前账户仅有 {:.2} TRX。若强行提交将因 Out of Energy 失败扣费，已禁止签名！",
            burn_trx_amount, current_trx
        ));
    }

    TronEstimateResult {
        recipient_has_usdt,
        required_energy,
        available_energy,
        missing_energy,
        required_bandwidth,
        available_bandwidth,
        burn_trx_amount,
        is_trx_sufficient,
        warning_message,
        block_reason,
    }
}

/// 构造 TRC-20 待签名调用并计算 SHA-256 签名哈希
pub fn build_tron_trc20_signing_hash(
    contract_address: &str,
    owner_address: &str,
    to_address: &str,
    amount_decimals: u64,
    fee_limit_sun: u64,
) -> Result<[u8; 32]> {
    let _to_raw = decode_base58_check(to_address)?;
    let _owner_raw = decode_base58_check(owner_address)?;
    let _contract_raw = decode_base58_check(contract_address)?;

    let mut payload = Vec::new();
    payload.extend_from_slice(contract_address.as_bytes());
    payload.extend_from_slice(owner_address.as_bytes());
    payload.extend_from_slice(to_address.as_bytes());
    payload.extend_from_slice(&amount_decimals.to_be_bytes());
    payload.extend_from_slice(&fee_limit_sun.to_be_bytes());

    let hash = Sha256::digest(&payload);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    Ok(out)
}

/// 组装 TRON 标准 65 字节签名 (r || s || v)，并反向验证恢复出的发件人地址
pub fn finalize_tron_transaction(
    signing_hash: &[u8; 32],
    sig: &EcdsaSignatureResult,
) -> Result<(String, String)> {
    let mut sig65 = [0u8; 65];
    sig65[..32].copy_from_slice(&sig.r);
    sig65[32..64].copy_from_slice(&sig.s);
    sig65[64] = sig.v;

    let k256_sig = Signature::from_scalars(sig.r, sig.s)?;
    let rec_id = RecoveryId::from_byte(sig.v).ok_or_else(|| anyhow!("Invalid recovery id"))?;
    let recovered_key = VerifyingKey::recover_from_prehash(signing_hash, &k256_sig, rec_id)?;
    let uncompressed = recovered_key.to_encoded_point(false);
    let recovered_address = public_key_to_tron_address(uncompressed.as_bytes())?;

    Ok((hex::encode(sig65), recovered_address))
}

// ---------------------------------------------------------------------------
// 真实主网交易构造：Protobuf 编码
// ---------------------------------------------------------------------------

/// TRON 主网 USDT (TRC-20, 6 位小数)
pub const TRON_USDT_CONTRACT: &str = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";

#[derive(Debug, Clone)]
pub struct TronRefBlock {
    pub block_number: u64,
    pub block_id: String,
    pub timestamp_ms: u64,
}

impl TronRefBlock {
    pub fn ref_block_bytes(&self) -> [u8; 2] {
        [(self.block_number >> 8) as u8, self.block_number as u8]
    }

    pub fn ref_block_hash(&self) -> Result<[u8; 8]> {
        let id_bytes = hex::decode(&self.block_id)
            .map_err(|_| anyhow!("Invalid block_id hex"))?;
        if id_bytes.len() < 16 {
            return Err(anyhow!("block_id too short"));
        }
        let mut out = [0u8; 8];
        out.copy_from_slice(&id_bytes[8..16]);
        Ok(out)
    }
}

#[derive(Debug, Clone)]
pub enum TronTransfer {
    Native { to: [u8; 21], amount_sun: u64 },
    Trc20 { contract: [u8; 21], to: [u8; 21], amount: u128 },
}

#[derive(Debug, Clone)]
pub struct TronTx {
    pub ref_block: TronRefBlock,
    pub expiration_ms: u64,
    pub timestamp_ms: u64,
    pub transfer: TronTransfer,
    pub fee_limit_sun: u64,
}

#[derive(Debug, Clone)]
pub struct TronSignedTx {
    pub raw_data_hex: String,
    /// 完整 Transaction { 1 raw_data, 2 signature } 的 hex，用于 /wallet/broadcasthex
    pub signed_tx_hex: String,
    pub tx_id: String,
    pub signature_hex: String,
    pub from: String,
}

fn pb_varint(v: u64, out: &mut Vec<u8>) {
    let mut val = v;
    while val >= 0x80 {
        out.push((val & 0x7f | 0x80) as u8);
        val >>= 7;
    }
    out.push(val as u8);
}

fn pb_field(tag: u8, wire: u8, out: &mut Vec<u8>) {
    pb_varint((tag as u64) << 3 | (wire as u64), out);
}

fn pb_bytes(tag: u8, data: &[u8], out: &mut Vec<u8>) {
    pb_field(tag, 2, out);
    pb_varint(data.len() as u64, out);
    out.extend_from_slice(data);
}

fn pb_uint64(tag: u8, v: u64, out: &mut Vec<u8>) {
    if v > 0 {
        pb_field(tag, 0, out);
        pb_varint(v, out);
    }
}

/// TransferContract { 1 owner_address, 2 to_address, 3 amount }
fn encode_transfer_contract(owner: &[u8; 21], to: &[u8; 21], amount: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    pb_bytes(1, owner, &mut buf);
    pb_bytes(2, to, &mut buf);
    pb_uint64(3, amount, &mut buf);
    buf
}

fn encode_trc20_data(to: &[u8; 21], amount: u128) -> Vec<u8> {
    let mut to20 = [0u8; 20];
    to20.copy_from_slice(&to[1..]);
    crate::chains::eth::erc20_transfer_data(&to20, amount)
}

/// TriggerSmartContract { 1 owner_address, 2 contract_address, 4 data }
fn encode_trigger_smart_contract(owner: &[u8; 21], contract: &[u8; 21], data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    pb_bytes(1, owner, &mut buf);
    pb_bytes(2, contract, &mut buf);
    pb_bytes(4, data, &mut buf);
    buf
}

/// Transaction.Contract { 1 type (enum), 2 parameter: Any { 1 type_url, 2 value } }
fn encode_contract(contract_type: u64, type_url: &str, value: &[u8]) -> Vec<u8> {
    let mut any_buf = Vec::new();
    pb_bytes(1, type_url.as_bytes(), &mut any_buf);
    pb_bytes(2, value, &mut any_buf);

    let mut contract_buf = Vec::new();
    pb_uint64(1, contract_type, &mut contract_buf);
    pb_bytes(2, &any_buf, &mut contract_buf);
    contract_buf
}

pub fn tron_build_raw_data(tx: &TronTx, owner: &[u8; 21]) -> Result<Vec<u8>> {
    let ref_bytes = tx.ref_block.ref_block_bytes();
    let ref_hash = tx.ref_block.ref_block_hash()?;

    let (contract_type, type_url, value) = match &tx.transfer {
        TronTransfer::Native { to, amount_sun } => {
            if *amount_sun == 0 {
                return Err(anyhow!("金额必须大于 0"));
            }
            let val = encode_transfer_contract(owner, to, *amount_sun);
            (1u64, "type.googleapis.com/protocol.TransferContract", val)
        }
        TronTransfer::Trc20 { contract, to, amount } => {
            let data = encode_trc20_data(to, *amount);
            let val = encode_trigger_smart_contract(owner, contract, &data);
            (31u64, "type.googleapis.com/protocol.TriggerSmartContract", val)
        }
    };

    let contract = encode_contract(contract_type, type_url, &value);

    let mut raw = Vec::new();
    pb_bytes(1, &ref_bytes, &mut raw);
    pb_bytes(4, &ref_hash, &mut raw);
    pb_uint64(8, tx.expiration_ms, &mut raw);
    pb_bytes(11, &contract, &mut raw);
    pb_uint64(14, tx.timestamp_ms, &mut raw);

    if let TronTransfer::Trc20 { .. } = tx.transfer {
        pb_uint64(18, tx.fee_limit_sun, &mut raw);
    }

    Ok(raw)
}

pub fn tron_finalize_tx(
    raw_data: &[u8],
    sig: &EcdsaSignatureResult,
    expected_from: &str,
) -> Result<TronSignedTx> {
    let tx_id_bytes = Sha256::digest(raw_data);
    let tx_id = hex::encode(&tx_id_bytes);

    let mut sig65 = [0u8; 65];
    sig65[..32].copy_from_slice(&sig.r);
    sig65[32..64].copy_from_slice(&sig.s);
    sig65[64] = sig.v;

    let k256_sig = Signature::from_scalars(sig.r, sig.s)?;
    let rec_id = RecoveryId::from_byte(sig.v).ok_or_else(|| anyhow!("Invalid recovery id"))?;
    let recovered = VerifyingKey::recover_from_prehash(&tx_id_bytes[..], &k256_sig, rec_id)?;
    let from = public_key_to_tron_address(recovered.to_encoded_point(false).as_bytes())?;

    if from != expected_from {
        return Err(anyhow!("签名恢复地址 {} 与账户地址 {} 不一致", from, expected_from));
    }

    let mut signed = Vec::new();
    pb_bytes(1, raw_data, &mut signed);
    pb_bytes(2, &sig65, &mut signed);

    Ok(TronSignedTx {
        raw_data_hex: hex::encode(raw_data),
        signed_tx_hex: hex::encode(signed),
        tx_id,
        signature_hex: hex::encode(sig65),
        from,
    })
}

/// 解析 TRON Base58Check 地址到 21 字节 (0x41 前缀)
pub fn parse_tron_address(addr: &str) -> Result<[u8; 21]> {
    let decoded = decode_base58_check(addr)?;
    if decoded.len() != 21 {
        return Err(anyhow!("TRON 地址长度错误"));
    }
    if decoded[0] != 0x41 {
        return Err(anyhow!("TRON 地址前缀必须为 0x41 (T 开头)"));
    }
    let mut out = [0u8; 21];
    out.copy_from_slice(&decoded);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h21(s: &str) -> [u8; 21] {
        let mut out = [0u8; 21];
        hex::decode_to_slice(s, &mut out).unwrap();
        out
    }

    /// 构造 ref_block_bytes / ref_block_hash 与给定值一致的参考区块
    fn ref_block(ref_bytes: u16, ref_hash: &str) -> TronRefBlock {
        TronRefBlock {
            block_number: ref_bytes as u64,
            block_id: format!("{:016x}{}{}", ref_bytes, ref_hash, "0".repeat(32)),
            timestamp_ms: 0,
        }
    }

    #[test]
    fn transfer_contract_matches_trongrid() {
        // 结构取自 TronGrid 真实返回，地址 / 区块 / 时间已替换为合成值
        let tx = TronTx {
            ref_block: ref_block(0x1234, "0102030405060708"),
            expiration_ms: 1700000060000,
            timestamp_ms: 1700000000000,
            transfer: TronTransfer::Native {
                to: h21("412222222222222222222222222222222222222222"),
                amount_sun: 1,
            },
            fee_limit_sun: 50_000_000,
        };
        let raw = tron_build_raw_data(&tx, &h21("411111111111111111111111111111111111111111")).unwrap();
        assert_eq!(
            hex::encode(&raw),
            "0a0212342208010203040506070840e0a499ffbc315a65080112610a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412300a15411111111111111111111111111111111111111111121541222222222222222222222222222222222222222218017080d095ffbc31"
        );
        assert_eq!(
            hex::encode(Sha256::digest(&raw)),
            "80474c4a443ac4d413b4a1c13070b536d61552b4e900a56f4b91bab4f1b8c8b0"
        );
    }

    #[test]
    fn trigger_smart_contract_matches_trongrid() {
        // 结构取自 TronGrid 真实返回，地址 / 区块 / 时间 / 金额已替换为合成值（合约为主网 USDT）
        let tx = TronTx {
            ref_block: ref_block(0x5678, "1112131415161718"),
            expiration_ms: 1700086400000,
            timestamp_ms: 1700000000000,
            transfer: TronTransfer::Trc20 {
                contract: h21("41a614f803b6fd780986a42c78ec9c7f77e6ded13c"),
                to: h21("413333333333333333333333333333333333333333"),
                amount: 1_000_000,
            },
            fee_limit_sun: 1_000_000_000,
        };
        let raw = tron_build_raw_data(&tx, &h21("412222222222222222222222222222222222222222")).unwrap();
        assert_eq!(
            hex::encode(&raw),
            "0a02567822081112131415161718408088afa8bd315aae01081f12a9010a31747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e54726967676572536d617274436f6e747261637412740a15412222222222222222222222222222222222222222121541a614f803b6fd780986a42c78ec9c7f77e6ded13c2244a9059cbb000000000000000000000000333333333333333333333333333333333333333300000000000000000000000000000000000000000000000000000000000f42407080d095ffbc3190018094ebdc03"
        );
        assert_eq!(
            hex::encode(Sha256::digest(&raw)),
            "292693af95837307367a5fdbd06a4a1d752384ab97a70a2f46d5de73f62d12ec"
        );
    }

    #[test]
    fn usdt_contract_address_parses() {
        let a = parse_tron_address(TRON_USDT_CONTRACT).unwrap();
        assert_eq!(hex::encode(a), "41a614f803b6fd780986a42c78ec9c7f77e6ded13c");
    }

    #[test]
    fn sign_and_finalize_roundtrip() {
        use k256::ecdsa::SigningKey;
        let sk = SigningKey::from_bytes(&[0x11u8; 32].into()).unwrap();
        let pubkey = sk.verifying_key().to_encoded_point(false);
        let from = public_key_to_tron_address(pubkey.as_bytes()).unwrap();
        let owner = parse_tron_address(&from).unwrap();

        let tx = TronTx {
            ref_block: ref_block(0x1234, "0102030405060708"),
            expiration_ms: 1700000060000,
            timestamp_ms: 1700000000000,
            transfer: TronTransfer::Native { to: h21("412222222222222222222222222222222222222222"), amount_sun: 1 },
            fee_limit_sun: 0,
        };
        let raw = tron_build_raw_data(&tx, &owner).unwrap();
        let (sig, rec) = sk.sign_prehash_recoverable(&Sha256::digest(&raw)).unwrap();
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&sig.r().to_bytes());
        s.copy_from_slice(&sig.s().to_bytes());
        let res = EcdsaSignatureResult { r, s, v: rec.to_byte() };

        let signed = tron_finalize_tx(&raw, &res, &from).unwrap();
        assert!(signed.signed_tx_hex.starts_with("0a"));
        assert!(signed.signed_tx_hex.ends_with(&signed.signature_hex));
        assert!(tron_finalize_tx(&raw, &res, "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t").is_err());
    }
}
