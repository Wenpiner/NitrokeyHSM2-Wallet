use anyhow::Result;
use sha3::{Digest, Keccak256};
use crate::types::EcdsaSignatureResult;
use crate::crypto::address::to_checksum_address;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

#[derive(Debug, Clone)]
pub struct EthUnsignedTx {
    pub to: String,
    pub value_wei: u128,
    pub nonce: u64,
    pub gas_limit: u64,
    pub gas_price_wei: u128,
    pub chain_id: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct EthSignedTx {
    pub raw_tx_hex: String,
    pub recovered_from: String,
}

/// 计算待签名的以太坊交易摘要 (EIP-155 格式)
pub fn build_eth_signing_hash(tx: &EthUnsignedTx) -> [u8; 32] {
    // 简易 RLP 序列化用于哈希计算 (或标准 EIP-155 [nonce, gasprice, gaslimit, to, value, data, chainid, 0, 0])
    let mut payload = Vec::new();
    payload.extend_from_slice(&tx.nonce.to_be_bytes());
    payload.extend_from_slice(&tx.gas_price_wei.to_be_bytes());
    payload.extend_from_slice(&tx.gas_limit.to_be_bytes());
    payload.extend_from_slice(tx.to.as_bytes());
    payload.extend_from_slice(&tx.value_wei.to_be_bytes());
    payload.extend_from_slice(&tx.data);
    payload.extend_from_slice(&tx.chain_id.to_be_bytes());

    let hash = Keccak256::digest(&payload);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    out
}

/// 将 HSM 计算得到的 (r, s, v) 组装并验证
pub fn finalize_eth_transaction(
    tx: &EthUnsignedTx,
    sig: &EcdsaSignatureResult,
    signing_hash: &[u8; 32],
) -> Result<EthSignedTx> {
    // 计算 EIP-155 v = v + chainId * 2 + 35
    let v_eip155 = sig.v as u64 + tx.chain_id * 2 + 35;

    // 本地反向验签
    let k256_sig = Signature::from_scalars(sig.r, sig.s)?;
    let rec_id = RecoveryId::from_byte(sig.v).ok_or_else(|| anyhow::anyhow!("Invalid recovery id"))?;
    let recovered_key = VerifyingKey::recover_from_prehash(signing_hash, &k256_sig, rec_id)?;
    let uncompressed = recovered_key.to_encoded_point(false);
    let recovered_address = crate::crypto::address::public_key_to_eth_address(uncompressed.as_bytes())?;

    let raw_tx = format!(
        "0x{}{}{}{:02x}",
        hex::encode(sig.r),
        hex::encode(sig.s),
        hex::encode(v_eip155.to_be_bytes()),
        tx.nonce
    );

    Ok(EthSignedTx {
        raw_tx_hex: raw_tx,
        recovered_from: to_checksum_address(&recovered_address),
    })
}

// ---------------------------------------------------------------------------
// 真实主网交易构造：Legacy + EIP-155，RLP 编码
// ---------------------------------------------------------------------------

/// 以太坊主网 USDT (ERC-20, 6 位小数)
pub const ETH_USDT_CONTRACT: &str = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
pub const ETH_MAINNET_CHAIN_ID: u64 = 1;

/// EIP-155 Legacy 交易字段，`to` 为 20 字节原始地址
#[derive(Debug, Clone)]
pub struct EthLegacyTx {
    pub nonce: u64,
    pub gas_price_wei: u128,
    pub gas_limit: u64,
    pub to: [u8; 20],
    pub value_wei: u128,
    pub data: Vec<u8>,
    pub chain_id: u64,
}

/// 签名后的交易：raw_tx_hex 可直接用于 eth_sendRawTransaction
#[derive(Debug, Clone)]
pub struct EthSignedRawTx {
    pub raw_tx_hex: String,
    pub tx_hash: String,
    pub from: String,
}

fn rlp_trim_be(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    &bytes[start..]
}

fn rlp_length_prefix(len: usize, offset: u8, out: &mut Vec<u8>) {
    if len < 56 {
        out.push(offset + len as u8);
    } else {
        let len_bytes = (len as u64).to_be_bytes();
        let trimmed = rlp_trim_be(&len_bytes);
        out.push(offset + 55 + trimmed.len() as u8);
        out.extend_from_slice(trimmed);
    }
}

/// RLP 编码字节串
pub fn rlp_encode_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        out.push(bytes[0]);
    } else {
        rlp_length_prefix(bytes.len(), 0x80, out);
        out.extend_from_slice(bytes);
    }
}

/// RLP 编码无符号整数（大端、去前导零，0 编码为空串）
pub fn rlp_encode_uint(v: u128, out: &mut Vec<u8>) {
    rlp_encode_bytes(rlp_trim_be(&v.to_be_bytes()), out);
}

fn rlp_wrap_list(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 9);
    rlp_length_prefix(payload.len(), 0xc0, &mut out);
    out.extend_from_slice(payload);
    out
}

fn rlp_tx_fields(tx: &EthLegacyTx, out: &mut Vec<u8>) {
    rlp_encode_uint(tx.nonce as u128, out);
    rlp_encode_uint(tx.gas_price_wei, out);
    rlp_encode_uint(tx.gas_limit as u128, out);
    rlp_encode_bytes(&tx.to, out);
    rlp_encode_uint(tx.value_wei, out);
    rlp_encode_bytes(&tx.data, out);
}

/// EIP-155 签名摘要: keccak256(rlp([nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]))
pub fn eth_legacy_signing_hash(tx: &EthLegacyTx) -> [u8; 32] {
    let mut payload = Vec::new();
    rlp_tx_fields(tx, &mut payload);
    rlp_encode_uint(tx.chain_id as u128, &mut payload);
    rlp_encode_uint(0, &mut payload);
    rlp_encode_uint(0, &mut payload);
    let mut out = [0u8; 32];
    out.copy_from_slice(&Keccak256::digest(rlp_wrap_list(&payload)));
    out
}

/// 组装已签名交易并本地恢复发送方地址，与预期地址不一致则拒绝
pub fn eth_legacy_finalize(
    tx: &EthLegacyTx,
    sig: &EcdsaSignatureResult,
    expected_from: &str,
) -> Result<EthSignedRawTx> {
    let signing_hash = eth_legacy_signing_hash(tx);
    let k256_sig = Signature::from_scalars(sig.r, sig.s)?;
    let rec_id = RecoveryId::from_byte(sig.v).ok_or_else(|| anyhow::anyhow!("Invalid recovery id"))?;
    let recovered = VerifyingKey::recover_from_prehash(&signing_hash, &k256_sig, rec_id)?;
    let from = crate::crypto::address::public_key_to_eth_address(recovered.to_encoded_point(false).as_bytes())?;
    if !from.eq_ignore_ascii_case(expected_from) {
        return Err(anyhow::anyhow!("签名恢复地址 {} 与账户地址 {} 不一致", from, expected_from));
    }

    let v = sig.v as u128 + tx.chain_id as u128 * 2 + 35;
    let mut payload = Vec::new();
    rlp_tx_fields(tx, &mut payload);
    rlp_encode_uint(v, &mut payload);
    rlp_encode_bytes(rlp_trim_be(&sig.r), &mut payload);
    rlp_encode_bytes(rlp_trim_be(&sig.s), &mut payload);
    let raw = rlp_wrap_list(&payload);

    Ok(EthSignedRawTx {
        tx_hash: format!("0x{}", hex::encode(Keccak256::digest(&raw))),
        raw_tx_hex: format!("0x{}", hex::encode(&raw)),
        from,
    })
}

/// 解析 0x 地址；混合大小写时强制校验 EIP-55 校验和
pub fn parse_eth_address(addr: &str) -> Result<[u8; 20]> {
    let s = addr.trim();
    let body = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .ok_or_else(|| anyhow::anyhow!("ETH 地址需以 0x 开头"))?;
    if body.len() != 40 || !body.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow::anyhow!("ETH 地址格式无效"));
    }
    let has_upper = body.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = body.chars().any(|c| c.is_ascii_lowercase());
    if has_upper && has_lower && to_checksum_address(body) != format!("0x{}", body) {
        return Err(anyhow::anyhow!("ETH 地址校验和错误，请检查是否输错"));
    }
    let mut out = [0u8; 20];
    hex::decode_to_slice(body.to_ascii_lowercase(), &mut out)?;
    Ok(out)
}

/// ERC-20 transfer(address,uint256) 调用数据
pub fn erc20_transfer_data(to: &[u8; 20], amount: u128) -> Vec<u8> {
    let mut data = Vec::with_capacity(68);
    data.extend_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(to);
    data.extend_from_slice(&[0u8; 16]);
    data.extend_from_slice(&amount.to_be_bytes());
    data
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;

    /// EIP-155 规范中的示例交易
    #[test]
    fn eip155_spec_vector() {
        let tx = EthLegacyTx {
            nonce: 9,
            gas_price_wei: 20_000_000_000,
            gas_limit: 21000,
            to: [0x35; 20],
            value_wei: 1_000_000_000_000_000_000,
            data: vec![],
            chain_id: 1,
        };
        let hash = eth_legacy_signing_hash(&tx);
        assert_eq!(hex::encode(hash), "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53");

        let sk = SigningKey::from_bytes(&[0x46u8; 32].into()).unwrap();
        let (sig, rec) = sk.sign_prehash_recoverable(&hash).unwrap();
        let sig = sig.normalize_s().unwrap_or(sig);
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&sig.r().to_bytes());
        s.copy_from_slice(&sig.s().to_bytes());
        // 恢复 ID：与归一化后的签名匹配
        let expected_key = sk.verifying_key();
        let v = (0..=1u8)
            .find(|v| {
                VerifyingKey::recover_from_prehash(&hash, &sig, RecoveryId::from_byte(*v).unwrap())
                    .map(|k| &k == expected_key)
                    .unwrap_or(false)
            })
            .unwrap();
        let _ = rec;
        let from = crate::crypto::address::public_key_to_eth_address(
            expected_key.to_encoded_point(false).as_bytes(),
        )
        .unwrap();

        let signed = eth_legacy_finalize(&tx, &EcdsaSignatureResult { r, s, v }, &from).unwrap();
        assert_eq!(
            signed.raw_tx_hex,
            "0xf86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"
        );
        assert!(eth_legacy_finalize(&tx, &EcdsaSignatureResult { r, s, v }, "0x0000000000000000000000000000000000000000").is_err());
    }

    #[test]
    fn address_parsing() {
        assert!(parse_eth_address(ETH_USDT_CONTRACT).is_ok());
        assert!(parse_eth_address("0xdac17f958d2ee523a2206206994597c13d831ec7").is_ok());
        assert!(parse_eth_address("0xdAC17F958D2ee523a2206206994597C13D831EC7").is_err());
        assert!(parse_eth_address("dac17f958d2ee523a2206206994597c13d831ec7").is_err());
        assert!(parse_eth_address("0x1234").is_err());
    }

    #[test]
    fn erc20_data_layout() {
        let data = erc20_transfer_data(&[0xab; 20], 1_000_000);
        assert_eq!(data.len(), 68);
        assert_eq!(&data[..4], &[0xa9, 0x05, 0x9c, 0xbb]);
        assert_eq!(&data[16..36], &[0xab; 20]);
        assert_eq!(&data[64..], &[0x00, 0x0f, 0x42, 0x40]);
    }
}
