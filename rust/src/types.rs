use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 硬件设备基础信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_id: String,
    pub pin_retry_count: u8,
}

/// Slot 导出的公钥信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotPublicKey {
    pub slot_id: u8,
    pub public_key_uncompressed: Vec<u8>, // 65 字节: 04 || X || Y
}

/// 多链账户模型：以设备内密钥的 CKA_ID 作为账户标识 (1 个 CKA_ID = 1 个多链账户)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountSlot {
    /// PKCS#11 CKA_ID (0-254)；兼容旧缓存中的 slot_id 字段
    #[serde(alias = "slot_id")]
    pub key_id: u8,
    pub account_name: String,
    pub public_key_hex: String,
    pub eth_address: String,
    pub tron_address: String,
}

/// 本地 Watch-only 钱包缓存
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceWalletCache {
    pub device_id: String,
    pub device_name: String,
    pub last_sync_timestamp: u64,
    pub slots: Vec<AccountSlot>,
}

/// ECDSA secp256k1 签名结果
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EcdsaSignatureResult {
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub v: u8, // 0 或 1 (Recovery ID)
}

/// TRON 账户链上资源状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TronAccountResource {
    pub free_net_limit: u64,
    pub free_net_used: u64,
    pub energy_limit: u64,
    pub energy_used: u64,
    pub trx_balance_sun: u64,
}

/// TRON TRC-20 转账能量/带宽预估与阻断结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TronEstimateResult {
    pub recipient_has_usdt: bool,
    pub required_energy: u64,
    pub available_energy: u64,
    pub missing_energy: u64,
    pub required_bandwidth: u64,
    pub available_bandwidth: u64,
    pub burn_trx_amount: f64,
    pub is_trx_sufficient: bool,
    pub warning_message: Option<String>,
    pub block_reason: Option<String>,
}

/// 密码安全擦除容器 (离开作用域时由 zeroize 自动在汇编层覆写清零)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SafePin {
    pub pin: String,
}

impl SafePin {
    pub fn new(pin: impl Into<String>) -> Self {
        Self { pin: pin.into() }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.pin.as_bytes()
    }
}
