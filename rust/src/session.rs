use anyhow::{anyhow, Result};
use crate::schsm::client::SmartCardHsmClient;
use crate::transport::Transport;
use crate::types::{EcdsaSignatureResult, SafePin};
use crate::crypto::secp256k1::process_hsm_signature;

pub struct SignSessionManager<'a, T: Transport> {
    client: &'a mut SmartCardHsmClient<T>,
}

impl<'a, T: Transport> SignSessionManager<'a, T> {
    pub fn new(client: &'a mut SmartCardHsmClient<T>) -> Self {
        Self { client }
    }

    /// 执行安全的硬件签名流水线 (PIN 即用即销)
    pub fn execute_signing(
        &mut self,
        slot_id: u8,
        msg_hash: &[u8; 32],
        expected_pubkey: &[u8],
        pin: SafePin, // 所有权转移，函数结束自动 Zeroize 覆写清零
    ) -> Result<EcdsaSignatureResult> {
        // 1. 预检 PIN 剩余次数
        let retry_count = self.client.get_pin_retry_counter()?;
        if retry_count == 0 {
            return Err(anyhow!("【严重阻断】设备已被硬件锁死 (PIN 剩余尝试次数为 0)！"));
        }

        // 2. 校验 PIN
        self.client.verify_pin(&pin)?;

        // 3. 请求芯片计算签名
        let der_bytes = self.client.compute_digital_signature(slot_id, msg_hash)?;

        // pin 将在此处隐式 drop 并触发 zeroize 擦除！

        // 4. 解析 DER、规范化 Low-s 并恢复 v
        let sig = process_hsm_signature(&der_bytes, msg_hash, expected_pubkey)?;

        Ok(sig)
    }
}
