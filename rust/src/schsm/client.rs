use anyhow::{anyhow, Result};
use crate::transport::Transport;
use crate::types::{SafePin, SlotPublicKey};
use crate::schsm::constants::*;

pub struct SmartCardHsmClient<T: Transport> {
    transport: T,
}

impl<T: Transport> SmartCardHsmClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// 选中 SmartCard-HSM Applet
    pub fn select_applet(&mut self) -> Result<()> {
        let mut apdu = vec![0x00, INS_SELECT, 0x04, 0x00, SCHSM_AID.len() as u8];
        apdu.extend_from_slice(&SCHSM_AID);
        apdu.push(0x00);

        let res = self.transport.transmit(&apdu)?;
        self.assert_success(&res, "Select SmartCard-HSM applet failed")
    }

    /// 读取硬件唯一设备 ID (Serial Number)
    pub fn get_device_id(&mut self) -> Result<String> {
        let apdu = [0x00, INS_GET_DATA, 0x01, 0x01, 0x00];
        let res = self.transport.transmit(&apdu)?;
        self.assert_success(&res, "Failed to read Device ID")?;
        
        let data = &res[..res.len() - 2];
        if data.is_empty() {
            return Ok("Nitrokey-HSM2-Connected".into());
        }

        // 若含有 0x5A Tag (Cardholder/Serial Number)，提取内容
        if data.len() >= 4 && data[0] == 0x5a {
            let len = data[1] as usize;
            if data.len() >= 2 + len {
                return Ok(format!("NK-HSM2-{}", hex::encode(&data[2..2 + len])));
            }
        }

        let s = String::from_utf8_lossy(data).trim().to_string();
        if s.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
            Ok(s)
        } else {
            Ok(format!("NK-HSM2-{}", hex::encode(data)))
        }
    }

    /// 获取 User PIN 剩余重试次数
    pub fn get_pin_retry_counter(&mut self) -> Result<u8> {
        let apdu = [0x00, INS_VERIFY, 0x00, 0x81, 0x00];
        let res = self.transport.transmit(&apdu)?;
        let sw = self.get_sw(&res)?;

        if (sw & 0xfff0) == SW_AUTH_FAILED_PREFIX {
            return Ok((sw & 0x000f) as u8);
        }
        if sw == SW_SUCCESS {
            return Ok(3);
        }
        if sw == SW_BLOCKED {
            return Ok(0);
        }

        Err(anyhow!("Unexpected status while reading PIN counter: 0x{:04X}", sw))
    }

    /// 校验 User PIN
    pub fn verify_pin(&mut self, pin: &SafePin) -> Result<()> {
        let pin_bytes = pin.as_bytes();
        let mut apdu = vec![0x00, INS_VERIFY, 0x00, 0x81, pin_bytes.len() as u8];
        apdu.extend_from_slice(pin_bytes);

        let res = self.transport.transmit(&apdu)?;
        let sw = self.get_sw(&res)?;

        if sw == SW_SUCCESS {
            return Ok(());
        }

        if (sw & 0xfff0) == SW_AUTH_FAILED_PREFIX {
            let retries = sw & 0x000f;
            return Err(anyhow!("PIN 码错误！剩余尝试机会: {} 次", retries));
        }

        if sw == SW_BLOCKED {
            return Err(anyhow!("【严重警告】设备已被硬件锁死 (PIN Retry: 0)，必须使用 SO-PIN 解锁！"));
        }

        Err(anyhow!("PIN verification failed with status: 0x{:04X}", sw))
    }

    /// 读取指定 Slot 导出的公钥 (65 字节 SEC1 未压缩)
    /// 自动解析真实 SmartCard-HSM 的 ASN.1 Public Key Template (Tag 7F49 / 86)
    pub fn get_slot_public_key(&mut self, slot_id: u8) -> Result<SlotPublicKey> {
        let apdu = [0x00, INS_READ_KEY, slot_id, 0x00, 0x00];
        let res = self.transport.transmit(&apdu)?;
        self.assert_success(&res, &format!("Failed to read public key for Slot {}", slot_id))?;

        let raw_data = &res[..res.len() - 2];
        let pubkey_bytes = extract_uncompressed_sec1_key(raw_data)?;
        Ok(SlotPublicKey {
            slot_id,
            public_key_uncompressed: pubkey_bytes,
        })
    }

    /// 请求卡片计算 ECDSA 签名并返回 ASN.1 DER 字节
    pub fn compute_digital_signature(&mut self, slot_id: u8, msg_hash: &[u8; 32]) -> Result<Vec<u8>> {
        let mut apdu = vec![0x00, INS_PSO, 0x9e, 0x9a, 0x20];
        apdu.extend_from_slice(msg_hash);
        apdu.push(0x00);

        let res = self.transport.transmit(&apdu)?;
        self.assert_success(&res, &format!("PSO: COMPUTE DIGITAL SIGNATURE failed on Slot {}", slot_id))?;

        Ok(res[..res.len() - 2].to_vec())
    }

    fn get_sw(&self, res: &[u8]) -> Result<u16> {
        if res.len() < 2 {
            return Err(anyhow!("Response APDU too short"));
        }
        let sw = ((res[res.len() - 2] as u16) << 8) | (res[res.len() - 1] as u16);
        Ok(sw)
    }

    fn assert_success(&self, res: &[u8], msg: &str) -> Result<()> {
        let sw = self.get_sw(res)?;
        if sw != SW_SUCCESS {
            return Err(anyhow!("{}: SW=0x{:04X}", msg, sw));
        }
        Ok(())
    }
}

/// 兼容解析真实 SmartCard-HSM 返回的各种公钥封装结构 (原始 65 字节或 TLV Template 7F49 / 86)
fn extract_uncompressed_sec1_key(raw_bytes: &[u8]) -> Result<Vec<u8>> {
    // 1. 如果刚好是 65 字节 SEC1 未压缩格式 (04 || X || Y)
    if raw_bytes.len() == 65 && raw_bytes[0] == 0x04 {
        return Ok(raw_bytes.to_vec());
    }

    // 2. 检测并提取 ASN.1 TLV Tag 0x86 (0x86 0x41 0x04 ...)
    for i in 0..raw_bytes.len().saturating_sub(66) {
        if raw_bytes[i] == 0x86 && raw_bytes[i + 1] == 0x41 && raw_bytes[i + 2] == 0x04 {
            return Ok(raw_bytes[i + 2..i + 67].to_vec());
        }
    }

    // 3. 通用搜索任意以 0x04 开头的有效 secp256k1 点 (65 字节)
    for i in 0..raw_bytes.len().saturating_sub(64) {
        if raw_bytes[i] == 0x04 {
            let candidate = &raw_bytes[i..i + 65];
            if k256::ecdsa::VerifyingKey::from_sec1_bytes(candidate).is_ok() {
                return Ok(candidate.to_vec());
            }
        }
    }

    Err(anyhow!(
        "无法从卡片响应中提取 65 字节未压缩公钥 (数据长度: {})",
        raw_bytes.len()
    ))
}
