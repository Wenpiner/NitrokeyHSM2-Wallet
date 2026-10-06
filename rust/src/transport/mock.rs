use anyhow::{anyhow, Result};
use std::collections::HashMap;
use k256::ecdsa::SigningKey;
use crate::transport::Transport;
use crate::schsm::constants::*;

pub struct MockSlot {
    pub slot_id: u8,
    pub signing_key: SigningKey,
    pub public_key_uncompressed: Vec<u8>,
}

pub struct MockTransport {
    pub device_id: String,
    pub user_pin: String,
    pub pin_retry_count: u8,
    pub is_authenticated: bool,
    connected: bool,
    slots: HashMap<u8, MockSlot>,
}

impl MockTransport {
    pub fn new(device_id: impl Into<String>, user_pin: impl Into<String>) -> Self {
        let mut slots = HashMap::new();

        // 预置 Slot 1
        let priv1 = [0x11u8; 32];
        let key1 = SigningKey::from_bytes(&priv1.into()).unwrap();
        let pub1 = key1.verifying_key().to_encoded_point(false).as_bytes().to_vec();
        slots.insert(1, MockSlot {
            slot_id: 1,
            signing_key: key1,
            public_key_uncompressed: pub1,
        });

        // 预置 Slot 2
        let priv2 = [0x22u8; 32];
        let key2 = SigningKey::from_bytes(&priv2.into()).unwrap();
        let pub2 = key2.verifying_key().to_encoded_point(false).as_bytes().to_vec();
        slots.insert(2, MockSlot {
            slot_id: 2,
            signing_key: key2,
            public_key_uncompressed: pub2,
        });

        Self {
            device_id: device_id.into(),
            user_pin: user_pin.into(),
            pin_retry_count: 3,
            is_authenticated: false,
            connected: false,
            slots,
        }
    }
}

impl Default for MockTransport {
    fn default() -> Self {
        Self::new("SCHSM2-RUST-DEMO-001", "648219")
    }
}

impl Transport for MockTransport {
    fn name(&self) -> &str {
        "Mock-Nitrokey-HSM2-Rust"
    }

    fn connect(&mut self) -> Result<()> {
        self.connected = true;
        Ok(())
    }

    fn disconnect(&mut self) -> Result<()> {
        self.connected = false;
        self.is_authenticated = false;
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected
    }

    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>> {
        if !self.connected {
            return Err(anyhow!("Transport not connected"));
        }

        if apdu.len() < 4 {
            return Err(anyhow!("APDU too short"));
        }

        let ins = apdu[1];
        let p1 = apdu[2];

        // 1. SELECT AID (00 A4 ...)
        if ins == INS_SELECT {
            return Ok(vec![0x90, 0x00]);
        }

        // 2. GET DATA (读取 EF.GDO / Serial Number)
        if ins == INS_GET_DATA {
            let mut res = self.device_id.as_bytes().to_vec();
            res.extend_from_slice(&[0x90, 0x00]);
            return Ok(res);
        }

        // 3. VERIFY PIN (00 20 ...)
        if ins == INS_VERIFY {
            let lc = if apdu.len() > 4 { apdu[4] as usize } else { 0 };
            
            // 空验证查询计数器
            if lc == 0 || apdu.len() == 5 {
                return Ok(vec![0x63, 0xc0 | (self.pin_retry_count & 0x0f)]);
            }

            if self.pin_retry_count == 0 {
                return Ok(vec![0x69, 0x83]); // SW_BLOCKED
            }

            let pin_slice = &apdu[5..5 + lc];
            let input_pin = String::from_utf8_lossy(pin_slice);

            if input_pin == self.user_pin {
                self.pin_retry_count = 3;
                self.is_authenticated = true;
                return Ok(vec![0x90, 0x00]);
            } else {
                self.pin_retry_count = self.pin_retry_count.saturating_sub(1);
                self.is_authenticated = false;
                if self.pin_retry_count == 0 {
                    return Ok(vec![0x69, 0x83]);
                }
                return Ok(vec![0x63, 0xc0 | (self.pin_retry_count & 0x0f)]);
            }
        }

        // 4. READ PUBLIC KEY (00 B6 [slot_id] 00 00)
        if ins == INS_READ_KEY {
            let slot_id = p1;
            if let Some(slot) = self.slots.get(&slot_id) {
                let mut res = slot.public_key_uncompressed.clone();
                res.extend_from_slice(&[0x90, 0x00]);
                return Ok(res);
            } else {
                return Ok(vec![0x6a, 0x88]); // Key not found
            }
        }

        // 5. PSO: COMPUTE DIGITAL SIGNATURE (00 2A 9E 9A ...)
        if ins == INS_PSO {
            if !self.is_authenticated {
                return Ok(vec![0x69, 0x82]); // Security status not satisfied
            }

            let lc = apdu[4] as usize;
            if lc != 32 || apdu.len() < 5 + lc {
                return Ok(vec![0x67, 0x00]); // Wrong length
            }

            let msg_hash = &apdu[5..5 + lc];
            let slot = self.slots.get(&1).ok_or_else(|| anyhow!("Slot 1 not found"))?;

            // 传入的已经是 32 字节 Hash，必须使用 sign_prehash 而不是对 hash 再次做哈希
            let (sig, _) = slot.signing_key.sign_prehash_recoverable(msg_hash)
                .map_err(|e| anyhow!("Signing failed: {:?}", e))?;
            let der_bytes = sig.to_der();

            let mut res = der_bytes.as_bytes().to_vec();
            res.extend_from_slice(&[0x90, 0x00]);
            return Ok(res);
        }

        Ok(vec![0x6d, 0x00]) // Unknown instruction
    }
}
