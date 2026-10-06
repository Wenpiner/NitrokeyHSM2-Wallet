use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use crate::types::{AccountSlot, DeviceWalletCache};
use crate::crypto::address::{public_key_to_eth_address, public_key_to_tron_address};
use anyhow::{anyhow, Result};

/// Watch-only 钱包缓存：只保存公钥与派生地址，不保存 PIN 与密钥标签
#[derive(Default, Serialize, Deserialize)]
pub struct WalletStore {
    devices: HashMap<String, DeviceWalletCache>,
}

impl WalletStore {
    pub fn new() -> Self {
        Self {
            devices: HashMap::new(),
        }
    }

    /// 默认缓存文件路径，可通过 WALLET_CACHE_PATH 覆盖
    pub fn default_path() -> PathBuf {
        if let Ok(p) = std::env::var("WALLET_CACHE_PATH") {
            return PathBuf::from(p);
        }
        let home = std::env::var("HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("."));
        let base = if cfg!(target_os = "macos") {
            home.join("Library/Application Support")
        } else {
            std::env::var("XDG_DATA_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|_| home.join(".local/share"))
        };
        base.join("nitrokey-wallet").join("wallet_cache.json")
    }

    /// 从磁盘加载缓存，文件不存在时返回空缓存
    pub fn load(path: &Path) -> Result<Self> {
        match fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| anyhow!("解析钱包缓存失败 ({}): {}", path.display(), e)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::new()),
            Err(e) => Err(anyhow!("读取钱包缓存失败 ({}): {}", path.display(), e)),
        }
    }

    /// 写入磁盘：先写临时文件再原子替换，Unix 下权限为 0600
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
        }
        fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn get_device_cache(&self, device_id: &str) -> Option<&DeviceWalletCache> {
        self.devices.get(device_id)
    }

    /// 最近一次同步的设备缓存
    pub fn latest_device(&self) -> Option<&DeviceWalletCache> {
        self.devices.values().max_by_key(|d| d.last_sync_timestamp)
    }

    /// 写入 / 更新一个账户（按 CKA_ID 去重），列表按 ID 升序
    pub fn upsert_account(
        &mut self,
        device_id: &str,
        key_id: u8,
        uncompressed_pubkey: &[u8],
        account_name: Option<&str>,
    ) -> Result<AccountSlot> {
        let eth_addr = public_key_to_eth_address(uncompressed_pubkey)?;
        let tron_addr = public_key_to_tron_address(uncompressed_pubkey)?;
        let pubkey_hex = hex::encode(uncompressed_pubkey);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let cache = self.devices.entry(device_id.to_string()).or_insert_with(|| {
            DeviceWalletCache {
                device_id: device_id.to_string(),
                device_name: format!("Nitrokey HSM 2 ({})", &device_id[device_id.len().saturating_sub(6)..]),
                last_sync_timestamp: now,
                slots: Vec::new(),
            }
        });
        cache.last_sync_timestamp = now;

        let slot = AccountSlot {
            key_id,
            account_name: account_name.unwrap_or(&format!("Account {}", key_id)).to_string(),
            public_key_hex: pubkey_hex,
            eth_address: eth_addr,
            tron_address: tron_addr,
        };

        if let Some(pos) = cache.slots.iter().position(|s| s.key_id == key_id) {
            cache.slots[pos] = slot.clone();
        } else {
            cache.slots.push(slot.clone());
        }
        cache.slots.sort_by_key(|s| s.key_id);

        Ok(slot)
    }

    /// 从最近同步的设备缓存中移除指定 CKA_ID 的账户（只删除本地公钥缓存，不触碰设备上的私钥）
    pub fn remove_account(&mut self, key_id: u8) -> Result<()> {
        let device_id = self
            .latest_device()
            .map(|d| d.device_id.clone())
            .ok_or_else(|| anyhow!("本地没有钱包缓存"))?;
        let cache = self
            .devices
            .get_mut(&device_id)
            .ok_or_else(|| anyhow!("本地没有钱包缓存"))?;
        let before = cache.slots.len();
        cache.slots.retain(|s| s.key_id != key_id);
        if cache.slots.len() == before {
            return Err(anyhow!("ID {} 没有账户", key_id));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::elliptic_curve::sec1::ToEncodedPoint;

    fn pubkey(seed: u8) -> Vec<u8> {
        let sk = k256::SecretKey::from_slice(&[seed; 32]).unwrap();
        sk.public_key().to_encoded_point(false).as_bytes().to_vec()
    }

    #[test]
    fn remove_account_only_drops_target() {
        let mut store = WalletStore::new();
        store.upsert_account("DEV123456", 20, &pubkey(1), None).unwrap();
        store.upsert_account("DEV123456", 3, &pubkey(2), None).unwrap();
        // 按 CKA_ID 升序
        let ids: Vec<u8> = store.latest_device().unwrap().slots.iter().map(|s| s.key_id).collect();
        assert_eq!(ids, vec![3, 20]);

        store.remove_account(20).unwrap();
        let dev = store.latest_device().unwrap();
        assert_eq!(dev.slots.len(), 1);
        assert_eq!(dev.slots[0].key_id, 3);

        // 再次删除同一个账户应报错
        assert!(store.remove_account(20).is_err());
        // 删完最后一个，设备条目保留，slots 为空
        store.remove_account(3).unwrap();
        assert!(store.latest_device().unwrap().slots.is_empty());
    }

    #[test]
    fn remove_account_without_cache_errors() {
        assert!(WalletStore::new().remove_account(0).is_err());
    }

    #[test]
    fn legacy_slot_id_cache_still_loads() {
        let mut store = WalletStore::new();
        store.upsert_account("DEV123456", 1, &pubkey(3), None).unwrap();
        let json = serde_json::to_string(&store).unwrap().replace("\"key_id\"", "\"slot_id\"");
        assert!(json.contains("slot_id"));
        let loaded: WalletStore = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.latest_device().unwrap().slots[0].key_id, 1);
    }
}
