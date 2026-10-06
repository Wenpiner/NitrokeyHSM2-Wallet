use anyhow::{anyhow, Result};
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::RvError;
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, ObjectClass};
use cryptoki::session::{Session, UserType};
use secrecy::SecretString;
use std::env;
use std::path::Path;

use crate::types::EcdsaSignatureResult;
use crate::crypto::secp256k1::process_hsm_signature;

// secp256k1 OID: 1.3.132.0.10 -> 06 05 2B 81 04 00 0A
pub const OID_SECP256K1: [u8; 7] = [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a];

/// PKCS#11 会话封装。
///
/// 不持有 PIN：PIN 仅在 `connect` 调用期间以引用传入，由调用方负责其生命周期与清零。
/// 实例 drop 时自动登出并 finalize，确保用完即断开。
pub struct Pkcs11Hsm {
    module_path: String,
    slot_id: Option<u64>,
    default_label: String,
    hsm_sn: Option<String>,
    token_serial: Option<String>,
    ctx: Option<Pkcs11>,
    session: Option<Session>,
}

impl Pkcs11Hsm {
    /// 自动发现模块路径并创建配置，key_label 必须由调用方显式提供
    pub fn new(key_label: &str) -> Result<Self> {
        let key_label = key_label.trim();
        if key_label.is_empty() {
            return Err(anyhow!("密钥标签 (Key Label) 不能为空"));
        }
        let module_path = Self::detect_module_path()?;
        let slot_id = env::var("HSM_SLOT")
            .ok()
            .and_then(|s| s.parse::<u64>().ok());
        let hsm_sn = env::var("HSM_SN")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        Ok(Self {
            module_path,
            slot_id,
            default_label: key_label.to_string(),
            hsm_sn,
            token_serial: None,
            ctx: None,
            session: None,
        })
    }

    pub fn set_key_label(&mut self, label: &str) {
        self.default_label = label.to_string();
    }

    /// 探测可用的 OpenSC PKCS#11 动态库路径
    pub fn detect_module_path() -> Result<String> {
        if let Ok(p) = env::var("PKCS11_MODULE") {
            if Path::new(&p).exists() {
                return Ok(p);
            }
        }

        let candidates = [
            "/Library/OpenSC/lib/opensc-pkcs11.so",
            "/usr/local/lib/opensc-pkcs11.so",
            "/opt/homebrew/lib/opensc-pkcs11.so",
            "/usr/lib/opensc-pkcs11.so",
        ];

        for &c in &candidates {
            if Path::new(c).exists() {
                return Ok(c.to_string());
            }
        }

        Err(anyhow!(
            "未找到 opensc-pkcs11.so 动态库，请确认已安装 OpenSC (例如 /Library/OpenSC/lib/opensc-pkcs11.so)"
        ))
    }

    /// 连接并登录 PKCS#11 HSM 会话。PIN 仅借用，不会被保存。
    pub fn connect(&mut self, pin: &SecretString) -> Result<()> {
        self.disconnect();

        let pkcs11 = Pkcs11::new(&self.module_path)
            .map_err(|e| anyhow!("加载 PKCS#11 模块失败 ({}): {:?}", self.module_path, e))?;

        pkcs11
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|e| anyhow!("PKCS#11 初始化失败: {:?}", e))?;

        // cryptoki 的 Pkcs11 drop 时不会 C_Finalize，失败路径必须手动 finalize，
        // 否则同进程内下次 initialize 会返回 CKR_CRYPTOKI_ALREADY_INITIALIZED。
        match self.open_and_login(&pkcs11, pin) {
            Ok((session, serial)) => {
                self.token_serial = Some(serial);
                self.ctx = Some(pkcs11);
                self.session = Some(session);
                Ok(())
            }
            Err(e) => {
                let _ = pkcs11.finalize();
                Err(e)
            }
        }
    }

    /// 选择目标 Slot、打开会话并登录，返回会话与 Token 序列号
    fn open_and_login(&self, pkcs11: &Pkcs11, pin: &SecretString) -> Result<(Session, String)> {
        // 查找有可用 Token 的 Slot
        let slots = pkcs11
            .get_slots_with_token()
            .map_err(|e| anyhow!("获取 PKCS#11 Slots 失败: {:?}", e))?;

        if slots.is_empty() {
            return Err(anyhow!("未检测到任何插入的 Nitrokey HSM 2 (Slot 列表为空)"));
        }

        // HSM_SLOT 表示 PKCS#11 slot ID（非列表下标）。
        // 未设置时：有 HSM_SN 则按 Token 序列号匹配；否则只接受唯一一个 SmartCard-HSM Token，
        // 避免选中其他智能卡（如 YubiKey）。
        let target_slot = match self.slot_id {
            Some(id) => slots
                .iter()
                .copied()
                .find(|s| s.id() == id)
                .ok_or_else(|| anyhow!("HSM_SLOT={} 对应的 Slot 不存在或未插入 Token", id))?,
            None => {
                let mut seen = Vec::new();
                let mut matched = Vec::new();
                for &s in &slots {
                    let info = match pkcs11.get_token_info(s) {
                        Ok(info) => info,
                        Err(_) => continue,
                    };
                    let sn = info.serial_number().trim().to_string();
                    let hit = match &self.hsm_sn {
                        Some(want) => sn == *want,
                        None => {
                            info.label().contains("SmartCard-HSM")
                                || info.manufacturer_id().contains("CardContact")
                        }
                    };
                    if hit {
                        matched.push(s);
                    }
                    seen.push(format!("slot 0x{:x}: {} (SN={})", s.id(), info.label().trim(), sn));
                }
                match (matched.as_slice(), &self.hsm_sn) {
                    ([s], _) => *s,
                    ([], Some(sn)) => {
                        return Err(anyhow!(
                            "未找到序列号为 {} 的 Token，当前可用: [{}]",
                            sn,
                            seen.join(", ")
                        ))
                    }
                    ([], None) => {
                        return Err(anyhow!(
                            "未找到 SmartCard-HSM Token，可设置 HSM_SN 或 HSM_SLOT 指定，当前可用: [{}]",
                            seen.join(", ")
                        ))
                    }
                    _ => {
                        return Err(anyhow!(
                            "检测到多个匹配的 Token，请设置 HSM_SN 或 HSM_SLOT 指定目标: [{}]",
                            seen.join(", ")
                        ))
                    }
                }
            }
        };

        let token_info = pkcs11
            .get_token_info(target_slot)
            .map_err(|e| anyhow!("读取 Token 信息失败: {:?}", e))?;
        if token_info.user_pin_locked() {
            return Err(anyhow!("User PIN 已被锁定，请使用 SO PIN 解锁后再试"));
        }
        let serial = token_info.serial_number().trim().to_string();

        // 打开可读写会话
        let session = pkcs11
            .open_rw_session(target_slot)
            .map_err(|e| anyhow!("打开 Slot 会话失败: {:?}", e))?;

        // 登录 User PIN
        if let Err(e) = session.login(UserType::User, Some(pin)) {
            return Err(match e {
                cryptoki::error::Error::Pkcs11(RvError::PinIncorrect, _) => {
                    let final_try = pkcs11
                        .get_token_info(target_slot)
                        .map(|i| i.user_pin_final_try())
                        .unwrap_or(false);
                    if final_try {
                        anyhow!("PIN 错误，仅剩最后 1 次尝试机会，再错将锁定设备")
                    } else {
                        anyhow!("PIN 错误")
                    }
                }
                cryptoki::error::Error::Pkcs11(RvError::PinLocked, _) => {
                    anyhow!("User PIN 已被锁定，请使用 SO PIN 解锁后再试")
                }
                other => anyhow!("HSM PIN 码登录失败: {:?}", other),
            });
        }

        Ok((session, serial))
    }

    /// 登出、关闭会话并 finalize PKCS#11 上下文
    pub fn disconnect(&mut self) {
        // Session 内部持有 Pkcs11 引用，必须先关闭会话再 finalize
        if let Some(session) = self.session.take() {
            let _ = session.logout();
            drop(session);
        }
        if let Some(ctx) = self.ctx.take() {
            let _ = ctx.finalize();
        }
    }

    pub fn is_connected(&self) -> bool {
        self.session.is_some()
    }

    /// 查找指定 Label 的公钥对象并提取 65 字节 SEC1 未压缩公钥
    pub fn get_public_key(&mut self, label: Option<&str>) -> Result<Vec<u8>> {
        let target_label = label.unwrap_or(&self.default_label).to_string();
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| anyhow!("HSM 未连接，请先输入 PIN 登录"))?;

        // 查找公钥对象
        let template = vec![
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::Label(target_label.as_bytes().to_vec()),
        ];

        let objects = session
            .find_objects(&template)
            .map_err(|e| anyhow!("查找公钥失败: {:?}", e))?;

        if objects.is_empty() {
            return Err(anyhow!("未找到标签为 '{}' 的公钥对象", target_label));
        }

        let pub_handle = objects[0];
        let attrs = session
            .get_attributes(pub_handle, &[AttributeType::EcPoint])
            .map_err(|e| anyhow!("获取 EC_POINT 属性失败: {:?}", e))?;

        if attrs.is_empty() {
            return Err(anyhow!("公钥对象没有 EC_POINT 属性"));
        }

        if let Attribute::EcPoint(raw_point) = &attrs[0] {
            Self::decode_ec_point(raw_point)
        } else {
            Err(anyhow!("返回的属性不是 EC_POINT"))
        }
    }

    /// 解码 EC_POINT 属性（兼容 DER OCTET STRING 封装与原始未压缩点）
    pub fn decode_ec_point(raw: &[u8]) -> Result<Vec<u8>> {
        // 1. 如果带有 04 41 04 前缀 (DER 04 41 + 65 字节点)
        if raw.len() == 67 && raw[0] == 0x04 && raw[1] == 0x41 && raw[2] == 0x04 {
            return Ok(raw[2..].to_vec());
        }

        // 2. 如果带有 04 41 前缀
        if raw.len() > 65 && raw[0] == 0x04 && raw[1] == 0x41 {
            return Ok(raw[2..67].to_vec());
        }

        // 3. 如果恰好是 65 字节且以 0x04 开头
        if raw.len() == 65 && raw[0] == 0x04 {
            return Ok(raw.to_vec());
        }

        // 4. 扫描内部包含的以 0x04 开头的 65 字节点
        for i in 0..raw.len().saturating_sub(64) {
            if raw[i] == 0x04 {
                let candidate = &raw[i..i + 65];
                if k256::ecdsa::VerifyingKey::from_sec1_bytes(candidate).is_ok() {
                    return Ok(candidate.to_vec());
                }
            }
        }

        Err(anyhow!(
            "无法解码 EC_POINT (长度={}, 首字节=0x{:02x})",
            raw.len(),
            raw.get(0).unwrap_or(&0)
        ))
    }

    /// 读取所有指定类别对象的 (CKA_LABEL, CKA_ID)，用于标签 / ID 双重校验
    fn list_key_refs(session: &Session, class: ObjectClass) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let handles = session
            .find_objects(&[Attribute::Class(class)])
            .map_err(|e| anyhow!("枚举密钥对象失败: {:?}", e))?;
        let mut refs = Vec::with_capacity(handles.len());
        for h in handles {
            let attrs = session
                .get_attributes(h, &[AttributeType::Label, AttributeType::Id])
                .map_err(|e| anyhow!("读取密钥属性失败: {:?}", e))?;
            let (mut label, mut id) = (Vec::new(), Vec::new());
            for a in attrs {
                match a {
                    Attribute::Label(l) => label = l,
                    Attribute::Id(i) => id = i,
                    _ => {}
                }
            }
            refs.push((label, id));
        }
        Ok(refs)
    }

    /// 导入：只有 CKA_LABEL 与 CKA_ID 同时匹配，且公私钥都存在时才返回公钥
    pub fn get_public_key_by_label_id(&mut self, label: &str, key_id: u8) -> Result<Vec<u8>> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| anyhow!("HSM 未连接，请先输入 PIN 登录"))?;
        let label_bytes = label.as_bytes().to_vec();
        let id = vec![key_id];

        let pubs = session
            .find_objects(&[
                Attribute::Class(ObjectClass::PUBLIC_KEY),
                Attribute::Label(label_bytes.clone()),
                Attribute::Id(id.clone()),
            ])
            .map_err(|e| anyhow!("查找公钥失败: {:?}", e))?;
        let privs = session
            .find_objects(&[
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::Label(label_bytes.clone()),
                Attribute::Id(id.clone()),
            ])
            .map_err(|e| anyhow!("查找私钥失败: {:?}", e))?;

        if pubs.len() == 1 && privs.len() == 1 {
            let attrs = session
                .get_attributes(pubs[0], &[AttributeType::EcPoint])
                .map_err(|e| anyhow!("获取 EC_POINT 属性失败: {:?}", e))?;
            return match attrs.first() {
                Some(Attribute::EcPoint(raw)) => Self::decode_ec_point(raw),
                _ => Err(anyhow!("公钥对象没有 EC_POINT 属性")),
            };
        }
        if pubs.len() > 1 || privs.len() > 1 {
            return Err(anyhow!("导入失败：标签与 ID {} 匹配到多个密钥对象，无法确定唯一账户", fmt_key_id(key_id)));
        }

        // 精确匹配失败：给出原因（不回显标签内容）
        let refs = Self::list_key_refs(session, ObjectClass::PRIVATE_KEY)?;
        let label_hit = refs.iter().any(|(l, _)| *l == label_bytes);
        let id_hit = refs.iter().any(|(_, i)| *i == id);
        Err(match (label_hit, id_hit) {
            (true, true) => anyhow!("导入失败：标签和 ID {} 分别属于不同的密钥，二者不匹配", fmt_key_id(key_id)),
            (true, false) => anyhow!("导入失败：该标签的密钥 CKA_ID 不是 {}", fmt_key_id(key_id)),
            (false, true) => anyhow!("导入失败：ID {} 的密钥标签与输入不一致", fmt_key_id(key_id)),
            (false, false) if pubs.is_empty() && !privs.is_empty() => {
                anyhow!("导入失败：找到私钥但缺少对应的公钥对象")
            }
            (false, false) => anyhow!("导入失败：设备中没有标签与 ID {} 匹配的密钥", fmt_key_id(key_id)),
        })
    }

    /// 创建：先校验标签与 CKA_ID 都未被占用，再用指定的 ID 生成密钥对，生成后按 标签+ID 回读校验
    pub fn generate_key_pair_with_id(&mut self, label: &str, key_id: u8) -> Result<Vec<u8>> {
        let label_bytes = label.as_bytes().to_vec();
        let id = vec![key_id];
        {
            let session = self
                .session
                .as_ref()
                .ok_or_else(|| anyhow!("HSM 未连接，请先输入 PIN 登录"))?;
            let mut refs = Self::list_key_refs(session, ObjectClass::PRIVATE_KEY)?;
            refs.extend(Self::list_key_refs(session, ObjectClass::PUBLIC_KEY)?);

            let id_owner_labels: Vec<&Vec<u8>> = refs.iter().filter(|(_, i)| *i == id).map(|(l, _)| l).collect();
            let label_ids: Vec<&Vec<u8>> = refs.iter().filter(|(l, _)| *l == label_bytes).map(|(_, i)| i).collect();

            if !id_owner_labels.is_empty() {
                return Err(if id_owner_labels.iter().all(|l| **l == label_bytes) {
                    anyhow!("创建失败：标签与 ID {} 的密钥已存在，请使用「导入」", fmt_key_id(key_id))
                } else {
                    anyhow!("创建失败：ID {} 已被另一个标签的密钥占用", fmt_key_id(key_id))
                });
            }
            if !label_ids.is_empty() {
                return Err(anyhow!("创建失败：该标签已用于其他 ID 的密钥，请换一个标签"));
            }
        }

        let pubkey = self.generate_inner(label_bytes, id)?;
        let readback = self.get_public_key_by_label_id(label, key_id)
            .map_err(|e| anyhow!("创建后校验失败: {:#}", e))?;
        if readback != pubkey {
            return Err(anyhow!("创建后校验失败：回读公钥与生成结果不一致"));
        }
        Ok(pubkey)
    }

    /// 按 标签 + CKA_ID 查找唯一私钥并签名
    pub fn sign_by_label_id(
        &mut self,
        label: &str,
        key_id: u8,
        hash: &[u8; 32],
        expected_pubkey: &[u8],
    ) -> Result<EcdsaSignatureResult> {
        // 先确认 标签+ID 指向的公钥与本地缓存一致，避免用错密钥
        let pubkey = self.get_public_key_by_label_id(label, key_id)
            .map_err(|e| anyhow!("{:#}", e).context("签名前校验密钥失败"))?;
        if pubkey != expected_pubkey {
            return Err(anyhow!("设备中 ID {} 的公钥与本地缓存不一致，请重新导入该账户", fmt_key_id(key_id)));
        }
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| anyhow!("HSM 未连接，请先输入 PIN 登录"))?;
        let objects = session
            .find_objects(&[
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::Label(label.as_bytes().to_vec()),
                Attribute::Id(vec![key_id]),
            ])
            .map_err(|e| anyhow!("查找私钥失败: {:?}", e))?;
        let priv_handle = match objects.as_slice() {
            [h] => *h,
            [] => return Err(anyhow!("未在 HSM 中找到对应的私钥对象")),
            _ => return Err(anyhow!("标签与 ID 匹配到多个私钥对象")),
        };
        Self::sign_with_handle(session, priv_handle, hash, expected_pubkey)
    }

    /// 在 HSM 上生成 secp256k1 密钥对
    pub fn generate_key_pair(&mut self, label: Option<&str>) -> Result<Vec<u8>> {
        let target_label = label.unwrap_or(&self.default_label).to_string();
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| anyhow!("HSM 未连接，请先输入 PIN 登录"))?;

        // 同名密钥已存在时拒绝生成，避免覆盖/混淆
        let existing = session
            .find_objects(&[
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::Label(target_label.clone().into_bytes()),
            ])
            .map_err(|e| anyhow!("查找已有密钥失败: {:?}", e))?;
        if !existing.is_empty() {
            return Err(anyhow!("该标签的密钥已存在，拒绝重复生成"));
        }

        // 分配一个未被占用的 CKA_ID (1..=255)
        let mut used_ids = std::collections::HashSet::new();
        let all = session
            .find_objects(&[])
            .map_err(|e| anyhow!("枚举 Token 对象失败: {:?}", e))?;
        for handle in all {
            if let Ok(attrs) = session.get_attributes(handle, &[AttributeType::Id]) {
                if let Some(Attribute::Id(id)) = attrs.first() {
                    used_ids.insert(id.clone());
                }
            }
        }
        let key_id = (1u8..=255)
            .map(|i| vec![i])
            .find(|id| !used_ids.contains(id))
            .ok_or_else(|| anyhow!("没有可用的密钥 ID"))?;
        self.generate_inner(target_label.into_bytes(), key_id)
    }

    /// 用给定 CKA_LABEL / CKA_ID 生成密钥对，返回 65 字节未压缩公钥（调用方负责冲突检查）
    fn generate_inner(&mut self, label_bytes: Vec<u8>, key_id: Vec<u8>) -> Result<Vec<u8>> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| anyhow!("HSM 未连接，请先输入 PIN 登录"))?;

        let pub_tpl = vec![
            Attribute::Token(true),
            Attribute::Verify(true),
            Attribute::Label(label_bytes.clone()),
            Attribute::Id(key_id.clone()),
            Attribute::EcParams(OID_SECP256K1.to_vec()),
        ];

        let priv_tpl = vec![
            Attribute::Token(true),
            Attribute::Sign(true),
            Attribute::Label(label_bytes),
            Attribute::Sensitive(true),
            Attribute::Id(key_id),
            Attribute::Extractable(true),
        ];

        let (pub_handle, _priv_handle) = session
            .generate_key_pair(&Mechanism::EccKeyPairGen, &pub_tpl, &priv_tpl)
            .map_err(|e| anyhow!("HSM 生成密钥对失败: {:?}", e))?;

        let attrs = session
            .get_attributes(pub_handle, &[AttributeType::EcPoint])
            .map_err(|e| anyhow!("获取新生成公钥的 EC_POINT 失败: {:?}", e))?;

        if let Some(Attribute::EcPoint(raw_point)) = attrs.first() {
            Self::decode_ec_point(raw_point)
        } else {
            Err(anyhow!("未能读取新生成公钥的 EC_POINT"))
        }
    }

    /// 使用 HSM 私钥对 32 字节 Hash 执行 ECDSA 签名
    /// 返回标准化的 (r, s, v) 签名结果
    pub fn sign(
        &mut self,
        label: Option<&str>,
        hash: &[u8; 32],
        expected_pubkey: &[u8],
    ) -> Result<EcdsaSignatureResult> {
        let target_label = label.unwrap_or(&self.default_label).to_string();
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| anyhow!("HSM 未连接，请先输入 PIN 登录"))?;

        // 查找私钥对象
        let template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Label(target_label.into_bytes()),
        ];

        let objects = session
            .find_objects(&template)
            .map_err(|e| anyhow!("查找私钥失败: {:?}", e))?;

        if objects.is_empty() {
            return Err(anyhow!("未在 HSM 中找到对应的私钥对象"));
        }

        Self::sign_with_handle(session, objects[0], hash, expected_pubkey)
    }

    fn sign_with_handle(
        session: &Session,
        priv_handle: cryptoki::object::ObjectHandle,
        hash: &[u8; 32],
        expected_pubkey: &[u8],
    ) -> Result<EcdsaSignatureResult> {
        // 硬件计算 ECDSA 签名
        let sig_raw = session
            .sign(&Mechanism::Ecdsa, priv_handle, hash)
            .map_err(|e| anyhow!("HSM ECDSA 签名计算失败: {:?}", e))?;

        // 解析签名：若正好是 64 字节 (r 32 + s 32)
        let (r, raw_s) = if sig_raw.len() == 64 {
            let mut r = [0u8; 32];
            let mut s = [0u8; 32];
            r.copy_from_slice(&sig_raw[..32]);
            s.copy_from_slice(&sig_raw[32..64]);
            (r, s)
        } else {
            // 否则解析 ASN.1 DER 编码
            let parsed = process_hsm_signature(&sig_raw, hash, expected_pubkey)?;
            return Ok(parsed);
        };

        // 规范化 Low-s 并穷举恢复 v
        let k256_sig = k256::ecdsa::Signature::from_scalars(r, raw_s)
            .map_err(|e| anyhow!("构造 Signature 失败: {:?}", e))?;
        let sig_low_s = k256_sig.normalize_s().unwrap_or(k256_sig);

        let expected_key = k256::ecdsa::VerifyingKey::from_sec1_bytes(expected_pubkey)
            .map_err(|e| anyhow!("无效的目标公钥: {:?}", e))?;

        for v_candidate in 0..=1 {
            if let Some(rec_id) = k256::ecdsa::RecoveryId::from_byte(v_candidate) {
                if let Ok(recovered_key) =
                    k256::ecdsa::VerifyingKey::recover_from_prehash(hash, &sig_low_s, rec_id)
                {
                    if recovered_key == expected_key {
                        let r_out = sig_low_s.r().to_bytes();
                        let s_out = sig_low_s.s().to_bytes();
                        let mut final_r = [0u8; 32];
                        let mut final_s = [0u8; 32];
                        final_r.copy_from_slice(&r_out);
                        final_s.copy_from_slice(&s_out);

                        return Ok(EcdsaSignatureResult {
                            r: final_r,
                            s: final_s,
                            v: v_candidate,
                        });
                    }
                }
            }
        }

        Err(anyhow!("未能恢复出匹配该公钥的 Recovery ID (v)"))
    }

    /// 检查是否存在指定 Label 的私钥
    pub fn has_key(&mut self, label: Option<&str>) -> bool {
        let target_label = label.unwrap_or(&self.default_label).to_string();
        let session = match self.session.as_ref() {
            Some(s) => s,
            None => return false,
        };

        let template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Label(target_label.into_bytes()),
        ];

        match session.find_objects(&template) {
            Ok(objs) => !objs.is_empty(),
            Err(_) => false,
        }
    }

    /// 已连接时返回 Token 实际序列号，否则返回配置的 HSM_SN（未配置时为空串）
    pub fn device_sn(&self) -> &str {
        self.token_serial
            .as_deref()
            .or(self.hsm_sn.as_deref())
            .unwrap_or("")
    }

    pub fn key_label(&self) -> &str {
        &self.default_label
    }
}

/// 账户允许的 CKA_ID 上限（单字节，0..=254）
pub const MAX_KEY_ID: u8 = 254;

/// 以「十进制 (0x十六进制)」展示 CKA_ID，方便与 pkcs11-tool --id（十六进制）对照
pub fn fmt_key_id(id: u8) -> String {
    format!("{} (0x{:02x})", id, id)
}

/// 解析用户输入的 CKA_ID：十进制 "20" 或十六进制 "0x14"，必须小于 255
pub fn parse_key_id(input: &str) -> Result<u8> {
    let s = input.trim();
    let n = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) if !h.is_empty() => u32::from_str_radix(h, 16),
        _ if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => s.parse::<u32>(),
        _ => return Err(anyhow!("CKA_ID 格式无效，请输入 0-{} 的整数", MAX_KEY_ID)),
    }
    .map_err(|_| anyhow!("CKA_ID 超出范围 (0-{})", MAX_KEY_ID))?;
    u8::try_from(n)
        .ok()
        .filter(|&v| v <= MAX_KEY_ID)
        .ok_or_else(|| anyhow!("CKA_ID 超出范围 (0-{})", MAX_KEY_ID))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_key_id_accepts_dec_and_hex() {
        assert_eq!(parse_key_id("20").unwrap(), 20);
        assert_eq!(parse_key_id(" 0x14 ").unwrap(), 20);
        assert_eq!(parse_key_id("0").unwrap(), 0);
        assert_eq!(parse_key_id("254").unwrap(), 254);
    }

    #[test]
    fn parse_key_id_rejects_invalid() {
        for bad in ["255", "0xff", "256", "-1", "", "abc", "1.5", "0x", "20a"] {
            assert!(parse_key_id(bad).is_err(), "{bad} 应被拒绝");
        }
    }
}

impl Drop for Pkcs11Hsm {
    fn drop(&mut self) {
        self.disconnect();
    }
}
