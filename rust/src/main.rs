use anyhow::{anyhow, Result};
use nitrokey_wallet_core::*;
#[cfg(all(target_os = "macos", feature = "macos-pcsc"))]
use nitrokey_wallet_core::transport::pcsc::PcscTransport;
#[cfg(all(target_os = "macos", feature = "macos-pcsc"))]
use secrecy::ExposeSecret;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;
use std::sync::{Arc, Mutex};
use tao::{
    event::{Event, StartCause, WindowEvent},
    event_loop::{ControlFlow, EventLoop},
    window::WindowBuilder,
};
use wry::WebViewBuilder;
use zeroize::Zeroize;

const INDEX_HTML: &str = include_str!("ui/index.html");

/// 前端展示用的账户视图（不包含标签）
#[derive(Serialize)]
struct AccountView {
    key_id: u8,
    account_name: String,
    eth_address: String,
    tron_address: String,
}

/// 前端展示用的钱包视图（包含所有账户）
#[derive(Serialize)]
struct WalletView {
    device_id: String,
    device_name: String,
    accounts: Vec<AccountView>,
    last_sync_timestamp: u64,
}

impl WalletView {
    fn from_cache(cache: &DeviceWalletCache) -> Self {
        let accounts = cache
            .slots
            .iter()
            .map(|s| AccountView {
                key_id: s.key_id,
                account_name: s.account_name.clone(),
                eth_address: s.eth_address.clone(),
                tron_address: s.tron_address.clone(),
            })
            .collect();

        Self {
            device_id: cache.device_id.clone(),
            device_name: cache.device_name.clone(),
            accounts,
            last_sync_timestamp: cache.last_sync_timestamp,
        }
    }
}

#[derive(Serialize)]
struct SignedTxResult {
    raw_tx_hex: String,
    tx_id: String,
    from: String,
}

/// 硬件后端抽象
enum HardwareBackend {
    Pkcs11(Pkcs11Hsm),
    #[cfg(all(target_os = "macos", feature = "macos-pcsc"))]
    Pcsc(SmartCardHsmClient<PcscTransport>),
}

fn open_backend(key_label: &str, pin: &SecretString) -> Result<HardwareBackend> {
    if key_label.trim().is_empty() {
        return Err(anyhow!("请输入密钥标签 (Key Label)"));
    }
    match Pkcs11Hsm::new(key_label) {
        Ok(mut hsm) => {
            hsm.connect(pin)?;
            Ok(HardwareBackend::Pkcs11(hsm))
        }
        Err(e) => open_pcsc_fallback(e),
    }
}

#[cfg(all(target_os = "macos", feature = "macos-pcsc"))]
fn open_pcsc_fallback(reason: anyhow::Error) -> Result<HardwareBackend> {
    eprintln!("ℹ️ PKCS#11 不可用 ({})，回退到原生 PC/SC 通道", reason);
    let mut transport = PcscTransport::new();
    transport.connect()?;
    let mut client = SmartCardHsmClient::new(transport);
    client.select_applet()
        .map_err(|e| anyhow!("选择 SmartCard-HSM Applet 失败: {}", e))?;
    Ok(HardwareBackend::Pcsc(client))
}

#[cfg(not(all(target_os = "macos", feature = "macos-pcsc")))]
fn open_pcsc_fallback(reason: anyhow::Error) -> Result<HardwareBackend> {
    Err(reason)
}

/// 读取 IPC 中的 key_id（CKA_ID）：整数 0-254，也接受 "20" / "0x14" 字符串
fn parse_ipc_key_id(v: &Value) -> Result<u8> {
    match v.get("key_id") {
        Some(Value::Number(n)) => n
            .as_u64()
            .and_then(|n| u8::try_from(n).ok())
            .filter(|&n| n <= MAX_KEY_ID)
            .ok_or_else(|| anyhow!("CKA_ID 超出范围 (0-{})", MAX_KEY_ID)),
        Some(Value::String(s)) => parse_key_id(s),
        _ => Err(anyhow!("请输入 CKA_ID (0-{})", MAX_KEY_ID)),
    }
}

fn find_account(store: &WalletStore, key_id: u8) -> Result<AccountSlot> {
    let cache = store.latest_device()
        .ok_or_else(|| anyhow!("本地没有钱包缓存，请先导入账户"))?;
    cache.slots.iter()
        .find(|s| s.key_id == key_id)
        .cloned()
        .ok_or_else(|| anyhow!("ID {} 的账户未找到，请先导入或创建", fmt_key_id(key_id)))
}

fn default_account_name(key_id: u8) -> String {
    format!("账户 #{}", key_id)
}

/// 导入账户：设备中必须存在 CKA_LABEL 与 CKA_ID 同时匹配的密钥，读取公钥后写入缓存
fn import_account(
    store: &mut WalletStore,
    cache_path: &Path,
    key_id: u8,
    key_label: &str,
    pin: &SecretString,
) -> Result<WalletView> {
    let (device_id, pubkey) = match open_backend(key_label, pin)? {
        HardwareBackend::Pkcs11(mut hsm) => {
            let pubkey = hsm.get_public_key_by_label_id(key_label, key_id)?;
            (hsm.device_sn().to_string(), pubkey)
        }
        #[cfg(all(target_os = "macos", feature = "macos-pcsc"))]
        HardwareBackend::Pcsc(_) => {
            return Err(anyhow!("PC/SC 通道无法校验 CKA_LABEL / CKA_ID，请安装 OpenSC 后使用 PKCS#11 导入"));
        }
    };

    // 同一把密钥不允许以两个 ID 出现在缓存中
    if let Some(cache) = store.get_device_cache(&device_id) {
        let pubkey_hex = hex::encode(&pubkey);
        if let Some(s) = cache.slots.iter().find(|s| s.key_id != key_id && s.public_key_hex == pubkey_hex) {
            return Err(anyhow!("该密钥已作为 {} (ID {}) 导入", s.account_name, fmt_key_id(s.key_id)));
        }
    }

    store.upsert_account(&device_id, key_id, &pubkey, Some(&default_account_name(key_id)))?;
    store.save(cache_path)?;

    store.get_device_cache(&device_id)
        .map(WalletView::from_cache)
        .ok_or_else(|| anyhow!("写入缓存后读取失败"))
}

/// 创建账户：标签与 CKA_ID 都未被占用时，才在 HSM 上用指定的 标签 + ID 生成密钥对
fn create_account(
    store: &mut WalletStore,
    cache_path: &Path,
    key_id: u8,
    key_label: &str,
    pin: &SecretString,
) -> Result<WalletView> {
    match open_backend(key_label, pin)? {
        HardwareBackend::Pkcs11(mut hsm) => {
            let device_id = hsm.device_sn().to_string();
            let cached = store.get_device_cache(&device_id)
                .map_or(false, |c| c.slots.iter().any(|s| s.key_id == key_id));
            if cached {
                return Err(anyhow!("创建失败：本地已有 ID {} 的账户，如需刷新请使用「导入」", fmt_key_id(key_id)));
            }
            let pubkey = hsm.generate_key_pair_with_id(key_label, key_id)?;
            store.upsert_account(&device_id, key_id, &pubkey, Some(&default_account_name(key_id)))?;
            store.save(cache_path)?;
            store.get_device_cache(&device_id)
                .map(WalletView::from_cache)
                .ok_or_else(|| anyhow!("写入缓存后读取失败"))
        }
        #[cfg(all(target_os = "macos", feature = "macos-pcsc"))]
        HardwareBackend::Pcsc(_) => {
            Err(anyhow!("PC/SC 通道不支持生成密钥，请安装 OpenSC 并使用 PKCS#11"))
        }
    }
}

#[derive(Deserialize)]
struct SignTxParams {
    #[serde(alias = "slot_id")]
    key_id: u8,
    chain: String,
    asset: String,
    to: String,
    amount: String,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    gas_price: Option<String>,
    #[serde(default)]
    gas_limit: Option<String>,
    #[serde(default)]
    block_number: Option<String>,
    #[serde(default)]
    block_id: Option<String>,
    #[serde(default)]
    block_timestamp: Option<String>,
}

fn parse_u64_hex_or_dec(s: &str) -> Result<u64> {
    let s = s.trim();
    match s.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => s.parse::<u64>(),
    }
    .map_err(|_| anyhow!("数值格式无效: {}", s))
}

fn parse_u128_hex_or_dec(s: &str) -> Result<u128> {
    let s = s.trim();
    match s.strip_prefix("0x") {
        Some(hex) => u128::from_str_radix(hex, 16),
        None => s.parse::<u128>(),
    }
    .map_err(|_| anyhow!("数值格式无效: {}", s))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 校验前端传入的参考区块：block_id 前 8 字节即区块高度，且时间不能偏离太多
fn validate_tron_ref_block(block_number: u64, block_id: &str, block_timestamp: u64) -> Result<()> {
    let id = hex::decode(block_id).map_err(|_| anyhow!("block_id 不是有效 hex"))?;
    if id.len() != 32 {
        return Err(anyhow!("block_id 长度应为 32 字节"));
    }
    let mut num = [0u8; 8];
    num.copy_from_slice(&id[..8]);
    if u64::from_be_bytes(num) != block_number {
        return Err(anyhow!("block_id 与区块高度不匹配"));
    }
    let now = now_ms();
    if block_timestamp + 5 * 60_000 < now || block_timestamp > now + 60_000 {
        return Err(anyhow!("参考区块时间异常，请刷新后重试"));
    }
    Ok(())
}

/// 签名交易：根据链类型构造并签名
fn sign_tx(
    store: &WalletStore,
    key_label: &str,
    pin: &SecretString,
    params: SignTxParams,
) -> Result<SignedTxResult> {
    let slot = find_account(store, params.key_id)?;
    let pubkey = hex::decode(&slot.public_key_hex)?;

    match params.chain.as_str() {
        "ETH" => {
            let nonce = parse_u64_hex_or_dec(params.nonce.as_ref().ok_or_else(|| anyhow!("缺少 nonce"))?)?;
            let gas_price_wei = parse_u128_hex_or_dec(params.gas_price.as_ref().ok_or_else(|| anyhow!("缺少 gas_price"))?)?;
            let gas_limit = parse_u64_hex_or_dec(params.gas_limit.as_ref().ok_or_else(|| anyhow!("缺少 gas_limit"))?)?;

            // 安全限制
            if gas_limit > 10_000_000 {
                return Err(anyhow!("gas_limit 超出安全范围 (>10M)"));
            }
            if gas_price_wei > 500_000_000_000 {
                return Err(anyhow!("gas_price 过高 (>500 Gwei)"));
            }

            let (to, value_wei, data) = match params.asset.as_str() {
                "ETH" => {
                    let value = parse_amount(&params.amount, 18)?;
                    (parse_eth_address(&params.to)?, value, vec![])
                }
                "USDT" => {
                    let value = parse_amount(&params.amount, 6)?;
                    let to_addr = parse_eth_address(&params.to)?;
                    let data = erc20_transfer_data(&to_addr, value);
                    (parse_eth_address(ETH_USDT_CONTRACT)?, 0, data)
                }
                _ => return Err(anyhow!("不支持的 ETH 资产: {}", params.asset)),
            };

            let tx = EthLegacyTx {
                nonce,
                gas_price_wei,
                gas_limit,
                to,
                value_wei,
                data,
                chain_id: ETH_MAINNET_CHAIN_ID,
            };

            let signing_hash = eth_legacy_signing_hash(&tx);
            let sig = hardware_sign(open_backend(key_label, pin)?, key_label, slot.key_id, pin, &signing_hash, &pubkey)?;
            let result = eth_legacy_finalize(&tx, &sig, &slot.eth_address)?;

            println!("✅ [ETH 签名] {} {} → {}", params.amount, params.asset, params.to);
            println!("   TxHash: {}", result.tx_hash);

            Ok(SignedTxResult {
                raw_tx_hex: result.raw_tx_hex,
                tx_id: result.tx_hash,
                from: result.from,
            })
        }
        "TRON" => {
            let block_number = parse_u64_hex_or_dec(params.block_number.as_ref().ok_or_else(|| anyhow!("缺少 block_number"))?)?;
            let block_id = params.block_id.as_ref().ok_or_else(|| anyhow!("缺少 block_id"))?.clone();
            let block_timestamp = parse_u64_hex_or_dec(params.block_timestamp.as_ref().ok_or_else(|| anyhow!("缺少 block_timestamp"))?)?;

            validate_tron_ref_block(block_number, &block_id, block_timestamp)?;

            let to_addr = parse_tron_address(&params.to)?;
            let owner_addr = parse_tron_address(&slot.tron_address)?;

            let transfer = match params.asset.as_str() {
                "TRX" => {
                    let amount_sun = parse_amount(&params.amount, 6)?;
                    let amount_sun = u64::try_from(amount_sun).map_err(|_| anyhow!("金额过大"))?;
                    TronTransfer::Native { to: to_addr, amount_sun }
                }
                "USDT" => {
                    let amount = parse_amount(&params.amount, 6)?;
                    let contract = parse_tron_address(TRON_USDT_CONTRACT)?;
                    TronTransfer::Trc20 { contract, to: to_addr, amount }
                }
                _ => return Err(anyhow!("不支持的 TRON 资产: {}", params.asset)),
            };

            let tx = TronTx {
                ref_block: TronRefBlock { block_number, block_id, timestamp_ms: block_timestamp },
                expiration_ms: block_timestamp + 600_000,
                timestamp_ms: now_ms(),
                transfer,
                fee_limit_sun: 50_000_000,
            };

            let raw_data = tron_build_raw_data(&tx, &owner_addr)?;
            let mut signing_hash = [0u8; 32];
            signing_hash.copy_from_slice(&<sha2::Sha256 as sha2::Digest>::digest(&raw_data));

            let sig = hardware_sign(open_backend(key_label, pin)?, key_label, slot.key_id, pin, &signing_hash, &pubkey)?;
            let result = tron_finalize_tx(&raw_data, &sig, &slot.tron_address)?;

            println!("✅ [TRON 签名] {} {} → {}", params.amount, params.asset, params.to);
            println!("   TxID: {}", result.tx_id);

            Ok(SignedTxResult {
                raw_tx_hex: result.signed_tx_hex,
                tx_id: result.tx_id,
                from: result.from,
            })
        }
        _ => Err(anyhow!("不支持的链: {}", params.chain)),
    }
}

/// 用硬件私钥签名 32 字节摘要；后端在函数结束时 drop（登出并断开）
#[cfg_attr(not(all(target_os = "macos", feature = "macos-pcsc")), allow(unused_variables))]
fn hardware_sign(
    backend: HardwareBackend,
    key_label: &str,
    key_id: u8,
    pin: &SecretString,
    hash: &[u8; 32],
    expected_pubkey: &[u8],
) -> Result<EcdsaSignatureResult> {
    match backend {
        // PKCS#11 已在 open_backend 中用 PIN 登录；按 标签 + CKA_ID 定位私钥
        HardwareBackend::Pkcs11(mut hsm) => hsm.sign_by_label_id(key_label, key_id, hash, expected_pubkey),
        #[cfg(all(target_os = "macos", feature = "macos-pcsc"))]
        HardwareBackend::Pcsc(mut client) => {
            let mut session = SignSessionManager::new(&mut client);
            session.execute_signing(1, hash, expected_pubkey, SafePin::new(pin.expose_secret()))
        }
    }
}

fn take_pin(v: &mut Value) -> Option<SecretString> {
    match v.get_mut("pin").map(Value::take) {
        Some(Value::String(s)) if !s.is_empty() => Some(SecretString::from(s)),
        Some(Value::String(mut s)) => {
            s.zeroize();
            None
        }
        _ => None,
    }
}

/// 取出 key_label（从 JSON 中移除），调用方用完后需 zeroize
fn take_label(v: &mut Value) -> String {
    match v.get_mut("key_label").map(Value::take) {
        Some(Value::String(mut s)) => {
            let trimmed = s.trim().to_string();
            s.zeroize();
            trimmed
        }
        _ => String::new(),
    }
}

fn emit(webview: &Mutex<Option<wry::WebView>>, callback: &str, payload: &Value) {
    if let Ok(guard) = webview.lock() {
        if let Some(wv) = guard.as_ref() {
            let js = format!("if(window.{0}) window.{0}({1});", callback, payload);
            let _ = wv.evaluate_script(&js);
        }
    }
}

/// 安装 macOS 原生菜单栏（tao 0.37 不再提供默认菜单）
/// 提供 Cmd+H 隐藏、Cmd+Q 退出，以及 WebView 内的复制/粘贴/全选快捷键
#[cfg(target_os = "macos")]
fn install_macos_menu() {
    use objc2::rc::Retained;
    use objc2::runtime::Sel;
    use objc2::{sel, MainThreadMarker, MainThreadOnly};
    use objc2_app_kit::{NSApplication, NSMenu, NSMenuItem};
    use objc2_foundation::NSString;

    let Some(mtm) = MainThreadMarker::new() else { return };
    let app = NSApplication::sharedApplication(mtm);

    let item = |title: &str, action: Option<Sel>, key: &str| unsafe {
        NSMenuItem::initWithTitle_action_keyEquivalent(
            NSMenuItem::alloc(mtm),
            &NSString::from_str(title),
            action,
            &NSString::from_str(key),
        )
    };
    let submenu = |title: &str, items: Vec<Retained<NSMenuItem>>| {
        let menu = NSMenu::initWithTitle(NSMenu::alloc(mtm), &NSString::from_str(title));
        for i in &items {
            menu.addItem(i);
        }
        let top = item(title, None, "");
        top.setSubmenu(Some(&menu));
        top
    };

    let app_menu = submenu(
        "Nitrokey Wallet",
        vec![
            item("隐藏 Nitrokey Wallet", Some(sel!(hide:)), "h"),
            NSMenuItem::separatorItem(mtm),
            item("退出 Nitrokey Wallet", Some(sel!(terminate:)), "q"),
        ],
    );
    let edit_menu = submenu(
        "编辑",
        vec![
            item("撤销", Some(sel!(undo:)), "z"),
            item("重做", Some(sel!(redo:)), "Z"),
            NSMenuItem::separatorItem(mtm),
            item("剪切", Some(sel!(cut:)), "x"),
            item("复制", Some(sel!(copy:)), "c"),
            item("粘贴", Some(sel!(paste:)), "v"),
            item("全选", Some(sel!(selectAll:)), "a"),
        ],
    );
    let window_menu = submenu(
        "窗口",
        vec![
            item("最小化", Some(sel!(performMiniaturize:)), "m"),
            item("关闭窗口", Some(sel!(performClose:)), "w"),
        ],
    );

    let main_menu = NSMenu::new(mtm);
    main_menu.addItem(&app_menu);
    main_menu.addItem(&edit_menu);
    main_menu.addItem(&window_menu);
    app.setMainMenu(Some(&main_menu));
}

fn main() -> anyhow::Result<()> {
    let event_loop = EventLoop::new();
    #[cfg(target_os = "macos")]
    install_macos_menu();
    let window = WindowBuilder::new()
        .with_title("Nitrokey HSM 2 硬件钱包")
        .with_inner_size(tao::dpi::LogicalSize::new(1100.0, 780.0))
        .with_resizable(true)
        .build(&event_loop)?;

    let cache_path = WalletStore::default_path();
    let store = WalletStore::load(&cache_path).unwrap_or_else(|e| {
        eprintln!("⚠️ {}，将使用空缓存", e);
        WalletStore::new()
    });
    println!("📂 [缓存] {}", cache_path.display());
    let store = Arc::new(Mutex::new(store));

    let webview_holder = Arc::new(Mutex::new(None::<wry::WebView>));
    let webview_clone = Arc::clone(&webview_holder);
    let store_clone = Arc::clone(&store);

    let webview = WebViewBuilder::new()
        .with_html(INDEX_HTML)
        .with_ipc_handler(move |req: wry::http::Request<String>| {
            let mut body = req.into_body();
            let parsed = serde_json::from_str::<Value>(&body);
            body.zeroize();
            let Ok(mut v) = parsed else { return };

            let action = v.get("action").and_then(|a| a.as_str()).unwrap_or("").to_string();
            let key_id = parse_ipc_key_id(&v);
            let mut key_label = take_label(&mut v);
            let pin = take_pin(&mut v);

            let Ok(mut store) = store_clone.lock() else { key_label.zeroize(); return };

            match action.as_str() {
                "load_cache" => {
                    let view = store.latest_device().map(WalletView::from_cache);
                    emit(&webview_clone, "onWalletLoaded", &json!(view));
                }

                // 导入 / 创建都要求 标签 + CKA_ID 双重校验；sync_wallet 为旧名称
                "import_account" | "sync_wallet" | "create_account" => {
                    let creating = action == "create_account";
                    let result = match (key_id, pin) {
                        (Err(e), _) => Err(e),
                        (_, None) => Err(anyhow!("请输入 PIN")),
                        (Ok(id), Some(pin)) => {
                            let r = if creating {
                                create_account(&mut store, &cache_path, id, &key_label, &pin)
                            } else {
                                import_account(&mut store, &cache_path, id, &key_label, &pin)
                            };
                            drop(pin);
                            r.map(|view| (id, view))
                        }
                    };
                    let tag = if creating { "创建" } else { "导入" };
                    let payload = match result {
                        Ok((id, view)) => {
                            println!("✅ [{}] ID {} 公钥已缓存", tag, fmt_key_id(id));
                            json!({ "ok": true, "wallet": view, "key_id": id })
                        }
                        Err(e) => {
                            eprintln!("❌ [{}] {:#}", tag, e);
                            json!({ "ok": false, "error": format!("{:#}", e) })
                        }
                    };
                    let mode = if creating { "create" } else { "import" };
                    emit(&webview_clone, "onAuthCompleted", &json!({ "mode": mode, "result": payload }));
                }

                // 仅删除本地缓存的公钥/地址，不需要设备和 PIN；之后可通过「导入」重新添加
                "remove_account" => {
                    let result = key_id.and_then(|id| {
                        store.remove_account(id)?;
                        store.save(&cache_path)?;
                        Ok((id, store.latest_device().map(WalletView::from_cache)))
                    });
                    let payload = match result {
                        Ok((id, view)) => {
                            println!("🗑️ [移除] ID {} 已从本地缓存删除", fmt_key_id(id));
                            json!({ "ok": true, "wallet": view, "key_id": id })
                        }
                        Err(e) => {
                            eprintln!("❌ [移除] {:#}", e);
                            json!({ "ok": false, "error": format!("{:#}", e) })
                        }
                    };
                    emit(&webview_clone, "onAccountRemoved", &payload);
                }

                "sign_tx" => {
                    let params: Result<SignTxParams> = serde_json::from_value(v.clone())
                        .map_err(|e| anyhow!("参数解析失败: {}", e));

                    let result = match (params, pin) {
                        (Ok(p), Some(pin)) => {
                            let r = sign_tx(&store, &key_label, &pin, p);
                            drop(pin);
                            r
                        }
                        (Err(e), _) => Err(e),
                        (_, None) => Err(anyhow!("请输入 PIN")),
                    };

                    let payload = match result {
                        Ok(signed) => json!({ "ok": true, "signed": signed }),
                        Err(e) => {
                            eprintln!("❌ [签名] {:#}", e);
                            json!({ "ok": false, "error": format!("{:#}", e) })
                        }
                    };
                    emit(&webview_clone, "onAuthCompleted", &json!({ "mode": "sign", "result": payload }));
                }

                _ => {}
            }
            key_label.zeroize();
        })
        .build(&window)?;

    if let Ok(mut guard) = webview_holder.lock() {
        *guard = Some(webview);
    }

    println!("🚀 钱包客户端启动完成");

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;

        match event {
            Event::NewEvents(StartCause::Init) => {}
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                *control_flow = ControlFlow::Exit;
            }
            _ => (),
        }
    });
}
