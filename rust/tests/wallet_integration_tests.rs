use nitrokey_wallet_core::*;
use nitrokey_wallet_core::transport::mock::MockTransport;
use k256::ecdsa::SigningKey;

#[test]
fn test_address_derivation() {
    // 测试私钥 0x01
    let mut priv_bytes = [0u8; 32];
    priv_bytes[31] = 0x01;
    let signing_key = SigningKey::from_bytes(&priv_bytes.into()).unwrap();
    let pubkey = signing_key.verifying_key().to_encoded_point(false);
    let pub_bytes = pubkey.as_bytes();

    let eth_addr = public_key_to_eth_address(pub_bytes).unwrap();
    let tron_addr = public_key_to_tron_address(pub_bytes).unwrap();

    assert_eq!(eth_addr.to_lowercase(), "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf");
    assert!(tron_addr.starts_with('T'));
    
    let decoded = decode_base58_check(&tron_addr).unwrap();
    assert_eq!(decoded.len(), 21);
    assert_eq!(decoded[0], 0x41);
}

#[test]
fn test_schsm_mock_and_pin_flow() {
    let mut transport = MockTransport::new("NK-HSM2-TEST-9999", "123456");
    transport.connect().unwrap();

    let mut client = SmartCardHsmClient::new(transport);
    client.select_applet().unwrap();

    // 1. 读取 Device ID
    let device_id = client.get_device_id().unwrap();
    assert_eq!(device_id, "NK-HSM2-TEST-9999");

    // 2. 初始 PIN 重试计数器应为 3
    let retries = client.get_pin_retry_counter().unwrap();
    assert_eq!(retries, 3);

    // 3. 输错一次 PIN
    let wrong_pin = SafePin::new("000000");
    let err = client.verify_pin(&wrong_pin).unwrap_err();
    assert!(err.to_string().contains("剩余尝试机会: 2 次"));

    // 4. 输入正确 PIN
    let correct_pin = SafePin::new("123456");
    client.verify_pin(&correct_pin).unwrap();

    // 5. 读取 Slot 1 公钥
    let slot1 = client.get_slot_public_key(1).unwrap();
    assert_eq!(slot1.public_key_uncompressed.len(), 65);
}

#[test]
fn test_watch_only_wallet_store() {
    let mut store = WalletStore::new();
    let device_id = "NK-CACHE-TEST-001";

    let priv1 = [0x11u8; 32];
    let key1 = SigningKey::from_bytes(&priv1.into()).unwrap();
    let pub1 = key1.verifying_key().to_encoded_point(false);

    let slot = store.upsert_account(device_id, 1, pub1.as_bytes(), Some("Main Account")).unwrap();
    assert_eq!(slot.account_name, "Main Account");

    let cache = store.get_device_cache(device_id).unwrap();
    assert_eq!(cache.slots.len(), 1);
    assert_eq!(cache.slots[0].eth_address, slot.eth_address);
    assert_eq!(cache.slots[0].tron_address, slot.tron_address);
}

#[test]
fn test_wallet_store_persist_roundtrip() {
    let dir = std::env::temp_dir().join(format!("nk-wallet-test-{}", std::process::id()));
    let path = dir.join("wallet_cache.json");

    let key = SigningKey::from_bytes(&[0x22u8; 32].into()).unwrap();
    let pubkey = key.verifying_key().to_encoded_point(false);

    // 文件不存在时返回空缓存
    assert!(WalletStore::load(&path).unwrap().latest_device().is_none());

    let mut store = WalletStore::new();
    let slot = store.upsert_account("DENK-TEST", 0, pubkey.as_bytes(), None).unwrap();
    store.save(&path).unwrap();

    let loaded = WalletStore::load(&path).unwrap();
    let device = loaded.latest_device().unwrap();
    assert_eq!(device.device_id, "DENK-TEST");
    assert!(device.last_sync_timestamp > 0);
    assert_eq!(device.slots[0].tron_address, slot.tron_address);
    assert_eq!(device.slots[0].public_key_hex, hex::encode(pubkey.as_bytes()));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_tron_resource_estimation_and_blocking() {
    // 场景 1: 能量充足
    let res1 = estimate_tron_trc20_fee(
        &TronAccountResource {
            free_net_limit: 600,
            free_net_used: 100,
            energy_limit: 100_000,
            energy_used: 20_000,
            trx_balance_sun: 100_000_000,
        },
        false, // 新地址
    );
    assert_eq!(res1.required_energy, 65_000);
    assert_eq!(res1.missing_energy, 0);
    assert_eq!(res1.burn_trx_amount, 0.0);
    assert!(res1.block_reason.is_none());

    // 场景 2: 能量为 0，TRX 余额不足支付燃烧，触发阻断！
    let res2 = estimate_tron_trc20_fee(
        &TronAccountResource {
            free_net_limit: 600,
            free_net_used: 600,
            energy_limit: 0,
            energy_used: 0,
            trx_balance_sun: 1_000_000, // 仅 1 TRX
        },
        true, // 老地址
    );
    assert_eq!(res2.required_energy, 32_000);
    assert_eq!(res2.missing_energy, 32_000);
    assert!(res2.burn_trx_amount > 13.0);
    assert!(!res2.is_trx_sufficient);
    assert!(res2.block_reason.unwrap().contains("【余额不足阻断】"));
}

#[test]
fn test_full_eth_signing_flow() {
    let mut transport = MockTransport::default();
    transport.connect().unwrap();

    let mut client = SmartCardHsmClient::new(transport);
    client.select_applet().unwrap();
    let slot1 = client.get_slot_public_key(1).unwrap();
    let expected_eth_address = public_key_to_eth_address(&slot1.public_key_uncompressed).unwrap();

    let unsigned_tx = EthUnsignedTx {
        to: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045".into(),
        value_wei: 1_000_000_000_000_000_000,
        nonce: 0,
        gas_limit: 21_000,
        gas_price_wei: 20_000_000_000,
        chain_id: 1,
        data: vec![],
    };

    let msg_hash = build_eth_signing_hash(&unsigned_tx);

    let mut session = SignSessionManager::new(&mut client);
    let sig = session.execute_signing(
        1,
        &msg_hash,
        &slot1.public_key_uncompressed,
        SafePin::new("648219"),
    ).unwrap();

    let finalized = finalize_eth_transaction(&unsigned_tx, &sig, &msg_hash).unwrap();
    assert_eq!(finalized.recovered_from.to_lowercase(), expected_eth_address.to_lowercase());
}

#[test]
fn test_full_tron_trc20_signing_flow() {
    let mut transport = MockTransport::default();
    transport.connect().unwrap();

    let mut client = SmartCardHsmClient::new(transport);
    client.select_applet().unwrap();
    let slot1 = client.get_slot_public_key(1).unwrap();
    let sender_tron = public_key_to_tron_address(&slot1.public_key_uncompressed).unwrap();

    let slot2 = client.get_slot_public_key(2).unwrap();
    let recipient_tron = public_key_to_tron_address(&slot2.public_key_uncompressed).unwrap();

    let msg_hash = build_tron_trc20_signing_hash(
        "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
        &sender_tron,
        &recipient_tron,
        500_000_000,
        30_000_000,
    ).unwrap();

    let mut session = SignSessionManager::new(&mut client);
    let sig = session.execute_signing(
        1,
        &msg_hash,
        &slot1.public_key_uncompressed,
        SafePin::new("648219"),
    ).unwrap();

    let (sig_hex, recovered_tron) = finalize_tron_transaction(&msg_hash, &sig).unwrap();
    assert_eq!(sig_hex.len(), 130); // 65 字节十六进制
    assert_eq!(recovered_tron, sender_tron);
}
