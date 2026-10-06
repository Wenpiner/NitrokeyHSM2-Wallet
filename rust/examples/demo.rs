use nitrokey_wallet_core::*;
use nitrokey_wallet_core::transport::mock::MockTransport;

fn main() -> anyhow::Result<()> {
    println!("╔════════════════════════════════════════════════════════════════════════════╗");
    println!("║       Nitrokey HSM 2 硬件钱包 (ETH / TRON) Rust 核心引擎演练演示           ║");
    println!("╚════════════════════════════════════════════════════════════════════════════╝\n");

    let mut store = WalletStore::new();

    // 1. 模拟插入 Nitrokey HSM 2
    println!("🔌 [1] 检测到 USB 设备插入: 正在连接 Nitrokey HSM 2...");
    let mut transport = MockTransport::new("NK-HSM2-RUST-PROD-99", "648219");
    transport.connect()?;

    let mut client = SmartCardHsmClient::new(transport);
    client.select_applet()?;

    let device_id = client.get_device_id()?;
    let retry_count = client.get_pin_retry_counter()?;

    println!("   ✅ 设备就绪！唯一序列号 (Device ID): {}", device_id);
    println!("   ℹ️ User PIN 状态: 正常 (剩余可试次数: {} 次)\n", retry_count);

    // 2. 发现并同步硬件 Slot (账户模型: 1 Slot = 1 多链账户)
    println!("🔍 [2] 正在扫描卡内 Slot 密钥，并映射多链账户...");
    let slot1 = client.get_slot_public_key(1)?;
    let account1 = store.upsert_account(&device_id, 1, &slot1.public_key_uncompressed, Some("Account 1 (主账户)"))?;

    let slot2 = client.get_slot_public_key(2)?;
    let account2 = store.upsert_account(&device_id, 2, &slot2.public_key_uncompressed, Some("Account 2 (金库账户)"))?;

    println!("   -----------------------------------------------------------------");
    println!("   📁 账户 1 [{}] (Slot 1)", account1.account_name);
    println!("      🔹 ETH  地址: {}", account1.eth_address);
    println!("      🔹 TRON 地址: {}", account1.tron_address);
    println!("   -----------------------------------------------------------------");
    println!("   📁 账户 2 [{}] (Slot 2)", account2.account_name);
    println!("      🔹 ETH  地址: {}", account2.eth_address);
    println!("      🔹 TRON 地址: {}", account2.tron_address);
    println!("   -----------------------------------------------------------------\n");

    // 3. 模拟拔出硬件，验证 Watch-only 本地观察钱包缓存
    println!("🔌 [3] 模拟拔出硬件设备 (断开 USB 连接)...");
    client.transport_mut().disconnect()?;
    println!("   ⚠️ 硬件已拔出。App 自动切换为【Watch-only 观察模式】:");
    if let Some(cached) = store.get_device_cache(&device_id) {
        println!("      已缓存设备: {}", cached.device_name);
        println!("      无需插卡即可查看 {} 个账户的资产及收款地址！\n", cached.slots.len());
    }

    // 4. 发起一笔 TRC-20 USDT 转账，并分析能量/带宽
    println!("🚀 [4] 在 Account 1 发起 TRC-20 USDT 转账");
    let recipient_tron = &account2.tron_address;
    println!("   💸 收款方 (Account 2): {}", recipient_tron);
    println!("   💰 转账金额: 200.00 USDT");

    let mock_resource = TronAccountResource {
        free_net_limit: 600,
        free_net_used: 100,
        energy_limit: 10_000,
        energy_used: 10_000, // 可用能量为 0
        trx_balance_sun: 30_000_000, // 30 TRX
    };

    let estimate = estimate_tron_trc20_fee(&mock_resource, true);
    println!("\n   📊 【TRON 资源与手续费预检报告】");
    println!("      - ⚡ 需要能量: {} (当前可用: {})", estimate.required_energy, estimate.available_energy);
    println!("      - 🌐 需要带宽: {} bytes (当前可用免费带宽: {})", estimate.required_bandwidth, estimate.available_bandwidth);
    println!("      - 🔥 需燃烧 TRX: 约 {:.2} TRX (当前余额: 30.00 TRX)", estimate.burn_trx_amount);
    if let Some(warn) = estimate.warning_message {
        println!("      - ⚠️  提示: {}", warn);
    }

    // 5. 硬件签名流水线 (重新插入硬件 -> 强制输入 User PIN -> 即签即销 Zeroize)
    println!("\n🔐 [5] 进入硬件签名流水线 (Zero-Trust PIN 流水线)");
    println!("   🔌 重新插入 Nitrokey HSM 2...");
    client.transport_mut().connect()?;

    let msg_hash = build_tron_trc20_signing_hash(
        "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
        &account1.tron_address,
        recipient_tron,
        200_000_000,
        30_000_000,
    )?;

    println!("   📝 待签名 SHA-256 消息摘要: 0x{}", hex::encode(msg_hash));
    println!("   🔑 用户在界面弹窗输入 User PIN: ******");

    let mut session = SignSessionManager::new(&mut client);
    let sig = session.execute_signing(
        1,
        &msg_hash,
        &slot1.public_key_uncompressed,
        SafePin::new("648219"), // 离开作用域自动 Zeroize 擦除
    )?;

    println!("   ✅ HSM 芯片签名完成，PIN 内存已自动强制清零 (Zeroized)！");
    println!("      r: 0x{}", hex::encode(sig.r));
    println!("      s: 0x{} (Low-s 规范化)", hex::encode(sig.s));
    println!("      v: {} (公钥恢复匹配确认)", sig.v);

    let (sig_hex, recovered_tron) = finalize_tron_transaction(&msg_hash, &sig)?;
    println!("   🎉 组装 TRON 交易签名成功！Hex: {}", sig_hex);
    println!("   🔍 反向验签校验签名者: {}", recovered_tron);
    println!("      与发件人一致: {}\n", if recovered_tron == account1.tron_address { "✅ 完全一致" } else { "❌ 不一致" });

    println!("════════════════════════════════════════════════════════════════════════════");
    println!("         🎉 Nitrokey HSM 2 Rust 核心引擎全流程模拟演练成功完成！            ");
    println!("════════════════════════════════════════════════════════════════════════════\n");

    Ok(())
}
