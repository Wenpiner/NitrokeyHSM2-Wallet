# 技术架构

## 总览

```
┌──────────────────────────────── 桌面进程 (Rust) ────────────────────────────────┐
│                                                                                 │
│  ┌─────────────── WebView (wry) ───────────────┐                                │
│  │ ui/index.html                               │   HTTPS   ┌──────────────────┐ │
│  │ · 余额 / 交易记录查询                          │ ────────▶ │ publicnode       │ │
│  │ · 构造转账参数、预估手续费                      │           │ blockscout       │ │
│  │ · 广播已签名交易                               │ ◀──────── │ trongrid         │ │
│  └──────────────┬──────────────────────────────┘           └──────────────────┘ │
│                 │ window.ipc.postMessage(JSON)  ▲ evaluate_script(callback)       │
│  ┌──────────────▼───────────────────────────────┴────────┐                      │
│  │ main.rs  IPC 分发 · 参数校验 · 交易构造 · 安全限额        │                      │
│  └──────┬──────────────────┬────────────────────┬────────┘                      │
│         │                  │                    │                               │
│  ┌──────▼──────┐   ┌───────▼────────┐   ┌───────▼────────┐                      │
│  │ chains/     │   │ pkcs11/        │   │ storage.rs     │──▶ wallet_cache.json │
│  │ eth · tron  │   │ (cryptoki)     │   │ watch-only 缓存 │    (0600，仅公钥)     │
│  └──────┬──────┘   └───────┬────────┘   └────────────────┘                      │
│  ┌──────▼──────┐           │  回退（实验性）                                      │
│  │ crypto/     │   ┌───────▼────────┐                                           │
│  │ 地址·签名处理 │   │ schsm/ + transport/ (PC/SC APDU)                          │
│  └─────────────┘   └───────┬────────┘                                           │
└────────────────────────────┼────────────────────────────────────────────────────┘
                             │ opensc-pkcs11.so / PC/SC
                     ┌───────▼────────┐
                     │ Nitrokey HSM 2 │  私钥在此生成、在此签名
                     └────────────────┘
```

只有 WebView 访问网络；Rust 核心没有 HTTP 客户端依赖，只和 HSM 及本地文件打交道。

## 目录结构

```
rust/
├── src/
│   ├── main.rs              桌面入口：窗口、macOS 菜单、IPC 分发、交易签名编排
│   ├── lib.rs               核心库 nitrokey_wallet_core（可编译为 rlib / cdylib / staticlib）
│   ├── ui/index.html        单文件前端，编译期通过 include_str! 内嵌
│   ├── pkcs11/              主后端：通过 OpenSC PKCS#11 登录、查找 / 生成密钥、签名
│   ├── schsm/               SmartCard-HSM APDU 客户端（PC/SC 回退通道用）
│   ├── transport/           APDU 传输抽象：pcsc（macOS）、android（原型）、mock（测试）
│   ├── chains/              eth.rs：RLP / EIP-155；tron.rs：protobuf raw_data；金额解析
│   ├── crypto/              地址派生（EIP-55 / Base58Check）、DER 签名解析与 v 恢复
│   ├── storage.rs           watch-only 缓存读写
│   ├── session.rs           PC/SC 通道的签名会话（PIN 预检、校验、签名）
│   └── types.rs             公共数据结构、SafePin
├── tests/                   集成测试（Mock 设备）
├── examples/demo.rs         Mock 设备全流程演示
└── scripts/bundle-macos.sh  打包 .app
android/                     Android USB CCID 插件原型（Kotlin）
```

## 账户模型

一个账户 = 设备中一对 secp256k1 密钥，由 `CKA_LABEL` + `CKA_ID` 共同定位：

- `CKA_ID`：单字节 0-254，作为账户编号，在界面上显示为「十进制 (0x十六进制)」，与 `pkcs11-tool --id` 对应
- `CKA_LABEL`：用户自己记住的标签，不保存、不显示，每次操作时输入

同一个未压缩公钥 `04 || X || Y` 取 `Keccak256(X || Y)` 的后 20 字节，加 `0x` 前缀并做 EIP-55 大小写校验得到 ETH 地址，加 `0x41` 前缀并做 Base58Check 得到 TRON 地址。因此一个账户在两条链上对应同一把私钥。

## IPC 协议

前端通过 `window.ipc.postMessage(JSON.stringify({...}))` 发起请求，Rust 处理完后用 `evaluate_script` 调用页面上的全局回调。所有请求在 IPC 处理器中同步执行。

| action | 关键参数 | 是否访问设备 | 回调 |
|---|---|---|---|
| `load_cache` | — | 否 | `onWalletLoaded(wallet \| null)` |
| `import_account`（旧名 `sync_wallet`） | `key_id`, `key_label`, `pin` | 是 | `onAuthCompleted({mode:"import", result})` |
| `create_account` | `key_id`, `key_label`, `pin` | 是 | `onAuthCompleted({mode:"create", result})` |
| `remove_account` | `key_id` | 否，只删本地缓存 | `onAccountRemoved(result)` |
| `sign_tx` | `key_id`, `key_label`, `pin`, `chain`, `asset`, `to`, `amount` 及链相关字段 | 是 | `onAuthCompleted({mode:"sign", result})` |

`result` 统一为 `{ ok: true, ... }` 或 `{ ok: false, error }`。`sign_tx` 成功时返回 `{ raw_tx_hex, tx_id, from }`，由前端在用户确认后广播。

`key_id` 接受整数或 `"20"` / `"0x14"` 形式的字符串。IPC 请求体解析后立即 zeroize，`pin` 和 `key_label` 从 JSON 中 `take` 出来单独持有，避免随 `Value` 被复制。

## 核心流程

所有访问设备的操作都遵循同一个模式：打开后端 → 用 PIN 登录 → 完成单个操作 → `Pkcs11Hsm` 被 drop 时登出并 `C_Finalize`。程序不保持长连接，也不缓存 PIN。

### 导入账户

1. 用 PIN 登录 Token
2. 分别查找 `CKA_LABEL == label && CKA_ID == id` 的公钥和私钥对象
3. 公钥、私钥必须各自唯一存在；否则根据「标签存在但 ID 不对」「ID 存在但标签不对」「多个匹配」「只有私钥没有公钥」等情况返回具体错误
4. 读取 `CKA_EC_POINT`，去掉 DER OCTET STRING 包装得到 65 字节未压缩公钥
5. 如果同一个公钥已经以别的 ID 存在于缓存中，拒绝导入
6. 派生 ETH / TRON 地址，写入缓存

### 创建账户

1. 检查本地缓存中没有该 ID
2. 在设备上检查：该 ID 未被任何标签占用，该标签也未用于其他 ID
3. `C_GenerateKeyPair`（`CKM_EC_KEY_PAIR_GEN`，曲线 secp256k1），私钥属性 `CKA_TOKEN / CKA_SENSITIVE / CKA_SIGN` 为真
4. 用 标签 + ID 重新查一次公钥，必须与生成结果一致才写入缓存

私钥模板中 `CKA_EXTRACTABLE = true`，目的是允许在 SmartCard-HSM 上做 DKEK 加密导出（`sc-hsm-tool --wrap-key`）以便备份。明文私钥无法导出；如果你不需要备份，可以改成 `false`。

### 签名

1. 从本地缓存取出该 ID 的公钥和地址
2. 在 Rust 中构造交易并计算 32 字节摘要（见下节）
3. 登录设备，用 标签 + ID 重新读取公钥，必须与缓存一致，防止设备中的密钥被替换
4. 定位唯一私钥，`C_Sign`（`CKM_ECDSA`，对预先计算好的摘要签名）
5. 解析 64 字节 `r || s`（若返回 ASN.1 DER 编码同样支持），做 low-s 规范化
6. 依次尝试 recovery id 0 / 1，恢复出的公钥等于预期公钥时确定 `v`
7. 组装签名交易，再从签名恢复发送方地址，必须等于缓存中的地址，否则报错

## 交易构造

### Ethereum

- Legacy 交易 + EIP-155，`chain_id = 1`，RLP 编码由 `chains/eth.rs` 手写
- 签名摘要：`keccak256(rlp([nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]))`
- 最终 `v = chainId * 2 + 35 + recid`
- ERC-20 转账：`to` 为 USDT 合约，`data = a9059cbb || pad32(收款地址) || pad32(数量)`
- 前端从 RPC 获取 `nonce`、`gasPrice`（加 20% 余量）、`estimateGas`；后端拒绝 `gas_limit > 10,000,000` 或 `gas_price > 500 Gwei`

### TRON

- 不依赖任何 TRON SDK，`chains/tron.rs` 按 TRON protobuf 定义手写 `Transaction.raw` 编码，支持 `TransferContract`（TRX）和 `TriggerSmartContract`（TRC-20）
- `ref_block_bytes` 取区块高度的低 2 字节，`ref_block_hash` 取 block_id 的第 8-15 字节
- 签名摘要：`sha256(raw_data)`，即 txID
- 后端校验前端传来的参考区块：block_id 前 8 字节必须等于区块高度，区块时间不能早于当前 5 分钟或晚于当前 1 分钟
- `expiration = 参考区块时间 + 10 分钟`，`fee_limit = 50 TRX`
- 签名格式为 65 字节 `r || s || v`（`v` 取 0/1），输出带签名的 protobuf `Transaction` 十六进制

单元测试用 TronGrid 返回的真实 raw_data 结构做对照（数值已替换为合成数据），保证编码字节级一致。

金额统一通过 `chains::parse_amount` 将十进制字符串解析为最小单位整数，拒绝空值、零、负数、前导零、非数字字符和超过精度的小数位，全程不经过浮点数。

## 本地存储

`WalletStore` 是一个 watch-only 缓存，结构为 `{ devices: { <设备序列号>: DeviceWalletCache } }`：

```json
{
  "devices": {
    "<token serial>": {
      "device_id": "<token serial>",
      "device_name": "Nitrokey HSM 2 (<序列号后 6 位>)",
      "last_sync_timestamp": 1700000000,
      "slots": [
        {
          "key_id": 1,
          "account_name": "账户 #1",
          "public_key_hex": "04...",
          "eth_address": "0x...",
          "tron_address": "T..."
        }
      ]
    }
  }
}
```

- 只包含设备序列号、公钥和地址，不包含 PIN、标签或任何私钥材料。序列号和地址可以把你和设备关联起来，分享日志或缓存文件前请注意
- 界面展示 `last_sync_timestamp` 最新的那台设备
- 写入时先写 `wallet_cache.json.tmp` 并设为 `0600`，再 `rename` 原子替换
- 默认路径：macOS `~/Library/Application Support/nitrokey-wallet/`，其他 Unix `$XDG_DATA_HOME/nitrokey-wallet/`，可用 `WALLET_CACHE_PATH` 覆盖
- 「移除账户」只删缓存条目，设备上的密钥不受影响，随时可以重新导入

缓存被篡改的后果有限：签名前会用设备中的公钥重新比对，签名后会从签名恢复地址再比对，任何一项不一致都会拒绝。但篡改者可以让界面显示错误的地址或余额，见[安全设计](#安全设计)。

## 敏感数据生命周期

| 数据 | 产生 | 存活范围 | 清除方式 |
|---|---|---|---|
| PIN | 前端输入框 | 一次 IPC 请求 | 前端读取后立即清空输入框；Rust 侧为 `SecretString`（PC/SC 通道为 `SafePin`），drop 时 zeroize |
| Key Label | 前端输入框 | 一次 IPC 请求 | 同上；Rust 侧 `String` 用完 zeroize |
| IPC 请求体 | `postMessage` | 解析前 | 解析成 `Value` 后立即 zeroize 原始字符串 |
| PKCS#11 会话 | 登录时 | 一次操作 | `Pkcs11Hsm` drop 时 `C_Logout` + `C_Finalize` |
| 私钥 | HSM 内部生成 | 永久留在 HSM | 不离开设备 |

局限：WebView 中的 JavaScript 字符串不可控地存在于 JS 堆中，无法保证被覆写；`serde_json::Value` 解析过程中的中间缓冲也无法全部覆盖。zeroize 只是减小暴露窗口，不能抵御能读取本进程内存的攻击者。

## 硬件后端

| 后端 | 状态 | 说明 |
|---|---|---|
| PKCS#11（OpenSC） | 主路径 | 支持导入、创建、签名，按 标签 + CKA_ID 定位密钥 |
| PC/SC 原生 APDU | 实验性，仅 macOS + `macos-pcsc` feature | 只在 PKCS#11 模块加载失败时启用；只支持签名，固定使用密钥引用 1，PSO 参数未在真机上完整验证 |
| Android USB CCID | 原型 | `transport/android.rs` + `android/` 下的 Kotlin 插件，未接入 UI |
| Mock | 测试用 | 内存中模拟 SmartCard-HSM，供集成测试和 `examples/demo.rs` 使用 |

PC/SC 通道即使选错密钥也不会签出错误交易：签名解析时必须能恢复出缓存中的公钥，交易组装后还要再比对一次地址，任何一步失败都直接报错。

PKCS#11 Slot 选择顺序：`HSM_SLOT` 指定的 Slot → 序列号等于 `HSM_SN` 的 Token → 标签含 `SmartCard-HSM` 或厂商为 `CardContact` 的唯一 Token。匹配到多个时报错并列出候选，要求用环境变量指定。

## 网络模型

Rust 核心不发起任何网络请求。所有链上数据由 WebView 内的前端直接请求公共服务：

| 用途 | 服务 |
|---|---|
| ETH 余额、nonce、gasPrice、estimateGas、广播 | `https://ethereum-rpc.publicnode.com`（JSON-RPC） |
| ETH 交易记录 | `https://eth.blockscout.com/api/v2` |
| TRON 余额、资源、参考区块、交易记录、广播 | `https://api.trongrid.io` |

这些服务能看到你的 IP 与查询的地址。签名需要的链上参数（nonce、gas、参考区块）都来自这些服务，后端只做范围校验，不能验证它们是否真实。

## 安全设计

### 信任边界

```
  不可信                         部分可信                       可信
┌───────────┐   HTTPS   ┌──────────────────────────────┐   USB   ┌────────────┐
│ 公共 RPC  │ ◀───────▶ │ 主机：macOS + 本程序 + OpenSC  │ ◀─────▶ │ HSM 芯片    │
└───────────┘           └──────────────────────────────┘         └────────────┘
```

HSM 是唯一被假定可信的组件。主机只在「未被攻陷」的前提下可信，这是本项目和专业硬件钱包最大的差别。

### 它能防住什么

| 威胁 | 措施 |
|---|---|
| 主机被植入窃密木马，想拿走私钥 | 私钥在 HSM 内生成，`CKA_SENSITIVE`，签名在芯片内完成，主机上从未出现过私钥明文 |
| 笔记本丢失或磁盘被拷走 | 磁盘上只有公钥缓存；没有 HSM 和 PIN 无法签名 |
| HSM 丢失 | 需要 PIN 才能使用，连续输错达到重试上限后锁定；还需要知道标签和 CKA_ID 才能定位账户 |
| 暴力尝试 PIN | 由 HSM 硬件计数，程序在剩余 1 次时给出警告 |
| 本地缓存被篡改成别人的公钥 | 签名前用设备中的公钥比对缓存，签名后从签名恢复地址再比对 |
| 签名畸形 / 可延展 | 强制 low-s，`v` 通过公钥恢复确定而不是猜测 |
| 前端传入离谱的手续费 | ETH 限制 `gas_limit ≤ 10M`、`gas_price ≤ 500 Gwei`；TRON `fee_limit` 固定 50 TRX |
| TRON 参考区块被伪造或过期 | 校验 block_id 与高度一致，时间在合理窗口内，交易 10 分钟后过期 |
| 长时间保持登录态 | 每次操作单独登录，结束即登出并卸载 PKCS#11 模块 |
| 静默签名 | 每次签名都要求重新输入标签和 PIN；签名后不会自动广播 |

### 它防不住什么

这些是结构性问题，不是 bug，代码层面无法修复：

- **没有可信显示**：HSM 没有屏幕和按键，你在屏幕上核对的收款地址和金额由主机渲染。被完全控制的主机可以显示 A 地址、实际让 HSM 签 B 地址的交易，HSM 无法察觉。专业硬件钱包会在设备屏幕上显示交易内容，并要求按物理键确认，正好解决这个问题
- **PIN 经过主机键盘**：键盘记录器可以拿到 PIN。配合物理接触或远程持续控制，攻击者可以在设备插着的时候签任意交易
- **标签不是密钥**：标签只是用来降低误操作和撞库概率的「第二因子」，它同样经过主机输入，不应视为安全边界
- **内存中的敏感数据**：JS 字符串无法擦除，能读取进程内存的攻击者可以拿到 PIN
- **链上参数来自公共 RPC**：nonce、gas、参考区块由前端从公共服务获取，后端只做范围校验。恶意或被劫持的 RPC 可以让交易失败，或在限额内抬高手续费，但无法改变收款地址和金额
- **界面信息可伪造**：余额、交易记录来自公共 API，缓存文件也可以被改，被篡改后界面可能显示错误的「我的地址」。收款前请在另一台设备上用区块浏览器核对
- **没有助记词**：私钥无法用 BIP-39 助记词恢复。备份只能依赖 SmartCard-HSM 的 DKEK 机制，在初始化时设置 DKEK 并把加密后的密钥导出到另一台设备，否则设备损坏即资产丢失
- **供应链与构建**：没有可复现构建和签名发布，OpenSC、Rust 依赖、WebView 的安全性都需要你自己评估

### 和手机钱包、专业硬件钱包的对比

| | 手机热钱包 | 本项目 | 专业硬件钱包 |
|---|---|---|---|
| 私钥是否离开安全芯片 | 依赖系统 Keychain / Keystore，通常离开 | 不离开 | 不离开 |
| 主机 / 手机被 0day 攻陷后 | 私钥可能被窃取 | 私钥安全，但可被诱导签错交易 | 私钥安全，屏幕核对可防篡改 |
| 交易内容可信显示 | 无 | 无 | 有 |
| 物理确认 | 无 | 无（只需 PIN） | 有 |
| 助记词备份 | 有 | 无，只有 DKEK | 有 |
| 安全审计 | 视产品而定 | 无 | 主流产品有 |

结论与 README 一致：它比手机热钱包多了一层「私钥不出芯片」的保护，但缺少可信显示和物理确认。存放重要资产，请使用专业的区块链硬件钱包。

### 使用建议

- 在专用、尽量干净的 Mac 上运行，签名时才插入 HSM，用完立即拔出
- 初始化时设置 DKEK 并完成备份，妥善保管 SO-PIN 和 DKEK 分片
- 先用小额测试每个新账户，确认导入的地址能正常收发
- 每次签名前在弹窗中逐字核对收款地址，大额转账前先在另一台设备上确认对方地址

## 测试

```bash
cd rust
cargo test                 # 单元测试 + 集成测试
cargo run --example demo   # Mock 设备全流程演示
```

| 位置 | 覆盖内容 |
|---|---|
| `chains/eth.rs` | EIP-155 规范示例向量、地址与校验和解析、ERC-20 calldata 布局 |
| `chains/tron.rs` | TransferContract / TriggerSmartContract 编码与 TronGrid 结构对照、USDT 合约地址、签名组装往返 |
| `chains/mod.rs` | 金额解析边界 |
| `storage.rs` | 账户移除、空缓存报错、旧版 `slot_id` 字段兼容 |
| `pkcs11/mod.rs` | CKA_ID 十进制 / 十六进制解析与非法输入 |
| `tests/wallet_integration_tests.rs` | 地址派生、Mock 设备 PIN 流程、缓存持久化、TRON 资源估算、ETH / TRC-20 完整签名流程 |

真实 HSM 相关的路径（PKCS#11 登录、密钥生成、签名）没有自动化测试，需要连接设备手动验证。

## 已知限制与后续方向

- 只支持以太坊主网和 TRON 主网，资产只有 ETH / USDT / TRX
- ETH 只支持 Legacy 交易，未支持 EIP-1559
- 只在 macOS 上测试；Linux 未验证（需用 `--no-default-features` 关闭 `macos-pcsc`），Windows 未适配
- PC/SC 通道与 Android 传输层仍是原型
- 未做可复现构建、代码签名与公证
- 没有地址簿、多签、合约交互等功能，也不打算往通用钱包方向扩展
