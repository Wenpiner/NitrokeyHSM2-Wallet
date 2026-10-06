# NitrokeyHSM2-Wallet

[English](README.md) | **简体中文**

把 Nitrokey HSM 2 当作 ETH / TRON 硬件钱包使用的桌面客户端。私钥在 HSM 芯片内生成、在芯片内签名，电脑上的软件只接触公钥和签名结果。

> [!WARNING]
> 这是个人业余项目，未经任何第三方安全审计，与 Nitrokey GmbH / CardContact 没有任何关联。
> **如果你要保管真实的、有价值的资产，请购买专业的区块链硬件钱包。** 原因见下文「为什么会有这个项目」。

## 为什么会有这个项目

说实话，起因很简单：手边刚好有一个 Nitrokey HSM 2。

它本来是给 PKI、CA 根密钥、代码签名准备的通用 HSM，但它支持 secp256k1 曲线，而这正是以太坊和 TRON 用的签名曲线。既然设备已经在抽屉里了，私钥不出芯片的特性又是现成的，那就顺手写一个客户端，把它变成一个能用的冷签名钱包。

### 为什么不直接用手机钱包

手机钱包的私钥或助记词最终存在手机里。即便有 Secure Enclave / StrongBox 加持，助记词在创建、备份、恢复时仍会经过 App 的内存。而这几年 iOS、Android 的 0day 层出不穷，零点击（zero-click）漏洞利用链在野外被反复发现，普通用户根本无从得知自己的手机是否干净。在这样的环境下，我们不敢保证任何一台手机是安全的，也就不愿意把私钥交给它。

HSM 的思路是：私钥在芯片内部生成，没有任何接口可以把明文私钥读出来，主机上的软件（包括本项目）从头到尾都碰不到私钥。即使电脑被完全攻破，攻击者也拿不走私钥本身。

### 但它不是专业硬件钱包

HSM 能保证「私钥偷不走」，但不能保证「签的就是你想签的那笔交易」：

- **没有屏幕，没有按键。** 交易在电脑上构造、在电脑上计算哈希，HSM 只看到一个 32 字节摘要。如果电脑已被入侵，恶意软件可以在你点击签名的瞬间把收款地址换掉，HSM 无从察觉。
- **PIN 在电脑键盘上输入。** 键盘记录器可以拿到 PIN，在设备保持插入时再签一笔你不知道的交易。
- **没有助记词。** 设备损坏或丢失，资产能否找回取决于你是否事先做了 DKEK 备份（见下文）。

Ledger、Trezor、Keystone、OneKey 等专业硬件钱包会在**设备自己的屏幕**上解析并显示收款地址和金额，需要在设备上物理确认，并提供标准化的助记词备份，这正是本项目做不到的。它们也经过了长期的公开审计和攻防检验。

**结论：** 本项目适合手上恰好有 HSM、想理解硬件签名全过程、愿意自己承担风险的极客。存放真实资产，请用专业硬件钱包。

## 功能

- 在 HSM 内创建 secp256k1 密钥，或导入设备中已有的密钥
- 同一把密钥同时派生 ETH 地址（EIP-55）和 TRON 地址（Base58Check）
- 查询余额与交易记录：ETH、USDT (ERC-20)、TRX、USDT (TRC-20)
- 构造转账、预估手续费（TRON 包括能量 / 带宽燃烧预估），硬件签名后由用户手动广播
- Watch-only：查看余额不需要插入设备，只有创建、导入、签名时才需要 PIN
- 签名前在设备上回读公钥并与本地缓存比对，防止用错密钥

## 安全模型速览

| 威胁 | 能否防御 | 说明 |
| --- | --- | --- |
| 电脑被入侵，窃取私钥 | ✅ | 私钥不出 HSM，主机侧不存在私钥 |
| 本地缓存文件泄露 | ✅ | 缓存只含公钥与地址，不含 PIN、密钥标签 |
| 设备被盗 | ⚠️ | 需要 User PIN；连续输错达到重试上限（默认 3 次）后锁定 |
| 电脑被入侵，篡改交易内容 | ❌ | 设备无屏幕，无法独立核对收款地址和金额 |
| 电脑被入侵，截获 PIN 后偷签 | ❌ | 签完请立即拔出设备，缩小暴露窗口 |
| 设备损坏 / 丢失 | ⚠️ | 无助记词，只能依赖事先配置的 DKEK 备份 |

完整的分析见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#安全设计)。

## 快速开始

### 环境要求

- macOS 11+（主要开发与测试平台）
- Rust stable 工具链
- [OpenSC](https://github.com/OpenSC/OpenSC)：提供 `opensc-pkcs11.so`、`pkcs11-tool`、`sc-hsm-tool`
- Nitrokey HSM 2（或其他 SmartCard-HSM 兼容设备）

```bash
brew install --cask opensc
```

程序会依次查找 `/Library/OpenSC/lib`、`/usr/local/lib`、`/opt/homebrew/lib`、`/usr/lib` 下的 `opensc-pkcs11.so`，也可以用 `PKCS11_MODULE` 指定。

### 编译与运行

```bash
cd rust
cargo run --release

# 或打包成 .app 并安装到 /Applications
./scripts/bundle-macos.sh             # 加 --no-install 只打包不安装
```

打包脚本使用 ad-hoc 签名，只适合本机使用。

### 初始化设备（可选）

全新设备或想重置时才需要。**初始化会清空设备上的所有密钥。**

```bash
# SO-PIN 必须是 16 位十六进制；User PIN 至少 6 位
sc-hsm-tool --initialize --so-pin <16位SO-PIN> --pin <User-PIN>
```

不要沿用出厂默认 PIN。如果需要备份密钥，请在生成密钥**之前**按 [Nitrokey 文档](https://docs.nitrokey.com/) 配置 DKEK，之后生成的密钥才能被加密导出。

密钥可以在客户端里创建，也可以用命令行创建后再导入：

```bash
# --id 是十六进制，0x14 即客户端里的 CKA_ID 20
pkcs11-tool --module /Library/OpenSC/lib/opensc-pkcs11.so --login \
  --keypairgen --key-type EC:secp256k1 --label <标签> --id 14
```

### 环境变量

| 变量 | 说明 |
| --- | --- |
| `PKCS11_MODULE` | PKCS#11 动态库路径，默认自动探测 |
| `HSM_SN` | 按 Token 序列号选择设备，插了多张智能卡时使用 |
| `HSM_SLOT` | 直接指定 PKCS#11 slot ID，优先级高于 `HSM_SN` |
| `WALLET_CACHE_PATH` | 本地缓存路径，默认 `~/Library/Application Support/nitrokey-wallet/wallet_cache.json` |

都不设置时，程序会自动选中唯一一个 SmartCard-HSM Token；检测到多个时会报错并列出候选。

## 使用流程

1. 插入设备，点击「添加账户」，选择「导入已有密钥」或「创建新密钥」，输入密钥标签、CKA_ID（0-254）和 PIN
2. 读取公钥后会话立即关闭，可以拔出设备；之后查看余额、交易记录都不需要设备
3. 发起转账：填写地址和金额，软件查询链上数据并预估手续费
4. 确认签名：插入设备，核对弹窗里的收款地址、金额和手续费，输入标签与 PIN
5. 签名完成后**不会自动广播**，确认无误再点击「广播交易」，也可以复制原始交易自行广播

密钥标签不会被保存或显示，请自己记住。它的作用是防止选错密钥，不是额外的密码（读取标签不需要 PIN）。

## 网络与隐私

Rust 核心不发起任何网络请求。界面（WebView）直接访问以下公共服务，用于查询余额、交易记录和广播交易：

- Ethereum：`ethereum-rpc.publicnode.com`、`eth.blockscout.com`
- TRON：`api.trongrid.io`

这些服务能看到你查询的地址和你的 IP。如果在意，可以修改 `rust/src/ui/index.html` 顶部的常量，换成自建节点。

## 当前限制

- 只支持 Ethereum 主网与 TRON 主网，资产仅 ETH / USDT / TRX / USDT
- ETH 使用 Legacy (EIP-155) 交易，暂不支持 EIP-1559
- 只在 macOS 上测试过；Linux 未验证（需用 `--no-default-features` 关闭 `macos-pcsc`）
- Android 只有 USB CCID 传输层原型，尚未接入完整应用
- PC/SC 原生通道只是 OpenSC 缺失时的实验性回退，不支持导入 / 创建，请以 PKCS#11 为准
- 没有可复现构建，也没有发布签名的二进制，请自行从源码编译

## 开发

```bash
cd rust
cargo test                  # 单元测试 + 集成测试（使用 Mock 设备，不需要硬件）
cargo run --example demo    # 用 Mock 设备演示完整的导入、签名流程
```

技术架构见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。

## 开源协议

本项目以 [The Unlicense](LICENSE) 发布到公有领域：你可以复制、修改、发布、商用、闭源再分发，无需署名，也无需保留许可声明。

## 免责声明

本软件按「原样」提供，不附带任何形式的担保。使用本软件造成的任何资产损失，作者不承担责任。转账前请先用小额测试。

Nitrokey 是 Nitrokey GmbH 的商标，SmartCard-HSM 是 CardContact Systems GmbH 的商标，本项目与它们没有任何关联。
