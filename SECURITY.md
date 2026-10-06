# Security Policy

**English** | [简体中文](#安全策略)

This is an unaudited hobby project maintained on a best-effort basis. Please read the [warning in the README](README.md#why-this-project-exists) before trusting it with real funds.

## Supported versions

Only the latest commit on the default branch receives security fixes. There are no maintained release branches.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately through GitHub: open the repository's **Security** tab and click **Report a vulnerability**. This creates a private advisory visible only to you and the maintainers.

Please include:

- What the issue is and what an attacker could achieve (e.g. sign an unintended transaction, extract the PIN, corrupt the cache)
- The affected file / function and commit hash
- Steps to reproduce, ideally using the mock device (`cargo test` / `cargo run --example demo`) rather than real funds
- Your environment if relevant: macOS version, OpenSC version, device firmware
- Whether you would like to be credited, and under what name

Never include real PINs, SO-PINs, DKEK shares or seed material in a report.

## What to expect

- This project has no dedicated security team and no bug bounty. Reports are handled on a best-effort basis
- You will get an acknowledgement once the report has been read, and updates as the investigation progresses
- Fixes are released on the default branch, followed by a GitHub Security Advisory describing the issue
- Please allow up to 90 days for a fix before public disclosure. If an issue is being actively exploited, we will coordinate an earlier disclosure with you

## Scope

In scope, issues in this repository's code, for example:

- A way to make the app sign a transaction different from the one shown in the confirmation dialog, without compromising the host OS
- Bypassing the public key / recovered address checks before or after signing
- Incorrect transaction encoding (RLP, EIP-155, TRON protobuf) that changes the recipient, amount, fee or chain
- PIN or key label leaking to disk, logs, or the network
- Bypassing the gas / fee limits or the TRON reference block validation
- Malicious IPC messages or web content gaining control of the Rust core

Out of scope:

- **Known structural limitations** documented in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#它防不住什么): the HSM has no trusted display or physical confirmation, the PIN is typed on the host keyboard, JavaScript strings can't be zeroized, and chain parameters come from public RPC services. A fully compromised host can already exploit these by design
- Vulnerabilities in OpenSC, the Nitrokey HSM 2 / SmartCard-HSM firmware, macOS, or WebKit. Please report those to the [OpenSC project](https://github.com/OpenSC/OpenSC) or the respective vendor
- Privacy exposure to the public RPC / API providers listed in the README
- Attacks that require physical access to an unlocked device together with its PIN

If you're unsure whether something is in scope, report it anyway.

## Testing guidelines

- Test only against your own devices, keys and accounts
- Prefer the mock device. If you must test on chain, use your own accounts with negligible amounts
- Do not attack the third-party RPC services the app uses

---

# 安全策略

[English](#security-policy) | **简体中文**

这是一个未经审计、尽力维护的个人项目。使用真实资产前，请先阅读 [README 中的警告](README.zh-CN.md#为什么会有这个项目)。

## 支持的版本

只有默认分支的最新提交会获得安全修复，没有长期维护的发布分支。

## 报告漏洞

**请不要通过公开 Issue 报告安全问题。**

请在仓库的 **Security** 标签页点击 **Report a vulnerability**，通过 GitHub 私密漏洞报告提交，内容只有你和维护者可见。

报告中请说明问题与影响、涉及的文件 / 函数及提交哈希、复现步骤（尽量用 Mock 设备，不要动用真实资产）、相关环境，以及是否希望署名致谢。**请勿在报告中附带真实的 PIN、SO-PIN、DKEK 分片或任何密钥材料。**

## 处理方式

- 本项目没有专职安全团队，也没有漏洞赏金，按尽力原则处理
- 阅读报告后会回复确认，并同步调查进展
- 修复合入默认分支后，会发布 GitHub Security Advisory 说明问题
- 公开披露前请预留最多 90 天修复时间；如漏洞已被在野利用，会与你协商提前披露

## 范围

属于范围内：在不攻破主机操作系统的前提下，让程序签出与确认弹窗不一致的交易；绕过签名前后的公钥 / 恢复地址校验；交易编码错误导致收款方、金额、手续费或链被改变；PIN 或标签泄露到磁盘、日志或网络；绕过手续费限额或 TRON 参考区块校验；恶意 IPC 消息或网页内容控制 Rust 核心。

不属于范围内：[架构文档](docs/ARCHITECTURE.md#它防不住什么)中已说明的结构性限制（无可信显示、PIN 经主机键盘输入、JS 字符串无法擦除、链上参数来自公共 RPC）；OpenSC、设备固件、macOS、WebKit 自身的漏洞（请报告给 [OpenSC](https://github.com/OpenSC/OpenSC) 或对应厂商）；对 README 所列公共 RPC 服务的隐私暴露；需要同时物理接触设备并知道 PIN 的攻击。

拿不准是否在范围内，也欢迎提交。

## 测试守则

只在自己的设备、密钥和账户上测试；优先使用 Mock 设备，必须上链时只用自己账户里的极小金额；不要攻击本程序使用的第三方 RPC 服务。
