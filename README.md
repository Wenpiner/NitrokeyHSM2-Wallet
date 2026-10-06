# NitrokeyHSM2-Wallet

**English** | [简体中文](README.zh-CN.md)

A desktop client that turns a Nitrokey HSM 2 into an ETH / TRON hardware wallet. Private keys are generated and used for signing inside the HSM chip. The software on your computer only ever sees public keys and signatures.

> [!WARNING]
> This is a personal hobby project. It has not been audited by any third party and is not affiliated with Nitrokey GmbH or CardContact.
> **If you are protecting real, valuable assets, buy a dedicated blockchain hardware wallet.** See [Why this project exists](#why-this-project-exists) for the reasons.

## Why this project exists

Honestly, the reason is simple: I happened to have a Nitrokey HSM 2 lying around.

It is a general-purpose HSM meant for PKI, CA root keys and code signing. But it supports the secp256k1 curve, which is exactly the curve Ethereum and TRON use. The device was already in the drawer and "the private key never leaves the chip" came for free, so I wrote a client to turn it into a usable cold-signing wallet.

### Why not just use a mobile wallet

A mobile wallet ultimately keeps its private key or seed phrase on the phone. Even with Secure Enclave / StrongBox, the seed phrase still passes through app memory during creation, backup and recovery. Meanwhile iOS and Android 0days keep coming, and zero-click exploit chains are repeatedly found in the wild. Ordinary users have no way to know whether their phone is clean. In that environment I can't vouch for the security of any phone, so I'd rather not hand it a private key.

The HSM approach is different: the key is generated inside the chip, and no interface can read the plaintext key back out. Software on the host, including this project, never touches the private key. Even if the computer is fully compromised, the attacker cannot take the key itself.

### But it is not a dedicated hardware wallet

An HSM guarantees the key can't be stolen. It does not guarantee that what gets signed is the transaction you meant to sign:

- **No screen, no buttons.** The transaction is built and hashed on the computer; the HSM only sees a 32-byte digest. If the computer is compromised, malware can swap the recipient address the moment you click sign, and the HSM has no way to notice.
- **The PIN is typed on the computer keyboard.** A keylogger can capture it and sign another transaction while the device is still plugged in.
- **No seed phrase.** If the device is lost or broken, recovery depends on whether you set up a DKEK backup in advance (see below).

Hardware wallets such as Ledger, Trezor, Keystone and OneKey parse and show the recipient and amount **on the device's own screen**, require a physical confirmation on the device, and offer standard seed-phrase backup. This project can do none of that. They have also been through years of public audits and real-world attacks.

**Bottom line:** this project is for geeks who happen to own an HSM, want to understand hardware signing end to end, and are willing to take the risk themselves. For real assets, use a dedicated hardware wallet.

## Features

- Create secp256k1 keys inside the HSM, or import keys already on the device
- One key derives both an ETH address (EIP-55) and a TRON address (Base58Check)
- Balances and history for ETH, USDT (ERC-20), TRX and USDT (TRC-20)
- Build transfers and estimate fees (including TRON energy / bandwidth burn), sign on the hardware, then broadcast manually
- Watch-only: viewing balances doesn't need the device; only create, import and sign ask for the PIN
- Before signing, the public key is read back from the device and compared with the local cache, so the wrong key is never used

## Security at a glance

| Threat | Protected | Notes |
| --- | --- | --- |
| Compromised computer steals the private key | ✅ | The key never leaves the HSM; no key material exists on the host |
| Local cache file leaks | ✅ | The cache holds only public keys and addresses, no PIN or key label |
| Device stolen | ⚠️ | Needs the User PIN; locks after the retry limit (3 by default) |
| Compromised computer alters the transaction | ❌ | No screen on the device, so recipient and amount can't be verified independently |
| Compromised computer captures the PIN and signs behind your back | ❌ | Unplug the device right after signing to shrink the window |
| Device lost or broken | ⚠️ | No seed phrase; relies on a DKEK backup set up beforehand |

The full analysis is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#安全设计) (Chinese).

## Quick start

### Requirements

- macOS 11+ (the main development and test platform)
- Rust stable toolchain
- [OpenSC](https://github.com/OpenSC/OpenSC), which provides `opensc-pkcs11.so`, `pkcs11-tool` and `sc-hsm-tool`
- Nitrokey HSM 2 (or another SmartCard-HSM compatible device)

```bash
brew install --cask opensc
```

The app looks for `opensc-pkcs11.so` in `/Library/OpenSC/lib`, `/usr/local/lib`, `/opt/homebrew/lib` and `/usr/lib`, in that order. Set `PKCS11_MODULE` to override.

### Build and run

```bash
cd rust
cargo run --release

# Or bundle as a .app and install into /Applications
./scripts/bundle-macos.sh             # add --no-install to bundle only
```

The bundle script uses ad-hoc signing and is only meant for your own machine.

### Initialize the device (optional)

Only needed for a new device or a reset. **Initializing wipes every key on the device.**

```bash
# SO-PIN must be 16 hex digits; User PIN at least 6 digits
sc-hsm-tool --initialize --so-pin <16-hex-SO-PIN> --pin <User-PIN>
```

Don't keep the factory default PINs. If you want to back up keys, set up a DKEK **before** generating keys, following the [Nitrokey docs](https://docs.nitrokey.com/). Only keys generated afterwards can be exported in wrapped form.

Keys can be created in the client, or created on the command line and then imported:

```bash
# --id is hex: 0x14 is CKA_ID 20 in the client
pkcs11-tool --module /Library/OpenSC/lib/opensc-pkcs11.so --login \
  --keypairgen --key-type EC:secp256k1 --label <label> --id 14
```

### Environment variables

| Variable | Description |
| --- | --- |
| `PKCS11_MODULE` | Path to the PKCS#11 library; auto-detected by default |
| `HSM_SN` | Select the device by token serial number, for when several smart cards are plugged in |
| `HSM_SLOT` | Use this PKCS#11 slot ID directly; takes precedence over `HSM_SN` |
| `WALLET_CACHE_PATH` | Local cache path; defaults to `~/Library/Application Support/nitrokey-wallet/wallet_cache.json` |

With none of these set, the app picks the only SmartCard-HSM token present. If it finds more than one, it reports an error listing the candidates.

## Usage

The UI is currently in Chinese only; button names are given below with their on-screen text.

1. Plug in the device, click "Add account" (添加账户), choose "Import existing key" (导入已有密钥) or "Create new key" (创建新密钥), then enter the key label, CKA_ID (0-254) and PIN
2. The session closes as soon as the public key is read, and you can unplug the device. Balances and history no longer need it
3. Start a transfer: enter the address and amount; the app queries chain data and estimates fees
4. Confirm and sign: plug in the device, check the recipient, amount and fee in the dialog, then enter the label and PIN
5. Signed transactions are **never broadcast automatically**. When everything looks right, click "Broadcast" (广播交易), or copy the raw transaction and broadcast it yourself

The key label is never stored or displayed, so remember it yourself. It guards against picking the wrong key; it is not an extra password (reading labels doesn't require the PIN).

## Network and privacy

The Rust core makes no network requests. The UI (WebView) talks directly to these public services to fetch balances and history and to broadcast transactions:

- Ethereum: `ethereum-rpc.publicnode.com`, `eth.blockscout.com`
- TRON: `api.trongrid.io`

These services can see the addresses you query and your IP. If that matters to you, change the constants at the top of `rust/src/ui/index.html` to point at your own nodes.

## Current limitations

- Ethereum mainnet and TRON mainnet only; assets limited to ETH / USDT / TRX / USDT
- ETH uses Legacy (EIP-155) transactions; EIP-1559 is not supported yet
- Tested on macOS only; Linux is unverified (build with `--no-default-features` to drop `macos-pcsc`)
- Android only has a USB CCID transport prototype, not a full app
- The native PC/SC channel is an experimental fallback for when OpenSC is missing; it can't import or create keys, so treat PKCS#11 as the supported path
- No reproducible builds and no signed release binaries; build from source yourself

## Development

```bash
cd rust
cargo test                  # unit + integration tests (mock device, no hardware needed)
cargo run --example demo    # walk through import and signing with a mock device
```

The technical architecture is documented in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) (Chinese).

## License

Released into the public domain under [The Unlicense](LICENSE). You may copy, modify, publish, sell, or redistribute it, closed-source or not, with no attribution and no need to keep the license notice.

## Disclaimer

This software is provided "as is", without warranty of any kind. The authors are not responsible for any loss of assets resulting from its use. Test with small amounts before making real transfers.

Nitrokey is a trademark of Nitrokey GmbH, and SmartCard-HSM is a trademark of CardContact Systems GmbH. This project is not affiliated with either.
