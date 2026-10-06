#!/usr/bin/env bash
# 将 release 二进制打包为 macOS .app 并安装到 /Applications
# 用法: ./scripts/bundle-macos.sh [--no-install]
set -euo pipefail

APP_NAME="Nitrokey Wallet"
BIN_NAME="nitrokey-wallet"
BUNDLE_ID="com.nitrokey.wallet"
INSTALL_DIR="/Applications"

cd "$(dirname "$0")/.."
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)

echo "🔨 编译 release..."
cargo build --release

APP="target/release/${APP_NAME}.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "target/release/${BIN_NAME}" "$APP/Contents/MacOS/${BIN_NAME}"

cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>                <string>${APP_NAME}</string>
    <key>CFBundleDisplayName</key>         <string>${APP_NAME}</string>
    <key>CFBundleIdentifier</key>          <string>${BUNDLE_ID}</string>
    <key>CFBundleExecutable</key>          <string>${BIN_NAME}</string>
    <key>CFBundlePackageType</key>         <string>APPL</string>
    <key>CFBundleShortVersionString</key>  <string>${VERSION}</string>
    <key>CFBundleVersion</key>             <string>${VERSION}</string>
    <key>CFBundleDevelopmentRegion</key>   <string>zh_CN</string>
    <key>LSMinimumSystemVersion</key>      <string>11.0</string>
    <key>LSApplicationCategoryType</key>   <string>public.app-category.finance</string>
    <key>NSHighResolutionCapable</key>     <true/>
    <key>NSPrincipalClass</key>            <string>NSApplication</string>
</dict>
</plist>
EOF

# 可选图标：放置 assets/AppIcon.icns 即可自动打包
if [[ -f assets/AppIcon.icns ]]; then
    cp assets/AppIcon.icns "$APP/Contents/Resources/AppIcon.icns"
    /usr/libexec/PlistBuddy -c "Add :CFBundleIconFile string AppIcon" "$APP/Contents/Info.plist"
fi

# ad-hoc 签名（本机运行足够；分发给他人需 Developer ID 签名 + 公证）
codesign --force --deep --sign - "$APP"
echo "✅ 已生成 $APP"

if [[ "${1:-}" == "--no-install" ]]; then
    exit 0
fi

if pgrep -x "$BIN_NAME" >/dev/null; then
    echo "⏹  正在退出运行中的 ${APP_NAME}..."
    osascript -e "quit app \"${APP_NAME}\"" || true
    sleep 1
fi

rm -rf "${INSTALL_DIR}/${APP_NAME}.app"
cp -R "$APP" "${INSTALL_DIR}/"
echo "📦 已安装到 ${INSTALL_DIR}/${APP_NAME}.app"
