#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TARGET=aarch64-apple-darwin
TARGET_DIR=${CARGO_TARGET_DIR:-"$ROOT_DIR/target"}
APP_DIR="$ROOT_DIR/dist/Codex Fast.app"
CONTENTS_DIR="$APP_DIR/Contents"
MACOS_DIR="$CONTENTS_DIR/MacOS"
RESOURCES_DIR="$CONTENTS_DIR/Resources"
INFO_PLIST="$CONTENTS_DIR/Info.plist"

cd "$ROOT_DIR"
PACKAGE_VERSION=$(cargo pkgid --locked)
PACKAGE_VERSION=${PACKAGE_VERSION##*#}
PACKAGE_VERSION=${PACKAGE_VERSION##*@}
cargo build --locked --release --target "$TARGET" --target-dir "$TARGET_DIR"

rm -rf -- "$APP_DIR"
mkdir -p "$MACOS_DIR" "$RESOURCES_DIR"
install -m 0755 "$TARGET_DIR/$TARGET/release/codex-fast" "$MACOS_DIR/codex-fast"
install -m 0644 "$ROOT_DIR/packaging/macos/Info.plist" "$INFO_PLIST"
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $PACKAGE_VERSION" "$INFO_PLIST"
install -m 0644 "$ROOT_DIR/packaging/macos/Codex.icns" "$RESOURCES_DIR/Codex.icns"

printf 'Built %s\n' "$APP_DIR"
