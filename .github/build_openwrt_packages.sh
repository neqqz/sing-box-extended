#!/usr/bin/env bash
set -e -o pipefail

VERSION="$1"
TARGET="$2"
BINARY_PATH="$3"

PROJECT=$(cd "$(dirname "$0")/.."; pwd)
DIST="$PROJECT/dist"

case "$TARGET" in
  linux_amd64*)            ARCHITECTURES="x86_64" ;;
  linux_arm64*)            ARCHITECTURES="aarch64_cortex-a53 aarch64_cortex-a72 aarch64_cortex-a76 aarch64_generic" ;;
  linux_386*softfloat)     ARCHITECTURES="i386_pentium-mmx" ;;
  linux_386*)              ARCHITECTURES="i386_pentium4" ;;
  linux_arm_7*)            ARCHITECTURES="arm_cortex-a5_vfpv4 arm_cortex-a7_neon-vfpv4 arm_cortex-a7_vfpv4 arm_cortex-a8_vfpv3 arm_cortex-a9_neon arm_cortex-a9_vfpv3-d16 arm_cortex-a15_neon-vfpv4" ;;
  linux_arm_6*)            ARCHITECTURES="arm_arm1176jzf-s_vfp" ;;
  linux_arm_5*)            ARCHITECTURES="arm_arm926ej-s arm_cortex-a7 arm_cortex-a9 arm_fa526 arm_xscale" ;;
  linux_mips64_*)          ARCHITECTURES="mips64_mips64r2 mips64_octeonplus" ;;
  linux_mips64le*)         ARCHITECTURES="mips64el_mips64r2" ;;
  linux_mipsle*hardfloat)  ARCHITECTURES="mipsel_24kc_24kf" ;;
  linux_mipsle*)           ARCHITECTURES="mipsel_24kc mipsel_74kc mipsel_mips32" ;;
  linux_mips_*)            ARCHITECTURES="mips_24kc mips_4kec mips_mips32" ;;
  linux_riscv64*)          ARCHITECTURES="riscv64_generic" ;;
  linux_loong64*)          ARCHITECTURES="loongarch64_generic" ;;
  *) echo "Unknown target: $TARGET"; exit 1 ;;
esac

PKG_VERSION="${VERSION//-/\~}"

FPM_DIR=$(mktemp -d)
sed "s|release/|$PROJECT/release/|g;s|^LICENSE|$PROJECT/LICENSE|" "$PROJECT/.fpm_openwrt" > "$FPM_DIR/.fpm"
trap 'rm -rf "$FPM_DIR"' EXIT

for ARCH in $ARCHITECTURES; do
  TMP_DEB=$(mktemp -p "$DIST" _openwrt_XXXXXX.deb)
  rm -f "$TMP_DEB"
  (cd "$FPM_DIR" && fpm -t deb \
    -v "$PKG_VERSION" \
    -p "$TMP_DEB" \
    --architecture all \
    "$BINARY_PATH=/usr/bin/sing-box")

  bash "$PROJECT/.github/deb2ipk.sh" \
    "$ARCH" \
    "$TMP_DEB" \
    "$DIST/sing-box-extended_${VERSION}_openwrt_${ARCH}.ipk"
  rm -f "$TMP_DEB"

  if command -v apk &>/dev/null; then
    bash "$PROJECT/.github/build_openwrt_apk.sh" \
      "$ARCH" "$VERSION" "$BINARY_PATH" \
      "$DIST/sing-box-extended_${VERSION}_openwrt_${ARCH}.apk"
  fi

  echo "Built: sing-box-extended_${VERSION}_openwrt_${ARCH} (.ipk/.apk)"
done
