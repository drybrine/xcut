#!/bin/bash
# xcut installer - Linux cross-distro (Arch, Debian/Ubuntu, Fedora, openSUSE, Alpine)
#
#   ./install.sh             install dependencies + copy tools to ~/.local/bin
#   ./install.sh --no-deps   only copy the tools (skip package install)
#   ./install.sh --deps-only only install dependencies
#   ./install.sh --system    install to /usr/local/bin instead of ~/.local/bin
#
# The tools need kernel-level access (raw sockets, monitor mode, BLE mgmt
# channel) so only Linux is supported - Windows/macOS have no equivalent.
# Prefer a USB WiFi adapter (Realtek RTL8812AU / mt76) for deauth injection.

set -u

DEST="${XDG_BIN_HOME:-$HOME/.local/bin}"
DO_DEPS=1
USE_SUDO=""

usage() {
    sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
}

for a in "$@"; do
    case "$a" in
        --no-deps)   DO_DEPS=0 ;;
        --deps-only) DO_DEPS=2 ;;
        --system)    DEST="/usr/local/bin" ;;
        -h|--help)   usage ;;
        *) echo "unknown option: $a (see --help)"; exit 1 ;;
    esac
done

# ---- package manager detection + per-distro package names ----
PM=""
PKGS=""
install_deps() {
    case "$PM" in
        pacman)
            PKGS="iproute2 iputils dsniff iw aircrack-ng networkmanager python bluez arp-scan mdk4 ethtool wpa_supplicant"
            $USE_SUDO pacman -S --noconfirm $PKGS ;;
        apt)
            PKGS="iproute2 iputils-ping iputils-arping dsniff iw aircrack-ng network-manager python3 bluez arp-scan mdk4 ethtool wpasupplicant"
            $USE_SUDO apt-get update -y
            $USE_SUDO apt-get install -y $PKGS ;;
        dnf)
            PKGS="iproute iputils dsniff iw aircrack-ng NetworkManager python3 bluez arp-scan mdk4 ethtool wpa_supplicant"
            $USE_SUDO dnf install -y $PKGS ;;
        zypper)
            PKGS="iproute2 iputils dsniff iw aircrack-ng NetworkManager python3 bluez arp-scan mdk4 ethtool wpa_supplicant"
            $USE_SUDO zypper --non-interactive install $PKGS ;;
        apk)
            PKGS="iproute2 iputils dsniff iw aircrack-ng networkmanager python3 bluez arp-scan mdk4 ethtool wpa_supplicant"
            $USE_SUDO apk add --no-cache $PKGS ;;
        *)
            echo "error: no supported package manager found (pacman/apt/dnf/zypper/apk)"
            echo "install the tools manually, then re-run with --no-deps"
            exit 1 ;;
    esac
}

if [ "$(id -u)" -ne 0 ] && [ "$DO_DEPS" != "0" ]; then
    USE_SUDO="sudo"
fi

if [ "$DO_DEPS" != "0" ]; then
    echo "== installing dependencies =="
    for p in pacman apt dnf zypper apk; do
        if command -v "$p" >/dev/null 2>&1; then PM="$p"; break; fi
    done
    install_deps
fi

# ---- copy the tools ----
echo "== installing tools to $DEST =="
# /usr/local/bin needs root regardless of --no-deps; sudo ONLY the file copy.
COPY_SUDO=""
if [ "$(id -u)" -ne 0 ] && [ "$DEST" = "/usr/local/bin" ]; then
    COPY_SUDO="sudo"
fi
$COPY_SUDO mkdir -p "$DEST"
$COPY_SUDO install -m755 xcut xcut-ble xcut-ble-raw "$DEST"/
# xcut sources xcut-lib/*.sh from a dir next to itself (or the system share)
LIBDIR="$DEST/xcut-lib"
[ "$DEST" = "/usr/local/bin" ] && LIBDIR="/usr/local/share/xcut/lib"
$COPY_SUDO mkdir -p "$LIBDIR"
$COPY_SUDO install -m644 xcut-lib/vendor.sh xcut-lib/wifi.sh xcut-lib/deauth.sh "$LIBDIR"/
[ "$DEST" != "/usr/local/bin" ] && \
    echo "  PATH: add '$DEST' if not already there (echo 'export PATH=\"\$PATH:$DEST\"' >> ~/.bashrc)"

# ---- verify ----
echo "== checking =="
ok=1
for t in ip arpspoof aireplay-ng iw nmcli python3; do
    if command -v "$t" >/dev/null 2>&1; then
        echo "  ok: $t"
    else
        echo "  MISSING: $t"
        ok=0
    fi
done
for t in arp-scan mdk4 ethtool wpa_cli bluetoothctl; do
    command -v "$t" >/dev/null 2>&1 && echo "  ok (optional): $t"
done
[ "$ok" = "1" ] || echo "  some required tools are missing - install them or fix your PATH"
echo "done. run:  xcut scan"
