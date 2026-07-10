#!/bin/sh
# Installer for SNI-Spoofing on OpenWRT.
#
# Installs the Python runtime, copies the project to /opt/sni-spoof and registers
# a procd service.  Requires a few MB of free space for Python — on small routers
# use extroot / a USB stick (see README).  Run as root on the router.
set -e

PROG_DIR=/opt/sni-spoof
SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "[*] Updating opkg and installing Python runtime..."
opkg update
# python3 pulls the stdlib; asyncio and ctypes are separate feeds. The raw-socket
# engine needs no third-party Python packages at all.
opkg install python3 python3-asyncio python3-ctypes || {
    echo "[!] Package install failed. Ensure you have free space (try extroot) and network access."
    exit 1
}

echo "[*] Installing project to $PROG_DIR ..."
mkdir -p "$PROG_DIR"
cp -a "$SRC_DIR"/main.py "$SRC_DIR"/fake_tcp.py "$SRC_DIR"/injecter.py \
      "$SRC_DIR"/monitor_connection.py "$SRC_DIR"/config.json \
      "$SRC_DIR"/utils "$SRC_DIR"/engines "$PROG_DIR"/

# Headless box: skip the interactive interface menu.
sed -i 's/"AUTO_SELECT_INTERFACE": false/"AUTO_SELECT_INTERFACE": true/' "$PROG_DIR/config.json" 2>/dev/null || true

echo "[*] Installing procd service..."
cp "$SRC_DIR/openwrt/sni-spoof.init" /etc/init.d/sni-spoof
chmod +x /etc/init.d/sni-spoof

echo
echo "[+] Done. Edit $PROG_DIR/config.json (CONNECT_IP / FAKE_SNI / LISTEN_PORT), then:"
echo "      /etc/init.d/sni-spoof enable"
echo "      /etc/init.d/sni-spoof start"
echo "      logread -f    # to watch output"
echo
echo "    Point your clients / firewall at this router's LISTEN_PORT (default 40443)."
