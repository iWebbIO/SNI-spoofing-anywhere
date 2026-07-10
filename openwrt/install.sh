#!/bin/sh
# Installer for SNI-Spoofing on OpenWrt (with optional LuCI UI).
#
# Installs the Python runtime, copies the project to /opt/sni-spoof, registers a
# procd service driven by UCI (/etc/config/sni-spoof), and installs a minimal
# LuCI page under Services -> SNI Spoofing.
#
# The raw-socket engine needs NO third-party Python packages. Run as root.
set -e

PROG_DIR=/opt/sni-spoof
SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# ---- 1. Python runtime (apk on new OpenWrt, opkg on older) -------------------
PKGS="python3-light python3-asyncio python3-ctypes python3-logging"
echo "[*] Installing Python runtime: $PKGS"
if command -v apk >/dev/null 2>&1; then
	apk update
	apk add $PKGS
elif command -v opkg >/dev/null 2>&1; then
	opkg update
	# older feeds ship a combined python3-logging inside python3-light; ignore misses
	opkg install python3-light python3-asyncio python3-ctypes || \
		opkg install python3 python3-asyncio python3-ctypes
else
	echo "[!] Neither apk nor opkg found — install python3 manually." >&2
	exit 1
fi

# ---- 2. Program files --------------------------------------------------------
echo "[*] Installing project to $PROG_DIR"
mkdir -p "$PROG_DIR"
cp -a "$SRC_DIR"/main.py "$SRC_DIR"/fake_tcp.py "$SRC_DIR"/injecter.py \
      "$SRC_DIR"/monitor_connection.py "$SRC_DIR"/utils "$SRC_DIR"/engines "$PROG_DIR"/

# ---- 3. UCI config (do not clobber an existing one) --------------------------
if [ ! -f /etc/config/sni-spoof ]; then
	echo "[*] Installing default UCI config to /etc/config/sni-spoof"
	cp "$SRC_DIR/openwrt/config/sni-spoof" /etc/config/sni-spoof
else
	echo "[=] Keeping existing /etc/config/sni-spoof"
fi

# ---- 4. procd service --------------------------------------------------------
echo "[*] Installing procd service"
cp "$SRC_DIR/openwrt/sni-spoof.init" /etc/init.d/sni-spoof
chmod +x /etc/init.d/sni-spoof
/etc/init.d/sni-spoof enable   # autostart on boot (the UCI 'enabled' flag gates running)

# ---- 5. LuCI UI (optional but installed if LuCI is present) ------------------
if [ -d /www/luci-static/resources ]; then
	echo "[*] Installing LuCI app (Services -> SNI Spoofing)"
	LUCI_SRC="$SRC_DIR/openwrt/luci-app-sni-spoof"
	cp -a "$LUCI_SRC/htdocs/." /www/
	cp -a "$LUCI_SRC/root/." /
	# refresh ACLs + LuCI menu cache
	rm -f /tmp/luci-indexcache* 2>/dev/null || true
	/etc/init.d/rpcd reload 2>/dev/null || /etc/init.d/rpcd restart 2>/dev/null || true
else
	echo "[=] LuCI not detected — skipping web UI (CLI + UCI still work)."
fi

echo
echo "[+] Done."
echo "    Configure:  LuCI -> Services -> SNI Spoofing   (or edit /etc/config/sni-spoof)"
echo "    Then:       /etc/init.d/sni-spoof start   (Save & Apply in LuCI does this for you)"
echo "    Watch:      logread -e sni-spoof"
echo
echo "    Passwall2:  set a node's address/port to the listen address/port above,"
echo "                and add CONNECT_IP to Passwall2's direct/bypass list."
