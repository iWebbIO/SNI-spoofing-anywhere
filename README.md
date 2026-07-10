# SNI-Spoofing (cross-platform)

Bypass DPI (Deep Packet Inspection) with IP/TCP header manipulation.

This is a **cross-platform rewrite** of the original Windows-only
[iWebbIO/SNI-Spoofing](https://github.com/iWebbIO/SNI-Spoofing). The original
depended on **WinDivert** and ran only on Windows. This version keeps the exact
same desync technique but abstracts packet capture/injection behind a small
engine interface, so it runs on:

| Platform            | Engine                     | Extra dependencies |
|---------------------|----------------------------|--------------------|
| **Windows**         | WinDivert (`pydivert`)     | `pip install pydivert` |
| **Linux / OpenWRT** | raw `AF_PACKET` + raw send | **none** (pure stdlib) |
| **macOS / *BSD**    | scapy (fallback)           | `pip install scapy` (needs libpcap) |

The backend is auto-detected; nothing to configure.

---

## How it works

It is a local TCP proxy that performs a **fake-ClientHello TCP desync** (the
"wrong sequence number" method):

1. You point a client at the local listener (`LISTEN_PORT`, default `40443`).
2. For each connection the tool opens a real TCP connection to `CONNECT_IP:443`.
3. Right after the TCP handshake, it injects **one fake TLS ClientHello** carrying
   an innocuous `FAKE_SNI` (e.g. `chatgpt.com`) but with a **deliberately wrong
   TCP sequence number** (just *before* the real data).
4. The on-path DPI box sees the "allowed" SNI and lets the flow through. The
   destination server, however, treats the wrong-seq segment as already-seen
   data and **discards it** — so it never reaches the application.
5. The real client data (with the real SNI) then flows normally over the now
   desynchronised path.

The packet-fiddling logic (`fake_tcp.py`) is identical across platforms; only the
capture/injection **engine** differs.

```
main.py ── asyncio proxy ──┐
                           ├─ FakeTcpInjector (state machine, platform-agnostic)
engines/ ── PacketEngine ──┘        │
   ├─ windivert_engine (Windows)    │ uses a uniform packet facade:
   ├─ raw_socket_engine (Linux)     │   pkt.ip / pkt.ipv4 / pkt.tcp
   └─ scapy_engine (macOS/BSD)      │   pkt.is_inbound / is_outbound
utils/rawpacket.py ── pure-Python IPv4/TCP parse+build (pydivert-compatible)
```

---

## Configuration — `config.json`

```json
{
  "LISTEN_HOST": "0.0.0.0",
  "LISTEN_PORT": 40443,
  "CONNECT_IP": "188.114.99.0",
  "CONNECT_PORT": 443,
  "FAKE_SNI": "chatgpt.com",
  "BACKEND": "auto",
  "AUTO_SELECT_INTERFACE": false
}
```

- `CONNECT_IP` — the real IP you want to reach (e.g. a Cloudflare edge IP).
- `FAKE_SNI` — the decoy hostname shown to the DPI.
- `BACKEND` — `auto` (recommended), or force `windivert` / `raw` / `scapy`.
- `AUTO_SELECT_INTERFACE` — `true` to skip the interactive interface menu (also
  auto-skipped whenever stdin is not a TTY, e.g. under systemd/procd).

It is created with defaults on first run.

---

## Requirements

- **Python 3.8+** and **root/administrator** privileges (raw packets need it).
- Linux/OpenWRT need **no third-party Python packages**.
- Windows: `pip install -r requirements.txt` (installs `pydivert`).

---

## Running

### Linux (desktop/server)

```bash
sudo python3 main.py
```

(The program will try to re-exec itself with `sudo` if not run as root; set
`SNI_NO_SUDO=1` to disable that.)

### Windows

```powershell
pip install -r requirements.txt
python main.py     # will prompt for UAC elevation
```

### macOS / *BSD

```bash
pip install scapy         # needs libpcap (brew install libpcap on macOS)
sudo python3 main.py
```

Then send traffic through the listener, e.g.:

```bash
curl --resolve real-host:443:127.0.0.1 https://real-host/ --connect-to ::127.0.0.1:40443
```

(or configure your client/router to use `THIS_HOST:40443`).

---

## OpenWRT

OpenWRT is fully supported by the pure-stdlib Linux engine. There are no
third-party Python dependencies — only the Python runtime itself.

> **Space note:** Python needs a few MB of free space. On small routers use
> [extroot](https://openwrt.org/docs/guide-user/additional-software/extroot_configuration)
> or a USB stick.

```sh
# on the router (as root):
opkg update
opkg install python3 python3-asyncio python3-ctypes

# copy this repo to the router, then:
sh openwrt/install.sh          # installs to /opt/sni-spoof + a procd service

# edit /opt/sni-spoof/config.json (CONNECT_IP / FAKE_SNI / LISTEN_PORT), then:
/etc/init.d/sni-spoof enable
/etc/init.d/sni-spoof start
logread -f                     # watch output
```

Under procd there is no TTY, so the interface menu is skipped automatically and
the default-route interface is used.

### Performance / lightweightness

- The Linux engine attaches an **in-kernel BPF** filter (offsets relative to
  `SKF_NET_OFF`, so it works on Ethernet, PPPoE and tun alike). Only packets of
  the one flow being manipulated are ever copied to userspace — CPU stays near
  zero even on a busy WAN link.
- No packets are dropped or rewritten in the kernel path; the tool only *sniffs*
  and injects one extra packet, so it adds no forwarding latency.
- If a particular kernel's BPF ever misbehaves, set `SNI_NO_BPF=1` to skip the
  kernel filter and rely on the pure-Python pre-filter alone — guaranteed correct,
  just higher CPU. (Verified: the end-to-end desync passes with BPF on *and* off.)

---

## Notes & limitations

- **WSL2 is not a valid runtime** for actual operation: its virtualised NIC does
  not deliver locally-generated (outbound) packets to `AF_PACKET`, which the
  desync needs. Use native Linux / a router / a VM. (WSL2 is fine for editing and
  for the non-capture unit tests.)
- IPv4 only (matching the original). The target flow is the IPv4 connection to
  `CONNECT_IP`.
- This is a research / censorship-circumvention tool; use it responsibly and
  legally.

---

## Tests

```bash
# packet parse/build + checksums + imports (any OS):
python3 tests/test_rawpacket.py

# Linux engine logic, no root needed:
python3 tests/test_raw_engine_logic.py

# real AF_PACKET + BPF + injection on a live interface (root):
sudo python3 tests/test_linux_integration.py

# FULL end-to-end desync in a veth/netns sandbox (root, no internet needed):
sudo python3 tests/net_e2e.py
```

The end-to-end test proves the real behaviour: the peer receives the genuine
payload while the fake SNI packet is discarded as old data.

---

## Credits

Original technique and Windows implementation: **@patterniha** /
[iWebbIO/SNI-Spoofing](https://github.com/iWebbIO/SNI-Spoofing). Licensed under
GPL-3.0 (see `LICENSE`).

Support free & open internet access:
USDT (BEP20): `0x76a768B53Ca77B43086946315f0BDF21156bF424`
