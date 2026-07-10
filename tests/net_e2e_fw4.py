"""END-TO-END desync test THROUGH an fw4-style firewall, fully isolated.

Motivation: on OpenWrt, fw4 installs a rule that drops locally-generated
packets leaving the WAN if conntrack marks them `invalid`:

    oifname "wan" ct state invalid counter drop   # "!fw4: Prevent NAT leakage"

The wrong-seq desync injects a fake ClientHello positioned just *behind* the
connection's first real byte. This test proves conntrack treats that packet as
a valid retransmission (NOT invalid), so fw4 does not drop it — i.e. the tool
works on a router without touching the firewall.

It builds TWO throwaway network namespaces (client + server) joined by a veth
pair, and inside the CLIENT namespace it replicates fw4 exactly:
  * net.netfilter.nf_conntrack_tcp_be_liberal = 0   (strict window checking)
  * output hook: accept established/related, then DROP ct state invalid

The host's real network namespace and firewall are never touched.

PASS = desync reaches fake_data_ack_recv AND the invalid-drop counter stays 0
       AND the server got the real payload but never the fake SNI.

Run as root on Linux:  sudo python3 tests/net_e2e_fw4.py
"""
import os
import re
import subprocess
import sys
import time

CLI = "10.213.0.1"
SRV = "10.213.0.2"
PORT = 443
NSC = "sni_cli"
NSS = "sni_srv"
V0 = "vfw0"
V1 = "vfw1"
FAKE_SNI = b"totally-allowed-sni.example.com"
REAL = b"REALDATA-hello-real-server"
RECV = "/tmp/sni_fw4_recv.bin"


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=True, **kw)


def teardown():
    sh(f"ip netns del {NSC} 2>/dev/null")
    sh(f"ip netns del {NSS} 2>/dev/null")


def setup():
    teardown()
    sh(f"ip netns add {NSC}", check=True)
    sh(f"ip netns add {NSS}", check=True)
    sh(f"ip link add {V0} netns {NSC} type veth peer name {V1} netns {NSS}", check=True)
    sh(f"ip -n {NSC} addr add {CLI}/24 dev {V0}", check=True)
    sh(f"ip -n {NSC} link set {V0} up", check=True)
    sh(f"ip -n {NSC} link set lo up", check=True)
    sh(f"ip -n {NSS} addr add {SRV}/24 dev {V1}", check=True)
    sh(f"ip -n {NSS} link set {V1} up", check=True)
    sh(f"ip -n {NSS} link set lo up", check=True)
    # Replicate fw4 inside the client namespace only.
    sh(f"ip netns exec {NSC} sysctl -w net.netfilter.nf_conntrack_tcp_be_liberal=0", check=True,
       stdout=subprocess.DEVNULL)
    sh(f"ip netns exec {NSC} nft add table inet fw4test", check=True)
    sh(f"ip netns exec {NSC} nft 'add chain inet fw4test out {{ type filter hook output priority filter; policy accept; }}'",
       check=True)
    sh(f"ip netns exec {NSC} nft add rule inet fw4test out oifname {V0} ct state established,related accept", check=True)
    sh(f"ip netns exec {NSC} nft add rule inet fw4test out oifname {V0} ct state invalid counter drop", check=True)


SERVER_SRC = (
    "import socket\n"
    "s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
    f"s.bind(('{SRV}',{PORT}));s.listen()\n"
    "c,a=s.accept();c.settimeout(3);d=b''\n"
    "try:\n"
    " while True:\n"
    "  x=c.recv(4096)\n"
    "  if not x: break\n"
    "  d+=x\n"
    "except Exception: pass\n"
    f"open('{RECV}','wb').write(d)\n"
)


def invalid_drop_count():
    r = sh(f"ip netns exec {NSC} nft list chain inet fw4test out", capture_output=True, text=True)
    for line in r.stdout.splitlines():
        if "ct state invalid" in line and "drop" in line:
            m = re.search(r"packets (\d+)", line)
            return int(m.group(1)) if m else -1
    return -1


def main():
    if os.geteuid() != 0:
        sys.exit("must run as root")
    try:
        os.path.exists(RECV) and os.remove(RECV)
    except OSError:
        pass
    setup()
    srv = subprocess.Popen(["ip", "netns", "exec", NSS, "python3", "-c", SERVER_SRC])
    time.sleep(1.0)
    try:
        before = invalid_drop_count()
        env = dict(os.environ, CLI_IP=CLI, SRV_IP=SRV)
        client = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_fw4_client.py")
        cp = subprocess.run(["ip", "netns", "exec", NSC, "python3", client],
                            env=env, capture_output=True, text=True)
        after = invalid_drop_count()
        time.sleep(0.3)
        received = b""
        if os.path.exists(RECV):
            received = open(RECV, "rb").read()

        out = cp.stdout.strip()
        print(f"[i] client: {out or '(no output)'}")
        if cp.stderr.strip():
            print(f"[i] client stderr (tail): {cp.stderr.strip()[-400:]}")
        print(f"[i] fw4-style invalid-drop counter: before={before} after={after} (delta={after - before})")
        print(f"[i] server received {len(received)} bytes: {received!r}")

        ok = ("CLIENT_RESULT=OK" in out) and (after == before) \
            and (REAL in received) and (FAKE_SNI not in received)
        if ok:
            print("\nFW4 CONNTRACK TEST PASSED — fake packet is NOT invalid; desync works "
                  "behind fw4's INVALID-drop rule without touching the firewall.")
        else:
            print("\nFW4 CONNTRACK TEST FAILED — the injected packet was dropped/marked invalid "
                  "by conntrack. Layer-2 (AF_PACKET) injection would be needed on this router.")
        sys.exit(0 if ok else 1)
    finally:
        srv.terminate()
        teardown()


if __name__ == "__main__":
    main()
