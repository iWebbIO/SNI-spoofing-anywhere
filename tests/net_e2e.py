"""Self-contained END-TO-END desync test for the Linux raw-socket engine.

Creates a veth pair + network namespace, runs a plain TCP "server" in the ns,
then drives the REAL FakeTcpInjector + RawSocketEngine exactly as main.py would
for one connection and asserts:

  1. the state machine reaches ``fake_data_ack_recv`` (the wrong-seq fake
     ClientHello was injected and acknowledged by the peer), and
  2. the server received ONLY the real payload, never the fake SNI — i.e. the
     peer discarded the fake packet as old data, which is the whole point of the
     DPI-desync: an on-path inspector sees the fake "allowed" SNI, the real
     server does not.

Run as root on Linux:  sudo python3 tests/net_e2e.py
(Needs `ip`, root, and CAP_NET_RAW. Uses a veth pair so it needs no internet.)
"""
import asyncio
import os
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from engines.raw_socket_engine import RawSocketEngine
from fake_tcp import FakeInjectiveConnection, FakeTcpInjector
from utils.packet_templates import ClientHelloMaker

LOCAL = "10.211.0.1"
DST = "10.211.0.2"
PORT = 443
NS = "sni_e2e"
VETH = "vethsni0"
VPEER = "vethsni1"
FAKE_SNI = b"totally-allowed-sni.example.com"
REAL = b"REALDATA-hello-real-server"


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=True, **kw)


def setup():
    teardown()
    sh(f"ip link add {VETH} type veth peer name {VPEER}", check=True)
    sh(f"ip addr add {LOCAL}/24 dev {VETH}", check=True)
    sh(f"ip link set {VETH} up", check=True)
    sh(f"ip netns add {NS}", check=True)
    sh(f"ip link set {VPEER} netns {NS}", check=True)
    sh(f"ip -n {NS} addr add {DST}/24 dev {VPEER}", check=True)
    sh(f"ip -n {NS} link set {VPEER} up", check=True)
    sh(f"ip -n {NS} link set lo up", check=True)


def teardown():
    sh(f"ip netns del {NS} 2>/dev/null")
    sh(f"ip link del {VETH} 2>/dev/null")


SERVER_SRC = (
    "import socket\n"
    "s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
    f"s.bind(('{DST}',{PORT}));s.listen()\n"
    "c,a=s.accept();c.settimeout(3);d=b''\n"
    "try:\n"
    " while True:\n"
    "  x=c.recv(4096)\n"
    "  if not x: break\n"
    "  d+=x\n"
    "except Exception: pass\n"
    "open('/tmp/sni_e2e_recv.bin','wb').write(d)\n"
)


async def drive():
    conns = {}
    loop = asyncio.get_running_loop()
    engine = RawSocketEngine(LOCAL, DST, PORT)
    injector = FakeTcpInjector(engine, conns)
    threading.Thread(target=injector.run, daemon=True).start()
    await asyncio.sleep(0.6)  # let capture warm up

    fake = ClientHelloMaker.get_client_hello_with(
        os.urandom(32), os.urandom(32), FAKE_SNI, os.urandom(32))
    peer_a, peer_b = socket.socketpair()
    out = socket.socket()
    out.setblocking(False)
    out.bind((LOCAL, 0))
    sport = out.getsockname()[1]
    conn = FakeInjectiveConnection(out, LOCAL, DST, sport, PORT, fake, "wrong_seq", peer_a)
    conns[conn.id] = conn
    try:
        await loop.sock_connect(out, (DST, PORT))
        await asyncio.wait_for(conn.t2a_event.wait(), 3)
    finally:
        conn.monitor = False
        conns.pop(conn.id, None)

    assert conn.t2a_msg == "fake_data_ack_recv", f"state machine failed: {conn.t2a_msg!r}"
    await loop.sock_sendall(out, REAL)
    await asyncio.sleep(0.4)
    out.close(); peer_a.close(); peer_b.close()
    engine.close()


def main():
    if os.geteuid() != 0:
        sys.exit("must run as root")
    try:
        os.path.exists("/tmp/sni_e2e_recv.bin") and os.remove("/tmp/sni_e2e_recv.bin")
    except OSError:
        pass
    setup()
    srv = subprocess.Popen(["ip", "netns", "exec", NS, "python3", "-c", SERVER_SRC])
    time.sleep(1.0)
    try:
        asyncio.run(drive())
        time.sleep(0.3)
        received = b""
        if os.path.exists("/tmp/sni_e2e_recv.bin"):
            received = open("/tmp/sni_e2e_recv.bin", "rb").read()
        print(f"[i] state machine: fake_data_ack_recv  ✓")
        print(f"[i] server received {len(received)} bytes: {received!r}")
        assert REAL in received, "server did not get the real payload"
        assert FAKE_SNI not in received, "server WRONGLY received the fake SNI!"
        print("[i] server got REAL data and NOT the fake SNI  ✓")
        print("\nEND-TO-END DESYNC TEST PASSED")
    finally:
        srv.terminate()
        teardown()


if __name__ == "__main__":
    main()
