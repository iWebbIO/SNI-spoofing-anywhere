"""Client half of net_e2e_fw4.py — meant to be run INSIDE the `sni_cli` netns
via `ip netns exec`. Drives one real desync connection to SRV_IP and prints
CLIENT_RESULT=OK / CLIENT_RESULT=FAIL:<reason>.
"""
import asyncio
import os
import socket
import sys
import threading

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from engines.raw_socket_engine import RawSocketEngine
from fake_tcp import FakeInjectiveConnection, FakeTcpInjector
from utils.packet_templates import ClientHelloMaker

LOCAL = os.environ["CLI_IP"]
DST = os.environ["SRV_IP"]
PORT = 443
FAKE_SNI = b"totally-allowed-sni.example.com"
REAL = b"REALDATA-hello-real-server"


async def drive():
    conns = {}
    loop = asyncio.get_running_loop()
    engine = RawSocketEngine(LOCAL, DST, PORT)
    injector = FakeTcpInjector(engine, conns)
    threading.Thread(target=injector.run, daemon=True).start()
    await asyncio.sleep(0.6)

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
        await asyncio.wait_for(conn.t2a_event.wait(), 4)
    finally:
        conn.monitor = False
        conns.pop(conn.id, None)

    if conn.t2a_msg != "fake_data_ack_recv":
        print("CLIENT_RESULT=FAIL:" + str(conn.t2a_msg))
        engine.close()
        sys.exit(2)

    await loop.sock_sendall(out, REAL)
    await asyncio.sleep(0.4)
    out.close(); peer_a.close(); peer_b.close()
    engine.close()
    print("CLIENT_RESULT=OK")


if __name__ == "__main__":
    asyncio.run(drive())
