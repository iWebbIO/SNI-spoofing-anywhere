"""Logic tests for the Linux raw-socket engine that do NOT require root.

We bypass the actual AF_PACKET/AF_INET sockets by injecting fakes, then feed the
engine synthetic captured frames and assert its filtering, parsing, direction
detection and send() semantics. Run: python3 tests/test_raw_engine_logic.py
"""
import os, sys, struct, socket
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from utils.rawpacket import IPv4TCPPacket, _checksum
from engines.raw_socket_engine import RawSocketEngine, PACKET_OUTGOING

LOCAL = "192.168.1.50"
DST = "188.114.99.0"


def make_pkt(src, dst, sp, dp, flags, payload=b""):
    src_p = socket.inet_aton(src); dst_p = socket.inet_aton(dst)
    tcp_wo = struct.pack("!HHIIHHHH", sp, dp, 100, 0, (5 << 12) | flags, 65535, 0, 0)
    seg = tcp_wo + payload
    pseudo = src_p + dst_p + struct.pack("!BBH", 0, 6, len(seg))
    tcp = tcp_wo[:16] + struct.pack("!H", _checksum(pseudo + seg)) + tcp_wo[18:] + payload
    total = 20 + len(tcp)
    ip_wo = struct.pack("!BBHHHBBH", 0x45, 0, total, 1, 0x4000, 64, 6, 0) + src_p + dst_p
    ip = ip_wo[:10] + struct.pack("!H", _checksum(ip_wo)) + ip_wo[12:]
    return ip + tcp


class FakeRecvSock:
    def __init__(self, queue):
        self.queue = list(queue)
    def recvfrom(self, n):
        return self.queue.pop(0)


class FakeSendSock:
    def __init__(self):
        self.sent = []
    def sendto(self, data, addr):
        self.sent.append((data, addr))


def make_engine():
    eng = RawSocketEngine(LOCAL, DST, 443)  # __init__ does no socket I/O
    return eng


def test_prefilter_drops_unrelated():
    eng = make_engine()
    # A packet to an unrelated host must be dropped by the cheap prefilter.
    unrelated = make_pkt(LOCAL, "9.9.9.9", 5000, 443, 0x02)
    eng.recv_sock = FakeRecvSock([(unrelated, ("eth0", 0, PACKET_OUTGOING, 0, b""))])
    assert eng.recv() is None
    print("test_prefilter_drops_unrelated OK")


def test_outbound_syn():
    eng = make_engine()
    raw = make_pkt(LOCAL, DST, 55000, 443, 0x02)  # SYN out
    eng.recv_sock = FakeRecvSock([(raw, ("eth0", 0, PACKET_OUTGOING, 0, b""))])
    p = eng.recv()
    assert p is not None and p.is_outbound and not p.is_inbound
    assert p.tcp.syn and not p.tcp.ack and p.tcp.dst_port == 443
    assert p.ip.src_addr == LOCAL and p.ip.dst_addr == DST
    print("test_outbound_syn OK")


def test_inbound_synack():
    eng = make_engine()
    raw = make_pkt(DST, LOCAL, 443, 55000, 0x12)  # SYN-ACK in
    PACKET_HOST = 0
    eng.recv_sock = FakeRecvSock([(raw, ("eth0", 0, PACKET_HOST, 0, b""))])
    p = eng.recv()
    assert p is not None and p.is_inbound and not p.is_outbound
    assert p.tcp.syn and p.tcp.ack
    print("test_inbound_synack OK")


def test_send_semantics():
    eng = make_engine()
    eng.send_sock = FakeSendSock()
    raw = make_pkt(LOCAL, DST, 55000, 443, 0x10)
    p = IPv4TCPPacket.parse(raw)
    eng.send(p, False)               # real passthrough -> must NOT transmit
    assert eng.send_sock.sent == []
    eng.send(p, True)                # inject -> must transmit exactly the bytes
    assert len(eng.send_sock.sent) == 1
    data, addr = eng.send_sock.sent[0]
    assert data == p.to_bytes() and addr == (DST, 0)
    print("test_send_semantics OK")


if __name__ == "__main__":
    test_prefilter_drops_unrelated()
    test_outbound_syn()
    test_inbound_synack()
    test_send_semantics()
    print("\nRAW ENGINE LOGIC TESTS PASSED")
