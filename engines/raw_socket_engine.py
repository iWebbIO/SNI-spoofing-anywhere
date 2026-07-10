"""
Linux (and OpenWRT) packet engine using only the Python standard library.

Design
------
The desync technique never needs to *drop* or *rewrite* a real packet — it lets
every real packet flow normally and merely injects one extra "fake" ClientHello
after the TCP handshake.  So instead of pulling the flow into userspace with
NFQUEUE (which needs libnetfilter_queue + a python binding not packaged on
OpenWRT), we:

  * SNIFF the flow read-only with an ``AF_PACKET`` / ``SOCK_DGRAM`` socket bound
    to the outgoing interface.  The kernel keeps delivering the real packets
    normally; we only observe them to learn the sequence numbers and the moment
    the handshake completes.  Packet direction comes for free from the capture
    metadata (``PACKET_OUTGOING`` vs. incoming).

  * INJECT the fake packet with an ``AF_INET`` / ``SOCK_RAW`` socket with
    ``IP_HDRINCL`` — we hand the kernel a fully-formed IP packet and it routes it.

Both socket types are in stdlib ``socket`` and work on musl / minimal Python, so
no external dependency is required — important for OpenWRT.

``send(pkt, recalc=False)`` is a no-op here: the real packet was never removed
from the wire.  ``send(pkt, recalc=True)`` serialises the mutated packet (fresh
checksums) and raw-sends it.

Root privileges are required (raw sockets).
"""

import os
import socket
import struct

from utils.rawpacket import IPv4TCPPacket
from utils.platform_utils import ifname_for_ip

# We MUST register the capture socket with ETH_P_ALL, not ETH_P_IP. The kernel's
# transmit tap (dev_queue_xmit_nit) only delivers *outgoing* packets to sockets on
# the ptype_all list — i.e. those bound to ETH_P_ALL. A socket bound to a specific
# ethertype (ETH_P_IP) receives inbound packets only, so we would never observe our
# own outbound SYN/ACK and the desync could never fire. (Verified empirically.)
ETH_P_ALL = 0x0003
PACKET_OUTGOING = 4  # linux/if_packet.h

SO_ATTACH_FILTER = getattr(socket, "SO_ATTACH_FILTER", 26)
# SKF_NET_OFF: base offset for loads relative to the *network* (IP) header, so the
# filter is independent of the L2 header length (Ethernet vs PPPoE vs tun). Linux 3.7+.
SKF_NET_OFF = -0x100000


def _build_bpf(dst_ip: str) -> bytes:
    """A classic-BPF program: keep only TCP packets whose src or dst IP == dst_ip.

    Offsets are relative to SKF_NET_OFF so they land inside the IP header on any
    link type. Returns (packed sock_fprog, backing buffer) — the caller must keep
    the buffer alive across the setsockopt() call (the kernel copies it there).
    """
    dst = struct.unpack("!I", socket.inet_aton(dst_ip))[0]

    def off(o):
        return (SKF_NET_OFF + o) & 0xFFFFFFFF

    # sock_filter: (u16 code, u8 jt, u8 jf, u32 k)
    # BPF opcodes: LD|B|ABS=0x30  LD|W|ABS=0x20  JMP|JEQ|K=0x15  RET|K=0x06
    prog = [
        (0x30, 0, 0, off(9)),    # 0: A = ip.proto (byte at IP+9)
        (0x15, 0, 5, 6),         # 1: if A != TCP(6) -> drop (instr 7)
        (0x20, 0, 0, off(12)),   # 2: A = ip.src
        (0x15, 2, 0, dst),       # 3: if A == dst_ip -> accept (instr 6)
        (0x20, 0, 0, off(16)),   # 4: A = ip.dst
        (0x15, 0, 1, dst),       # 5: if A != dst_ip -> drop (instr 7)
        (0x06, 0, 0, 0x40000),   # 6: accept (return up to 256KiB)
        (0x06, 0, 0, 0),         # 7: drop
    ]
    filters = b"".join(struct.pack("HBBI", *f) for f in prog)
    import ctypes
    buf = ctypes.create_string_buffer(filters)
    # struct sock_fprog { u16 len; struct sock_filter *filter; } (native alignment)
    return struct.pack("HP", len(prog), ctypes.addressof(buf)), buf


class RawSocketEngine:
    def __init__(self, local_ip: str, dst_ip: str, dst_port: int):
        self.local_ip = local_ip
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self._dst_ip_packed = socket.inet_aton(dst_ip)
        self._local_ip_packed = socket.inet_aton(local_ip)
        self.ifname = ifname_for_ip(local_ip)
        self.recv_sock = None
        self.send_sock = None
        # Signatures of packets WE injected. Unlike WinDivert, a raw-injected
        # packet is also delivered back to our own AF_PACKET capture as an
        # outbound packet (the kernel taps egress). Without this the state
        # machine would see the fake ClientHello as an "unexpected outbound
        # packet". We record each injected packet and drop its echo once.
        self._injected = set()

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def open(self):
        # Capture socket: cooked (L3) frames, ETH_P_ALL so we see BOTH directions
        # (see the ETH_P_ALL note above). SOCK_DGRAM strips the link-layer header,
        # so recv() data starts at the IP header regardless of Ethernet/PPPoE/tun.
        self.recv_sock = socket.socket(
            socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_ALL)
        )
        # Attach an in-kernel BPF so only this flow's packets are copied to
        # userspace — keeps CPU near zero even on a busy router. Best-effort:
        # if it fails, the Python pre-filter in recv() still keeps us correct.
        #
        # Escape hatch: if some kernel's BPF wrongly dropped our packets, the
        # in-kernel filter would starve the (correct) Python pre-filter, breaking
        # the tool. Set SNI_NO_BPF=1 to skip the kernel filter entirely and rely
        # on the Python pre-filter alone (higher CPU, but guaranteed correct).
        if os.environ.get("SNI_NO_BPF") != "1":
            try:
                fprog, _buf = _build_bpf(self.dst_ip)
                self.recv_sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)
            except Exception:
                pass
        # NB: we intentionally do NOT bind() to a single interface. The BPF
        # already restricts capture to this flow (by CONNECT_IP), so binding
        # buys nothing, and binding to an interface by name proved unreliable on
        # some virtualised NICs (it silently captured zero packets). Capturing on
        # all interfaces is correct because the flow only ever egresses one.
        # Injection socket: we supply the full IP header ourselves.
        self.send_sock = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW
        )
        try:
            self.send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except OSError:
            pass  # IPPROTO_RAW already implies HDRINCL on Linux

    def recv(self, bufsize: int = 65565):
        sock = self.recv_sock
        if sock is None:  # closed underneath us (rebind/shutdown) — stop the loop
            raise OSError("capture socket closed")
        data, addr = sock.recvfrom(bufsize)
        # addr == (ifname, proto, pkttype, hatype, hwaddr)
        pkttype = addr[2]

        # Cheap pre-filter before the full parse: must involve CONNECT_IP so we
        # stay light even on a busy router carrying unrelated traffic.
        if len(data) < 20:
            return None
        if data[12:16] != self._dst_ip_packed and data[16:20] != self._dst_ip_packed:
            return None
        if data[9] != 6:  # IP protocol == TCP
            return None

        pkt = IPv4TCPPacket.parse(data)
        if pkt is None:
            return None

        outbound = (pkttype == PACKET_OUTGOING) or (pkt.ip.src_addr == self.local_ip)

        # Drop the echo of a packet we injected ourselves (see _injected above).
        if outbound:
            sig = self._sig(pkt)
            if sig in self._injected:
                self._injected.discard(sig)
                return None

        pkt.is_outbound = outbound
        pkt.is_inbound = not outbound
        return pkt

    @staticmethod
    def _sig(pkt):
        return (pkt.tcp.src_port, pkt.tcp.dst_port, pkt.tcp.seq_num, len(pkt.tcp.payload))

    def send(self, packet, recalc: bool = True):
        if not recalc:
            # Real, already-in-flight packet: nothing to do, it was never held.
            return
        # Remember this injection so we can ignore its captured echo.
        self._injected.add(self._sig(packet))
        if len(self._injected) > 4096:  # safety bound; echoes normally clear it
            self._injected.clear()
        raw = packet.to_bytes()
        self.send_sock.sendto(raw, (self.dst_ip, 0))

    def close(self):
        for sock in (self.recv_sock, self.send_sock):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        self.recv_sock = None
        self.send_sock = None
