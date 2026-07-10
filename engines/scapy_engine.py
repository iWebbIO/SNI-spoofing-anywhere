"""
Generic fallback packet engine backed by scapy.

Used on platforms that are neither Windows nor Linux (macOS, *BSD) — anywhere the
``AF_PACKET`` capture socket of ``raw_socket_engine`` is unavailable but scapy's
libpcap-based sniffing is.  This is what makes the tool "run on anything": if a
platform can sniff and send raw packets through scapy, it is supported.

Same contract as the other engines: sniff read-only, inject the fake packet.
Direction is inferred from the source IP (outbound == sourced from our interface),
which is sufficient for the single flow we track.

Requires: pip install scapy   (needs libpcap; on macOS install via Homebrew).
Experimental relative to the first-class Windows and Linux engines.
"""

import socket

from utils.rawpacket import IPv4TCPPacket


class ScapyEngine:
    def __init__(self, local_ip: str, dst_ip: str, dst_port: int):
        self.local_ip = local_ip
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self._listener = None
        self._sender = None
        self._conf = None
        # See RawSocketEngine: our own injected packet is captured back as an
        # outbound packet, so record and drop its echo once.
        self._injected = set()

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def open(self):
        from scapy.config import conf  # lazy: scapy is optional

        self._conf = conf
        bpf = f"tcp and host {self.dst_ip} and port {self.dst_port}"
        # L2listen gives us per-packet recv(); the BPF filter keeps it cheap.
        self._listener = conf.L2listen(filter=bpf)
        self._sender = conf.L3socket()

    def recv(self, bufsize: int = 65565):
        pkt = self._listener.recv()
        if pkt is None:
            return None
        raw = bytes(pkt.payload) if pkt.name in ("Ethernet", "cooked linux") else bytes(pkt)
        parsed = IPv4TCPPacket.parse(raw)
        if parsed is None:
            return None
        outbound = parsed.ip.src_addr == self.local_ip
        if outbound:
            sig = self._sig(parsed)
            if sig in self._injected:
                self._injected.discard(sig)
                return None
        parsed.is_outbound = outbound
        parsed.is_inbound = not outbound
        return parsed

    @staticmethod
    def _sig(pkt):
        return (pkt.tcp.src_port, pkt.tcp.dst_port, pkt.tcp.seq_num, len(pkt.tcp.payload))

    def send(self, packet, recalc: bool = True):
        if not recalc:
            return
        from scapy.layers.inet import IP

        self._injected.add(self._sig(packet))
        if len(self._injected) > 4096:
            self._injected.clear()
        self._sender.send(IP(packet.to_bytes()))

    def close(self):
        for obj in (self._listener, self._sender):
            if obj is not None:
                try:
                    obj.close()
                except Exception:
                    pass
        self._listener = None
        self._sender = None
