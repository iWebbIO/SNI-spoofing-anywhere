import sys
from abc import ABC, abstractmethod


class TcpInjector(ABC):
    """Drives a packet engine: receive relevant packets, feed them to ``inject``.

    ``engine`` is any object satisfying :class:`engines.base.PacketEngine`
    (WinDivert on Windows, raw sockets on Linux/OpenWRT, scapy elsewhere). It is
    stored as ``self.w`` so the connection state machine can call ``self.w.send``
    exactly as it did with the original WinDivert handle.
    """

    def __init__(self, engine):
        self.w = engine

    @abstractmethod
    def inject(self, packet):
        sys.exit("Not implemented")

    def run(self):
        with self.w:
            while True:
                try:
                    packet = self.w.recv(65575)
                except OSError:
                    # Engine/capture socket was closed (shutdown or interface
                    # rebind). Stop this injector cleanly.
                    break
                if packet is None:
                    continue
                self.inject(packet)
