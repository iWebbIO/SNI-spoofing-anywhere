"""
Packet-engine abstraction.

A *packet engine* is the platform-specific mechanism that lets us observe the
raw packets of one outbound TCP flow and inject a crafted "fake" packet into it.
Everything above this layer (the connection state machine in ``fake_tcp.py`` and
the asyncio proxy in ``main.py``) is platform independent and talks only to this
interface.

The interface is deliberately shaped like the small slice of ``pydivert.WinDivert``
that the original Windows-only code relied on, so the state machine did not have
to change:

    engine.recv(bufsize)   -> a packet object, or None to skip this read
    engine.send(packet, recalc_checksum)
    engine.close()
    with engine: ...

``send(packet, recalc=False)`` means "let this real, observed packet continue on
its way unchanged".  On WinDivert that re-injects the packet that was removed from
the stack; on the sniff-based POSIX engines the packet was never removed from the
wire, so it is a no-op.

``send(packet, recalc=True)`` means "emit this (mutated) packet" — i.e. the fake
ClientHello.  Every engine must actually put it on the wire with fresh checksums.
"""

from abc import ABC, abstractmethod


class PacketEngine(ABC):
    @abstractmethod
    def recv(self, bufsize: int = 65565):
        """Return the next relevant packet, or None if this read should be ignored."""

    @abstractmethod
    def send(self, packet, recalc: bool = True):
        """Emit ``packet``. ``recalc`` True => recompute checksums and inject.
        ``recalc`` False => allow the (already in-flight) real packet to proceed."""

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False
