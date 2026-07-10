"""
Windows packet engine, backed by WinDivert (via the ``pydivert`` package).

WinDivert already exposes exactly the ``recv`` / ``send`` / context-manager
interface we need, and its ``Packet`` object already has the ``.ip`` / ``.ipv4``
/ ``.tcp`` facade the state machine expects.  So the "engine" here is really just
a WinDivert handle opened with the right capture filter — we only add the small
factory that builds that filter from high-level flow parameters.

Requires: pip install pydivert   (and the WinDivert.dll / WinDivert64.sys binaries,
which pydivert bundles).  Windows only.
"""


def build_filter(local_ip: str, dst_ip: str, dst_port: int) -> str:
    """The WinDivert capture filter for the single outbound flow we manipulate.

    Matches the SYN / handshake / empty control packets in both directions between
    our interface IP and CONNECT_IP:CONNECT_PORT — enough to observe sequence
    numbers and to inject the fake ClientHello, without capturing bulk data.
    """
    return (
        "tcp and "
        f"((ip.SrcAddr == {local_ip} and ip.DstAddr == {dst_ip} and tcp.DstPort == {dst_port}) or "
        f"(ip.SrcAddr == {dst_ip} and ip.DstAddr == {local_ip} and tcp.SrcPort == {dst_port})) and "
        "(tcp.Syn or tcp.Rst or tcp.Fin or tcp.PayloadLength == 0)"
    )


def create(local_ip: str, dst_ip: str, dst_port: int):
    """Return an opened WinDivert handle usable as a PacketEngine."""
    from pydivert import WinDivert  # imported lazily: only present on Windows

    return WinDivert(build_filter(local_ip, dst_ip, dst_port))
