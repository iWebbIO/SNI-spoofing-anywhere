"""
Small cross-platform helpers: privilege checks, (best-effort) elevation,
network-interface enumeration and interface-name lookup.

Everything here degrades gracefully: if a rich source (psutil, PowerShell) is not
available it falls back to stdlib-only paths so the tool still runs on a minimal
target such as OpenWRT.
"""

import os
import socket
import struct
import sys

# ---------------------------------------------------------------------------
# Privileges
# ---------------------------------------------------------------------------

def is_admin() -> bool:
    """True if we can open raw sockets / packet capture (root, or Windows admin)."""
    if os.name == "nt":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def elevate_or_exit():
    """Re-launch elevated. On Windows via UAC; on POSIX via sudo if available."""
    if os.name == "nt":
        try:
            import ctypes
            script = sys.argv[0]
            params = f'"{script}" ' + " ".join(f'"{a}"' for a in sys.argv[1:])
            ret = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, params, None, 1
            )
            sys.exit(0 if int(ret) > 32 else 1)
        except Exception as e:
            print(f"Failed to elevate privileges: {e}")
            sys.exit(1)
    else:
        # Try a transparent sudo re-exec; fall back to a clear instruction.
        from shutil import which
        if which("sudo") and os.environ.get("SNI_NO_SUDO") != "1":
            print("[Info] Re-launching with sudo (set SNI_NO_SUDO=1 to disable)...")
            try:
                os.execvp("sudo", ["sudo", "-E", sys.executable] + sys.argv)
            except Exception as e:
                print(f"[Warning] sudo re-exec failed: {e}")
        print("Please run this program as root (e.g. `sudo python3 main.py`).")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Interface enumeration
# ---------------------------------------------------------------------------

_SIOCGIFADDR = 0x8915  # Linux


def _linux_ifaddr(sock, ifname: str) -> str:
    """Return the primary IPv4 of ``ifname`` via ioctl, or '' (Linux only)."""
    import fcntl
    try:
        packed = struct.pack("256s", ifname.encode()[:15])
        res = fcntl.ioctl(sock.fileno(), _SIOCGIFADDR, packed)
        return socket.inet_ntoa(res[20:24])
    except OSError:
        return ""


def list_interfaces() -> "list[dict]":
    """Return [{'name': str, 'ip': str}, ...] for IPv4-capable interfaces.

    Tries, in order: psutil (any OS), Windows PowerShell, Linux ioctl, and finally
    a single default-route entry so there is always at least one usable choice.
    """
    # 1) psutil — best and fully cross-platform, if installed.
    try:
        import psutil  # optional
        out = []
        for name, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if a.family == socket.AF_INET and a.address:
                    out.append({"name": name, "ip": a.address})
        if out:
            return out
    except Exception:
        pass

    # 2) Windows without psutil — PowerShell.
    if os.name == "nt":
        try:
            import json
            import subprocess
            cmd = ["powershell", "-NoProfile", "-Command",
                   "Get-NetIPAddress -AddressFamily IPv4 | "
                   "Select-Object IPAddress, InterfaceAlias | ConvertTo-Json"]
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True, check=True)
            data = json.loads(res.stdout) if res.stdout.strip() else []
            if isinstance(data, dict):
                data = [data]
            return [{"name": d.get("InterfaceAlias", "?"), "ip": d["IPAddress"]}
                    for d in data if d.get("IPAddress")]
        except Exception:
            pass

    # 3) Linux without psutil — enumerate via ioctl.
    if hasattr(socket, "if_nameindex"):
        out = []
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            for _idx, name in socket.if_nameindex():
                ip = _linux_ifaddr(s, name)
                if ip:
                    out.append({"name": name, "ip": ip})
        finally:
            s.close()
        if out:
            return out

    # 4) Last resort — whatever the default route gives us.
    ip = default_route_ip()
    return [{"name": "default", "ip": ip}] if ip else []


def ifname_for_ip(ip: str) -> str:
    """Return the interface name that owns ``ip`` (or '' if unknown).

    Used by the Linux raw-socket engine to bind its capture to one interface.
    If empty, the caller captures on all interfaces (still correct, just broader).
    """
    for iface in list_interfaces():
        if iface.get("ip") == ip:
            return iface.get("name", "")
    return ""


def default_route_ip(addr: str = "8.8.8.8") -> str:
    """The local IPv4 the kernel would use to reach ``addr`` (no packets sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((addr, 53))
        return s.getsockname()[0]
    except OSError:
        return ""
    finally:
        s.close()
