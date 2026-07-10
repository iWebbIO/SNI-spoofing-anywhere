import asyncio
import os
import socket
import sys
import traceback
import threading
import json
import time

from utils.network_tools import get_default_interface_ipv4
from utils.packet_templates import ClientHelloMaker
from utils.platform_utils import (
    is_admin,
    elevate_or_exit,
    list_interfaces,
    ifname_for_ip,
    ip_for_ifname,
    default_route_ip,
)
from engines import create_engine, detect_backend
from fake_tcp import FakeInjectiveConnection, FakeTcpInjector


def get_exe_dir():
    """Returns the directory where the executable (or this script) lives."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


DEFAULT_CONFIG = {
    "LISTEN_HOST": "0.0.0.0",
    "LISTEN_PORT": 40443,
    "CONNECT_IP": "188.114.99.0",
    "CONNECT_PORT": 443,
    "FAKE_SNI": "chatgpt.com",
    # "auto" selects the engine from the OS (windivert / raw / scapy). Override
    # only for testing on an unusual platform.
    "BACKEND": "auto",
    # When true (or when stdin is not a TTY, e.g. under an init system), skip the
    # interactive interface menu and use the default-route interface. Handy for
    # headless boxes and OpenWRT.
    "AUTO_SELECT_INTERFACE": False,
    # Pin the outbound interface by name (e.g. "wan") or by IPv4. Empty or "default"
    # = pick the default-route interface automatically. This is what the OpenWRT /
    # LuCI interface selector sets; it works on every platform.
    "INTERFACE": "",
}


# Load or create the config
config_path = os.path.join(get_exe_dir(), "config.json")
if not os.path.exists(config_path):
    try:
        with open(config_path, "w") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
        print(f"[Info] Created default config.json at {config_path}")
        config = dict(DEFAULT_CONFIG)
    except Exception as e:
        print(f"[Warning] Could not write default config.json: {e}")
        config = dict(DEFAULT_CONFIG)
else:
    try:
        with open(config_path, "r") as f:
            config = json.load(f)
    except Exception as e:
        print(f"[Error] Failed to read config.json: {e}. Using defaults.")
        config = dict(DEFAULT_CONFIG)

LISTEN_HOST = config.get("LISTEN_HOST", DEFAULT_CONFIG["LISTEN_HOST"])
LISTEN_PORT = config.get("LISTEN_PORT", DEFAULT_CONFIG["LISTEN_PORT"])
FAKE_SNI = config.get("FAKE_SNI", DEFAULT_CONFIG["FAKE_SNI"]).encode()
CONNECT_IP = config.get("CONNECT_IP", DEFAULT_CONFIG["CONNECT_IP"])
CONNECT_PORT = config.get("CONNECT_PORT", DEFAULT_CONFIG["CONNECT_PORT"])
BACKEND = config.get("BACKEND", "auto")
if not BACKEND or BACKEND == "auto":
    BACKEND = detect_backend()
AUTO_SELECT_INTERFACE = bool(config.get("AUTO_SELECT_INTERFACE", False))
CONFIG_INTERFACE = str(config.get("INTERFACE", "") or "").strip()
INTERFACE_IPV4 = get_default_interface_ipv4(CONNECT_IP)


def _looks_like_ipv4(s: str) -> bool:
    try:
        socket.inet_aton(s)
        return s.count(".") == 3
    except OSError:
        return False


DATA_MODE = "tls"
BYPASS_METHOD = "wrong_seq"

##################

fake_injective_connections: "dict[tuple, FakeInjectiveConnection]" = {}


async def relay_main_loop(sock_1: socket.socket, sock_2: socket.socket, peer_task: asyncio.Task,
                          first_prefix_data: bytes):
    try:
        loop = asyncio.get_running_loop()
        while True:
            try:
                data = await loop.sock_recv(sock_1, 65575)
                if not data:
                    break
                if first_prefix_data:
                    data = first_prefix_data + data
                    first_prefix_data = b""
                await loop.sock_sendall(sock_2, data)
            except (ConnectionResetError, OSError, asyncio.CancelledError):
                break
    except Exception:
        traceback.print_exc()
        sys.exit("relay main loop error!")
    finally:
        if peer_task and not peer_task.done():
            for sock in (sock_1, sock_2):
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        sock_1.close()
        sock_2.close()


async def handle(incoming_sock: socket.socket, incoming_remote_addr):
    conn_id = f"{incoming_remote_addr[0]}:{incoming_remote_addr[1]}"
    print(f"[+] Client connected: {conn_id}")
    try:
        loop = asyncio.get_running_loop()
        if DATA_MODE == "tls":
            fake_data = ClientHelloMaker.get_client_hello_with(os.urandom(32), os.urandom(32), FAKE_SNI,
                                                               os.urandom(32))
        else:
            sys.exit("impossible mode!")
        outgoing_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        outgoing_sock.setblocking(False)
        outgoing_sock.bind((INTERFACE_IPV4, 0))
        outgoing_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        _set_keepalive(outgoing_sock)
        src_port = outgoing_sock.getsockname()[1]
        fake_injective_conn = FakeInjectiveConnection(outgoing_sock, INTERFACE_IPV4, CONNECT_IP, src_port, CONNECT_PORT,
                                                      fake_data,
                                                      BYPASS_METHOD, incoming_sock)
        fake_injective_connections[fake_injective_conn.id] = fake_injective_conn
        try:
            try:
                await loop.sock_connect(outgoing_sock, (CONNECT_IP, CONNECT_PORT))
            except Exception:
                outgoing_sock.close()
                incoming_sock.close()
                return

            if BYPASS_METHOD == "wrong_seq":
                try:
                    await asyncio.wait_for(fake_injective_conn.t2a_event.wait(), 2)
                    if fake_injective_conn.t2a_msg == "unexpected_close":
                        raise ValueError("unexpected close")
                    if fake_injective_conn.t2a_msg == "fake_data_ack_recv":
                        pass
                    else:
                        sys.exit("impossible t2a msg!")
                except Exception:
                    outgoing_sock.close()
                    incoming_sock.close()
                    return
            else:
                sys.exit("unknown bypass method!")
        finally:
            fake_injective_conn.monitor = False
            fake_injective_connections.pop(fake_injective_conn.id, None)

        oti_task = asyncio.create_task(
            relay_main_loop(outgoing_sock, incoming_sock, asyncio.current_task(), b""))
        await relay_main_loop(incoming_sock, outgoing_sock, oti_task, b"")

    except Exception:
        traceback.print_exc()
        sys.exit("handle should not raise exception")
    finally:
        print(f"[-] Client disconnected: {conn_id}")


def _set_keepalive(sock: socket.socket):
    """Enable TCP keepalive tuning where the platform supports the options."""
    for opt, val in (("TCP_KEEPIDLE", 11), ("TCP_KEEPINTVL", 2), ("TCP_KEEPCNT", 3)):
        num = getattr(socket, opt, None)
        if num is not None:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, num, val)
            except OSError:
                pass


async def main():
    mother_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mother_sock.setblocking(False)
    mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mother_sock.bind((LISTEN_HOST, LISTEN_PORT))
    mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    _set_keepalive(mother_sock)
    mother_sock.listen()
    print(f"[Info] Listening on {LISTEN_HOST}:{LISTEN_PORT} -> {CONNECT_IP}:{CONNECT_PORT} "
          f"(fake SNI: {FAKE_SNI.decode(errors='replace')})")
    loop = asyncio.get_running_loop()
    while True:
        incoming_sock, addr = await loop.sock_accept(mother_sock)
        incoming_sock.setblocking(False)
        incoming_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        _set_keepalive(incoming_sock)
        asyncio.create_task(handle(incoming_sock, addr))


def select_network_interface() -> "tuple[str, str]":
    """Return (interface_name, ipv4). Portable across Windows / Linux / macOS.

    Non-interactive (AUTO_SELECT_INTERFACE, or no TTY) picks the default-route
    interface so the tool works headless and under init systems / OpenWRT procd.
    """
    default_ip = get_default_interface_ipv4(CONNECT_IP) or default_route_ip(CONNECT_IP)
    interfaces = list_interfaces()

    def name_for(ip: str) -> str:
        for i in interfaces:
            if i.get("ip") == ip:
                return i.get("name", "")
        return ifname_for_ip(ip)

    # A pinned interface (from config / the LuCI selector) wins on every platform.
    # Empty or "default" means auto default-route.
    if CONFIG_INTERFACE and CONFIG_INTERFACE.lower() != "default":
        if _looks_like_ipv4(CONFIG_INTERFACE):
            name = name_for(CONFIG_INTERFACE) or "manual"
            print(f"[Info] Using configured interface IP {CONFIG_INTERFACE} ({name})")
            return name, CONFIG_INTERFACE
        ip = ip_for_ifname(CONFIG_INTERFACE)
        if ip:
            print(f"[Info] Using configured interface {CONFIG_INTERFACE} ({ip})")
        else:
            print(f"[Info] Configured interface {CONFIG_INTERFACE} has no IPv4 yet; "
                  f"waiting for it to come up")
        return CONFIG_INTERFACE, ip

    non_interactive = AUTO_SELECT_INTERFACE or not sys.stdin or not sys.stdin.isatty()
    if non_interactive or not interfaces:
        name = name_for(default_ip) or "default"
        print(f"[Info] Using interface {name} ({default_ip})")
        return name, default_ip

    print("\n==================================================")
    print("Available Network Interfaces:")
    for idx, i in enumerate(interfaces, 1):
        mark = "  (Default)" if i.get("ip") == default_ip else ""
        print(f" {idx}. {i.get('name', '?'):<24} -> {i.get('ip', ''):<16}{mark}")
    print("==================================================\n")

    default_hint = f" [Default: {default_ip}]" if default_ip else ""
    while True:
        try:
            choice = input(f"Select interface (1-{len(interfaces)}){default_hint}: ").strip()
        except EOFError:
            choice = ""
        if not choice:
            name = name_for(default_ip) or "default"
            print(f"Using interface: {name} ({default_ip})")
            return name, default_ip
        if choice.isdigit() and 1 <= int(choice) <= len(interfaces):
            sel = interfaces[int(choice) - 1]
            print(f"Using interface: {sel.get('name')} ({sel.get('ip')})")
            return sel.get("name", ""), sel.get("ip", "")
        print("Invalid selection.")


fake_tcp_injector = None
injector_thread = None


def run_injector_safe(local_ip: str):
    global fake_tcp_injector
    try:
        engine = create_engine(local_ip, CONNECT_IP, CONNECT_PORT, backend=BACKEND)
        fake_tcp_injector = FakeTcpInjector(engine, fake_injective_connections)
        fake_tcp_injector.run()
    except Exception as e:
        print(f"\n[Info] Injector stopped: {e}")


def stop_injector():
    global fake_tcp_injector
    if fake_tcp_injector:
        try:
            fake_tcp_injector.w.close()
        except Exception:
            pass
        fake_tcp_injector = None


def start_injector(local_ip: str):
    global injector_thread
    print(f"\n[Info] Starting fake-TCP injector ({BACKEND} backend) on {local_ip} "
          f"-> {CONNECT_IP}:{CONNECT_PORT}")
    injector_thread = threading.Thread(target=run_injector_safe, args=(local_ip,), daemon=True)
    injector_thread.start()


def monitor_adapter_loop(adapter_name: str, initial_ip: str):
    """Watch the chosen adapter's IPv4 and rebind the injector when it changes."""
    global INTERFACE_IPV4
    last_ip = initial_ip

    if last_ip:
        start_injector(last_ip)
    else:
        print(f"\n[Warning] Adapter '{adapter_name}' has no IP yet. Waiting...")

    while True:
        time.sleep(2)
        current_ip = ""
        try:
            for i in list_interfaces():
                if i.get("name") == adapter_name:
                    ip = i.get("ip", "")
                    if ip and not ip.startswith("169.254"):
                        current_ip = ip
                        break
        except Exception:
            pass

        if last_ip and not current_ip:
            print(f"\n[Warning] Adapter '{adapter_name}' disconnected. Pausing tunnel...")
            stop_injector()
            last_ip = ""
            INTERFACE_IPV4 = ""
        elif current_ip and current_ip != last_ip:
            if not last_ip:
                print(f"\n[Info] Adapter '{adapter_name}' up (IP: {current_ip}). Resuming...")
            else:
                print(f"\n[Info] Adapter '{adapter_name}' IP changed {last_ip} -> {current_ip}. Rebinding...")
                stop_injector()
            INTERFACE_IPV4 = current_ip
            last_ip = current_ip
            start_injector(current_ip)


if __name__ == "__main__":
    if not is_admin():
        print("This program requires root/administrator privileges. Attempting to elevate...")
        elevate_or_exit()

    print(f"[Info] Platform backend: {BACKEND}")

    INTERFACE_NAME, INTERFACE_IPV4 = select_network_interface()

    threading.Thread(
        target=monitor_adapter_loop,
        args=(INTERFACE_NAME, INTERFACE_IPV4),
        daemon=True,
    ).start()

    print("\nProject to help provide free and open internet access.")
    print("USDT (BEP20): 0x76a768B53Ca77B43086946315f0BDF21156bF424")
    print("@patterniha\n")

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[Info] KeyboardInterrupt received. Stopping...")
        stop_injector()
        print("[Info] Goodbye!")
        sys.exit(0)
