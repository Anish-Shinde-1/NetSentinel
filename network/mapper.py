import subprocess
import socket
import psutil
from scapy.layers.inet import IP
from config import console


def get_full_app_path(app_name):
    ps_cmd = (
        f"Get-ChildItem -Path 'C:\\Program Files\\' -Filter '{app_name}' -Recurse -ErrorAction SilentlyContinue "
        f"| Select-Object -First 1 -ExpandProperty FullName"
    )
    try:
        result = subprocess.run(
            ["powershell", "-Command", ps_cmd], capture_output=True, text=True
        )
        full_path = (
            result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""
        )
        if full_path:
            return full_path
    except Exception as e:
        console.print(
            f"[bold red][ERROR][/bold red] Failed to retrieve path for {app_name}: {e}"
        )
    return app_name


def get_app_name(packet):
    app_name = "N/A"
    local_ips = socket.gethostbyname_ex(socket.gethostname())[2]

    if packet.haslayer("TCP"):
        sport = packet["TCP"].sport
        dport = packet["TCP"].dport
    elif packet.haslayer("UDP"):
        sport = packet["UDP"].sport
        dport = packet["UDP"].dport
    else:
        return app_name

    local_port = None
    if packet.haslayer(IP):  # <--- Add this safety check
        if packet[IP].src in local_ips:
            local_port = sport
        elif packet[IP].dst in local_ips:
            local_port = dport

    if not local_port:
        return app_name

    for conn in psutil.net_connections(kind="inet"):
        try:
            if conn.laddr and conn.laddr.port == local_port:
                if conn.pid:
                    proc = psutil.Process(conn.pid)
                    app_name = proc.name()
                    break
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue
    return app_name
