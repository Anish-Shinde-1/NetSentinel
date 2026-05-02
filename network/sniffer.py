import time
import logging
import threading
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from scapy.all import sniff
import config
from network.mapper import get_app_name


def sniff_prn(packet):
    try:
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = {6: "TCP", 17: "UDP"}.get(packet[IP].proto, "Other")
        else:
            src_ip = dst_ip = "N/A"
            proto = "N/A"

        if packet.haslayer(TCP):
            port = packet[TCP].sport
        elif packet.haslayer(UDP):
            port = packet[UDP].sport
        elif packet.haslayer(ICMP):
            proto = "ICMP"
            port = ""
        elif packet.haslayer(ARP):
            src_ip = packet[ARP].psrc
            dst_ip = packet[ARP].pdst
            proto = "ARP"
            port = ""
        else:
            port = ""

        app_name = get_app_name(packet)
        line = (
            f"[cyan]{time.strftime('%H:%M:%S')}[/cyan]  "
            f"[green]{src_ip}[/green]  ->  [green]{dst_ip}[/green]  |  "
            f"[yellow]{proto}[/yellow]  |  [red]Port: {port}[/red]  |  "
            f"[plum4]App: {app_name}[/plum4]"
        )

        with config.sniff_lock:
            config.sniffed_packets.append(line)
            if len(config.sniffed_packets) > 30:
                config.sniffed_packets.pop(0)
    except Exception as e:
        logging.error(f"Error in sniff_prn: {e}")


def sniffer_thread_func():
    while True:
        if config.sniffing_active:
            sniff(filter="ip or arp", prn=sniff_prn, store=False, timeout=0.5)
        else:
            time.sleep(0.5)


def start_sniffer_thread():
    sniffer_thread = threading.Thread(target=sniffer_thread_func, daemon=True)
    sniffer_thread.start()
