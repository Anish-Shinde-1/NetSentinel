#dashboard.py
import os
import sys
import time
import subprocess
import threading
import msvcrt
import logging

from rich.console import Console
from rich.panel import Panel
from rich.layout import Layout
from rich.table import Table
from rich.prompt import Prompt
from rich.live import Live
from rich.console import Group
from rich.align import Align

from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP

from config import sniffed_packets, sniff_lock, sniffing_active, SCRIPT_PATH
from utils import get_app_name

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
        line = (f"[cyan]{time.strftime('%H:%M:%S')}[/cyan]  "
                f"[green]{src_ip}[/green]  ->  [green]{dst_ip}[/green]  |  "
                f"[yellow]{proto}[/yellow]  |  [red]Port: {port}[/red]  |  "
                f"[plum4]App: {app_name}[/plum4]")
        with sniff_lock:
            sniffed_packets.append(line)
            if len(sniffed_packets) > 30:
                sniffed_packets.pop(0)
    except Exception as e:
        logging.error(f"Error in sniff_prn: {e}")

def sniffer_thread_func():
    while True:
        from config import sniffing_active
        if sniffing_active:
            sniff(filter="ip or arp", prn=sniff_prn, store=False, timeout=0.5)
        else:
            time.sleep(0.5)

def integrated_dashboard():
    global sniffing_active
    sniffer_thread = threading.Thread(target=sniffer_thread_func, daemon=True)
    sniffer_thread.start()

    exit_dashboard = False
    last_command_time = 0

    with Live(refresh_per_second=4, screen=True) as live:
        while not exit_dashboard:
            if msvcrt.kbhit():
                ch = msvcrt.getch().decode('utf-8', errors='ignore').lower()
                current_time = time.time()
                if current_time - last_command_time < 1:
                    pass
                else:
                    last_command_time = current_time
                    if ch == '1':
                        cmd = f'start cmd /c "{sys.executable} \"{SCRIPT_PATH}\" --list"'
                        subprocess.Popen(cmd, shell=True)
                    elif ch == '2':
                        cmd = f'start cmd /c "{sys.executable} \"{SCRIPT_PATH}\" --add"'
                        subprocess.Popen(cmd, shell=True)
                    elif ch == '3':
                        cmd = f'start cmd /c "{sys.executable} \"{SCRIPT_PATH}\" --remove"'
                        subprocess.Popen(cmd, shell=True)
                    elif ch == '4':
                        cmd = f'start cmd /c "{sys.executable} \"{SCRIPT_PATH}\" --edit"'
                        subprocess.Popen(cmd, shell=True)
                    elif ch == '5':
                        cmd = f'start cmd /c "{sys.executable} \"{SCRIPT_PATH}\" --search"'
                        subprocess.Popen(cmd, shell=True)
                    elif ch == '6':
                        cmd = f'start cmd /c "{sys.executable} \"{SCRIPT_PATH}\" --apply"'
                        subprocess.Popen(cmd, shell=True)
                    elif ch == '7':
                        cmd = f'start cmd /c "{sys.executable} \"{SCRIPT_PATH}\" --clear"'
                        subprocess.Popen(cmd, shell=True)
                    elif ch == '8':
                        sniffing_active = not sniffing_active
                    elif ch == '0':
                        exit_dashboard = True
            menu_items = [
                ("📋", "1. List Firewall Rules"),
                ("➕", "2. Add Firewall Rule"),
                ("❌", "3. Remove Firewall Rule"),
                ("📝", "4. Edit Firewall Rule"),
                ("🔍", "5. Search/Filter Rules"),
                ("🚀", "6. Apply Firewall Rules"),
                ("🧹", "7. Clear All Firewall Rules"),
                ("🚪", "0. Exit Dashboard")
            ]
            
            menu_panels = [
                Panel(
                    Align.center(f"{icon} {label}", vertical="middle"),
                    style="bold white on black",
                    border_style="bright_black",
                    padding=(0, 0)
                )
                for icon, label in menu_items
            ]
            
            main_menu_group = Group(*menu_panels)
            left_upper = Panel(
                main_menu_group,
                title="[bold cyan]Main Menu[/bold cyan]",
                border_style="bright_black"
            )
            
            try:
                with open("firewall.log", "r") as f:
                    log_lines = f.readlines()[-10:]
            except Exception:
                log_lines = ["No logs available."]
            logs_text = ""
            for line in log_lines:
                parts = line.strip().split(' ', 2)
                if len(parts) == 3:
                    timestamp, level, message = parts
                    level = level.strip("[]")
                    color = {"INFO": "green", "WARNING": "yellow", "ERROR": "red"}.get(level, "white")
                    logs_text += f"[cyan]{timestamp}[/cyan] [bold {color}]{level}[/bold {color}] {message}\n"
                else:
                    logs_text += line
            left_lower = Panel(logs_text, title="Firewall Logs", border_style="bright_blue")
            left_column = Layout()
            left_column.split_column(
                Layout(left_upper, ratio=3),
                Layout(left_lower, ratio=2)
)
            with sniff_lock:
                packets_display = "\n\n".join(sniffed_packets) if sniffed_packets else "[grey]No packets captured.[/grey]"
            right_panel = Panel(packets_display, title="Live Packet Sniffing", border_style="bright_green")
            layout = Layout()
            layout.split_row(
                left_column,
                right_panel
            )
            live.update(layout)
            time.sleep(0.1)
