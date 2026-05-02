import sys
import time
import subprocess
import msvcrt
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.table import Table
from rich import box
from rich.align import Align
from rich.text import Text

import config
from network.sniffer import start_sniffer_thread


def generate_menu_table():
    """Generates a sleek, borderless table for the main menu."""
    table = Table(box=box.SIMPLE, expand=True, show_header=False)
    table.add_column("Icon", justify="center", width=3)
    table.add_column("Key", style="bold yellow", justify="right", width=3)
    table.add_column("Action", style="bold white")

    menu_items = [
        ("1", "List Firewall Rules"),
        ("2", "Add Firewall Rule"),
        ("3", "Remove Firewall Rule"),
        ("4", "Edit Firewall Rule"),
        ("5", "Search / Filter Rules"),
        ("6", "Apply Firewall Rules"),
        ("7", "Clear All Rules"),
        ("8", "Toggle Sniffer Status"),
        ("0", "Exit Dashboard"),
    ]

    for key, action in menu_items:
        table.add_row(f"[{key}]", action)

    return table


def get_formatted_logs():
    """Reads and colorizes the firewall.log file."""
    try:
        with open("firewall.log", "r") as f:
            log_lines = f.readlines()[-12:]  # Get last 12 lines
    except Exception:
        return Text("No logs available yet...", style="dim italic")

    logs_text = Text()
    for line in log_lines:
        parts = line.strip().split(" ", 2)
        if len(parts) == 3:
            timestamp, level, message = parts
            level = level.strip("[]")
            color = {
                "INFO": "bold green",
                "WARNING": "bold yellow",
                "ERROR": "bold red",
            }.get(level, "white")
            logs_text.append(f"{timestamp} ", style="cyan")
            logs_text.append(f"[{level}] ", style=color)
            logs_text.append(f"{message}\n")
        else:
            logs_text.append(f"{line}\n")
    return logs_text


def integrated_dashboard():
    start_sniffer_thread()
    exit_dashboard = False
    last_command_time = 0

    with Live(refresh_per_second=8, screen=True) as live:
        while not exit_dashboard:
            # --- Input Handling ---
            if msvcrt.kbhit():
                ch = msvcrt.getch().decode("utf-8", errors="ignore").lower()
                current_time = time.time()

                # Prevent spamming terminal windows
                if current_time - last_command_time >= 1:
                    last_command_time = current_time
                    if ch in {"1", "2", "3", "4", "5", "6", "7"}:
                        cmd_map = {
                            "1": "--list",
                            "2": "--add",
                            "3": "--remove",
                            "4": "--edit",
                            "5": "--search",
                            "6": "--apply",
                            "7": "--clear",
                        }

                        cmd = f'start cmd /c ""{sys.executable}" "{config.SCRIPT_PATH}" {cmd_map[ch]}"'
                        subprocess.Popen(cmd, shell=True)
                    elif ch == "8":
                        config.sniffing_active = not config.sniffing_active
                    elif ch == "0":
                        exit_dashboard = True

            # --- Layout Construction ---
            layout = Layout()

            # Root splits into Header, Main Body, and Footer
            layout.split_column(
                Layout(name="header", size=3),
                Layout(name="body"),
                Layout(name="footer", size=1),
            )

            # Body splits into Left (Menu/Logs) and Right (Sniffer)
            layout["body"].split_row(
                Layout(name="left_pane", ratio=2), Layout(name="right_pane", ratio=3)
            )

            # Left Pane splits into Menu and Logs
            layout["left_pane"].split_column(
                Layout(name="menu", size=14), Layout(name="logs")
            )

            # --- Populate Panels ---

            # 1. Header
            header_text = Align.center(
                "NETSENTINEL - Network Monitor & Firewall Manager",
                vertical="middle",
            )
            layout["header"].update(
                Panel(header_text, style="on black", border_style="cyan")
            )

            # 2. Menu
            menu_panel = Panel(
                generate_menu_table(),
                title="[bold white]Command Center[/bold white]",
                border_style="bright_black",
                padding=(1, 1),
            )
            layout["menu"].update(menu_panel)

            # 3. Logs
            logs_panel = Panel(
                get_formatted_logs(),
                title="[bold white]System Logs[/bold white]",
                border_style="bright_blue",
                padding=(0, 1),
            )
            layout["logs"].update(logs_panel)

            # 4. Packet Sniffer
            with config.sniff_lock:
                packets_display = (
                    "\n\n".join(config.sniffed_packets)
                    if config.sniffed_packets
                    else "[dim italic]Listening for network traffic...[/dim italic]"
                )

            sniffer_title = (
                "[bold bright_green]Live Packet Sniffer [ACTIVE][/bold bright_green]"
                if config.sniffing_active
                else "[bold red]Live Packet Sniffer [PAUSED][/bold red]"
            )
            right_panel = Panel(
                packets_display,
                title=sniffer_title,
                border_style="bright_green" if config.sniffing_active else "red",
                padding=(1, 2),
            )
            layout["right_pane"].update(right_panel)

            # 5. Footer
            footer_text = Align.center(
                "[dim white]Press the corresponding [bold yellow]number key[/bold yellow] to execute a command. Press [bold red]0[/bold red] to exit.[/dim white]"
            )
            layout["footer"].update(footer_text)

            # Render
            live.update(layout)
            time.sleep(0.1)
