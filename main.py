import argparse
import sys
from rich.prompt import Prompt

from utils.admin import is_admin
from config import console
from ui.dashboard import integrated_dashboard
from ui.prompts import (
    list_rules,
    add_rule,
    remove_rule_interactive,
    edit_rule,
    search_filter_rules,
)
from security.firewall import apply_firewall_rules, clear_firewall_rules
from network.cache import port_cache


def run_sniffer():
    from scapy.all import sniff
    import time

    console.print(
        "[bold cyan]Starting packet sniffing... Press Ctrl+C to stop.[/bold cyan]"
    )
    try:
        sniff(
            filter="ip or arp",
            prn=lambda pkt: console.print(
                f"{time.strftime('%H:%M:%S')} | {pkt.summary()}"
            ),
            store=False,
        )
    except KeyboardInterrupt:
        console.print("[bold red]Packet sniffing stopped.[/bold red]")


def main():
    if not is_admin():
        console.print("[bold red]ERROR: Requires administrator privileges[/bold red]")
        sys.exit(1)

    port_cache.start()

    parser = argparse.ArgumentParser(
        description="NetSentinel v1.0 - Network Monitor & Firewall Manager"
    )
    parser.add_argument(
        "--sniffer", action="store_true", help="Start standalone packet sniffing"
    )
    parser.add_argument("--list", action="store_true", help="List firewall rules")
    parser.add_argument("--add", action="store_true", help="Add firewall rule")
    parser.add_argument("--remove", action="store_true", help="Remove firewall rule")
    parser.add_argument("--edit", action="store_true", help="Edit firewall rule")
    parser.add_argument(
        "--search", action="store_true", help="Search/filter firewall rules"
    )
    parser.add_argument("--apply", action="store_true", help="Apply firewall rules")
    parser.add_argument("--clear", action="store_true", help="Clear firewall rules")

    args = parser.parse_args()

    if args.sniffer:
        run_sniffer()
    elif args.list:
        list_rules()
        Prompt.ask("Press Enter to exit")
    elif args.add:
        add_rule()
        Prompt.ask("Press Enter to exit")
    elif args.remove:
        remove_rule_interactive()
        Prompt.ask("Press Enter to exit")
    elif args.edit:
        edit_rule()
        Prompt.ask("Press Enter to exit")
    elif args.search:
        search_filter_rules()
        Prompt.ask("Press Enter to exit")
    elif args.apply:
        apply_firewall_rules()
    elif args.clear:
        clear_firewall_rules()
    else:
        integrated_dashboard()


if __name__ == "__main__":
    main()
