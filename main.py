#main.py
import sys
from admin import is_admin
from rule_engine import list_rules, add_rule, remove_rule_interactive, edit_rule, search_filter_rules
from firewall import apply_firewall_rules, clear_firewall_rules
from dashboard import integrated_dashboard
from config import console

if not is_admin():
    console.print("[bold red]ERROR: Requires administrator privileges[/bold red]")
    sys.exit(1)

if __name__ == "__main__":
    if "--sniffer" in sys.argv:
        from scapy.all import sniff
        import time
        console.print("[bold cyan]Starting packet sniffing... Press Ctrl+C to stop.[/bold cyan]")
        try:
            sniff(filter="ip or arp", prn=lambda pkt: console.print(f"{time.strftime('%H:%M:%S')} | {pkt.summary()}"), store=False)
        except KeyboardInterrupt:
            console.print("[bold red]Packet sniffing stopped.[/bold red]")
    elif "--list" in sys.argv:
        list_rules()
        from rich.prompt import Prompt
        Prompt.ask("Press Enter to exit")
        sys.exit(0)
    elif "--add" in sys.argv:
        add_rule()
        from rich.prompt import Prompt
        Prompt.ask("Press Enter to exit")
        sys.exit(0)
    elif "--remove" in sys.argv:
        remove_rule_interactive()
        from rich.prompt import Prompt
        Prompt.ask("Press Enter to exit")
        sys.exit(0)
    elif "--edit" in sys.argv:
        edit_rule()
        from rich.prompt import Prompt
        Prompt.ask("Press Enter to exit")
        sys.exit(0)
    elif "--search" in sys.argv:
        search_filter_rules()
        sys.exit(0)
    elif "--apply" in sys.argv:
        apply_firewall_rules()
        sys.exit(0)
    elif "--clear" in sys.argv:
        clear_firewall_rules()
        sys.exit(0)
    else:
        integrated_dashboard()
