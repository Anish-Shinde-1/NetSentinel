import logging

from rich.table import Table
from rich.prompt import Prompt

from config import console
from core.database import load_rules, save_rules
from utils.validators import validate_ip, validate_port
from network.mapper import get_full_app_path
from security.firewall import remove_firewall_rule
from core.models import FirewallRule


def list_rules(filter_term=""):
    rules = load_rules()
    if filter_term:
        filter_term = filter_term.lower()

        rules = [
            rule
            for rule in rules
            if filter_term in rule.name.lower()
            or filter_term in (rule.app or "").lower()
        ]
    if not rules:
        console.print("[bold red]No matching rules found.[/bold red]")
        return

    table = Table(title="Firewall Rules", header_style="bold cyan")
    table.add_column("Index", style="magenta", justify="center")
    table.add_column("Name", style="green")
    table.add_column("Application", style="yellow")
    table.add_column("Destination IP", style="blue")
    table.add_column("Port", style="red")
    table.add_column("Direction", style="cyan")
    table.add_column("Action", style="bright_white")
    table.add_column("Protocol", style="bright_blue")

    for idx, rule in enumerate(rules):
        table.add_row(
            str(idx),
            rule.name,
            rule.app or "N/A",
            rule.dst_ip or "N/A",
            str(rule.port) if rule.port else "N/A",
            rule.direction,
            rule.action,
            rule.protocol or "N/A",
        )

    console.print(table)


def add_rule():
    rule = FirewallRule.create(Prompt.ask("Enter rule name").strip())

    app_input = Prompt.ask("Enter application name (Optional)", default="").strip()
    if app_input:
        rule.app = get_full_app_path(app_input)

    dst_ip = Prompt.ask("Enter destination IP (Optional)", default="").strip()
    if dst_ip:
        if not validate_ip(dst_ip):
            console.print("[bold red]Invalid IP address.[/bold red]")
            return
        rule.dst_ip = dst_ip

    port = Prompt.ask("Enter port (Optional)", default="").strip()
    if port:
        if not (validate_port(port) and 1 <= int(port) <= 65535):
            console.print("[bold red]Port must be between 1 and 65535.[/bold red]")
            return
        rule.port = int(port)

    rule.direction = Prompt.ask(
        "Enter direction (inbound/outbound/both)",
        default="both"
    ).strip().lower()

    rule.action = Prompt.ask(
        "Enter action (allow/block)",
        default="block"
    ).strip().lower()

    protocol = Prompt.ask(
        "Enter protocol (TCP/UDP)",
        default=""
    ).strip().upper()

    if protocol:
        if protocol not in {"TCP", "UDP"}:
            console.print("[bold red]Protocol must be TCP or UDP.[/bold red]")
            return
        rule.protocol = protocol

    rules = load_rules()
    rules.append(rule)
    save_rules(rules)

    console.print("[bold green]Rule added successfully.[/bold green]")
    logging.info(f"Added rule: {rule}")


def remove_rule_interactive():
    rules = load_rules()

    if not rules:
        console.print("[bold red]No rules to remove.[/bold red]")
        return

    list_rules()

    try:
        index = int(Prompt.ask("Enter the index of the rule to remove"))

        if not 0 <= index < len(rules):
            console.print("[bold red]Invalid index.[/bold red]")
            return

        removed_rule = rules.pop(index)

        save_rules(rules)
        remove_firewall_rule(removed_rule)

        console.print(f"[bold green]Removed:[/bold green] {removed_rule.name}")
        logging.info(f"Removed rule {removed_rule.id}")

    except ValueError:
        console.print("[bold red]Invalid input.[/bold red]")


def edit_rule():
    rules = load_rules()

    if not rules:
        console.print("[bold red]No matching rules found.[/bold red]")
        Prompt.ask("[bold green]Press Enter to return[/bold green]")
        return

    list_rules()

    try:
        index = int(Prompt.ask("Enter the index of the rule to edit"))

        if not 0 <= index < len(rules):
            console.print("[bold red]Invalid index.[/bold red]")
            return

        rule = rules[index]

        console.print(f"Editing: [bold yellow]{rule.name}[/bold yellow]")

        rule.name = Prompt.ask("Rule name", default=rule.name).strip()

        app_input = Prompt.ask(
            "Enter application name (Optional)",
            default=rule.app or ""
        ).strip()
        rule.app = get_full_app_path(app_input) if app_input else None

        dst_ip = Prompt.ask(
            "Destination IP",
            default=rule.dst_ip or ""
        ).strip()

        if dst_ip:
            if not validate_ip(dst_ip):
                console.print("[bold red]Invalid IP address.[/bold red]")
                return
            rule.dst_ip = dst_ip
        else:
            rule.dst_ip = None

        port = Prompt.ask(
            "Port",
            default=str(rule.port) if rule.port else ""
        ).strip()

        if port:
            if not (validate_port(port) and 1 <= int(port) <= 65535):
                console.print("[bold red]Invalid port.[/bold red]")
                return
            rule.port = int(port)
        else:
            rule.port = None

        rule.direction = Prompt.ask(
            "Direction",
            default=rule.direction
        ).strip().lower()

        rule.action = Prompt.ask(
            "Action",
            default=rule.action
        ).strip().lower()

        protocol = Prompt.ask(
            "Protocol",
            default=rule.protocol or ""
        ).strip().upper()

        if protocol:
            if protocol not in {"TCP", "UDP"}:
                console.print("[bold red]Protocol must be TCP or UDP.[/bold red]")
                return
            rule.protocol = protocol
        else:
            rule.protocol = None

        save_rules(rules)

        console.print("[bold green]Rule updated successfully.[/bold green]")
        logging.info(f"Updated rule {rule.id}")

    except ValueError:
        console.print("[bold red]Invalid input.[/bold red]")
        logging.error("Non-integer input for rule editing")


def search_filter_rules():
    term = Prompt.ask("Enter search term (by rule name or application)", default="")
    list_rules(filter_term=term)
