#rule_engine.py
import json
import logging
import sys
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt

from utils import validate_ip, validate_port, get_full_app_path
from firewall import remove_firewall_rule
from config import console
from rule_database import load_rules, save_rules


def list_rules(filter_term=""):
    rules = load_rules()
    if filter_term:
        rules = [r for r in rules if filter_term.lower() in r.get("name", "").lower() or
                                   filter_term.lower() in r.get("app", "").lower()]
    if not rules:
        console.print("[bold red]No matching rules found.[/bold red]")
        Prompt.ask("[bold green]Press Enter to return[/bold green]")
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
            rule.get("name", "N/A"),
            rule.get("app", "N/A"),
            rule.get("dst_ip", "N/A"),
            str(rule.get("port", "N/A")),
            rule.get("direction", "N/A"),
            rule.get("action", "N/A"),
            rule.get("protocol", "N/A")
        )
    console.print(table)
    # Prompt.ask("[bold green]Press Enter to exit[/bold green]")

def add_rule():
    rule = {}
    rule["name"] = Prompt.ask("Enter rule name").strip()
    app_input = Prompt.ask("Enter application name (Optional)", default="").strip()
    if app_input:
        rule["app"] = get_full_app_path(app_input)
    dst_ip = Prompt.ask("Enter destination IP (Optional)", default="").strip()
    if dst_ip:
        if validate_ip(dst_ip):
            rule["dst_ip"] = dst_ip
        else:
            console.print("[bold red]Invalid IP address.[/bold red]")
            logging.error("Attempted to add rule with invalid IP address")
            return
    port = Prompt.ask("Enter port (Optional, leave blank for all ports)", default="").strip()
    if port:
        if validate_port(port) and 1 <= int(port) <= 65535:
            rule["port"] = port
        else:
            console.print("[bold red]Port must be a number between 1 and 65535.[/bold red]")
            logging.error("Attempted to add rule with invalid port")
            return
    rule["direction"] = Prompt.ask("Enter direction (inbound/outbound/both)", default="both").strip().lower()
    rule["action"] = Prompt.ask("Enter action (allow/block)", default="block").strip().lower()
    protocol = Prompt.ask("Enter protocol (TCP/UDP, leave blank for all)", default="").strip().upper()
    if protocol in ["TCP", "UDP"]:
        rule["protocol"] = protocol
    elif protocol:
        console.print("[bold red]Protocol must be TCP or UDP.[/bold red]")
        logging.error("Attempted to add rule with invalid protocol")
        return
    rule["enabled"] = True

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
        if 0 <= index < len(rules):
            removed_rule = rules.pop(index)
            save_rules(rules)
            console.print(f"[bold green]Removed rule:[/bold green] {removed_rule}")
            logging.info(f"Removed rule: {removed_rule}")
            remove_firewall_rule(removed_rule)
        else:
            console.print("[bold red]Invalid index.[/bold red]")
    except ValueError:
        console.print("[bold red]Invalid input.[/bold red]")
        logging.error("Non-integer input for rule removal")

def edit_rule():
    rules = load_rules()
    if not rules:
        console.print("[bold red]No rules available to edit.[/bold red]")
        return
    list_rules()
    try:
        index = int(Prompt.ask("Enter the index of the rule to edit"))
        if 0 <= index < len(rules):
            rule = rules[index]
            console.print(f"Editing rule: [bold yellow]{rule.get('name', 'N/A')}[/bold yellow]")
            rule["name"] = Prompt.ask("Enter rule name", default=rule.get("name", "")).strip()
            app_input = Prompt.ask("Enter application name (Optional)", default=rule.get("app", "")).strip()
            if app_input:
                rule["app"] = get_full_app_path(app_input)
            else:
                rule.pop("app", None)
            dst_ip = Prompt.ask("Enter destination IP (Optional)", default=rule.get("dst_ip", "")).strip()
            if dst_ip:
                if validate_ip(dst_ip):
                    rule["dst_ip"] = dst_ip
                else:
                    console.print("[bold red]Invalid IP address.[/bold red]")
                    return
            else:
                rule.pop("dst_ip", None)
            port = Prompt.ask("Enter port (Optional, leave blank for all ports)", default=str(rule.get("port", ""))).strip()
            if port:
                if validate_port(port) and 1 <= int(port) <= 65535:
                    rule["port"] = port
                else:
                    console.print("[bold red]Port must be a number between 1 and 65535.[/bold red]")
                    return
            else:
                rule.pop("port", None)
            rule["direction"] = Prompt.ask("Enter direction (inbound/outbound/both)", default=rule.get("direction", "both")).strip().lower()
            rule["action"] = Prompt.ask("Enter action (allow/block)", default=rule.get("action", "block")).strip().lower()
            protocol = Prompt.ask("Enter protocol (TCP/UDP, leave blank for all)", default=rule.get("protocol", "")).strip().upper()
            if protocol in ["TCP", "UDP"]:
                rule["protocol"] = protocol
            elif protocol:
                console.print("[bold red]Protocol must be TCP or UDP.[/bold red]")
                return
            else:
                rule.pop("protocol", None)
            rules[index] = rule
            save_rules(rules)
            console.print("[bold green]Rule updated successfully.[/bold green]")
            logging.info(f"Updated rule: {rule}")
        else:
            console.print("[bold red]Invalid index.[/bold red]")
    except ValueError:
        console.print("[bold red]Invalid input.[/bold red]")
        logging.error("Non-integer input for rule editing")

def search_filter_rules():
    term = Prompt.ask("Enter search term (by rule name or application)", default="")
    list_rules(filter_term=term)
