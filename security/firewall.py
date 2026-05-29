import subprocess
import logging
from rich.prompt import Prompt

from config import console
from core.database import load_rules, save_rules
from core.models import FirewallRule


def run_powershell(command: str):
    return subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
        ],
        capture_output=True,
        text=True,
    )


def build_firewall_command(rule: FirewallRule, direction: str) -> str:
    display_name = (
        rule.inbound_firewall_name
        if direction.lower() == "inbound"
        else rule.outbound_firewall_name
    )

    cmd = [
        "New-NetFirewallRule",
        f'-DisplayName "{display_name}"',
        f"-Direction {direction.capitalize()}",
        f"-Action {rule.action.capitalize()}",
    ]

    if rule.app:
        cmd.append(f'-Program "{rule.app}"')

    if rule.dst_ip:
        cmd.append(f'-RemoteAddress "{rule.dst_ip}"')

    if rule.port:
        cmd.append(f'-RemotePort "{rule.port}"')

    if rule.protocol:
        cmd.append(f'-Protocol "{rule.protocol}"')

    return " ".join(cmd)


def apply_firewall_rule(rule: FirewallRule):
    directions = []

    match rule.direction:
        case "inbound":
            directions.append("Inbound")
        case "outbound":
            directions.append("Outbound")
        case "both":
            directions.extend(["Inbound", "Outbound"])

    for direction in directions:
        cmd = build_firewall_command(rule, direction)
        result = run_powershell(cmd)

        if result.returncode != 0:
            console.print(
                f"[bold red][ERROR][/bold red] Failed to apply {direction} rule:\n{result.stderr}"
            )
            logging.error(
                f"Failed applying {direction} rule for {rule.id}: {result.stderr}"
            )
            continue

        console.print(
            f"[bold green][INFO][/bold green] Applied {direction} rule for {rule.name}"
        )
        logging.info(f"Applied {direction} firewall rule {rule.id}")


def remove_firewall_rule(rule: FirewallRule):
    names = []

    if rule.direction == "inbound":
        names.append(rule.inbound_firewall_name)

    elif rule.direction == "outbound":
        names.append(rule.outbound_firewall_name)

    else:
        names.extend(
            [
                rule.inbound_firewall_name,
                rule.outbound_firewall_name,
            ]
        )

    for name in names:
        cmd = f'Remove-NetFirewallRule -DisplayName "{name}"'
        result = run_powershell(cmd)

        if result.returncode == 0:
            logging.info(f"Removed firewall rule {name}")
        else:
            logging.info(f"Firewall rule may not exist: {name}")


def apply_firewall_rules():
    rules = load_rules()
    for rule in rules:
        remove_firewall_rule(rule)
    for rule in rules:
        apply_firewall_rule(rule)
    console.print("[bold green]All rules applied.[/bold green]")
    logging.info("Applied all firewall rules")
    Prompt.ask("Press Enter to exit")


def clear_firewall_rules():
    rules = load_rules()
    for rule in rules:
        remove_firewall_rule(rule)
    save_rules([])
    console.print("[bold green]All firewall rules cleared.[/bold green]")
    logging.info("Cleared all firewall rules")
    Prompt.ask("Press Enter to exit")
