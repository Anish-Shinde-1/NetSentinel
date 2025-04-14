import subprocess
import logging
from config import console, verbose
from persistence import load_rules, save_rules


def apply_firewall_rule(rule):
    logging.info(f"Applying rule: {rule}")
    
    # Normalize the path: convert double backslashes to single backslashes
    app_path = rule.get("app", "").replace("\\\\", "\\") if "app" in rule else None
    protocol = rule.get("protocol", "TCP").upper() if rule.get("protocol") else None
    direction = rule.get("direction", "both").lower()
    
    # Determine PowerShell direction
    if direction == "inbound":
        ps_direction = "Inbound"
    elif direction == "outbound":
        ps_direction = "Outbound"
    else:
        ps_direction = "Outbound"

    cmd = None
    display_name = None
    
    if "app" in rule and "dst_ip" in rule and "port" in rule and protocol:
        display_name = f"Block {app_path} on {rule['dst_ip']}:{rule['port']}"
        cmd = (
            f'New-NetFirewallRule -DisplayName "{display_name}" '
            f'-Direction {ps_direction} -Program "{app_path}" -RemoteAddress {rule["dst_ip"]} '
            f'-Protocol {protocol} -RemotePort {rule["port"]} -Action Block'
        )
    elif "app" in rule and "dst_ip" in rule:
        display_name = f"Block {app_path} on {rule['dst_ip']}"
        cmd = (
            f'New-NetFirewallRule -DisplayName "{display_name}" '
            f'-Direction {ps_direction} -Program "{app_path}" -RemoteAddress {rule["dst_ip"]} -Action Block'
        )
    elif "dst_ip" in rule and "port" in rule and protocol:
        display_name = f"Block IP {rule['dst_ip']}:{rule['port']}"
        cmd = (
            f'New-NetFirewallRule -DisplayName "{display_name}" '
            f'-Direction {ps_direction} -RemoteAddress {rule["dst_ip"]} '
            f'-Protocol {protocol} -RemotePort {rule["port"]} -Action Block'
        )
    elif "app" in rule and "port" in rule and protocol:
        display_name = f"Block {app_path} on Port {rule['port']}"
        cmd = (
            f'New-NetFirewallRule -DisplayName "{display_name}" '
            f'-Direction {ps_direction} -Program "{app_path}" '
            f'-Protocol {protocol} -RemotePort {rule["port"]} -Action Block'
        )
    elif "app" in rule:
        display_name = f"Block {app_path}"
        cmd = (
            f'New-NetFirewallRule -DisplayName "{display_name}" '
            f'-Direction {ps_direction} -Program "{app_path}" -Action Block'
        )
    elif "dst_ip" in rule:
        display_name = f"Block IP {rule['dst_ip']}"
        cmd = (
            f'New-NetFirewallRule -DisplayName "{display_name}" '
            f'-Direction {ps_direction} -RemoteAddress {rule["dst_ip"]} -Action Block'
        )
    elif "port" in rule and protocol:
        display_name = f"Block Port {rule['port']}"
        cmd = (
            f'New-NetFirewallRule -DisplayName "{display_name}" '
            f'-Direction {ps_direction} -Protocol {protocol} -RemotePort {rule["port"]} -Action Block'
        )

    if cmd:
        if verbose:
            console.print(f"[bold cyan][DEBUG][/bold cyan] Executing: {cmd}")
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            console.print(f"[bold red][ERROR][/bold red] Failed to apply rule: {result.stderr}")
            logging.error(f"Failed to apply rule: {cmd}. Error: {result.stderr}")
        else:
            console.print(f"[bold green][INFO][/bold green] Rule applied successfully: {display_name}")
            logging.info(f"Applied rule: {cmd}")

    if rule.get("direction", "both").lower() == "both" and cmd:
        extra_direction = "Inbound" if ps_direction == "Outbound" else "Outbound"
        extra_cmd = cmd.replace(f'-Direction {ps_direction}', f'-Direction {extra_direction}')
        if verbose:
            console.print(f"[bold cyan][DEBUG][/bold cyan] Executing {extra_direction} rule: {extra_cmd}")
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", extra_cmd],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            console.print(f"[bold red][ERROR][/bold red] Failed to apply {extra_direction} rule: {result.stderr}")
            logging.error(f"Failed to apply {extra_direction} rule: {extra_cmd}. Error: {result.stderr}")
        else:
            console.print(f"[bold green][INFO][/bold green] {extra_direction} rule applied successfully: {display_name}")
            logging.info(f"Applied additional rule for {extra_direction}: {extra_cmd}")

def remove_firewall_rule(rule):
    logging.info(f"Removing rule: {rule}")
    cmd = None
    app_path = rule.get("app", "") if "app" in rule else None  # Use original path, no doubling
    port = rule.get("port", "")
    if "app" in rule and "dst_ip" in rule and port:
        cmd = f'Remove-NetFirewallRule -DisplayName "Block {app_path} on {rule["dst_ip"]}:{port}"'
    elif "app" in rule and "dst_ip" in rule:
        cmd = f'Remove-NetFirewallRule -DisplayName "Block {app_path} on {rule["dst_ip"]}"'
    elif "dst_ip" in rule and port:
        cmd = f'Remove-NetFirewallRule -DisplayName "Block IP {rule["dst_ip"]}:{port}"'
    elif "app" in rule and port:
        cmd = f'Remove-NetFirewallRule -DisplayName "Block {app_path} on Port {port}"'
    elif "app" in rule:
        cmd = f'Remove-NetFirewallRule -DisplayName "Block {app_path}"'
    elif "dst_ip" in rule:
        cmd = f'Remove-NetFirewallRule -DisplayName "Block IP {rule["dst_ip"]}"'
    elif port:
        cmd = f'Remove-NetFirewallRule -DisplayName "Block Port {port}"'

    if not cmd:
        console.print("[bold yellow][WARNING][/bold yellow] No valid rule to remove.")
        logging.warning("No valid rule to remove.")
        return

    if verbose:
        console.print(f"[bold cyan][DEBUG][/bold cyan] Removing: {cmd}")
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        if verbose:
            console.print(f"[bold yellow][WARNING][/bold yellow] Failed to remove rule (may not exist): {result.stderr}")
        logging.info(f"Rule removal attempted, may not exist: {cmd}")
    else:
        # Extract the display name from the command for confirmation.
        display_part = cmd.split('-DisplayName ')[1].split(' ')[0]
        console.print(f"[bold green]Rule removed: {display_part}[/bold green]")
        logging.info(f"Removed firewall rule: {cmd}")

def apply_firewall_rules():
    rules = load_rules()
    for rule in rules:
        remove_firewall_rule(rule)  # Clear any existing instances
    for rule in rules:
        apply_firewall_rule(rule)
    console.print("[bold green]All rules applied.[/bold green]")
    logging.info("Applied all firewall rules")
    from rich.prompt import Prompt
    Prompt.ask("Press Enter to exit")

def clear_firewall_rules():
    rules = load_rules()
    for rule in rules:
        remove_firewall_rule(rule)
    save_rules([])  # Clear rules.json
    console.print("[bold green]All firewall rules cleared.[/bold green]")
    logging.info("Cleared all firewall rules")
    from rich.prompt import Prompt
    Prompt.ask("Press Enter to exit")

def process_firewall_rules():
    rules = load_rules()
    for rule in rules:
        apply_firewall_rule(rule)
