import json
import logging

from config import console
from core.models import FirewallRule


def load_rules() -> list[FirewallRule]:
    try:
        with open("rules.json", "r") as file:
            rules = json.load(file)
            unique_rules = []
            seen = set()
            for rule in rules:
                rule = FirewallRule.from_dict(rule)

                rule_key = (
                    rule.name,
                    rule.app,
                    rule.dst_ip,
                    rule.port,
                    rule.direction,
                    rule.action,
                    rule.protocol,
                )

                if rule_key not in seen:
                    seen.add(rule_key)
                    unique_rules.append(rule)

            logging.info("Loaded firewall rules")
            return unique_rules

    except (FileNotFoundError, json.JSONDecodeError) as e:
        logging.warning(f"Failed to load rules: {e}")
        return []


def save_rules(rules: list[FirewallRule]):
    try:
        with open("rules.json", "w") as file:
            json.dump([rule.to_dict() for rule in rules], file, indent=4)
        logging.info("Saved firewall rules")
    except Exception as e:
        console.print(f"[bold red]Error saving rules: {e}[/bold red]")
        logging.error(f"Error saving rules: {e}")
