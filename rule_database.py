#ruledatabase.py
import json
import logging
from rich.console import Console

console = Console()

def load_rules():
    try:
        with open("rules.json", "r") as file:
            rules = json.load(file)
            unique_rules = []
            seen = set()
            for rule in rules:
                rule_tuple = tuple(sorted(rule.items()))
                if rule_tuple not in seen:
                    seen.add(rule_tuple)
                    unique_rules.append(rule)
            logging.info("Loaded firewall rules")
            return unique_rules
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logging.warning(f"Failed to load rules: {e}")
        return []

def save_rules(rules):
    try:
        with open("rules.json", "w") as file:
            json.dump(rules, file, indent=4)
        logging.info("Saved firewall rules")
    except Exception as e:
        console.print(f"[bold red]Error saving rules: {e}[/bold red]")
        logging.error(f"Error saving rules: {e}")
