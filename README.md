# NetSentinel: A Simple Firewall Management Tool

NetSentinel is a Python-based tool we built as a group project during the fourth semester of our college to explore Windows firewall management and network traffic monitoring. It’s a learning project to understand how firewalls work, not a production-ready solution. It lets you manage firewall rules and monitor network packets through a basic interactive dashboard.

## Features

- **Manage Firewall Rules**: Add, edit, remove, or search rules to block apps or specific IPs/ports using Windows firewall via PowerShell.
- **Real-Time Packet Sniffing**: Monitor network traffic (TCP, UDP, ICMP, ARP) and map packets to running applications.
- **Interactive Dashboard**: View logs and packets live, with simple key-based controls (e.g., '1' to list rules, '8' to toggle sniffing).
- **Persistent Rules**: Store rules in a JSON file for easy reuse.
- **Simple CLI**: Use command-line flags (e.g., `--add`, `--list`) for quick rule management.

## How to Use

1. **Install Dependencies**:

   ```bash
   pip install scapy psutil rich
   ```

2. **Run the Program**:

   - Launch the dashboard: `python main.py`
   - Use CLI commands: `python main.py --add`, `python main.py --list`, etc.

3. **Dashboard Controls**:

   - `1`: List rules
   - `2`: Add a rule
   - `3`: Remove a rule
   - `4`: Edit a rule
   - `5`: Search rules
   - `6`: Apply rules
   - `7`: Clear all rules
   - `8`: Toggle packet sniffing
   - `0`: Exit


## Requirements

- Python 3.8+
- Windows OS (due to `msvcrt` and PowerShell integration)
- Libraries: `scapy`, `psutil`, `rich`
- Admin privileges required (open terminal in administrator mode)

## File Structure

- `main.py`: Entry point for CLI and dashboard.
- `dashboard.py`: Interactive terminal dashboard.
- `firewall.py`: Handles Windows firewall rule application.
- `rule_engine.py`: Manages rule creation, editing, and searching.
- `rules_database.py`: Loads/saves rules to `rules.json`.
- `utils.py`: Helper functions for packet processing.
- `admin.py`: Checks for admin privileges.
- `config.py`: Sets up logging and global variables.


## Acknowledgments

We learned a lot from online resources, tutorials, and our college coursework while building this. Thanks to the Python community and library developers for making this project possible.