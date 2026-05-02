import os
import sys
import logging
import threading
from rich.console import Console

SCRIPT_PATH = os.path.abspath(sys.argv[0])

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("firewall.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

console = Console()

# Global state for sniffer and dashboard communication
sniffed_packets = []
sniff_lock = threading.Lock()
sniffing_active = True