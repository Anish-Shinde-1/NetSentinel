import os
import sys
import logging
import threading
from rich.console import Console

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("firewall.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

console = Console()

# --- Global Variables ---
sniffed_packets = []  # List for formatted packet info
sniff_lock = threading.Lock()
sniffing_active = True   # Turn on live packet sniffing by default
verbose = False  # Control debug verbosity

# --- Script Path ---
SCRIPT_PATH = os.path.abspath(sys.argv[0])
