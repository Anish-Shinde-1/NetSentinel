#admin.py
import ctypes
import sys
import logging
from config import console

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception as e:
        logging.error(f"is_admin() exception: {e}")
        return False

if __name__ == "__main__":
    if not is_admin():
        console.print("[bold red]ERROR: Requires administrator privileges[/bold red]")
        sys.exit(1)
