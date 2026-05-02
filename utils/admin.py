import ctypes
import logging

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception as e:
        logging.error(f"is_admin() exception: {e}")
        return False