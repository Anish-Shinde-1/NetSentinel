import psutil
import threading
import time
import logging

class ConnectionCache:
    def __init__(self, update_interval: float = 3.0):
        self.update_interval = update_interval
        self._port_map: dict[int, str] = {}
        self._lock = threading.Lock()
        self._running = False
        self._thread: threading.Thread | None = None

    def start(self):
        """Starts the background caching thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._update_loop, daemon=True)
        self._thread.start()
        logging.info("Connection cache background thread started.")

    def stop(self):
        """Stops the background thread."""
        self._running = False
        if self._thread:
            self._thread.join()

    def _update_loop(self):
        """The loop that constantly queries psutil."""
        while self._running:
            new_map = {}
            try:
                for conn in psutil.net_connections(kind="inet"):
                    if conn.laddr and conn.pid:
                        try:
                            proc = psutil.Process(conn.pid)
                            new_map[conn.laddr.port] = proc.name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                            continue
                
                with self._lock:
                    self._port_map = new_map
                    
            except psutil.AccessDenied:
                logging.error("Access denied when reading net_connections. Run as Administrator.")
            except Exception as e:
                logging.error(f"Error updating connection cache: {e}")

            time.sleep(self.update_interval)

    def get_app_name(self, port: int) -> str:
        """O(1) lookup for the application name given a local port."""
        with self._lock:
            return self._port_map.get(port, "N/A")

port_cache = ConnectionCache()