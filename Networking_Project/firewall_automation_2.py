import os
import sqlite3
import tkinter as tk
from tkinter import messagebox, ttk
import psutil
import pyshark
import ctypes
import sys
import threading
import asyncio

THRESHOLD = 100
app_ip_count = {}

DB_FILE = "firewall_rules.db"

# Run with Admin Privileges
def run_as_admin():
    if ctypes.windll.shell32.IsUserAnAdmin():
        return  # Already running as admin, continue execution

    # Relaunch the script with admin privileges
    params = " ".join(f'"{arg}"' for arg in sys.argv)
    result = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)

    if result > 32:  # Successful execution
        sys.exit(0)  # Exit only the original (non-admin) process
    else:
        messagebox.showerror("Error", "Failed to get admin privileges.")
        sys.exit(1)

# Run this check before doing anything else
run_as_admin()



# Setup Database
def setup_database():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS blocked_ips (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip TEXT UNIQUE,
                        app TEXT)''')
    conn.commit()
    conn.close()

setup_database()

# Function to get the process name from an IP
def get_process_from_ip(ip):
    for conn in psutil.net_connections(kind='inet'):
        if conn.raddr and conn.raddr.ip == ip:
            try:
                process = psutil.Process(conn.pid)
                return process.name(), process.exe()  # Process name and full path
            except psutil.NoSuchProcess:
                return None, None
    return None, None

# Block IP for a specific application
def block_ip_for_app(ip, app_name, app_path):
    if not ip or not app_name:
        messagebox.showerror("Error", "Invalid IP or Application.")
        return

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT ip FROM blocked_ips WHERE ip=? AND app=?", (ip, app_name))
    if cursor.fetchone():
        conn.close()
        messagebox.showinfo("Firewall", f"IP {ip} is already blocked for {app_name}.")
        return

    command = f'netsh advfirewall firewall add rule name="Block {ip} ({app_name})" dir=out action=block remoteip={ip} program="{app_path}"'
    os.system(command)

    cursor.execute("INSERT INTO blocked_ips (ip, app) VALUES (?, ?)", (ip, app_name))
    conn.commit()
    conn.close()

    update_blocked_list()
    messagebox.showinfo("Firewall", f"Blocked {ip} for {app_name}.")

# Monitor network packets and track per-application traffic
def monitor_network():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        capture = pyshark.LiveCapture(interface='Wi-Fi')  # Adjust for correct network interface
        for packet in capture.sniff_continuously():
            if hasattr(packet, 'ip'):
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst

                app_name, app_path = get_process_from_ip(src_ip)
                if not app_name:
                    continue

                key = (app_name, src_ip)
                app_ip_count[key] = app_ip_count.get(key, 0) + 1

                if app_ip_count[key] > THRESHOLD:
                    block_ip_for_app(src_ip, app_name, app_path)

    except Exception as e:
        print(f"Error in monitoring: {e}")

# Start Network Monitoring
def start_monitoring():
    sniffing_thread = threading.Thread(target=monitor_network, daemon=True)
    sniffing_thread.start()
    messagebox.showinfo("Monitoring", "Application-wise network monitoring started!")

# Refresh Firewall
def refresh_firewall():
    os.system("netsh advfirewall reset")
    os.system("netsh advfirewall set allprofiles state on")
    messagebox.showinfo("Firewall", "Windows Firewall refreshed successfully!")

# Unblock an IP for a specific application
def unblock_ip():
    selected_entry = blocked_listbox.get(tk.ACTIVE)
    if not selected_entry:
        messagebox.showerror("Error", "Select an entry to unblock.")
        return

    ip, app_name = selected_entry.split(" - App: ")
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM blocked_ips WHERE ip=? AND app=?", (ip, app_name))
    conn.commit()
    conn.close()

    command = f'netsh advfirewall firewall delete rule name="Block {ip} ({app_name})"'
    os.system(command)

    update_blocked_list()
    messagebox.showinfo("Firewall", f"Unblocked {ip} for {app_name}.")

# GUI Setup
root = tk.Tk()
root.title("Application Firewall")
root.geometry("600x500")

ttk.Button(root, text="Start Monitoring", command=start_monitoring).pack(pady=5)
ttk.Button(root, text="Refresh Firewall", command=refresh_firewall).pack(pady=5)

tk.Label(root, text="Blocked IPs per Application:").pack()
blocked_listbox = tk.Listbox(root, width=60, height=10)
blocked_listbox.pack()

# Update Blocked List
def update_blocked_list():
    blocked_listbox.delete(0, tk.END)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT ip, app FROM blocked_ips")
    for row in cursor.fetchall():
        blocked_listbox.insert(tk.END, f"{row[0]} - App: {row[1]}")
    conn.close()

update_blocked_list()

# Manual Blocking
tk.Label(root, text="Enter IP:").pack(pady=2)
ip_entry = tk.Entry(root, width=30)
ip_entry.pack(pady=2)

tk.Label(root, text="Enter Application Name:").pack(pady=2)
app_entry = tk.Entry(root, width=30)
app_entry.pack(pady=2)

ttk.Button(root, text="Block IP for App", command=lambda: block_ip_for_app(ip_entry.get(), app_entry.get(), app_entry.get())).pack(pady=5)
ttk.Button(root, text="Unblock Selected", command=unblock_ip).pack(pady=5)

root.mainloop()