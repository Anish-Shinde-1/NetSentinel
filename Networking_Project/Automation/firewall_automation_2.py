import os
import sqlite3
import tkinter as tk
from tkinter import messagebox, simpledialog, filedialog
from tkinter import ttk
import ctypes
import sys
import threading
import asyncio
import pyshark

THRESHOLD = 100  # Packet count before blocking
suspicious_ips = {}
DB_FILE = "firewall_rules.db"

# Admin Privileges (Only ask if needed)
def run_as_admin():
    if not ctypes.windll.shell32.IsUserAnAdmin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()

# Only request admin if needed (like modifying firewall rules)
if "--admin" in sys.argv:
    run_as_admin()

# Database Setup
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

# Function to Refresh Windows Firewall
def refresh_firewall():
    os.system("netsh advfirewall reset")
    os.system("netsh advfirewall set allprofiles state on")
    messagebox.showinfo("Firewall", "Windows Firewall refreshed successfully!")

# Function to Block IP for a Specific App
def block_ip(ip, app):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT ip FROM blocked_ips WHERE ip=? AND app=?", (ip, app))
    if cursor.fetchone():
        conn.close()
        return
    
    command = f'netsh advfirewall firewall add rule name="Block {ip} in {app}" dir=out action=block remoteip={ip} program="{app}"'
    os.system(command)
    cursor.execute("INSERT INTO blocked_ips (ip, app) VALUES (?, ?)", (ip, app))
    conn.commit()
    conn.close()
    update_blocked_list()
    messagebox.showinfo("Firewall", f"Blocked {ip} for {app}")

# Function to Unblock IP
def unblock_ip():
    selected = blocked_listbox.get(tk.ACTIVE)
    if not selected:
        return
    
    ip, app = selected.split(" | App: ")
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM blocked_ips WHERE ip=? AND app=?", (ip, app))
    conn.commit()
    conn.close()
    
    command = f'netsh advfirewall firewall delete rule name="Block {ip} in {app}"'
    os.system(command)
    update_blocked_list()
    messagebox.showinfo("Firewall", f"Unblocked {ip} for {app}")

# Function to Manually Add a Rule
def add_manual_rule():
    ip = simpledialog.askstring("Manual Block", "Enter IP to Block:")
    if not ip:
        return
    app = filedialog.askopenfilename(title="Select Application", filetypes=[("Executable Files", "*.exe")])
    if app:
        block_ip(ip, app)

# Packet Sniffing Function
def monitor_network():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        capture = pyshark.LiveCapture(interface='Wi-Fi')  # Change if needed
        for packet in capture.sniff_continuously(packet_count=50):
            if hasattr(packet, 'ip'):
                src_ip = packet.ip.src
                if src_ip in suspicious_ips:
                    suspicious_ips[src_ip] += 1
                else:
                    suspicious_ips[src_ip] = 1
                
                if suspicious_ips[src_ip] > THRESHOLD:
                    app = filedialog.askopenfilename(title="Select Application to Block for:", filetypes=[("Executable Files", "*.exe")])
                    if app:
                        block_ip(src_ip, app)
    except Exception as e:
        print(f"Error in monitoring: {e}")

# Function to Start Sniffing in Background
def start_monitoring():
    sniffing_thread = threading.Thread(target=monitor_network, daemon=True)
    sniffing_thread.start()
    messagebox.showinfo("Monitoring", "Network monitoring started!")

# GUI Setup
root = tk.Tk()
root.title("Application-Specific Firewall")
root.geometry("500x500")

ttk.Button(root, text="Start Monitoring", command=start_monitoring).pack(pady=5)

ttk.Button(root, text="Refresh Firewall", command=refresh_firewall).pack(pady=5)

ttk.Button(root, text="Manually Block IP", command=add_manual_rule).pack(pady=5)

ttk.Button(root, text="Unblock Selected IP", command=unblock_ip).pack(pady=5)

tk.Label(root, text="Blocked IPs:").pack()
blocked_listbox = tk.Listbox(root, width=50, height=10)
blocked_listbox.pack()

# Function to Update Blocked IP List
def update_blocked_list():
    blocked_listbox.delete(0, tk.END)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT ip, app FROM blocked_ips")
    for row in cursor.fetchall():
        blocked_listbox.insert(tk.END, f"{row[0]} | App: {row[1]}")
    conn.close()

update_blocked_list()
root.mainloop()
