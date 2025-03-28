import os
import sqlite3
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import ctypes
import sys
import threading
import asyncio
import pyshark

THRESHOLD = 100  # Number of packets before blocking an IP
suspicious_ips = {}

# Admin Privileges
def run_as_admin():
    if ctypes.windll.shell32.IsUserAnAdmin():
        return
    else:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()

run_as_admin()

# Database Setup
DB_FILE = "firewall_rules.db"

def setup_database():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS blocked_ips (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip TEXT UNIQUE)''')
    conn.commit()
    conn.close()

setup_database()

# Function to Refresh Windows Firewall
def refresh_firewall():
    os.system("netsh advfirewall reset")
    os.system("netsh advfirewall set allprofiles state on")
    messagebox.showinfo("Firewall", "Windows Firewall refreshed successfully!")

# Function to Block IP
def block_ip(ip):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT ip FROM blocked_ips WHERE ip=?", (ip,))
    if cursor.fetchone():
        conn.close()
        return
    
    command_in = f'netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block remoteip={ip}'
    command_out = f'netsh advfirewall firewall add rule name="Block {ip}" dir=out action=block remoteip={ip}'
    os.system(command_in)
    os.system(command_out)
    cursor.execute("INSERT INTO blocked_ips (ip) VALUES (?)", (ip,))
    conn.commit()
    conn.close()
    update_blocked_list()
    messagebox.showinfo("Firewall", f"Automatically blocked suspicious IP: {ip}")

# Packet Sniffing Function
def monitor_network():
    loop = asyncio.new_event_loop()  # Create a new event loop
    asyncio.set_event_loop(loop)  # Set it as the current event loop

    try:
        capture = pyshark.LiveCapture(interface='Wi-Fi')  # Change interface accordingly
        for packet in capture.sniff_continuously(packet_count=10):
            if hasattr(packet, 'ip'):
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                print(f"Packet from {src_ip} to {dst_ip}")

                # IP Monitoring Logic
                if src_ip in suspicious_ips:
                    suspicious_ips[src_ip] += 1
                else:
                    suspicious_ips[src_ip] = 1

                if suspicious_ips[src_ip] > THRESHOLD:
                    block_ip(src_ip)

    except Exception as e:
        print(f"Error in monitoring: {e}")

# Function to Start Sniffing in Background
def start_monitoring():
    sniffing_thread = threading.Thread(target=monitor_network, daemon=True)
    sniffing_thread.start()
    messagebox.showinfo("Monitoring", "Network monitoring started!")

# GUI Setup
root = tk.Tk()
root.title("Windows Application Firewall")
root.geometry("500x500")

ttk.Button(root, text="Start Monitoring", command=start_monitoring).pack(pady=5)

ttk.Button(root, text="Refresh Firewall", command=refresh_firewall).pack(pady=5)

tk.Label(root, text="Blocked IPs:").pack()
blocked_listbox = tk.Listbox(root, width=50, height=10)
blocked_listbox.pack()

def update_blocked_list():
    blocked_listbox.delete(0, tk.END)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT ip FROM blocked_ips")
    for row in cursor.fetchall():
        blocked_listbox.insert(tk.END, f"IP: {row[0]}")
    conn.close()

update_blocked_list()
root.mainloop()
