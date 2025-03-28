import os
import sqlite3
import tkinter as tk
from tkinter import filedialog, messagebox
import ctypes
import sys

def run_as_admin():
    if ctypes.windll.shell32.IsUserAnAdmin():
        return  # Already running as admin
    else:
        # Relaunch the script with admin privileges
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
                        ip TEXT,
                        application TEXT,
                        protocol TEXT,
                        port TEXT)''')
    conn.commit()
    conn.close()

setup_database()

# Function to Add Rule
def add_rule():
    ip = ip_entry.get()
    application = app_entry.get()
    protocol = protocol_var.get()
    port = port_entry.get()

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    if application:
        os.system(f'netsh advfirewall firewall add rule name="Block {application}" dir=in action=block program="{application}"')
        os.system(f'netsh advfirewall firewall add rule name="Block {application}" dir=out action=block program="{application}"')
        cursor.execute("INSERT INTO blocked_ips (application) VALUES (?)", (application,))
        messagebox.showinfo("Success", f"Blocked Application: {application}")
    
    if ip:
        os.system(f'netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block remoteip={ip}')
        os.system(f'netsh advfirewall firewall add rule name="Block {ip}" dir=out action=block remoteip={ip}')
        cursor.execute("INSERT INTO blocked_ips (ip) VALUES (?)", (ip,))
        messagebox.showinfo("Success", f"Blocked IP: {ip}")
    
    if port and protocol:
        os.system(f'netsh advfirewall firewall add rule name="Block {protocol} {port}" dir=in action=block protocol={protocol} localport={port}')
        os.system(f'netsh advfirewall firewall add rule name="Block {protocol} {port}" dir=out action=block protocol={protocol} localport={port}')
        cursor.execute("INSERT INTO blocked_ips (protocol, port) VALUES (?, ?)", (protocol, port))
        messagebox.showinfo("Success", f"Blocked {protocol} on port {port}")
    
    conn.commit()
    conn.close()
    update_blocked_list()

# Function to Remove Rule
def remove_rule():
    selected = blocked_listbox.curselection()
    if not selected:
        messagebox.showwarning("Warning", "Select a rule to remove!")
        return

    rule = blocked_listbox.get(selected)
    rule_parts = rule.split(" | ")

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    if "App:" in rule:
        app_name = rule_parts[1].split(": ")[1]
        os.system(f'netsh advfirewall firewall delete rule name="Block {app_name}"')
        cursor.execute("DELETE FROM blocked_ips WHERE application=?", (app_name,))
    elif "IP:" in rule:
        ip_addr = rule_parts[1].split(": ")[1]
        os.system(f'netsh advfirewall firewall delete rule name="Block {ip_addr}"')
        cursor.execute("DELETE FROM blocked_ips WHERE ip=?", (ip_addr,))
    elif "Port:" in rule:
        proto = rule_parts[1].split(": ")[1]
        port_num = rule_parts[2].split(": ")[1]
        os.system(f'netsh advfirewall firewall delete rule name="Block {proto} {port_num}"')
        cursor.execute("DELETE FROM blocked_ips WHERE protocol=? AND port=?", (proto, port_num))
    
    conn.commit()
    conn.close()
    update_blocked_list()
    messagebox.showinfo("Success", "Rule removed successfully!")

# Function to Browse Application
def browse_app():
    filename = filedialog.askopenfilename(title="Select an Application", filetypes=[("Executable Files", "*.exe")])
    app_entry.delete(0, tk.END)
    app_entry.insert(0, filename)

# Function to Update Blocked List
def update_blocked_list():
    blocked_listbox.delete(0, tk.END)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM blocked_ips")
    rules = cursor.fetchall()
    conn.close()

    for rule in rules:
        rule_id, ip, app, proto, port = rule
        if app:
            blocked_listbox.insert(tk.END, f"App: {app}")
        elif ip:
            blocked_listbox.insert(tk.END, f"IP: {ip}")
        elif proto and port:
            blocked_listbox.insert(tk.END, f"Port: {proto} | Port: {port}")

# GUI Setup
root = tk.Tk()
root.title("Windows Application Firewall")
root.geometry("500x550")
root.configure(bg="#2C3E50")

# Labels & Inputs
tk.Label(root, text="Block by IP:", fg="white", bg="#2C3E50").pack()
ip_entry = tk.Entry(root, width=30)
ip_entry.pack()

tk.Label(root, text="Block by Application:", fg="white", bg="#2C3E50").pack()
app_entry = tk.Entry(root, width=30)
app_entry.pack()
tk.Button(root, text="Browse", command=browse_app, bg="#3498DB", fg="white").pack()

tk.Label(root, text="Block by Protocol and Port:", fg="white", bg="#2C3E50").pack()
protocol_var = tk.StringVar(root)
protocol_var.set("TCP")
protocol_menu = tk.OptionMenu(root, protocol_var, "TCP", "UDP")
protocol_menu.pack()
port_entry = tk.Entry(root, width=30)
port_entry.pack()

# Buttons
tk.Button(root, text="Add Rule", command=add_rule, bg="#27AE60", fg="white").pack(pady=5)
tk.Button(root, text="Remove Rule", command=remove_rule, bg="#E74C3C", fg="white").pack(pady=5)

# Blocked Listbox
tk.Label(root, text="Blocked Rules:", fg="white", bg="#2C3E50").pack()
blocked_listbox = tk.Listbox(root, width=50, height=10)
blocked_listbox.pack()

update_blocked_list()

root.mainloop()
