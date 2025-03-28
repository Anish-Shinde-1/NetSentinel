import os
import sqlite3
import tkinter as tk
from tkinter import filedialog, messagebox

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
        command = f'netsh advfirewall firewall add rule name="Block {application}" dir=in action=block program="{application}"'
        os.system(command)
        cursor.execute("INSERT INTO blocked_ips (application) VALUES (?)", (application,))
        messagebox.showinfo("Success", f"Blocked Application: {application}")

    if ip:
        command = f'netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block remoteip={ip}'
        os.system(command)
        cursor.execute("INSERT INTO blocked_ips (ip) VALUES (?)", (ip,))
        messagebox.showinfo("Success", f"Blocked IP: {ip}")

    if port and protocol:
        command = f'netsh advfirewall firewall add rule name="Block {protocol} {port}" dir=in action=block protocol={protocol} localport={port}'
        os.system(command)
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
        messagebox.showinfo("Success", f"Unblocked Application: {app_name}")

    elif "IP:" in rule:
        ip_addr = rule_parts[1].split(": ")[1]
        os.system(f'netsh advfirewall firewall delete rule name="Block {ip_addr}"')
        cursor.execute("DELETE FROM blocked_ips WHERE ip=?", (ip_addr,))
        messagebox.showinfo("Success", f"Unblocked IP: {ip_addr}")

    elif "Port:" in rule:
        proto = rule_parts[1].split(": ")[1]
        port_num = rule_parts[2].split(": ")[1]
        os.system(f'netsh advfirewall firewall delete rule name="Block {proto} {port_num}"')
        cursor.execute("DELETE FROM blocked_ips WHERE protocol=? AND port=?", (proto, port_num))
        messagebox.showinfo("Success", f"Unblocked {proto} on port {port_num}")

    conn.commit()
    conn.close()
    update_blocked_list()

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
root.geometry("500x500")

# IP Blocking
tk.Label(root, text="Block by IP:").pack()
ip_entry = tk.Entry(root, width=30)
ip_entry.pack()

# Application Blocking
tk.Label(root, text="Block by Application:").pack()
app_entry = tk.Entry(root, width=30)
app_entry.pack()
tk.Button(root, text="Browse", command=browse_app).pack()

# Port Blocking
tk.Label(root, text="Block by Protocol and Port:").pack()
protocol_var = tk.StringVar(root)
protocol_var.set("TCP")
protocol_menu = tk.OptionMenu(root, protocol_var, "TCP", "UDP")
protocol_menu.pack()

port_entry = tk.Entry(root, width=30)
port_entry.pack()

# Buttons to Add & Remove Rules
tk.Button(root, text="Add Rule", command=add_rule, bg="green", fg="white").pack(pady=5)
tk.Button(root, text="Remove Rule", command=remove_rule, bg="red", fg="white").pack(pady=5)

# Blocked Listbox
tk.Label(root, text="Blocked Rules:").pack()
blocked_listbox = tk.Listbox(root, width=50, height=10)
blocked_listbox.pack()

update_blocked_list()

root.mainloop()
