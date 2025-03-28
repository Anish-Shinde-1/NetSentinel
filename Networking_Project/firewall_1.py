import os
import sqlite3
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
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
    selected_item = blocked_tree.selection()
    if not selected_item:
        messagebox.showwarning("Warning", "Select a rule to remove!")
        return

    rule_id = blocked_tree.item(selected_item, "values")[0]
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT ip, application, protocol, port FROM blocked_ips WHERE id=?", (rule_id,))
    rule = cursor.fetchone()
    
    if rule:
        ip, app, proto, port = rule
        if app:
            os.system(f'netsh advfirewall firewall delete rule name="Block {app}"')
            messagebox.showinfo("Success", f"Unblocked Application: {app}")
        elif ip:
            os.system(f'netsh advfirewall firewall delete rule name="Block {ip}"')
            messagebox.showinfo("Success", f"Unblocked IP: {ip}")
        elif proto and port:
            os.system(f'netsh advfirewall firewall delete rule name="Block {proto} {port}"')
            messagebox.showinfo("Success", f"Unblocked {proto} on port {port}")
    
    cursor.execute("DELETE FROM blocked_ips WHERE id=?", (rule_id,))
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
    blocked_tree.delete(*blocked_tree.get_children())
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM blocked_ips")
    rules = cursor.fetchall()
    conn.close()

    for rule in rules:
        blocked_tree.insert("", tk.END, values=rule)

# GUI Setup
root = tk.Tk()
root.title("Windows Application Firewall")
root.geometry("600x500")

frame = ttk.Frame(root, padding=10)
frame.pack(fill=tk.BOTH, expand=True)

# IP Blocking
ttk.Label(frame, text="Block by IP:").grid(row=0, column=0, sticky=tk.W)
ip_entry = ttk.Entry(frame, width=30)
ip_entry.grid(row=0, column=1)

# Application Blocking
ttk.Label(frame, text="Block by Application:").grid(row=1, column=0, sticky=tk.W)
app_entry = ttk.Entry(frame, width=30)
app_entry.grid(row=1, column=1)
ttk.Button(frame, text="Browse", command=browse_app).grid(row=1, column=2)

# Port Blocking
ttk.Label(frame, text="Block by Protocol and Port:").grid(row=2, column=0, sticky=tk.W)
protocol_var = tk.StringVar()
protocol_var.set("TCP")
protocol_menu = ttk.Combobox(frame, textvariable=protocol_var, values=["TCP", "UDP"], width=5)
protocol_menu.grid(row=2, column=1, sticky=tk.W)

port_entry = ttk.Entry(frame, width=10)
port_entry.grid(row=2, column=2, sticky=tk.W)

# Buttons to Add & Remove Rules
ttk.Button(frame, text="Add Rule", command=add_rule).grid(row=3, column=0, pady=5)
ttk.Button(frame, text="Remove Rule", command=remove_rule).grid(row=3, column=1, pady=5)

# Blocked Rules List
ttk.Label(frame, text="Blocked Rules:").grid(row=4, column=0, sticky=tk.W, pady=5)

columns = ("ID", "IP", "Application", "Protocol", "Port")
blocked_tree = ttk.Treeview(frame, columns=columns, show="headings", height=8)
for col in columns:
    blocked_tree.heading(col, text=col)
    blocked_tree.column(col, width=100)
blocked_tree.grid(row=5, column=0, columnspan=3, sticky=tk.W+tk.E)

update_blocked_list()
root.mainloop()
