import os
import sqlite3
import tkinter as tk
from tkinter import messagebox

DB_FILE = "firewall_rules.db"

def create_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY,
            application TEXT,
            ip_address TEXT
        )
    """)
    conn.commit()
    conn.close()

def update_blocked_list():
    app_listbox.delete(0, tk.END)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT application FROM blocked_ips")
    for row in cursor.fetchall():
        app_listbox.insert(tk.END, row[0])
    conn.close()

def block_application(app_name):
    command_in = f'netsh advfirewall firewall add rule name="Block {app_name}" dir=in action=block program="{app_name}"'
    command_out = f'netsh advfirewall firewall add rule name="Block {app_name}" dir=out action=block program="{app_name}"'
    os.system(command_in)
    os.system(command_out)

def unblock_application():
    selected_app = app_listbox.get(tk.ACTIVE)
    if not selected_app:
        messagebox.showerror("Error", "Please select an application to unblock.")
        return

    command_in = f'netsh advfirewall firewall delete rule name="Block {selected_app}" dir=in'
    command_out = f'netsh advfirewall firewall delete rule name="Block {selected_app}" dir=out'
    os.system(command_in)
    os.system(command_out)

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM blocked_ips WHERE application=?", (selected_app,))
    conn.commit()
    conn.close()

    update_blocked_list()
    messagebox.showinfo("Firewall", f"Unblocked Application: {selected_app}")

root = tk.Tk()
root.title("Firewall Manager")

app_listbox = tk.Listbox(root, width=50)
app_listbox.pack(pady=10)
update_blocked_list()

unblock_button = tk.Button(root, text="Unblock Selected Application", command=unblock_application)
unblock_button.pack(pady=5)

root.mainloop()

create_db()
