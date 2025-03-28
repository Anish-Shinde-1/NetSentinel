import tkinter as tk
from tkinter import ttk
from ttkthemes import ThemedStyle

# Root window
root = tk.Tk()
root.title("Firewall Management")
root.geometry("900x550")
root.configure(bg="#0f0f0f")

# Styling
style = ThemedStyle(root)
style.set_theme("equilux")
style.configure("TFrame", background="#0f0f0f")
style.configure("TLabel", background="#0f0f0f", foreground="white", font=("Arial", 12))
style.configure("TButton", background="#1e1e1e", foreground="white", font=("Arial", 10))
style.configure("Treeview", background="#1e1e1e", foreground="white", fieldbackground="#1e1e1e", rowheight=25)
style.configure("Treeview.Heading", font=("Arial", 11, "bold"))
style.configure("TCombobox", fieldbackground="#1e1e1e", background="#1e1e1e", foreground="white")

# Greeting
greeting = ttk.Label(root, text="Hi Ankit", font=("Arial", 14, "bold"))
greeting.pack(pady=10, padx=20, anchor="w")

# Input Section
frame = ttk.Frame(root)
frame.pack(pady=10, padx=20, fill="x")

endpoints = ttk.Combobox(frame, values=["Select Endpoint"], width=18, state="readonly")
endpoints.grid(row=0, column=0, padx=5, pady=5)
endpoints.set("Select Endpoint")

ip_entry = ttk.Entry(frame, width=18)
ip_entry.grid(row=0, column=1, padx=5, pady=5)
ip_entry.insert(0, "Enter IP Address")

app_entry = ttk.Entry(frame, width=18)
app_entry.grid(row=0, column=2, padx=5, pady=5)
app_entry.insert(0, "App Name")

domain_entry = ttk.Entry(frame, width=18)
domain_entry.grid(row=0, column=3, padx=5, pady=5)
domain_entry.insert(0, "Domain")

action_combobox = ttk.Combobox(frame, values=["Block", "Allow"], width=10, state="readonly")
action_combobox.grid(row=0, column=4, padx=5, pady=5)
action_combobox.set("Block")

add_rule_btn = ttk.Button(frame, text="Add Rule", style="TButton")
add_rule_btn.grid(row=0, column=5, padx=5, pady=5)

# Firewall Rules Table
firewall_label = ttk.Label(root, text="Firewall Rules", font=("Arial", 12, "bold"))
firewall_label.pack(pady=10, padx=20, anchor="w")

columns = ("ID", "Application Name", "IP Address", "Domain", "Action", "Actions")
firewall_table = ttk.Treeview(root, columns=columns, show="headings", height=5)
for col in columns:
    firewall_table.heading(col, text=col)
    firewall_table.column(col, width=120, anchor="center")
firewall_table.pack(pady=5, padx=20, fill="x")

# Connected Endpoints Table
endpoints_label = ttk.Label(root, text="Connected Endpoints", font=("Arial", 12, "bold"))
endpoints_label.pack(pady=10, padx=20, anchor="w")

columns_endpoints = ("Name", "IP Address", "Action")
endpoints_table = ttk.Treeview(root, columns=columns_endpoints, show="headings", height=3)
for col in columns_endpoints:
    endpoints_table.heading(col, text=col)
    endpoints_table.column(col, width=120, anchor="center")
endpoints_table.pack(pady=5, padx=20, fill="x")

root.mainloop()