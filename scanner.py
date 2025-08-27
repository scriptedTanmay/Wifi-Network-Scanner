import customtkinter as ctk
from tkinter import filedialog, messagebox
from scapy.all import ARP, Ether, srp
import requests, socket, csv

# ---------------------- Network Scan ----------------------
def get_vendor(mac):
    try:
        response = requests.get(f"https://api.macvendors.com/{mac}", timeout=3)
        if response.status_code == 200:
            return response.text
    except:
        return "Unknown"
    return "Unknown"

def scan_network(ip_range):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []
    for sent, received in result:
        vendor = get_vendor(received.hwsrc)
        devices.append((received.psrc, received.hwsrc, vendor))
    return devices

# ---------------------- Port Scan ----------------------
def scan_ports(ip):
    open_ports = []
    common_ports = [21,22,23,25,53,80,110,139,143,443,445,3389]  # Common ports
    for port in common_ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            s.close()
        except:
            pass
    return open_ports

# ---------------------- GUI Functions ----------------------
def start_scan():
    ip_range = entry.get()
    if not ip_range:
        messagebox.showerror("Error", "Please enter IP range (e.g., 192.168.1.1/24)")
        return

    devices = scan_network(ip_range)

    table.delete("all")  # Clear old results
    for ip, mac, vendor in devices:
        table.insert("", "end", values=(ip, mac, vendor, "Click to Scan Ports"))

def on_row_click(event):
    selected = table.focus()
    if selected:
        values = table.item(selected, "values")
        ip = values[0]
        ports = scan_ports(ip)
        ports_str = ", ".join(map(str, ports)) if ports else "No open ports"
        messagebox.showinfo("Port Scan Result", f"Device: {ip}\nOpen Ports: {ports_str}")

def export_csv():
    filepath = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files","*.csv")])
    if not filepath:
        return
    rows = []
    for row in table.get_children():
        rows.append(table.item(row)["values"])

    with open(filepath, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["IP Address", "MAC Address", "Vendor", "Note"])
        writer.writerows(rows)
    messagebox.showinfo("Export", f"Data exported successfully to {filepath}")

# ---------------------- GUI Layout ----------------------
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

app = ctk.CTk()
app.title("Advanced Network & Port Scanner")
app.geometry("700x500")

frame = ctk.CTkFrame(app)
frame.pack(pady=10, padx=10, fill="x")

label = ctk.CTkLabel(frame, text="Enter IP Range (e.g. 192.168.1.1/24):")
label.pack(side="left", padx=5)

entry = ctk.CTkEntry(frame, width=200)
entry.pack(side="left", padx=5)

button = ctk.CTkButton(frame, text="Scan Network", command=start_scan)
button.pack(side="left", padx=5)

export_btn = ctk.CTkButton(frame, text="Export CSV", command=export_csv)
export_btn.pack(side="left", padx=5)

# Table
import tkinter.ttk as ttk
columns = ("IP Address", "MAC Address", "Vendor", "Note")
table = ttk.Treeview(app, columns=columns, show="headings")
for col in columns:
    table.heading(col, text=col)
    table.column(col, width=150)

table.pack(fill="both", expand=True, padx=10, pady=10)
table.bind("<Double-1>", on_row_click)  # Double click to scan ports

app.mainloop()
