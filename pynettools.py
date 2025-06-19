import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import subprocess
import threading
import importlib
import paramiko
import telnetlib

# Features and required packages
features = {
    "iperf3": (["iperf3"], []),
    "speedtest-cli": (["speedtest-cli"], []),
    "nmap": (["nmap"], []),
    "arp-scan": (["arp-scan"], []),
    "dnsutils": (["dnsutils"], []),
    "iptables": (["iptables"], []),
    "telnet": (["telnet"], []),
    "paramiko": ([], ["paramiko"]),
    "python3-tk": (["python3-tk"], []),
}

# --- Installer Functions ---
def run_cmd(cmd, output_box):
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for line in iter(process.stdout.readline, ''):
        output_box.insert(tk.END, line)
        output_box.see(tk.END)
    process.stdout.close()
    process.wait()

def is_apt_installed(pkg):
    result = subprocess.run(f"dpkg -s {pkg}", shell=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode == 0

def is_pip_installed(pkg):
    try:
        importlib.import_module(pkg)
        return True
    except ImportError:
        return False

def update_and_install():
    install_btn.config(state=tk.DISABLED)
    output_box.delete('1.0', tk.END)
    output_box.insert(tk.END, "Running sudo apt update...\n")
    run_cmd("sudo apt update", output_box)

    selected_features = [feat for feat, var in vars_checkboxes.items() if var.get()]
    if not selected_features:
        messagebox.showinfo("No Selection", "Please select at least one feature to install.")
        install_btn.config(state=tk.NORMAL)
        return

    for feat in selected_features:
        apt_pkgs, pip_pkgs = features[feat]

        # Check APT packages
        to_install_apt = []
        for pkg in apt_pkgs:
            if is_apt_installed(pkg):
                output_box.insert(tk.END, f"\n[SKIP] APT package '{pkg}' already installed.\n")
            else:
                to_install_apt.append(pkg)
        if to_install_apt:
            output_box.insert(tk.END, f"\nInstalling APT packages for {feat}: {' '.join(to_install_apt)}\n")
            run_cmd(f"sudo apt install -y {' '.join(to_install_apt)}", output_box)

        # Check PIP packages
        to_install_pip = []
        for pkg in pip_pkgs:
            if is_pip_installed(pkg):
                output_box.insert(tk.END, f"\n[SKIP] PIP package '{pkg}' already installed.\n")
            else:
                to_install_pip.append(pkg)
        if to_install_pip:
            output_box.insert(tk.END, f"\nInstalling PIP packages for {feat}: {' '.join(to_install_pip)}\n")
            run_cmd(f"pip3 install {' '.join(to_install_pip)}", output_box)

    output_box.insert(tk.END, "\nInstallation complete! Launching Toolbox...\n")
    root.after(2000, switch_to_toolbox)

def run_install_thread():
    threading.Thread(target=update_and_install, daemon=True).start()

# --- Toolbox Functions ---
def run_command(cmd):
    output_box_toolbox.delete('1.0', tk.END)
    try:
        result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
        output_box_toolbox.insert(tk.END, result)
    except subprocess.CalledProcessError as e:
        output_box_toolbox.insert(tk.END, f"Error:\n{e.output}")

def get_ip_input():
    ip = ip_entry.get().strip()
    return ip if ip else "8.8.8.8"

# Network Tools
def ping_test():
    run_command(f"ping -c 4 {get_ip_input()}")

def port_scan():
    run_command(f"nmap -F {get_ip_input()}")

def device_scan():
    run_command("arp-scan --interface=eth0 --localnet")

def dns_lookup():
    run_command("dig google.com")

def firewall_check():
    run_command("iptables -L")

def ip_info():
    run_command("ip a")

# Speed Tests
def speed_test():
    run_command("speedtest-cli --simple")

def iperf_server():
    run_command("iperf3 -s")

def iperf_client():
    run_command(f"iperf3 -c {get_ip_input()}")

# SSH/Telnet
def ssh_command():
    ip = ssh_ip_entry.get().strip()
    user = ssh_user_entry.get().strip()
    passwd = ssh_pass_entry.get().strip()
    cmd = ssh_cmd_entry.get().strip()
    output_box_toolbox.delete('1.0', tk.END)
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=user, password=passwd, timeout=5)
        stdin, stdout, stderr = client.exec_command(cmd)
        output_box_toolbox.insert(tk.END, stdout.read().decode() + stderr.read().decode())
        client.close()
    except Exception as e:
        output_box_toolbox.insert(tk.END, f"SSH Error: {str(e)}")

def telnet_command():
    ip = ssh_ip_entry.get().strip()
    user = ssh_user_entry.get().strip()
    passwd = ssh_pass_entry.get().strip()
    cmd = ssh_cmd_entry.get().strip()
    output_box_toolbox.delete('1.0', tk.END)
    try:
        tn = telnetlib.Telnet(ip, timeout=5)
        tn.read_until(b"login: ")
        tn.write(user.encode('ascii') + b"\n")
        tn.read_until(b"Password: ")
        tn.write(passwd.encode('ascii') + b"\n")
        tn.write(cmd.encode('ascii') + b"\n")
        tn.write(b"exit\n")
        output_box_toolbox.insert(tk.END, tn.read_all().decode('ascii'))
    except Exception as e:
        output_box_toolbox.insert(tk.END, f"Telnet Error: {str(e)}")

def save_report():
    try:
        with open("/boot/network_report.txt", "w") as f:
            f.write(output_box_toolbox.get("1.0", tk.END))
        output_box_toolbox.insert(tk.END, "\n✅ Report saved to /boot/network_report.txt")
    except Exception as e:
        output_box_toolbox.insert(tk.END, f"\n❌ Error saving report: {str(e)}")

def exit_app():
    root.destroy()

# --- UI SWITCH ---
def switch_to_toolbox():
    installer_frame.pack_forget()
    toolbox_frame.pack(fill=tk.BOTH, expand=True)

# --- Root Window ---
root = tk.Tk()
root.title("PiNet Toolbox Installer + App")
root.geometry("480x320")

# --- Installer Frame ---
installer_frame = tk.Frame(root)
installer_frame.pack(fill=tk.BOTH, expand=True)

tk.Label(installer_frame, text="Select features to install:", font=("Arial", 14)).pack(pady=10)

vars_checkboxes = {}
for feat in features.keys():
    var = tk.BooleanVar(value=False)
    cb = tk.Checkbutton(installer_frame, text=feat, variable=var)
    cb.pack(anchor="w", padx=20)
    vars_checkboxes[feat] = var

install_btn = tk.Button(installer_frame, text="Update & Install Selected", command=run_install_thread)
install_btn.pack(pady=10)

output_box = scrolledtext.ScrolledText(installer_frame, height=10)
output_box.pack(fill=tk.BOTH, padx=10, pady=10)

# --- Toolbox Frame (hidden initially) ---
toolbox_frame = tk.Frame(root)

# Top IP input
top_frame = tk.Frame(toolbox_frame)
top_frame.pack(fill=tk.X, padx=5, pady=3)
tk.Label(top_frame, text="Target IP / Host:").pack(side=tk.LEFT)
ip_entry = tk.Entry(top_frame, width=20)
ip_entry.pack(side=tk.LEFT)
ip_entry.insert(0, "8.8.8.8")

# Main area
main_frame = tk.Frame(toolbox_frame)
main_frame.pack(fill=tk.BOTH, expand=True)

# Sidebar
sidebar = tk.Frame(main_frame, width=110, bg="#ddd")
sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=2, pady=2)

# Content
content = tk.Frame(main_frame)
content.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=2, pady=2)

categories = ["Network Tools", "Speed Tests", "Remote Access", "Utilities"]
frames = {}

def show_frame(cat):
    for f in frames.values():
        f.pack_forget()
    frames[cat].pack(fill=tk.BOTH, expand=True)

for cat in categories:
    btn = tk.Button(sidebar, text=cat, width=12,
                    command=lambda c=cat: show_frame(c))
    btn.pack(pady=3)

# Network Tools Frame
frames["Network Tools"] = tk.Frame(content)
ntf = frames["Network Tools"]
nt_buttons = [
    ("Ping Test", ping_test),
    ("Port Scan", port_scan),
    ("Device Scan", device_scan),
    ("DNS Lookup", dns_lookup),
    ("Firewall Check", firewall_check),
    ("IP Info", ip_info),
]
for idx, (label, cmd) in enumerate(nt_buttons):
    tk.Button(ntf, text=label, width=15, height=2, command=cmd).grid(row=idx // 2, column=idx % 2, padx=5, pady=5)

# Speed Tests Frame
frames["Speed Tests"] = tk.Frame(content)
stf = frames["Speed Tests"]
st_buttons = [
    ("Speed Test", speed_test),
    ("iPerf Server", iperf_server),
    ("iPerf Client", iperf_client),
]
for idx, (label, cmd) in enumerate(st_buttons):
    tk.Button(stf, text=label, width=15, height=2, command=cmd).grid(row=0, column=idx, padx=5, pady=5)

# Remote Access Frame
frames["Remote Access"] = tk.Frame(content)
raf = frames["Remote Access"]
tk.Label(raf, text="Remote IP:").grid(row=0, column=0, sticky="e")
ssh_ip_entry = tk.Entry(raf, width=15)
ssh_ip_entry.grid(row=0, column=1, padx=3, pady=3)

tk.Label(raf, text="User:").grid(row=0, column=2, sticky="e")
ssh_user_entry = tk.Entry(raf, width=12)
ssh_user_entry.grid(row=0, column=3, padx=3, pady=3)

tk.Label(raf, text="Pass:").grid(row=0, column=4, sticky="e")
ssh_pass_entry = tk.Entry(raf, show="*", width=12)
ssh_pass_entry.grid(row=0, column=5, padx=3, pady=3)

tk.Label(raf, text="Command:").grid(row=1, column=0, sticky="e")
ssh_cmd_entry = tk.Entry(raf, width=50)
ssh_cmd_entry.grid(row=1, column=1, columnspan=5, padx=3, pady=3)

tk.Button(raf, text="SSH Exec", width=12, command=ssh_command).grid(row=2, column=1, pady=5)
tk.Button(raf, text="Telnet Exec", width=12, command=telnet_command).grid(row=2, column=2, pady=5)

# Utilities Frame
frames["Utilities"] = tk.Frame(content)
uf = frames["Utilities"]
utils_buttons = [
    ("Save Report", save_report),
    ("Exit", exit_app),
]
for idx, (label, cmd) in enumerate(utils_buttons):
    tk.Button(uf, text=label, width=15, height=2, command=cmd).grid(row=idx, column=0, padx=5, pady=5)

# Output Box at bottom (shared across all frames)
output_box_toolbox = scrolledtext.ScrolledText(toolbox_frame, height=8, width=60, wrap=tk.WORD)
output_box_toolbox.pack(padx=5, pady=5, fill=tk.X)

# Show default category when toolbox starts
show_frame("Network Tools")

root.mainloop()
