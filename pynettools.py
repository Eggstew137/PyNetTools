import os
import sys
import subprocess
import threading
import shutil
import importlib
from pathlib import Path
import tkinter as tk
from tkinter import scrolledtext, messagebox
import paramiko
import telnetlib

# --- GUI Style Fix ---
default_bg = "#f0f0f0"
default_fg = "#000000"

# --- Self Install ---
def self_install():
    target_local = Path.home() / "pynettools"
    current_path = Path(__file__).resolve()

    if current_path.samefile(target_local):
        return

    print("📦 PyNetTools not found in ~/ — installing...")

    os.makedirs(target_local.parent, exist_ok=True)

    with open(current_path, "r") as src:
        content = src.read()

    if not content.startswith("#!"):
        content = "#!/usr/bin/env python3\n" + content

    with open(target_local, "w") as dst:
        dst.write(content)

    os.chmod(target_local, 0o755)

    print(f"✅ Installed to: {target_local}")
    print("🔁 Please re-run using:\n")
    print(f"    python3 ~/pynettools\n")
    sys.exit(0)

# --- Feature Definitions ---
features = {
    "iperf3": (["iperf3"], []),
    "speedtest-cli": (["speedtest-cli"], []),
    "nmap": (["nmap"], []),
    "arp-scan": (["arp-scan"], []),
    "dnsutils": (["bind"], []),
    "iptables": ([], []),  # Not supported on macOS
    "telnet": (["telnet"], []),
    "paramiko": ([], ["paramiko"]),
    "python3-tk": ([], []),
}

# --- Install Helpers ---
def run_cmd(cmd, output_box):
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for line in iter(process.stdout.readline, ''):
        output_box.insert(tk.END, line)
        output_box.see(tk.END)
    process.stdout.close()
    process.wait()

def is_brew_installed(pkg):
    result = subprocess.run(f"brew list {pkg}", shell=True,
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
    output_box.insert(tk.END, "Running brew update...\n")
    run_cmd("brew update", output_box)

    selected_features = [feat for feat, var in vars_checkboxes.items() if var.get()]
    if not selected_features:
        messagebox.showinfo("No Selection", "Please select at least one feature to install.")
        install_btn.config(state=tk.NORMAL)
        return

    for feat in selected_features:
        brew_pkgs, pip_pkgs = features[feat]

        to_install_brew = [pkg for pkg in brew_pkgs if not is_brew_installed(pkg)]
        if to_install_brew:
            output_box.insert(tk.END, f"\nInstalling Brew packages: {' '.join(to_install_brew)}\n")
            run_cmd(f"brew install {' '.join(to_install_brew)}", output_box)

        to_install_pip = [pkg for pkg in pip_pkgs if not is_pip_installed(pkg)]
        if to_install_pip:
            output_box.insert(tk.END, f"\nInstalling PIP packages: {' '.join(to_install_pip)}\n")
            run_cmd(f"pip3 install {' '.join(to_install_pip)}", output_box)

    output_box.insert(tk.END, "\n✅ Installation complete! Launching Toolbox...\n")
    root.after(2000, switch_to_toolbox)

def run_install_thread():
    threading.Thread(target=update_and_install, daemon=True).start()

# --- Toolbox Commands ---
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

def ping_test(): run_command(f"ping -c 4 {get_ip_input()}")
def port_scan(): run_command(f"nmap -F {get_ip_input()}")
def device_scan(): run_command("arp-scan --interface=en0 --localnet")
def dns_lookup(): run_command("dig google.com")
def firewall_check(): output_box_toolbox.insert(tk.END, "⚠️ iptables not available on macOS\n")
def ip_info(): run_command("ifconfig")
def speed_test(): run_command("speedtest-cli --simple")
def iperf_server(): run_command("iperf3 -s")
def iperf_client(): run_command(f"iperf3 -c {get_ip_input()}")

def ssh_command():
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ssh_ip_entry.get(), username=ssh_user_entry.get(), password=ssh_pass_entry.get(), timeout=5)
        stdin, stdout, stderr = client.exec_command(ssh_cmd_entry.get())
        output_box_toolbox.insert(tk.END, stdout.read().decode() + stderr.read().decode())
        client.close()
    except Exception as e:
        output_box_toolbox.insert(tk.END, f"SSH Error: {str(e)}")

def telnet_command():
    try:
        tn = telnetlib.Telnet(ssh_ip_entry.get(), timeout=5)
        tn.read_until(b"login: ")
        tn.write(ssh_user_entry.get().encode() + b"\n")
        tn.read_until(b"Password: ")
        tn.write(ssh_pass_entry.get().encode() + b"\n")
        tn.write(ssh_cmd_entry.get().encode() + b"\nexit\n")
        output_box_toolbox.insert(tk.END, tn.read_all().decode())
    except Exception as e:
        output_box_toolbox.insert(tk.END, f"Telnet Error: {str(e)}")

def save_report():
    try:
        with open(Path.home() / "network_report.txt", "w") as f:
            f.write(output_box_toolbox.get("1.0", tk.END))
        output_box_toolbox.insert(tk.END, "\n✅ Saved to ~/network_report.txt")
    except Exception as e:
        output_box_toolbox.insert(tk.END, f"\n❌ {e}")

def exit_app():
    root.destroy()

def switch_to_toolbox():
    installer_frame.pack_forget()
    toolbox_frame.pack(fill=tk.BOTH, expand=True)

# --- GUI ---
root = tk.Tk()
root.title("PyNetTools Installer/Updater + App (macOS)")
root.geometry("700x440")
root.configure(bg=default_bg)

installer_frame = tk.Frame(root, bg=default_bg)
installer_frame.pack(fill=tk.BOTH, expand=True)

tk.Label(installer_frame, text="Select features to install:", font=("Arial", 14),
         bg=default_bg, fg=default_fg).pack(pady=10)

vars_checkboxes = {}
for feat in features:
    var = tk.BooleanVar()
    cb = tk.Checkbutton(installer_frame, text=feat, variable=var,
                        bg=default_bg, fg=default_fg, selectcolor="#ccc")
    cb.pack(anchor="w", padx=20)
    vars_checkboxes[feat] = var

install_btn = tk.Button(installer_frame, text="Update & Install Selected",
                        command=run_install_thread)
install_btn.pack(pady=10)

output_box = scrolledtext.ScrolledText(installer_frame, height=10,
                                       bg=default_bg, fg=default_fg,
                                       insertbackground=default_fg)
output_box.pack(fill=tk.BOTH, padx=10, pady=10)

# --- Toolbox Frame ---
toolbox_frame = tk.Frame(root, bg=default_bg)

top_frame = tk.Frame(toolbox_frame, bg=default_bg)
top_frame.pack(fill=tk.X, padx=5, pady=3)
tk.Label(top_frame, text="Target IP / Host:", bg=default_bg, fg=default_fg).pack(side=tk.LEFT)
ip_entry = tk.Entry(top_frame, width=20, bg="#fff", fg=default_fg, insertbackground=default_fg)
ip_entry.pack(side=tk.LEFT)
ip_entry.insert(0, "8.8.8.8")

main_frame = tk.Frame(toolbox_frame, bg=default_bg)
main_frame.pack(fill=tk.BOTH, expand=True)

sidebar = tk.Frame(main_frame, width=110, bg="#ddd")
sidebar.pack(side=tk.LEFT, fill=tk.Y)

content = tk.Frame(main_frame, bg=default_bg)
content.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

categories = ["Network Tools", "Speed Tests", "Remote Access", "Utilities"]
frames = {}

def show_frame(cat):
    for f in frames.values():
        f.pack_forget()
    frames[cat].pack(fill=tk.BOTH, expand=True)

for cat in categories:
    tk.Button(sidebar, text=cat, width=12, command=lambda c=cat: show_frame(c)).pack(pady=3)

# Network Tools
ntf = tk.Frame(content, bg=default_bg)
frames["Network Tools"] = ntf
nt_buttons = [
    ("Ping Test", ping_test), ("Port Scan", port_scan),
    ("Device Scan", device_scan), ("DNS Lookup", dns_lookup),
    ("Firewall Check", firewall_check), ("IP Info", ip_info)
]
for i, (txt, cmd) in enumerate(nt_buttons):
    tk.Button(ntf, text=txt, width=15, height=2, command=cmd).grid(row=i // 2, column=i % 2, padx=5, pady=5)

# Speed Tests
stf = tk.Frame(content, bg=default_bg)
frames["Speed Tests"] = stf
for i, (txt, cmd) in enumerate([("Speed Test", speed_test),
                                ("iPerf Server", iperf_server),
                                ("iPerf Client", iperf_client)]):
    tk.Button(stf, text=txt, width=15, height=2, command=cmd).grid(row=0, column=i, padx=5, pady=5)

# Remote Access
raf = tk.Frame(content, bg=default_bg)
frames["Remote Access"] = raf
tk.Label(raf, text="Remote IP:", bg=default_bg, fg=default_fg).grid(row=0, column=0)
ssh_ip_entry = tk.Entry(raf, width=15, bg="#fff", fg=default_fg, insertbackground=default_fg)
ssh_ip_entry.grid(row=0, column=1)
tk.Label(raf, text="User:", bg=default_bg, fg=default_fg).grid(row=0, column=2)
ssh_user_entry = tk.Entry(raf, width=12, bg="#fff", fg=default_fg, insertbackground=default_fg)
ssh_user_entry.grid(row=0, column=3)
tk.Label(raf, text="Pass:", bg=default_bg, fg=default_fg).grid(row=0, column=4)
ssh_pass_entry = tk.Entry(raf, show="*", width=12, bg="#fff", fg=default_fg, insertbackground=default_fg)
ssh_pass_entry.grid(row=0, column=5)
tk.Label(raf, text="Command:", bg=default_bg, fg=default_fg).grid(row=1, column=0)
ssh_cmd_entry = tk.Entry(raf, width=50, bg="#fff", fg=default_fg, insertbackground=default_fg)
ssh_cmd_entry.grid(row=1, column=1, columnspan=5, padx=3, pady=3)
tk.Button(raf, text="SSH Exec", command=ssh_command).grid(row=2, column=1, pady=5)
tk.Button(raf, text="Telnet Exec", command=telnet_command).grid(row=2, column=2, pady=5)

# Utilities
uf = tk.Frame(content, bg=default_bg)
frames["Utilities"] = uf
tk.Button(uf, text="Save Report", width=15, height=2, command=save_report).pack(pady=5)
tk.Button(uf, text="Exit", width=15, height=2, command=exit_app).pack(pady=5)

output_box_toolbox = scrolledtext.ScrolledText(toolbox_frame, height=8, width=60,
                                               wrap=tk.WORD, bg=default_bg, fg=default_fg,
                                               insertbackground=default_fg)
output_box_toolbox.pack(padx=5, pady=5, fill=tk.X)

show_frame("Network Tools")

root.mainloop()
