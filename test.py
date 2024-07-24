import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import nmap
import re
import requests
import os
import sys
import subprocess
import string

# Predefined unique key for access
PREDEFINED_KEY = "888"

def install_nmap():
    if os.name == 'nt':  # Windows
        nmap_installer_url = "https://nmap.org/dist/nmap-7.91-setup.exe"
        nmap_installer_path = "nmap-setup.exe"
        try:
            response = requests.get(nmap_installer_url, stream=True)
            with open(nmap_installer_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
            subprocess.call(nmap_installer_path)
            os.remove(nmap_installer_path)
        except Exception as e:
            messagebox.showerror("Installation Error", f"Error installing Nmap: {str(e)}")
            sys.exit()
    elif os.name == 'posix':  # macOS and Linux
        try:
            if os.system('command -v nmap') != 0:  # Check if nmap is not installed
                os.system('sudo apt-get install nmap -y' if 'ubuntu' in os.popen('cat /etc/os-release').read() else 'brew install nmap')
        except Exception as e:
            messagebox.showerror("Installation Error", f"Error installing Nmap: {str(e)}")
            sys.exit()

def check_and_install_dependencies():
    try:
        nmap.PortScanner()
        print("nmap is present")
    except nmap.PortScannerError:
        messagebox.showinfo("Dependency Installation", "All necessary files are installing, please wait.")
        install_nmap()

# Function to check for vulnerabilities using Nmap
def scan_vulnerabilities(ip, open_ports):
    nm = nmap.PortScanner()
    vulnerabilities = {}

    # Convert open ports to list of strings
    port_strings = [str(port) for port in open_ports]

    try:
        nm.scan(ip, ','.join(port_strings), arguments='--script vulners')

        for port in open_ports:
            if nm[ip]['tcp'][port].get('script'):
                vulnerabilities[port] = nm[ip]['tcp'][port]['script']
            else:
                vulnerabilities[port] = {}

    except Exception as e:
        for port in open_ports:
            vulnerabilities[port] = {'error': str(e)}

    return vulnerabilities

# Function to suggest improvements based on open ports
def suggest_improvements(open_ports):
    recommendations = []
    vulnerability_database = {
        21: "FTP service: Potential for anonymous login and data exposure.",
        22: "SSH service: Brute force attacks possible if weak passwords are used.",
        23: "Telnet service: Unencrypted communication, susceptible to interception.",
        25: "SMTP service: Open relays can be abused to send spam.",
        53: "DNS service: Cache poisoning and amplification attacks.",
        80: "HTTP service: Potential for outdated server software and various web vulnerabilities.",
        110: "POP3 service: Unencrypted communication, susceptible to interception.",
        139: "NetBIOS: Information leakage and potential for file sharing vulnerabilities.",
        143: "IMAP service: Unencrypted communication, susceptible to interception.",
        161: "SNMP service: Information leakage and weak authentication.",
        443: "HTTPS service: Ensure SSL/TTLS is properly configured to avoid vulnerabilities.",
        445: "SMB: Vulnerable to attacks like EternalBlue.",
        3389: "RDP: Susceptible to brute force attacks and remote code execution vulnerabilities."
    }

    for port in open_ports:
        if port in vulnerability_database:
            recommendations.append(f"Port {port}: {vulnerability_database[port]}")
            if port == 21:
                recommendations.append("Disable anonymous FTP login, use strong passwords.")
            elif port == 22:
                recommendations.append("Use strong, complex passwords, and consider using key-based authentication.")
            elif port == 23:
                recommendations.append("Disable Telnet and use SSH instead for secure communication.")
            elif port == 25:
                recommendations.append("Ensure SMTP server is not an open relay.")
            elif port == 53:
                recommendations.append("Implement DNSSEC to protect against DNS attacks.")
            elif port == 80:
                recommendations.append("Keep web server software updated and use HTTPS where possible.")
            elif port == 110:
                recommendations.append("Use secure versions of email protocols like POP3S.")
            elif port == 139:
                recommendations.append(
                    "Disable NetBIOS over TCP/IP if not needed, use firewall rules to restrict access.")
            elif port == 143:
                recommendations.append("Use secure versions of email protocols like IMAPS.")
            elif port == 161:
                recommendations.append("Use SNMPv3 with authentication and encryption.")
            elif port == 443:
                recommendations.append("Ensure SSL/TTLS is properly configured and use strong encryption protocols.")
            elif port == 445:
                recommendations.append("Disable SMBv1, ensure patching against known vulnerabilities.")
            elif port == 3389:
                recommendations.append("Use strong passwords, enable Network Level Authentication (NLA).")
    return recommendations

def scan_port(ip, port, open_ports, progress_bar, total_ports):
    try:
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.settimeout(1)  # Increased timeout for better reliability
        if not tcp.connect_ex((ip, port)):
            open_ports.append(port)
        tcp.close()
    except Exception as e:
        print(f"Error scanning port {port}: {str(e)}")
    finally:
        progress_bar['value'] += 100 / total_ports

def scan_host(ip, start_port, end_port, update_gui_callback, progress_bar):
    open_ports = []
    threads = []
    total_ports = end_port - start_port + 1
    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=scan_port, args=(ip, port, open_ports, progress_bar, total_ports))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

    # After finishing the scan, update the GUI
    update_gui_callback(open_ports)

def start_scan():
    ip = ip_entry.get()
    start_port = int(start_port_entry.get())
    end_port = int(end_port_entry.get())
    camera_brand = camera_brand_entry.get()
    password = password_entry.get()
    user_version = firmware_version_entry.get()

    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, f"Scanning {ip} from port {start_port} to {end_port}...\n")
    result_text.insert(tk.END, f"Camera Brand: {camera_brand}\n")

    global stop_loading
    stop_loading = False

    threading.Thread(target=run_scan, args=(ip, start_port, end_port, camera_brand, password, user_version)).start()

def run_scan(ip, start_port, end_port, camera_brand, password, user_version):
    def update_gui(open_ports):
        global stop_loading
        stop_loading = True

        result_text.insert(tk.END, f"Open ports on {ip}:\n")
        for port in open_ports:
            result_text.insert(tk.END, f"{port}/TCP Open\n")

        vulnerabilities = scan_vulnerabilities(ip, open_ports)
        for port, details in vulnerabilities.items():
            if details.get('error'):
                result_text.insert(tk.END, f"Error scanning port {port}: {details['error']}\n", 'red')
            elif details:
                result_text.insert(tk.END, f"Vulnerabilities on port {port}:\n")
                for script, output in details.items():
                    result_text.insert(tk.END, f"{script}: {output}\n")
                recommendations = suggest_improvements([port])
                for recommendation in recommendations:
                    result_text.insert(tk.END, f"Recommendation: {recommendation}\n")
            else:
                result_text.insert(tk.END, f"No vulnerabilities found on port {port}\n", 'green')

        password_strength = check_password_strength(password)
        result_text.insert(tk.END, f"Password Strength: {password_strength}\n")

        firmware_status = check_firmware_update(ip, camera_brand, user_version)
        if "Error" in firmware_status:
            result_text.insert(tk.END, f"Firmware Update Status: {firmware_status}\n", 'red')
        else:
            result_text.insert(tk.END, f"Firmware Update Status: {firmware_status}\n")

        result_text.insert(tk.END, f"Camera Brand: {camera_brand}\n")

    progress_bar['value'] = 0
    progress_bar.grid(row=7, column=0, columnspan=2, pady=(10, 0))
    scan_host(ip, start_port, end_port, update_gui, progress_bar)
    progress_bar.grid_forget()

def check_password_strength(password):
    if len(password) < 8:
        return "Weak"
    if not any(char.isdigit() for char in password):
        return "Weak"
    if not any(char.islower() for char in password):
        return "Weak"
    if not any(char.isupper() for char in password):
        return "Weak"
    if not any(char in string.punctuation for char in password):
        return "Weak"
    return "Strong"

# Dictionary containing the latest firmware versions for various camera brands
latest_firmware_versions = {
    "HIKVISION": "5.5.0",
    "DAHUA": "4.2.1",
    "BOSCH": "7.0.3",
    "IDIS": "2.5.0",
    "PELC0": "3.0.1",
    "IMOU": "1.0.7",
    "XIAOMI MI": "4.0.2",
    "PHILIPS": "2.1.4",
    "QUBO": "1.1.0",
    "VANTAGE": "3.2.5",
    "LG": "4.0.0",
    "AXIS COMMUNICATIONS": "8.2.1",
    "CP PLUS": "4.3.2",
    "HONEYWELL": "5.4.3",
    "GODREJ": "2.2.0",
    "SAMSUNG": "6.0.1",
    "SONY": "2.0.4",
    "HANWHA VISION": "3.1.2",
    "PANASONIC": "6.1.0",
    "TP-LINK": "1.1.5",
    "TVT": "3.0.2",
    "D-LINK": "4.0.8",
    "ZICOM": "3.1.1"
}

def check_firmware_update(ip, camera_brand, user_version):
    try:
        latest_version = get_latest_firmware_version(camera_brand)

        if latest_version is None:
            return "Your firmware version is up to date"

        if user_version >= latest_version:
            return "Your firmware version is up to date"
        else:
            return f"Update available: Please update to the latest firmware version "

    except requests.exceptions.RequestException as e:
        return f"Error checking firmware: {e}"


# Updated function to get the latest firmware version based on the camera brand
def get_latest_firmware_version(camera_brand):
    # Convert camera brand to uppercase and strip whitespace
    camera_brand = camera_brand.upper().strip()
    # Get the latest version from the dictionary or return a default value
    return latest_firmware_versions.get(camera_brand, None)


def check_key():
    entered_key = key_entry.get()
    if entered_key == PREDEFINED_KEY:
        messagebox.showinfo("Access Granted", "Access key is correct!")
        root.destroy()
        create_main_window()
    else:
        messagebox.showerror("Access Denied", "Incorrect access key!")

def create_main_window():
    global ip_entry, start_port_entry, end_port_entry, password_entry, result_text, progress_bar, camera_brand_entry, firmware_version_entry

    window = tk.Tk()
    window.title("Security Scanner")
    window.geometry("800x600")

    header_frame = tk.Frame(window, bg="blue")
    header_frame.pack(fill=tk.X)
    header_label = tk.Label(header_frame, text="Camera Security Scanner", font=("Helvetica", 16, "bold"), bg="blue", fg="white")
    header_label.pack(pady=10)

    frame = tk.Frame(window, padx=10, pady=10)
    frame.pack(fill=tk.BOTH, expand=True)

    tk.Label(frame, text="IP Address:", font=("Helvetica", 12, "bold")).grid(row=0, column=0, sticky="w", pady=(0, 5))
    ip_entry = tk.Entry(frame, font=("Helvetica", 12))
    ip_entry.grid(row=0, column=1, pady=(0, 5))

    tk.Label(frame, text="Start Port:", font=("Helvetica", 12, "bold")).grid(row=1, column=0, sticky="w", pady=(0, 5))
    start_port_entry = tk.Entry(frame, font=("Helvetica", 12))
    start_port_entry.grid(row=1, column=1, pady=(0, 5))

    tk.Label(frame, text="End Port:", font=("Helvetica", 12, "bold")).grid(row=2, column=0, sticky="w", pady=(0, 5))
    end_port_entry = tk.Entry(frame, font=("Helvetica", 12))
    end_port_entry.grid(row=2, column=1, pady=(0, 5))

    tk.Label(frame, text="Camera Brand:", font=("Helvetica", 12, "bold")).grid(row=3, column=0, sticky="w", pady=(0, 5))
    camera_brand_entry = tk.Entry(frame, font=("Helvetica", 12))
    camera_brand_entry.grid(row=3, column=1, pady=(0, 5))

    tk.Label(frame, text="Password:", font=("Helvetica", 12, "bold")).grid(row=4, column=0, sticky="w", pady=(0, 5))
    password_entry = tk.Entry(frame, font=("Helvetica", 12), show='*')
    password_entry.grid(row=4, column=1, pady=(0, 5))

    tk.Label(frame, text="Firmware Version:", font=("Helvetica", 12, "bold")).grid(row=5, column=0, sticky="w", pady=(0, 5))
    firmware_version_entry = tk.Entry(frame, font=("Helvetica", 12))
    firmware_version_entry.grid(row=5, column=1, pady=(0, 5))

    scan_button = tk.Button(frame, text="Start Scan", command=start_scan, font=("Helvetica", 12, "bold"), bg="blue", fg="white")
    scan_button.grid(row=6, column=0, columnspan=2, pady=(10, 5))

    progress_bar = ttk.Progressbar(frame, orient="horizontal", mode="determinate", length=400)
    progress_bar.grid(row=7, column=0, columnspan=2, pady=(10, 5))

    result_text = scrolledtext.ScrolledText(frame, width=80, height=20, font=("Courier", 10))
    result_text.grid(row=8, column=0, columnspan=2, pady=(10, 0))

    result_text.tag_config('green', foreground='green')
    result_text.tag_config('red', foreground='red')

    footer_frame = tk.Frame(window, bg="blue")
    footer_frame.pack(fill=tk.X, side=tk.BOTTOM)
    footer_label = tk.Label(footer_frame, text="Security Scanner © 2024", font=("Helvetica", 10, "italic"), bg="blue", fg="white")
    footer_label.pack(pady=5)

    window.mainloop()

def main():
    global key_entry, key_button, root

    root = tk.Tk()
    root.title("Access Verification")
    root.geometry("400x200")

    tk.Label(root, text="Enter Access Key:", font=("Helvetica", 12, "bold")).grid(row=0, column=0, pady=(50, 10))
    key_entry = tk.Entry(root, font=("Helvetica", 12))
    key_entry.grid(row=0, column=1, pady=(50, 10))

    key_button = tk.Button(root, text="Submit", command=check_key, font=("Helvetica", 12, "bold"), bg="blue", fg="white")
    key_button.grid(row=1, column=0, columnspan=2, pady=(10, 0))

    check_and_install_dependencies()

    root.mainloop()

main()
