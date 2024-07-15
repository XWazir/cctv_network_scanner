import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import nmap
import re
import requests

# Predefined unique key for access
PREDEFINED_KEY = "888"

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
        443: "HTTPS service: Ensure SSL/TLS is properly configured to avoid vulnerabilities.",
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
                recommendations.append("Disable NetBIOS over TCP/IP if not needed, use firewall rules to restrict access.")
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
        tcp.settimeout(0.5)  # Set timeout
        if not tcp.connect_ex((ip, port)):
            open_ports.append(port)
        tcp.close()
    except Exception:
        pass
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

def start_scan(camera_brand):
    ip = ip_entry.get()
    start_port = int(start_port_entry.get())
    end_port = int(end_port_entry.get())
    password = password_entry.get()

    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, f"Scanning {camera_brand} ({ip}) from port {start_port} to {end_port}...\n")

    # Start the loading animation
    global stop_loading
    stop_loading = False

    # Schedule the scanning function to run in a separate thread
    threading.Thread(target=run_scan, args=(ip, start_port, end_port, camera_brand, password)).start()

def run_scan(ip, start_port, end_port, camera_brand, password):
    def update_gui(open_ports):
        # Stop the loading animation
        global stop_loading
        stop_loading = True

        result_text.insert(tk.END, f"Open ports on {camera_brand} ({ip}):\n")
        for port in open_ports:
            result_text.insert(tk.END, f"{port}/TCP Open\n")

        vulnerabilities = scan_vulnerabilities(ip, open_ports)
        if all(not details for details in vulnerabilities.values()):
            result_text.insert(tk.END, "No vulnerabilities found\n", 'green')
        else:
            for port, details in vulnerabilities.items():
                if details.get('error'):
                    result_text.insert(tk.END, f"Error scanning port {port}: {details['error']}\n")
                elif details:
                    result_text.insert(tk.END, f"Vulnerabilities on port {port}:\n")
                    for script, output in details.items():
                        result_text.insert(tk.END, f"{script}: {output}\n")
                    recommendations = suggest_improvements([port])
                    for recommendation in recommendations:
                        result_text.insert(tk.END, f"Recommendation: {recommendation}\n")
                result_text.insert(tk.END, "\n")

        # Check password strength
        password_weakness = check_password_strength(password)
        result_text.insert(tk.END, f"Password Strength: {password_weakness}\n")

        # Check firmware update status
        firmware_status = check_firmware_update(ip)
        result_text.insert(tk.END, f"Firmware Update Status: {firmware_status}\n")

    progress_bar['value'] = 0
    progress_bar.grid(row=6, column=0, columnspan=2, pady=(10, 0))
    scan_host(ip, start_port, end_port, update_gui, progress_bar)
    progress_bar.grid_forget()

def check_password_strength(password):
    if len(password) < 8:
        return "Weak (too short)"
    if not re.search("[a-z]", password):
        return "Weak (no lowercase letters)"
    if not re.search("[A-Z]", password):
        return "Weak (no uppercase letters)"
    if not re.search("[0-9]", password):
        return "Weak (no digits)"
    if not re.search("[!@#$%^&*()_+]", password):
        return "Weak (no special characters)"
    return "Strong"

def check_firmware_update(ip):
    try:
        response = requests.get(f"http://{ip}/firmware_version")  
        if response.status_code == 200:
            current_version = response.json().get("version")
            latest_version = "1.2.3"  # Example latest version
            if current_version == latest_version:
                return "Firmware is up-to-date"
            else:
                return f"Firmware update needed (current: {current_version}, latest: {latest_version})"
        else:
            return "Failed to retrieve firmware version"
    except Exception as e:
        return f"Error checking firmware: {str(e)}"

def check_key():
    entered_key = key_entry.get()
    if entered_key == PREDEFINED_KEY:
        key_entry.grid_forget()
        key_button.grid_forget()
        messagebox.showinfo("Success", "Access Key Verified Successfully")
        show_main_window()
    else:
        messagebox.showerror("Invalid Key", "The key you entered is invalid. Please try again.")

def show_main_window():
    global ip_entry, start_port_entry, end_port_entry, result_text, brand_entry, password_entry, progress_bar

    window = tk.Tk()
    window.title("Camera Security Scanner")
    window.geometry("800x600")

    # Header
    header_frame = tk.Frame(window, bg="blue")
    header_frame.pack(fill=tk.X)
    header_label = tk.Label(header_frame, text="Camera Security Scanner", font=("Helvetica", 18, "bold"), bg="blue", fg="white")
    header_label.pack(pady=10)

    frame = tk.Frame(window, padx=10, pady=10)
    frame.pack(fill=tk.BOTH, expand=True)

    tk.Label(frame, text="Camera Brand:", font=("Helvetica", 12, "bold")).grid(row=0, column=0, sticky="w", pady=(0, 5))
    brand_entry = tk.Entry(frame, font=("Helvetica", 12))
    brand_entry.grid(row=0, column=1, pady=(0, 5))

    tk.Label(frame, text="IP Address:", font=("Helvetica", 12, "bold")).grid(row=1, column=0, sticky="w", pady=(0, 5))
    ip_entry = tk.Entry(frame, font=("Helvetica", 12))
    ip_entry.grid(row=1, column=1, pady=(0, 5))

    tk.Label(frame, text="Start Port:", font=("Helvetica", 12, "bold")).grid(row=2, column=0, sticky="w", pady=(0, 5))
    start_port_entry = tk.Entry(frame, font=("Helvetica", 12))
    start_port_entry.grid(row=2, column=1, pady=(0, 5))

    tk.Label(frame, text="End Port:", font=("Helvetica", 12, "bold")).grid(row=3, column=0, sticky="w", pady=(0, 5))
    end_port_entry = tk.Entry(frame, font=("Helvetica", 12))
    end_port_entry.grid(row=3, column=1, pady=(0, 5))

    tk.Label(frame, text="Password:", font=("Helvetica", 12, "bold")).grid(row=4, column=0, sticky="w", pady=(0, 5))
    password_entry = tk.Entry(frame, show="*", font=("Helvetica", 12))
    password_entry.grid(row=4, column=1, pady=(0, 5))

    scan_button = tk.Button(frame, text="Start Scan", command=lambda: start_scan(brand_entry.get()), font=("Helvetica", 12, "bold"), bg="blue", fg="white")
    scan_button.grid(row=5, column=0, columnspan=2, pady=(10, 5))

    progress_bar = ttk.Progressbar(frame, orient="horizontal", mode="determinate", length=400)

    result_text = scrolledtext.ScrolledText(frame, width=80, height=20, font=("Courier", 10))
    result_text.grid(row=7, column=0, columnspan=2, pady=(10, 0))

    # Configure tag for green text
    result_text.tag_config('green', foreground='green')

    # Footer
    footer_frame = tk.Frame(window, bg="blue")
    footer_frame.pack(fill=tk.X, side=tk.BOTTOM)
    footer_label = tk.Label(footer_frame, text="Security Scanner © 2024", font=("Helvetica", 10, "italic"), bg="blue", fg="white")
    footer_label.pack(pady=5)

    window.mainloop()

def main():
    global key_entry, key_button

    root = tk.Tk()
    root.title("Access Verification")
    root.geometry("400x200")

    tk.Label(root, text="Enter Access Key:", font=("Helvetica", 12, "bold")).grid(row=0, column=0, pady=(50, 10))
    key_entry = tk.Entry(root, font=("Helvetica", 12))
    key_entry.grid(row=0, column=1, pady=(50, 10))

    key_button = tk.Button(root, text="Submit", command=check_key, font=("Helvetica", 12, "bold"), bg="blue", fg="white")
    key_button.grid(row=1, column=0, columnspan=2, pady=(10, 0))

    root.mainloop()

main()
