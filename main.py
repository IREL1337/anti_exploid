import os
import subprocess
import socket
import psutil
import time
import platform
from cryptography.fernet import Fernet
from datetime import datetime
import ipaddress

# Fungsi untuk menghasilkan kunci enkripsi
def generate_key():
    return Fernet.generate_key()

# Fungsi untuk mengenkripsi log
def encrypt_log(log_message, key):
    cipher_suite = Fernet(key)
    encrypted_message = cipher_suite.encrypt(log_message.encode())
    return encrypted_message

# Fungsi untuk mencatat log dengan enkripsi
def log_event(message, key):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    encrypted_message = encrypt_log(f"{timestamp} - {message}", key)
    with open("defense_log.enc", "ab") as log_file:
        log_file.write(encrypted_message + b"\n")

# Fungsi untuk memonitor koneksi jaringan yang mencurigakan
def monitor_network(key):
    suspicious_ports = [22, 80, 443]  # Contoh: port yang harus diawasi
    connections = psutil.net_connections(kind='inet')
    
    ip_packet_count = {}
    for conn in connections:
        if conn.laddr.port in suspicious_ports and conn.status == 'ESTABLISHED':
            alert_message = f"Suspicious connection detected on port {conn.laddr.port} - IP Address: {conn.raddr.ip} - Status: {conn.status}"
            print(f"[ALERT] {alert_message}")
            log_event(alert_message, key)
        
        # Hitung paket per IP
        if conn.raddr:
            ip = conn.raddr.ip
            if ip in ip_packet_count:
                ip_packet_count[ip] += 1
            else:
                ip_packet_count[ip] = 1
    
    # Blokir IP yang melebihi 50 paket per detik
    for ip, count in ip_packet_count.items():
        if count > 50:
            block_ip(ip, key)

# Fungsi untuk memblokir IP
def block_ip(ip, key):
    system = platform.system()
    if system == 'Linux':
        rule = f"iptables -A INPUT -s {ip} -j DROP"
    elif system == 'Windows':
        rule = f"netsh advfirewall firewall add rule name=\"Block {ip}\" dir=in action=block remoteip={ip}"
    
    try:
        subprocess.run(rule, shell=True, check=True)
        alert_message = f"Blocked IP: {ip} for exceeding packet limit"
        print(f"[ALERT] {alert_message}")
        log_event(alert_message, key)
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to block IP: {ip}")
        print(f" - Error: {e}")

# Fungsi untuk memblokir paket ICMP, IGMP, dan RAW
def block_unwanted_packets():
    system = platform.system()
    if system == 'Linux':
        rules = [
            "iptables -A INPUT -p icmp -j DROP",
            "iptables -A INPUT -p igmp -j DROP",
            "iptables -A INPUT -p raw -j DROP"
        ]
    elif system == 'Windows':
        rules = [
            "netsh advfirewall firewall add rule name=\"Block ICMP\" dir=in action=block protocol=ICMPv4",
            "netsh advfirewall firewall add rule name=\"Block IGMP\" dir=in action=block protocol=2",
            "netsh advfirewall firewall add rule name=\"Block RAW\" dir=in action=block protocol=255"
        ]
    
    for rule in rules:
        try:
            subprocess.run(rule, shell=True, check=True)
            print(f"[INFO] Applied packet block rule: {rule}")
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to apply packet block rule: {rule}")
            print(f" - Error: {e}")

# Fungsi untuk mengatur aturan firewall pada Linux
def setup_firewall_linux():
    rules = [
        "iptables -A INPUT -p tcp --dport 22 -j DROP",  # Drop SSH connections
        "iptables -A INPUT -p tcp --dport 80 -j ACCEPT",  # Allow HTTP connections
        "iptables -A INPUT -p tcp --dport 443 -j ACCEPT",  # Allow HTTPS connections
        "iptables -A INPUT -p tcp --dport 3306 -j DROP"  # Drop MySQL connections
    ]

    for rule in rules:
        try:
            subprocess.run(rule, shell=True, check=True)
            print(f"[INFO] Applied firewall rule: {rule}")
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to apply firewall rule: {rule}")
            print(f" - Error: {e}")

# Fungsi untuk mengatur aturan firewall pada Windows
def setup_firewall_windows():
    rules = [
        "netsh advfirewall firewall add rule name=\"Block SSH\" dir=in action=block protocol=TCP localport=22",
        "netsh advfirewall firewall add rule name=\"Allow HTTP\" dir=in action=allow protocol=TCP localport=80",
        "netsh advfirewall firewall add rule name=\"Allow HTTPS\" dir=in action=allow protocol=TCP localport=443",
        "netsh advfirewall firewall add rule name=\"Block MySQL\" dir=in action=block protocol=TCP localport=3306"
    ]

    for rule in rules:
        try:
            subprocess.run(rule, shell=True, check=True)
            print(f"[INFO] Applied firewall rule: {rule}")
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to apply firewall rule: {rule}")
            print(f" - Error: {e}")

# Fungsi untuk mengeraskan layanan yang berjalan pada Linux
def harden_services_linux():
    services_to_disable = ['apache2', 'mysql', 'ftp']  # Contoh layanan yang mungkin tidak diperlukan

    for service in services_to_disable:
        result = subprocess.run(['systemctl', 'is-active', service], stdout=subprocess.PIPE)
        if b'active' in result.stdout:
            subprocess.run(['systemctl', 'stop', service])
            subprocess.run(['systemctl', 'disable', service])
            print(f"[INFO] Disabled unnecessary service: {service}")

# Fungsi untuk mengeraskan layanan yang berjalan pada Windows
def harden_services_windows():
    services_to_disable = ['W3SVC', 'MySQL', 'FTPSVC']  # Contoh layanan yang mungkin tidak diperlukan

    for service in services_to_disable:
        try:
            subprocess.run(['sc', 'stop', service], check=True)
            subprocess.run(['sc', 'config', service, 'start= disabled'], check=True)
            print(f"[INFO] Disabled unnecessary service: {service}")
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to disable service: {service}")
            print(f" - Error: {e}")

# Fungsi untuk memantau pembaruan sistem pada Linux
def check_for_updates_linux():
    try:
        subprocess.run(['apt-get', 'update'], check=True)
        subprocess.run(['apt-get', 'upgrade', '-y'], check=True)
        print("[INFO] System update completed.")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to update system: {e}")

# Fungsi untuk memantau pembaruan sistem pada Windows
def check_for_updates_windows():
    try:
        subprocess.run(['powershell', 'Get-WindowsUpdate', '-Install', '-AcceptAll'], check=True)
        print("[INFO] System update completed.")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to update system: {e}")

# Fungsi utama untuk mengelola pertahanan
def main():
    print("Running Super Defense Script...")
    
    # Generate encryption key for logs
    key = generate_key()

    system = platform.system()
    
    # Blokir paket yang tidak diinginkan
    print("[INFO] Blocking unwanted packets...")
    block_unwanted_packets()

    # Lakukan monitoring jaringan secara berkala
    while True:
        print("[INFO] Monitoring network connections...")
        monitor_network(key)

        # Terapkan aturan firewall
        print("[INFO] Setting up firewall...")
        if system == 'Linux':
            setup_firewall_linux()
        elif system == 'Windows':
            setup_firewall_windows()

        # Perkuat layanan yang berjalan
        print("[INFO] Hardening system services...")
        if system == 'Linux':
            harden_services_linux()
        elif system == 'Windows':
            harden_services_windows()

        # Periksa pembaruan sistem
        print("[INFO] Checking for system updates...")
        if system == 'Linux':
            check_for_updates_linux()
        elif system == 'Windows':
            check_for_updates_windows()

        # Tunggu sebelum menjalankan monitoring lagi
        time.sleep(60)  # Monitor setiap 60 detik

if __name__ == "__main__":
    main()
