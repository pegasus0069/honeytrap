import os
import time
import re
import subprocess
import json
from datetime import datetime

LEASES_FILE = "/var/lib/dhcp/dhcpd.leases"
BLOCKED_IPS_FILE = "blocked_ips.json"  # File to store blocked IPs persistently
BLOCKED_IPS = set()  # Keeps track of blocked IPs to avoid redundant rules

DHCP_SERVER_SERVICE = "isc-dhcp-server"  # DHCP server service name

def load_blocked_ips():
    """
    Load blocked IPs from a persistent file.
    """
    global BLOCKED_IPS
    if os.path.exists(BLOCKED_IPS_FILE):
        with open(BLOCKED_IPS_FILE, "r") as f:
            BLOCKED_IPS = set(json.load(f))

def save_blocked_ips():
    """
    Save blocked IPs to a persistent file.
    """
    with open(BLOCKED_IPS_FILE, "w") as f:
        json.dump(list(BLOCKED_IPS), f)

def restart_dhcp_server():
    """
    Restart the DHCP server to apply any changes.
    """
    try:
        subprocess.run(["sudo", "systemctl", "restart", DHCP_SERVER_SERVICE], check=True)
        print("DHCP server restarted successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error restarting DHCP server: {e}")

def parse_leases():
    """
    Parse the DHCP leases file to extract active IP addresses.
    Returns a list of dictionaries containing IP, MAC, and hostname.
    """
    if not os.path.exists(LEASES_FILE):
        print(f"Leases file not found: {LEASES_FILE}")
        return []

    devices = []
    current_device = {}

    # Regular expressions to match relevant lines
    ip_regex = re.compile(r"^lease\s+([\d.]+)\s+{")
    hardware_regex = re.compile(r"^\s+hardware ethernet\s+([0-9a-f:]+);")
    client_regex = re.compile(r"^\s+client-hostname\s+\"(.+?)\";")

    with open(LEASES_FILE, "r") as file:
        for line in file:
            ip_match = ip_regex.match(line)
            if ip_match:
                if current_device:  # Save the previous device if any
                    devices.append(current_device)
                current_device = {"ip": ip_match.group(1)}

            hardware_match = hardware_regex.match(line)
            if hardware_match and current_device:
                current_device["mac"] = hardware_match.group(1)

            client_match = client_regex.match(line)
            if client_match and current_device:
                current_device["hostname"] = client_match.group(1)

    if current_device:  # Add the last device
        devices.append(current_device)

    return devices

def block_ip(ip_address):
    """
    Block the specified IP address using iptables to prevent all traffic, including intra-network communication.
    """
    global BLOCKED_IPS
    if ip_address in BLOCKED_IPS:
        print(f"IP {ip_address} is already blocked.")
        return

    try:
        # Add iptables rules to block all traffic from/to the IP
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
        subprocess.run(["sudo", "iptables", "-A", "OUTPUT", "-d", ip_address, "-j", "DROP"], check=True)
        subprocess.run(["sudo", "iptables", "-A", "FORWARD", "-s", ip_address, "-j", "DROP"], check=True)
        subprocess.run(["sudo", "iptables", "-A", "FORWARD", "-d", ip_address, "-j", "DROP"], check=True)
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-d", ip_address, "-j", "DROP"], check=True)
        BLOCKED_IPS.add(ip_address)
        save_blocked_ips()
        print(f"IP address {ip_address} has been blocked from all network access.")
        restart_dhcp_server()
    except subprocess.CalledProcessError as e:
        print(f"Error blocking IP address {ip_address}: {e}")

def unblock_ip(ip_address):
    """
    Unblock the specified IP address by removing iptables rules.
    """
    global BLOCKED_IPS
    if ip_address not in BLOCKED_IPS:
        print(f"IP {ip_address} is not currently blocked.")
        return

    try:
        # Remove iptables rules
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
        subprocess.run(["sudo", "iptables", "-D", "OUTPUT", "-d", ip_address, "-j", "DROP"], check=True)
        subprocess.run(["sudo", "iptables", "-D", "FORWARD", "-s", ip_address, "-j", "DROP"], check=True)
        subprocess.run(["sudo", "iptables", "-D", "FORWARD", "-d", ip_address, "-j", "DROP"], check=True)
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-d", ip_address, "-j", "DROP"], check=True)
        BLOCKED_IPS.remove(ip_address)
        save_blocked_ips()
        print(f"IP address {ip_address} has been unblocked.")
        restart_dhcp_server()
    except subprocess.CalledProcessError as e:
        print(f"Error unblocking IP address {ip_address}: {e}")

def restore_blocked_ips():
    """
    Restore iptables rules for previously blocked IPs.
    """
    for ip in BLOCKED_IPS:
        try:
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            subprocess.run(["sudo", "iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"], check=True)
            subprocess.run(["sudo", "iptables", "-A", "FORWARD", "-s", ip, "-j", "DROP"], check=True)
            subprocess.run(["sudo", "iptables", "-A", "FORWARD", "-d", ip, "-j", "DROP"], check=True)
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-d", ip, "-j", "DROP"], check=True)
            print(f"Restored blocking for IP address {ip}.")
        except subprocess.CalledProcessError as e:
            print(f"Error restoring block for IP address {ip}: {e}")

def monitor_leases(interval=10):
    """
    Continuously monitor the DHCP leases file and allow real-time blocking and unblocking of IPs.
    """
    print("Monitoring DHCP leases and managing IP blocks... Press Ctrl+C to exit.")
    try:
        while True:
            os.system("clear")
            devices = parse_leases()

            print("Current DHCP Leases:")
            print(f"{'IP Address':<15} {'MAC Address':<20} {'Hostname':<25}")
            print("=" * 60)
            for device in devices:
                print(f"{device.get('ip', 'N/A'):<15} {device.get('mac', 'N/A'):<20} {device.get('hostname', 'N/A'):<25}")

            print("\nBlocked IPs:")
            print(", ".join(BLOCKED_IPS) if BLOCKED_IPS else "No IPs blocked.")

            print("\nOptions:")
            print("1. Block an IP")
            print("2. Unblock an IP")
            print("3. Refresh")
            print("4. Exit")

            choice = input("Enter your choice: ").strip()

            if choice == "1":
                ip_to_block = input("Enter the IP address to block: ").strip()
                block_ip(ip_to_block)
            elif choice == "2":
                ip_to_unblock = input("Enter the IP address to unblock: ").strip()
                unblock_ip(ip_to_unblock)
            elif choice == "4":
                print("Exiting...")
                break

            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nExiting monitoring.")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Please run this script as root (use sudo).")
    else:
        load_blocked_ips()
        restore_blocked_ips()
        monitor_leases()
