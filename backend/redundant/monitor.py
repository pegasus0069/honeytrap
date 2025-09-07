import os
import time
import json
import subprocess

# Path to the dnsmasq leases file and blocked IPs JSON file
LEASES_FILE = "/var/lib/misc/dnsmasq.leases"
BLOCKED_IPS_FILE = "blocked_ips.json"

def parse_leases():
    """Parse the dnsmasq leases file to extract lease details."""
    leases = []
    if os.path.exists(LEASES_FILE):
        with open(LEASES_FILE, 'r') as file:
            for line in file:
                # Each line has the format: <timestamp> <lease-time> <mac-address> <IP> <hostname> <client-name>
                parts = line.strip().split()
                if len(parts) >= 5:
                    timestamp = parts[0]
                    lease_time = parts[1]
                    mac_address = parts[2]
                    ip_address = parts[3]
                    hostname = parts[4]
                    leases.append({
                        'timestamp': timestamp,
                        'lease_time': lease_time,
                        'mac_address': mac_address,
                        'ip_address': ip_address,
                        'hostname': hostname
                    })
    return leases

def display_leases(leases):
    """Display the lease information."""
    print(f"{'Timestamp':<15}{'Lease Time':<12}{'MAC Address':<20}{'IP Address':<15}{'Hostname':<20}")
    print("-" * 75)
    
    for lease in leases:
        print(f"{lease['timestamp']:<15}{lease['lease_time']:<12}{lease['mac_address']:<20}{lease['ip_address']:<15}{lease['hostname']:<20}")
    print("\n")

def block_ip(ip_address):
    """Block the specified IP address using nftables."""
    try:
        subprocess.run(["sudo", "nft", "add", "rule", "inet", "filter", "input", "ip", "daddr", ip_address, "drop"], check=True)
        print(f"IP {ip_address} is now blocked.")
        add_to_blocked_ips(ip_address)
    except subprocess.CalledProcessError as e:
        print(f"Error blocking IP {ip_address}: {e}")

def unblock_ip(ip_address):
    """Unblock the specified IP address using nftables."""
    try:
        # List the rules with handles
        result = subprocess.run(["sudo", "nft", "list", "table", "inet", "filter", "-a"], capture_output=True, text=True)
        rules = result.stdout

        # Find the handle for the specified IP address
        handle = None
        for line in rules.splitlines():
            if f"ip daddr {ip_address} drop" in line:
                # Extract the handle from the line
                parts = line.split()
                handle_index = parts.index("#") + 1
                handle = parts[handle_index]
                break

        if not handle:
            print(f"No rule found for IP {ip_address}.")
            return

        # Delete the rule by handle
        subprocess.run(["sudo", "nft", "delete", "rule", "inet", "filter", "input", "handle", handle], check=True)
        print(f"IP {ip_address} is now unblocked.")
        remove_from_blocked_ips(ip_address)

    except subprocess.CalledProcessError as e:
        print(f"Error unblocking IP {ip_address}: {e}")




def add_to_blocked_ips(ip_address):
    """Add the blocked IP to the JSON file."""
    if os.path.exists(BLOCKED_IPS_FILE):
        with open(BLOCKED_IPS_FILE, "r") as f:
            blocked_ips = json.load(f)
    else:
        blocked_ips = []

    if ip_address not in blocked_ips:
        blocked_ips.append(ip_address)

    with open(BLOCKED_IPS_FILE, "w") as f:
        json.dump(blocked_ips, f, indent=4)
    
def remove_from_blocked_ips(ip_address):
    """Remove the IP from the blocked IPs JSON file."""
    if os.path.exists(BLOCKED_IPS_FILE):
        with open(BLOCKED_IPS_FILE, "r") as f:
            blocked_ips = json.load(f)
        
        if ip_address in blocked_ips:
            blocked_ips.remove(ip_address)

        with open(BLOCKED_IPS_FILE, "w") as f:
            json.dump(blocked_ips, f, indent=4)

def load_blocked_ips():
    """Load the list of blocked IPs from the JSON file."""
    if os.path.exists(BLOCKED_IPS_FILE):
        with open(BLOCKED_IPS_FILE, "r") as f:
            return json.load(f)
    return []

def block_ips_from_json():
    """Block IPs that are stored in the JSON file."""
    blocked_ips = load_blocked_ips()
    for ip in blocked_ips:
        block_ip(ip)

def view_blocked_ips():
    """View the blocked IPs from the JSON file."""
    blocked_ips = load_blocked_ips()
    if blocked_ips:
        print("\nBlocked IPs:")
        for ip in blocked_ips:
            print(f"- {ip}")
    else:
        print("\nNo IPs are currently blocked.")

def monitor_dhcp():
    """Monitor the DHCP server and display the lease information every second."""
    while True:
        print("Monitoring DHCP leases...\n")
        leases = parse_leases()
        display_leases(leases)
        block_ips_from_json()  # Block IPs from JSON
        time.sleep(1)  # Show leases every 1 second
        break

def main():
    while True:
        print("\nDHCP Lease Monitor")
        print("1. Monitor Leases")
        print("2. Block Device by IP")
        print("3. Unblock Device by IP")
        print("4. View Blocked Devices")
        print("5. Exit")
        
        choice = input("Select an option: ")

        if choice == "1":
            monitor_dhcp()
        elif choice == "2":
            ip_address = input("Enter IP address to block: ")
            block_ip(ip_address)
        elif choice == "3":
            ip_address = input("Enter IP address to unblock: ")
            unblock_ip(ip_address)
        elif choice == "4":
            view_blocked_ips()
        elif choice == "5":
            print("Exiting...")
            break
        else:
            print("Invalid option, please try again.")

if __name__ == "__main__":
    main()
