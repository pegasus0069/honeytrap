# Configuration
INTERFACE = "eth0"  # Change to "wlan0" if using Wi-Fi
STATIC_IP = "192.168.1.100/24"  # Set your static IP with subnet mask (e.g., 192.168.1.100/24)
GATEWAY = "192.168.1.1"  # Default gateway
DNS_SERVERS = "8.8.8.8,8.8.4.4"  # Google DNS

def run_command(command):
    """Run a shell command and return output"""
    try:
        subprocess.run(command, shell=True, check=True)
        print(f"Executed: {command}")
    except subprocess.CalledProcessError as e:
        print(f"Error executing: {command}\n{e}")

def set_static_ip():
    """Configure the network interface with a static IP"""
    print(f"Setting static IP for {INTERFACE}...")

    # Set IPv4 method to manual
    run_command(f"nmcli con mod {INTERFACE} ipv4.method manual")

    # Set static IP and subnet mask
    run_command(f"nmcli con mod {INTERFACE} ipv4.addresses {STATIC_IP}")

    # Set default gateway
    run_command(f"nmcli con mod {INTERFACE} ipv4.gateway {GATEWAY}")

    # Set DNS servers
    run_command(f"nmcli con mod {INTERFACE} ipv4.dns '{DNS_SERVERS}'")

    # Bring the connection down and up to apply changes
    run_command(f"nmcli con down {INTERFACE}")
    run_command(f"nmcli con up {INTERFACE}")

    print("Static IP configuration applied successfully!")