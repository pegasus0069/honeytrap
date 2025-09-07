import os
import subprocess
import netifaces

# Configuration
INTERFACE = "eth0"  # Change to "wlan0" if using Wi-Fi

# Function to get the default gateway IP
def get_default_gateway():
    try:
        gateways = netifaces.gateways()
        return gateways['default'][netifaces.AF_INET][0]  # Get the IPv4 default gateway
    except Exception as e:
        print(f"Error getting default gateway: {e}")
        return None

# Function to get the default DNS server assigned by the router
def get_default_dns():
    try:
        # Use nmcli to get DNS information for the interface
        result = subprocess.run(
            ["nmcli", "device", "show", INTERFACE],
            capture_output=True,
            text=True,
            check=True,
        )
        # Extract DNS servers from the output
        dns_servers = []
        for line in result.stdout.splitlines():
            if "IP4.DNS" in line:
                dns_servers.append(line.split(":")[1].strip())
        
        if dns_servers:
            return ",".join(dns_servers)  # Join DNS servers with commas
        else:
            print("No DNS servers found for the interface. Using fallback DNS.")
            return "8.8.8.8,8.8.4.4"  # Fallback to Google DNS
    except subprocess.CalledProcessError as e:
        print(f"Error getting DNS servers: {e}")
        return "8.8.8.8,8.8.4.4"  # Fallback to Google DNS

# Function to run a shell command
def run_command(command):
    """Run a shell command and return output"""
    try:
        subprocess.run(command, shell=True, check=True)
        print(f"Executed: {command}")
    except subprocess.CalledProcessError as e:
        print(f"Error executing: {command}\n{e}")
        exit(1)

# Function to set a static IP address
def set_static_ip():
    """Configure the network interface with a static IP"""
    gateway_ip = get_default_gateway()
    if not gateway_ip:
        print("Could not determine default gateway. Exiting.")
        exit(1)

    # Extract the first three octets of the gateway IP
    ip_parts = gateway_ip.split('.')
    if len(ip_parts) != 4:
        print("Invalid gateway IP format. Exiting.")
        exit(1)

    # Set the last octet to 99
    static_ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.99/24"

    # Get the default DNS servers assigned by the router
    dns_servers = get_default_dns()

    print(f"Setting static IP for {INTERFACE}...")

    # Set IPv4 method to manual
    run_command(f"nmcli con mod {INTERFACE} ipv4.method manual")

    # Set static IP and subnet mask
    run_command(f"nmcli con mod {INTERFACE} ipv4.addresses {static_ip}")

    # Set default gateway
    run_command(f"nmcli con mod {INTERFACE} ipv4.gateway {gateway_ip}")

    # Set DNS servers
    run_command(f"nmcli con mod {INTERFACE} ipv4.dns '{dns_servers}'")

    # Bring the connection down and up to apply changes
    run_command(f"nmcli con down {INTERFACE}")
    run_command(f"nmcli con up {INTERFACE}")

    print("Static IP configuration applied successfully!")

# Function to generate DHCP configuration based on the default gateway
def generate_dhcp_config():
    gateway_ip = get_default_gateway()
    if not gateway_ip:
        print("Could not determine default gateway. Exiting.")
        exit(1)

    # Extract the first three octets of the gateway IP
    ip_parts = gateway_ip.split('.')
    if len(ip_parts) != 4:
        print("Invalid gateway IP format. Exiting.")
        exit(1)

    subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0"
    range_start = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.100"
    range_end = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.200"

    # Get the default DNS servers assigned by the router
    dns_servers = get_default_dns()

    dhcp_config = f"""
subnet {subnet} netmask 255.255.255.0 {{
    range {range_start} {range_end};
    option routers {gateway_ip};
    option domain-name-servers {dns_servers};
    default-lease-time 3600;
    max-lease-time 7200;
}}
"""
    return dhcp_config

# Function to install isc-dhcp-server and configure it
def install_and_configure_dhcp():
    try:
        # Install isc-dhcp-server
        print("Installing isc-dhcp-server...")
        subprocess.run(["sudo", "apt-get", "update"], check=True)
        subprocess.run(["sudo", "apt-get", "install", "-y", "isc-dhcp-server"], check=True)

        # Generate DHCP configuration
        dhcp_config = generate_dhcp_config()

        # Write the configuration to /etc/dhcp/dhcpd.conf
        print("Configuring DHCP server...")
        with open("/etc/dhcp/dhcpd.conf", "w") as f:
            f.write(dhcp_config)

        # Configure the DHCP server to listen on the correct interface
        with open("/etc/default/isc-dhcp-server", "w") as f:
            f.write(f'INTERFACESv4="{INTERFACE}"\n')

        # Restart the DHCP server
        print("Restarting DHCP server...")
        subprocess.run(["sudo", "systemctl", "restart", "isc-dhcp-server"], check=True)
        subprocess.run(["sudo", "systemctl", "enable", "isc-dhcp-server"], check=True)

        print("DHCP server installed and configured successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error during DHCP server installation or configuration: {e}")
        exit(1)

# Function to create and activate the Python virtual environment
def setup_python_environment():
    try:
        # Install virtualenv if not already installed
        print("Installing virtualenv...")
        subprocess.run(["sudo", "apt-get", "install", "-y", "python3-venv"], check=True)

        # Create the ukcs virtual environment
        print("Creating ukcs virtual environment...")
        subprocess.run(["python3", "-m", "venv", "ukcs"], check=True)

        # Activate the virtual environment and install dependencies
        print("Activating ukcs virtual environment and installing dependencies...")
        activate_script = os.path.join("ukcs", "bin", "activate")
        subprocess.run(f"source {activate_script} && pip install -r requirements.txt", shell=True, executable="/bin/bash", check=True)

        print("Python virtual environment 'ukcs' created and dependencies installed.")
    except subprocess.CalledProcessError as e:
        print(f"Error setting up Python virtual environment: {e}")
        exit(1)

# Function to install Python dependencies
def install_python_dependencies():
    try:
        print("Installing Python dependencies...")
        subprocess.run(["pip", "install", "-r", "requirements.txt"], check=True)
        print("Python dependencies installed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error installing Python dependencies: {e}")
        exit(1)

# Main function
def main():
    # Set up the Python virtual environment
    setup_python_environment()

    # Set a static IP address
    set_static_ip()

    # Install and configure isc-dhcp-server
    install_and_configure_dhcp()

    print("Setup completed successfully. To run the server, activate the 'ukcs' environment and run 'server.py':")
    print("source ukcs/bin/activate")
    print("python server.py")

if __name__ == "__main__":
    main()