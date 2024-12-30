import os
import subprocess

def configure_dhcp_server():
    """
    Configure the DHCP server to operate on eth0 within the 192.168.1.0 network.
    """
    print("=== DHCP Server Configuration ===")

    # Static details for the DHCP server network
    interface = "eth0"  # Interface for the DHCP server
    subnet = "192.168.0.0"
    netmask = "255.255.255.0"
    range_start = "192.168.0.100"
    range_end = "192.168.0.249"
    router = "192.168.0.1"
    dns = "8.8.8.8"

    dhcp_config = f"""
default-lease-time 600;
max-lease-time 7200;

subnet {subnet} netmask {netmask} {{
    range {range_start} {range_end};
    option routers {router};
    option domain-name-servers {dns};
}}
"""
    # Write the configuration to the DHCP config file
    config_path = "/etc/dhcp/dhcpd.conf"
    with open(config_path, "w") as config_file:
        config_file.write(dhcp_config)
    
    print("\nDHCP configuration written to /etc/dhcp/dhcpd.conf.")
    
    # Configure the DHCP server to listen on the specified interface
    default_path = "/etc/default/isc-dhcp-server"
    with open(default_path, "w") as default_file:
        default_file.write(f'INTERFACESv4="{interface}"\n')

    print(f"\nDHCP server will use the interface: {interface}.")


def set_static_ip():
    """
    Configure eth0 with a static IP in the 192.168.1.0 network.
    """
    static_ip_config = f"""
interface eth0
static ip_address=192.168.0.3/24
static routers=192.168.0.1
static domain_name_servers=8.8.8.8
"""
    config_path = "/etc/dhcpcd.conf"
    with open(config_path, "a") as config_file:
        config_file.write(static_ip_config)
    
    print("\nStatic IP configuration added to /etc/dhcpcd.conf. Please reboot the Pi to apply.")


def start_dhcp_server():
    """
    Start the DHCP server and handle any errors.
    """
    print("\nStarting the DHCP server...")
    try:
        # Restart the DHCP server service
        subprocess.run(["sudo", "systemctl", "restart", "isc-dhcp-server"], check=True)
        subprocess.run(["sudo", "systemctl", "enable", "isc-dhcp-server"], check=True)
        print("DHCP server started and enabled to run on boot.")
    except subprocess.CalledProcessError as e:
        print(f"Error starting the DHCP server: {e}")


def main():
    """
    Main function to run the DHCP server setup.
    """
    # Check if the DHCP server is installed
    print("Checking for DHCP server installation...")
    if subprocess.run(["which", "dhcpd"]).returncode != 0:
        print("ISC DHCP Server is not installed. Installing now...")
        subprocess.run(["sudo", "apt-get", "update"])
        subprocess.run(["sudo", "apt-get", "install", "-y", "isc-dhcp-server"])
    
    print("\nISC DHCP Server is installed.")
    
    # Set the static IP for eth0
    set_static_ip()
    
    # Configure the DHCP server
    configure_dhcp_server()
    
    # Start the DHCP server
    start_dhcp_server()


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Please run this script as root (use sudo).")
    else:
        main()
