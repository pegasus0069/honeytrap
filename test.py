import os
import subprocess


def configure_dhcp_server():
    """
    Configure the DHCP server to operate on eth0 within the 192.168.0.0 network.
    """
    print("=== DHCP Server Configuration ===")

    # Static details for the DHCP server network
    interface = "eth0"
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
    config_path = "/etc/dhcp/dhcpd.conf"
    try:
        # Write the DHCP configuration
        with open(config_path, "w") as config_file:
            config_file.write(dhcp_config)
        print("\nDHCP configuration written to /etc/dhcp/dhcpd.conf.")

        # Set the DHCP server to listen on the specified interface
        default_path = "/etc/default/isc-dhcp-server"
        with open(default_path, "w") as default_file:
            default_file.write(f'INTERFACESv4="{interface}"\n')
        print(f"DHCP server will use the interface: {interface}.")
    except Exception as e:
        print(f"Error configuring DHCP server: {e}")


def set_static_ip():
    """
    Configure eth0 with a static IP in the 192.168.0.0 network using NetworkManager.
    """
    print("=== Configuring Static IP ===")

    interface = "eth0"
    ip_address = "192.168.0.134/24"
    gateway = "192.168.0.1"
    dns = "8.8.8.8"

    try:
        # Use nmcli to configure the static IP
        subprocess.run(["nmcli", "con", "mod", "Wired connection 1", "ipv4.addresses", ip_address], check=True)
        subprocess.run(["nmcli", "con", "mod", "Wired connection 1", "ipv4.gateway", gateway], check=True)
        subprocess.run(["nmcli", "con", "mod", "Wired connection 1", "ipv4.dns", dns], check=True)
        subprocess.run(["nmcli", "con", "mod", "Wired connection 1", "ipv4.method", "manual"], check=True)

        # Restart the network connection
        subprocess.run(["nmcli", "con", "down", "Wired connection 1"], check=True)
        subprocess.run(["nmcli", "con", "up", "Wired connection 1"], check=True)

        print(f"Static IP configuration applied: {ip_address} (Gateway: {gateway}, DNS: {dns})")
    except subprocess.CalledProcessError as e:
        print(f"Error configuring static IP: {e}")


def start_dhcp_server():
    """
    Start the DHCP server and enable it to run on boot.
    """
    print("=== Starting the DHCP Server ===")
    try:
        subprocess.run(["systemctl", "restart", "isc-dhcp-server"], check=True)
        subprocess.run(["systemctl", "enable", "isc-dhcp-server"], check=True)
        print("DHCP server started and enabled to run on boot.")
    except subprocess.CalledProcessError as e:
        print(f"Error starting the DHCP server: {e}")


def main():
    """
    Main function to set up and run the DHCP server.
    """
    print("=== Checking for DHCP server installation ===")
    if subprocess.run(["which", "dhcpd"]).returncode != 0:
        print("ISC DHCP Server is not installed. Installing now...")
        subprocess.run(["apt-get", "update"], check=True)
        subprocess.run(["apt-get", "install", "-y", "isc-dhcp-server"], check=True)

    print("\nISC DHCP Server is installed.")

    # Configure static IP and DHCP server
    set_static_ip()
    configure_dhcp_server()

    # Start the DHCP server
    start_dhcp_server()


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Please run this script as root (use sudo).")
    else:
        main()
