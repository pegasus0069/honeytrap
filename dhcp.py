import os
import subprocess

def start_dhcp_server():
  """
  Starts a custom DHCP server on the Raspberry Pi with user-defined settings,
  including setting a custom hostname. Installs dnsmasq only if not already present.
  Uses systemd-resolved for DNS cache flushing.
  """
  try:
    # Get Default Gateway (Router IP)
    print("\nFinding your Default Gateway (Router IP)...")
    process = subprocess.run(['ip', 'route'], capture_output=True, text=True)
    output = process.stdout
    gateway_line = next((line for line in output.splitlines() if "default via" in line), None)
    if gateway_line:
      default_gateway = gateway_line.split()[2]
      print(f"Found Default Gateway: {default_gateway}")
    else:
      default_gateway = input("Could not automatically determine the Default Gateway. "
                             "Please enter it manually: ")

    # Get Subnet Mask
    subnet_mask = input("\nEnter the Subnet Mask (usually 255.255.255.0): ")

    # Get Raspberry Pi's Static IP
    while True:
      pi_ip_address = input("\nEnter the desired Static IP address for the Raspberry Pi: ")
      if pi_ip_address.startswith(default_gateway.rsplit('.', 1)[0] + '.'):  # Check subnet
        break
      else:
        print("Invalid IP address. It must be in the same subnet as the Default Gateway.")

    # Get DHCP Range
    while True:
      dhcp_range_start = input("\nEnter the starting IP address of the DHCP range: ")
      dhcp_range_end = input("Enter the ending IP address of the DHCP range: ")
      if (dhcp_range_start.startswith(default_gateway.rsplit('.', 1)[0] + '.') and
          dhcp_range_end.startswith(default_gateway.rsplit('.', 1)[0] + '.')):
        break
      else:
        print("Invalid DHCP range. The IP addresses must be in the same subnet as the Default Gateway.")

    # Get desired hostname
    new_hostname = input("\nEnter the desired hostname for the Raspberry Pi: ")

    # Check if dnsmasq is installed
    print("\nChecking for dnsmasq...")
    dnsmasq_installed = subprocess.run(['which', 'dnsmasq'], capture_output=True, text=True).returncode == 0

    if not dnsmasq_installed:
      # Install dnsmasq
      print("\nInstalling dnsmasq...")
      subprocess.run(['sudo', 'apt-get', 'update'], check=True)
      subprocess.run(['sudo', 'apt-get', 'install', '-y', 'dnsmasq'], check=True)
    else:
      print("dnsmasq is already installed.")

    # Configure dnsmasq
    print("\nConfiguring dnsmasq...")
    with open('/etc/dnsmasq.conf', 'w') as f:
      f.write(f'interface=eth0\n')  # Use eth0 for wired, wlan0 for Wi-Fi
      f.write(f'dhcp-range={dhcp_range_start},{dhcp_range_end},12h\n')
      f.write(f'dhcp-option=3,{default_gateway}\n')
      f.write(f'dhcp-option=6,{default_gateway}\n')
      f.write(f'port=5353\n')

    # Set static IP for the Raspberry Pi
    print("\nConfiguring static IP for the Raspberry Pi...")
    with open('/etc/dhcpcd.conf', 'a') as f:
      f.write(f'\ninterface eth0\n')
      f.write(f'static ip_address={pi_ip_address}/{subnet_mask}\n')
      f.write(f'static routers={default_gateway}\n')
      f.write(f'static domain_name_servers={default_gateway} 8.8.8.8\n')

    # Change hostname
    print(f"\nChanging hostname to '{new_hostname}'...")
    try:
      # Edit /etc/hostname
      with open('/etc/hostname', 'w') as f:
        f.write(new_hostname + '\n')

      # Edit /etc/hosts
      with open('/etc/hosts', 'r') as f:
        lines = f.readlines()
      with open('/etc/hosts', 'w') as f:
        for line in lines:
          if line.startswith('127.0.0.1'):
            f.write(f'127.0.0.1\tlocalhost {new_hostname}\n')  # Update hostname
          else:
            f.write(line)

      # Refresh hostname without rebooting (using subprocess)
      subprocess.run(['hostnamectl', 'set-hostname', new_hostname], check=True)

      # Flush DNS cache (using systemd-resolved)
      subprocess.run(['sudo', 'systemctl', 'restart', 'systemd-resolved'], check=True)

      print(f"Hostname changed to {new_hostname}")

    except Exception as e:
      print(f"Error changing hostname: {e}")

    # Restart services
    print("\nRestarting services...")
    subprocess.run(['sudo', 'systemctl', 'restart', 'dhcpcd'], check=True)
    subprocess.run(['sudo', 'systemctl', 'restart', 'dnsmasq'], check=True)

    print("\nDHCP server started successfully!")

  except Exception as e:
    print(f"Error starting DHCP server: {e}")

if __name__ == "__main__":
  start_dhcp_server()