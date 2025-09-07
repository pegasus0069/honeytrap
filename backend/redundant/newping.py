import os
import re
import json
import socket
import time
import netifaces
from scapy.all import sniff, IP, TCP, ICMP
from datetime import datetime
from flask import Flask, jsonify, Response
from threading import Thread
from queue import Queue

# Initialize Flask app
app = Flask(__name__)

# Queue to safely share the latest event data between threads
latest_event_queue = Queue()

# JSON and log file paths
json_file_path = "events.json"
log_file_path = "events.log"

# Store the last recorded event to prevent duplicate writes
last_event = None  

# Get the Raspberry Pi's own IP addresses for both eth0 and wlan1
def get_own_ips():
    own_ips = []
    interfaces = ["eth0", "wlan1"]
    for interface in interfaces:
        try:
            addresses = netifaces.ifaddresses(interface)
            ipv4_info = addresses.get(netifaces.AF_INET)
            if ipv4_info:
                own_ips.append(ipv4_info[0]['addr'])
        except ValueError as e:
            print(f"Error getting IP for {interface}: {e}")
    return own_ips

OWN_IPS = get_own_ips()

def get_mac(ip):
    """Fetch the MAC address for a given IP address."""
    try:
        result = os.popen(f"arp -an | grep '({ip})'").read()
        mac_address = re.search(r"([0-9a-fA-F:]{17})", result)
        return mac_address.group(0) if mac_address else "Unknown MAC"
    except Exception as e:
        return f"Error: {e}"

def save_event(event_data):
    """Save the captured event data to both JSON and log files, ensuring no duplicates."""
    global last_event

    # Check if the new event is the same as the last recorded one
    if last_event == event_data:
        return  # No new event, skip saving

    # Update last recorded event
    last_event = event_data

    # Save to JSON file
    try:
        with open(json_file_path, "a") as json_file:
            json.dump(event_data, json_file)
            json_file.write("\n")  # Write each event on a new line
    except Exception as e:
        print(f"Error saving to JSON file: {e}")

    # Save to log file (plain text format)
    try:
        with open(log_file_path, "a") as log_file:
            log_file.write(f"{event_data['timestamp']} - {event_data['type']} - {event_data['src_ip']} - {event_data['mac_address']}\n")
    except Exception as e:
        print(f"Error saving to log file: {e}")

def packet_callback(packet):
    """Process sniffed packets and return JSON with details, ignoring own IP."""
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        print(f"Packet received from: {src_ip}")

        # Ignore packets from the Raspberry Pi itself
        if src_ip in OWN_IPS:
            print(f"Ignoring packet from own IP: {src_ip}")
            return

        mac_address = get_mac(src_ip)
        event_type = None

        if packet.haslayer(TCP) and packet[TCP].dport == 22:
            event_type = "SSH"
        elif packet.haslayer(ICMP):
            event_type = "PING"

        if event_type:
            # Get the current timestamp
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            # Create the JSON data
            latest_event = {
                "timestamp": timestamp,
                "type": event_type,
                "src_ip": src_ip,
                "mac_address": mac_address
            }

            # Put the event into the queue to share with Flask
            latest_event_queue.put(latest_event)

            # Save the event data to JSON and log files (only if it's new)
            save_event(latest_event)

            # Debugging print
            print(f"Captured event: {json.dumps(latest_event)}")

# Flask route to fetch the latest event as JSON
@app.route('/get_latest_event', methods=['GET'])
def get_latest_event():
    """Fetch and return the latest event in real-time."""
    if not latest_event_queue.empty():
        latest_event = latest_event_queue.get_nowait()
        return jsonify(latest_event)
    else:
        return jsonify({"message": "No new event detected"}), 404

# Flask route to get the contents of the log file
@app.route('/get_log_file', methods=['GET'])
def get_log_file():
    """Load and return the contents of the log file."""
    try:
        with open(log_file_path, "r") as log_file:
            log_content = log_file.read()
        return Response(log_content, mimetype='text/plain')
    except Exception as e:
        return jsonify({"error": f"Error reading log file: {e}"}), 500

# Start the sniffing process in a separate thread
def start_sniffing():
    print(f"Monitoring SSH and Ping attempts... Ignoring own IPs: {OWN_IPS}")

    def sniff_interface(interface):
        print(f"Starting sniffing on interface: {interface}")
        sniff(filter="port 22 or icmp", iface=interface, prn=packet_callback, store=0)

    # Start sniffing on eth0 and wlan1 in separate threads
    eth0_thread = Thread(target=sniff_interface, args=("eth0",))
    wlan1_thread = Thread(target=sniff_interface, args=("wlan1",))

    eth0_thread.daemon = True
    wlan1_thread.daemon = True

    eth0_thread.start()
    wlan1_thread.start()

    # Keep the threads alive
    eth0_thread.join()
    wlan1_thread.join()

if __name__ == '__main__':
    # Start sniffing in a separate thread or process
    sniff_thread = Thread(target=start_sniffing)
    sniff_thread.daemon = True
    sniff_thread.start()

    # Run the Flask server
    app.run(host='0.0.0.0', port=5000)