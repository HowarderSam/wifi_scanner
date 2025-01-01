import scapy.all as scapy
import socket
import os
import platform
from getmac import get_mac_address

# Function to get the local IP address of the machine
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(('10.254.254.254', 1))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = '127.0.0.1'
    finally:
        s.close()
    return local_ip

# Function to find the gateway IP address (Router IP)
def get_gateway_ip():
    system_platform = platform.system().lower()
    if system_platform == 'windows':
        # Windows command to get the gateway IP
        response = os.popen('ipconfig').read()
        for line in response.split('\n'):
            if 'Default Gateway' in line:
                return line.split(':')[1].strip()
    else:
        # Linux/Mac command to get the gateway IP
        response = os.popen('ip route | grep default').read()
        gateway_ip = response.split()[2]
        return gateway_ip
    return None

# Function to get the device manufacturer using MAC address
def get_device_manufacturer(mac_address):
    try:
        mac_info = get_mac_address(mac=mac_address)
        return mac_info
    except Exception as e:
        return "Unknown"

# Function to perform reverse DNS lookup to get the hostname (device name)
def get_device_name(ip):
    try:
        host = socket.gethostbyaddr(ip)
        return host[0]  # Return the hostname
    except socket.herror:
        return "Unknown Device"

# Function to scan the network
def scan(ip):
    # Send ARP request to get the IP and MAC addresses
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    devices_list = []
    for element in answered_list:
        device_info = {
            "ip": element[1].psrc,
            "mac": element[1].hwsrc,
            "name": get_device_name(element[1].psrc),  # Device Name
            "manufacturer": get_device_manufacturer(element[1].hwsrc)  # Device Manufacturer
        }
        devices_list.append(device_info)
    
    return devices_list

# Function to display the scanned devices
def display_result(devices_list):
    print("IP Address\t\tMAC Address\t\t\tDevice Name\t\tManufacturer")
    print("---------------------------------------------------------------------")
    for device in devices_list:
        print(f"{device['ip']}\t\t{device['mac']}\t\t{device['name']}\t\t{device['manufacturer']}")

# Main function
def main():
    gateway_ip = get_gateway_ip()
    if gateway_ip is None:
        print("Could not find the gateway IP. Exiting...")
        return

    network = gateway_ip.rsplit('.', 1)[0] + '.1/24'  # Get the network address, e.g., 192.168.1.1/24
    print(f"Scanning network: {network}...\n")
    devices_list = scan(network)
    display_result(devices_list)

if __name__ == "__main__":
    main()
