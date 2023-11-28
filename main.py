import socket
import netifaces
from scapy.all import ARP, Ether, srp

def get_local_ip():
    return socket.gethostbyname(socket.gethostname())

def get_mac(ip):
    arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=False)[0]
    return result[0][1].hwsrc if result else None

def scan_open_ports(ip, start_port, end_port):
    open_ports = []
    try:
        for port in range(start_port, end_port + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
    except KeyboardInterrupt:
        pass
    return open_ports

def get_network_info():
    gateways = netifaces.gateways()
    interfaces = netifaces.interfaces()
    addresses = {interface: netifaces.ifaddresses(interface) for interface in interfaces}
    return gateways, addresses

def get_device_info():
    local_ip = get_local_ip()
    local_mac = get_mac(local_ip)
    local_hostname = get_hostname(local_ip)
    return {
        "Local IP": local_ip,
        "Local MAC": local_mac,
        "Local Hostname": local_hostname
    }

def scan_network_vulnerabilities(target_ip_range):
    nm = nmap.PortScanner()
    nm.scan(hosts=target_ip_range, arguments='-sV -O')  # Scan for services and OS detection

    vulnerabilities = {}
    for host in nm.all_hosts():
        vulnerabilities[host] = {
            "Hostname": nm[host].hostname(),
            "OS": nm[host]['osmatch'][0]['osclass'][0]['osfamily'],  # OS details
            "Open Ports": list(nm[host]['tcp'].keys()),  # Open ports
            "Vendor": nm[host]['osmatch'][0]['osclass'][0].get('vendor', ''),
            "Device Type": nm[host]['osmatch'][0]['osclass'][0].get('type', ''),
            # Add more details or checks for vulnerabilities based on your requirements
        }

    return vulnerabilities

if __name__ == "__main__":
    # Fetch device information
    device_info = get_device_info()
    print("Device Information:")
    for key, value in device_info.items():
        print(f"{key}: {value}")

    # Scan open ports on a specific IP range
    start_port = 1
    end_port = 1024
    target_ip_range = "192.168.1.1/24"  # Modify this with your target IP range
    open_ports = scan_open_ports(target_ip_range, start_port, end_port)
    print("\nOpen Ports:", open_ports)

    # Get network-related information
    gateways, addresses = get_network_info()
    print("\nGateways:", gateways)
    print("\nAddresses:", addresses)

    # Perform vulnerability scanning using Nmap
    vulnerabilities = scan_network_vulnerabilities(target_ip_range)
    print("\nVulnerabilities:")
    for host, info in vulnerabilities.items():
        print(f"Host: {host}")
        for key, value in info.items():
            print(f"\t{key}: {value}")



if __name__ == "__main__":
    # 1. Fetch device information
    device_info = get_device_info()
    print("Device Information:")
    for key, value in device_info.items():
        print(f"{key}: {value}")

    # 2. Scan open ports on a specific IP range
    start_port = 1
    end_port = 1024
    target_ip_range = "192.168.1.1/24"  # Modify this with your target IP range
    open_ports = scan_open_ports(target_ip_range, start_port, end_port)
    print("\nOpen Ports:", open_ports)

    # 3. Get network-related information
    gateways, addresses = get_network_info()
    print("\nGateways:", gateways)
    print("\nAddresses:", addresses)

    # 4. Perform vulnerability scanning
    # scan_network_vulnerabilities()
