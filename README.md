# Network-simple-Tool-kit

This Python-based CLI (Command Line Interface) application is designed to scan a network for devices, open ports, and potential vulnerabilities.

## Features

- **Device Information**
  - Fetches details about the local device such as IP address, MAC address, and hostname.
- **Open Ports Scanning**
  - Scans a specified IP range to discover open ports within the range.
- **Network Information**
  - Retrieves network-related information, including gateway details and network interfaces.
- **Vulnerability Scanning**
  - Uses Nmap to perform a vulnerability assessment on the specified IP range, identifying potential security risks.

## Requirements

- Python 3.x
- `netifaces`
- `scapy`
- `nmap`

## Usage

### Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/Mf-malaak/Network-simple-Tool-kit.git
    ```

2. Install the required dependencies:

    ```bash
    pip install -r _requirements.txt
    ```

### Running the Scanner

1. Navigate to the project directory:

    ```bash
    cd network-scanner
    ```

2. Execute the script:

    ```bash
    python network_scanner.py
    ```

### Example Usage

```python
# Example usage within the script
# Modify the IP range and other parameters as needed

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
```
### Disclaimer
This tool is intended for educational and research purposes. Ensure that you have the necessary permissions before scanning any network. The developers and contributors are not responsible for any misuse or damage caused by this tool. Use it responsibly and at your own risk.
