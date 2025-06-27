import wmi
import scapy.all as scapy
import netifaces
from datetime import datetime
import socket
import time
import pyfiglet

# Global variables for statistics
total_packets = 0
total_packet_size = 0
packet_count_by_protocol = {'TCP': 0, 'UDP': 0, 'ICMP': 0}
top_talkers = {'IP': {}, 'Port': {}}

# Global variable for IP filter
ip_filter = None

def print_banner():
    banner = pyfiglet.figlet_format("KartNetPacklyser", font="big")
    print(banner)

def get_interface_names():
    interfaces = netifaces.interfaces()
    return interfaces



def get_interface_friendly_names():
    w = wmi.WMI()
    interface_map = {}
    for nic in w.Win32_NetworkAdapter():
        if nic.GUID:
            interface_map['{' + nic.GUID.upper() + '}'] = nic.Name
    return interface_map

def print_available_interfaces(interfaces):
    print("Available interfaces:")
    interface_names = get_interface_friendly_names()
    for i, interface in enumerate(interfaces, start=1):
        friendly_name = interface_names.get(interface, "Unknown")
        print(f"{i}. {friendly_name} ({interface})")


def get_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        hostname = ip
    return hostname

def update_protocol_count(protocol):
    global packet_count_by_protocol
    if protocol in packet_count_by_protocol:
        packet_count_by_protocol[protocol] += 1

def update_top_talkers(ip_src, ip_dst, src_port, dst_port):
    global top_talkers
    # Update IP talkers
    if ip_src in top_talkers['IP']:
        top_talkers['IP'][ip_src] += 1
    else:
        top_talkers['IP'][ip_src] = 1
    
    if ip_dst in top_talkers['IP']:
        top_talkers['IP'][ip_dst] += 1
    else:
        top_talkers['IP'][ip_dst] = 1
    
    # Update Port talkers
    if src_port in top_talkers['Port']:
        top_talkers['Port'][src_port] += 1
    else:
        top_talkers['Port'][src_port] = 1
    
    if dst_port in top_talkers['Port']:
        top_talkers['Port'][dst_port] += 1
    else:
        top_talkers['Port'][dst_port] = 1

def print_statistics():
    global total_packets, total_packet_size, packet_count_by_protocol, top_talkers

    print("\n--- Statistics ---")
    print(f"Total Packets Captured: {total_packets}")
    if total_packets > 0:
        print(f"Average Packet Size: {total_packet_size / total_packets:.2f} bytes")
        end_time = time.time()
        elapsed_time = end_time - start_time
        print(f"Packet Rate per Second: {total_packets / elapsed_time:.2f}")

    else:
        print("Average Packet Size: N/A (No packets captured)")

    print("\nProtocol Distribution:")
    for protocol, count in packet_count_by_protocol.items():
        print(f"{protocol}: {count} packets")

    print("\nTop Talkers (IPs):")
    sorted_ips = sorted(top_talkers['IP'].items(), key=lambda x: x[1], reverse=True)[:5]
    for ip, count in sorted_ips:
        print(f"{ip}: {count} packets")

    print("\nTop Talkers (Ports):")
    sorted_ports = sorted(top_talkers['Port'].items(), key=lambda x: x[1], reverse=True)[:5]
    for port, count in sorted_ports:
        print(f"{port}: {count} packets")

def dpi_http(packet):
    if packet.haslayer(scapy.Raw):
        payload = packet[scapy.Raw].load
        if b"HTTP" in payload:
            headers = payload.split(b"\r\n")
            for header in headers:
                print(header.decode('utf-8', errors='ignore'))

def dpi_dns(packet):
    if packet.haslayer(scapy.DNS):
        dns_layer = packet[scapy.DNS]
        query_name = dns_layer.qd.qname.decode('utf-8')
        if 'in-addr.arpa' in query_name:
            ip_parts = query_name.split('.')[:-2]
            ip_parts.reverse()
            ip_address = '.'.join(ip_parts)
            print(f"DNS Reverse Lookup Query: {query_name} (IP: {ip_address})")
        else:
            print(f"DNS Query: {query_name}")

def dpi_ftp(packet):
    if packet.haslayer(scapy.Raw):
        payload = packet[scapy.Raw].load
        if b"USER" in payload or b"PASS" in payload:
            print(f"FTP Payload: {payload.decode('utf-8', errors='ignore')}")

def packet_callback(packet):
    global total_packets, total_packet_size, start_time

    if total_packets == 0:
        start_time = time.time()

    total_packets += 1
    total_packet_size += len(packet)

    if packet.haslayer(scapy.Ether):
        eth_src = packet[scapy.Ether].src
        eth_dst = packet[scapy.Ether].dst

    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst

        if ip_filter and (ip_src != ip_filter and ip_dst != ip_filter):
            return  # Skip packet if it doesn't match filter

        src_hostname = get_hostname(ip_src)
        dst_hostname = get_hostname(ip_dst)
        protocol = packet[scapy.IP].proto
        update_protocol_count('TCP' if protocol == 6 else 'UDP' if protocol == 17 else 'ICMP')
        update_top_talkers(ip_src, ip_dst, packet[scapy.IP].sport, packet[scapy.IP].dport)

    if packet.haslayer(scapy.TCP):
        src_port = packet[scapy.TCP].sport
        dst_port = packet[scapy.TCP].dport
        protocol_name = "TCP"
        # DPI for HTTP and FTP
        dpi_http(packet)
        dpi_ftp(packet)

    elif packet.haslayer(scapy.UDP):
        src_port = packet[scapy.UDP].sport
        dst_port = packet[scapy.UDP].dport
        protocol_name = "UDP"
        # DPI for DNS
        dpi_dns(packet)

    else:
        protocol_name = "Unknown"

    # Print packet details
    print("\n--- New Packet ---")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    if packet.haslayer(scapy.Ether):
        print(f"Ethernet: {eth_src} -> {eth_dst}")

    if packet.haslayer(scapy.IP):
        print(f"IP: {src_hostname} ({ip_src}) -> {dst_hostname} ({ip_dst}), Protocol: {protocol_name}, Length: {packet[scapy.IP].len}")

    if packet.haslayer(scapy.TCP):
        print(f"TCP: Port {src_port} -> {dst_port}")
        print(f"Sequence Number: {packet[scapy.TCP].seq}, Ack: {packet[scapy.TCP].ack}")

    elif packet.haslayer(scapy.UDP):
        print(f"UDP: Port {src_port} -> {dst_port}")

    if packet.haslayer(scapy.Raw):
        payload = packet[scapy.Raw].load
        print(f"Payload: {payload}")

    print(f"Packet Size: {len(packet)} bytes")

def set_ip_filter():
    global ip_filter
    ip_filter = input("Enter the IP address to filter (leave empty for no filter): ").strip()
    if ip_filter:
        try:
            socket.inet_aton(ip_filter)  # Validate IP address format
        except socket.error:
            print("Invalid IP address format.")
            ip_filter = None

# Main execution
print_banner()  # Print banner at the start

interfaces = get_interface_names()
print_available_interfaces(interfaces)

try:
    selected_interface_index = int(input("Enter the number of the interface you wish to capture packets: "))
    selected_interface = interfaces[selected_interface_index - 1]
except (ValueError, IndexError):
    print("Invalid input. Please enter a valid interface number.")
    exit(1)

print(f"\nSelected interface: {selected_interface}")

# Set IP filter
set_ip_filter()

# Start packet capture
start_time = None
print("\nStarting packet capture...\n")
scapy.sniff(iface=selected_interface, store=False, prn=packet_callback)

# After packet capture ends, print statistics
print_statistics()
