# SOLUTION-OF-NETWORK-TRAFFIC-SIMPLE-PACKET-SNIFFING-WITH-SCAPY
from scapy.all import sniff, IP, TCP

def packet_handler(packet):
    """
    Processes each captured packet and prints a summary.
    """
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        print(f"Captured IP Packet: Source: {src_ip} -> Destination: {dst_ip} Protocol: {protocol}")
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"  > TCP Layer: Source Port: {src_port} -> Destination Port: {dst_port}")

print("Starting packet capture...")
# Capture 10 packets on the default interface
# Run with sufficient privileges (e.g., sudo python script.py)
packets = sniff(count=10, prn=packet_handler)
print("Capture finished.")
