import scapy.all as scapy
from scapy.layers import http, tls
import time
import threading
import sys

from tabulate import tabulate

OUTPUT_FILE = 'sniffed_packets.txt'

results = []

# Determine if the packet is encrypted or vulnerable
def get_security_status(packet):
    if packet.haslayer('TLS') or packet.haslayer('SSL') or (packet.haslayer(scapy.TCP) and packet[scapy.TCP].dport == 443):
        return 'Encrypted'
    elif packet.haslayer(http.HTTPRequest):
        return 'Vulnerable'
    else:
        return 'Unknown'

def process_packet(packet):
    src_ip = packet[scapy.IP].src if packet.haslayer(scapy.IP) else 'N/A'
    dst_ip = packet[scapy.IP].dst if packet.haslayer(scapy.IP) else 'N/A'
    proto = packet.lastlayer().name
    length = len(packet)
    security = get_security_status(packet)
    row = [src_ip, dst_ip, proto, length, security]
    results.append(row)
    print(tabulate([row], headers=["Source IP", "Destination IP", "Protocol", "Length", "Security"], tablefmt="plain"))

def sniff_packets(interface, duration=10):
    print(f"\nSniffing on interface: {interface} for {duration} seconds...\n")
    sniff_thread = threading.Thread(target=lambda: scapy.sniff(
        iface=interface,
        store=False,
        prn=process_packet,
        timeout=duration
    ))
    sniff_thread.start()
    sniff_thread.join()

def main():
    interface = 'Wi-Fi'
    print(f"Using interface: {interface}")
    try:
        sniff_packets(interface, duration=10)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
    if results:
        print("\nSummary Table:\n")
        print(tabulate(results, headers=["Source IP", "Destination IP", "Protocol", "Length", "Security"], tablefmt="grid"))
        with open(OUTPUT_FILE, 'w') as f:
            f.write(tabulate(results, headers=["Source IP", "Destination IP", "Protocol", "Length", "Security"], tablefmt="grid"))
        print(f"\nResults saved to {OUTPUT_FILE}")
    else:
        print("No packets captured.")

if __name__ == "__main__":
    main()