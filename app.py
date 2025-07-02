from flask import Flask, render_template, redirect, url_for, jsonify
import threading
import time
import scapy.all as scapy
from scapy.layers import http
from tabulate import tabulate

app = Flask(__name__, template_folder='.', static_folder='.')

sniff_results = []
sniffing = False

# Helper to determine security status
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
    row = {
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'proto': proto,
        'length': length,
        'security': security
    }
    sniff_results.append(row)

def sniff_packets(interface='Wi-Fi', duration=10):
    global sniffing, sniff_results
    sniffing = True
    sniff_results = []
    scapy.sniff(
        iface=interface,
        store=False,
        prn=process_packet,
        timeout=duration
    )
    sniffing = False

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/start-sniffing')
def start_sniffing():
    # Start sniffing in a background thread
    if not sniffing:
        thread = threading.Thread(target=sniff_packets)
        thread.start()
    return render_template('sniffing.html')

@app.route('/sniff-results')
def sniff_results_api():
    return jsonify(sniff_results)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/view-results')
def view_results():
    return render_template('view_results.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)  # Use debug=False for production 