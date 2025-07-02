# Packet Sniffer Web Application

This project is a user-friendly web-based **Packet Sniffer** built with Python and Flask. It allows users to capture, analyze, and view network packets directly from their browser, making network monitoring accessible and easy to use for both beginners and professionals.

## Features

- **Live Packet Sniffing:**  
  Capture real-time network packets on your machine with a simple click from the web interface.

- **Packet Analysis:**  
  View detailed information about each captured packet, including source/destination IP, protocol, ports, and more.

- **Results Storage:**  
  All sniffed packets are saved to a file (`sniffed_packets.txt`) for later review and analysis.

- **Modern Web Interface:**  
  Navigate through a clean and responsive UI with pages for:
  - Home
  - About
  - Live Sniffing
  - Viewing Sniffed Results

- **Easy to Use:**  
  No command-line knowledge required. Start and stop packet sniffing, and view results, all from your browser.

## File Structure

```
packet sniffer/
  ├── app.py                # Main Flask application, handles routing and web server logic
  ├── packet_sniffer.py     # Core packet sniffing logic
  ├── sniffed_packets.txt   # Stores captured packet data
  ├── requirements.txt      # Python dependencies
  ├── style.css             # Custom styles for the web interface
  ├── about.html            # About page
  ├── home.html             # Home page
  ├── sniffing.html         # Live sniffing page
  └── view_results.html     # Results viewing page
```

## Getting Started

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the application:**
   ```bash
   python app.py
   ```

3. **Open your browser:**  
   Visit `http://localhost:5000` to access the web interface.

## Use Cases

- Educational tool for learning about network protocols and packet structures.
- Lightweight network monitoring for small networks or personal use.
- Demonstration of Python's networking and web development capabilities.

## Disclaimer

- **Administrator/root privileges may be required** to capture packets on some systems.
- Use responsibly and only on networks you own or have permission to monitor. 