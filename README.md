IoT Network Scanner
Overview
The IoT Network Scanner is a Python-based application designed to detect and assess Internet of Things (IoT) devices on a local network for potential vulnerabilities. It provides a simple graphical user interface (GUI) built with Tkinter, allowing users to scan a specified network range, identify active devices, check for open ports, and evaluate common vulnerabilities. The tool is intended for network administrators and security enthusiasts to monitor endpoint security in environments with IoT devices.
Note: This tool performs basic network scanning and vulnerability assessment for demonstration purposes. Always ensure you have explicit permission to scan any network, as unauthorized scanning may violate legal and ethical guidelines.
Features

Network Discovery: Scans a specified IP range (e.g., 192.168.1.0/24) to identify active IoT devices.
Port Scanning: Checks for open ports commonly used by IoT devices (e.g., HTTP, HTTPS, Telnet, FTP, SSH, MQTT, CoAP).
Vulnerability Assessment: Identifies potential vulnerabilities based on open ports, such as weak credentials or unpatched services.
GUI Interface: Provides an intuitive Tkinter-based GUI for inputting scan parameters and viewing results.
Threaded Scanning: Utilizes multithreading to perform efficient scans without freezing the GUI.
Report Generation: Outputs a detailed Markdown report summarizing discovered devices, open ports, and potential vulnerabilities.

Requirements

Python: Version 3.6 or higher
Libraries: 
socket (standard library)
threading (standard library)
queue (standard library)
concurrent.futures (standard library)
tkinter (standard library)


Operating System: Compatible with Windows, macOS, or Linux
Network Access: Permission to scan the target network

No additional dependencies are required, as the program uses Python's standard libraries.
Installation



Verify Python Installation:Ensure Python 3.6+ is installed by running:
python3 --version


Run the Program:No additional installation is needed since the program uses standard Python libraries. Simply execute the script as described in the Usage section.


Usage

Launch the Application:Run the script using Python:
python3 iot_scanner_gui.py


GUI Instructions:

Network Range: Enter the network to scan in CIDR notation (e.g., 192.168.1.0/24).
Timeout: Specify the timeout for each connection attempt in seconds (e.g., 0.5 for half a second).
Start Scan: Click the "Start Scan" button to initiate the scan.
View Results: The scan results will appear in the text area below, formatted as a Markdown report.


Sample Report Output:
# IoT Network Scan Report

Scanned Network: 192.168.1.0/24
Scan Time: Fri Jul 18 11:55:00 2025
Total Devices Found: 2

## Device: 192.168.1.10
- Status: up
- Latency: 12.34 ms
- Open Ports:
  - Port 80 (HTTP)
  - Port 443 (HTTPS)
- Potential Vulnerabilities:
  - Weak credentials
  - Unpatched web server
  - SSL misconfiguration
  - Outdated TLS

## Device: 192.168.1.20
- Status: up
- Latency: 15.67 ms
- Open Ports:
  - Port 23 (Telnet)
- Potential Vulnerabilities:
  - Unencrypted traffic
  - Default passwords


Important Notes:

The scan may take several seconds to minutes, depending on the network size and timeout value.
Ensure you have legal authorization to scan the target network.
The vulnerability assessment is simulated based on common issues associated with open ports and should not be considered exhaustive.



Code Structure

iot_scanner.py:
IoTScanner class: Handles network scanning, port scanning, and vulnerability assessment logic.
IoTScannerGUI class: Implements the Tkinter-based GUI for user interaction.
Main components:
Network discovery using socket connections.
Multithreaded port scanning with ThreadPoolExecutor.
Markdown report generation for results.



Limitations

Basic Vulnerability Checks: The tool performs simulated vulnerability assessments based on open ports and does not interact with actual device firmware or configurations.
Network Scope: Limited to local network scanning (e.g., /24 subnets) for simplicity.
No External Dependencies: Relies solely on standard Python libraries, which limits advanced features like protocol-specific checks or CVE lookups.
GUI Simplicity: The interface is minimal and designed for ease of use, not for advanced configuration.

Future Improvements

Add support for protocol-specific vulnerability checks (e.g., banner grabbing, MQTT authentication tests).
Integrate with external vulnerability databases (e.g., CVE) via APIs.
Enhance the GUI with features like saving reports to files or filtering results.
Support for scanning larger networks or custom port ranges.

Contributing
Contributions are welcome! To contribute:

Fork the repository.
Create a new branch (git checkout -b feature/your-feature).
Make your changes and commit (git commit -m "Add your feature").
Push to the branch (git push origin feature/your-feature).
Open a Pull Request.

Please ensure your code follows PEP 8 style guidelines and includes appropriate documentation.
