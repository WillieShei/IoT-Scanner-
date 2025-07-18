import socket
import threading
import queue
import time
from concurrent.futures import ThreadPoolExecutor
import tkinter as tk
from tkinter import ttk, scrolledtext
from typing import List, Dict, Optional

class IoTScanner:
    def __init__(self, network: str, timeout: float = 1.0):
        self.network = network
        self.timeout = timeout
        self.devices: List[Dict] = []
        self.scan_queue = queue.Queue()
        self.common_ports = [80, 443, 23, 21, 22, 8080, 1883, 5683]
        self.vulnerability_db = {
            "80": {"service": "HTTP", "common_vulns": ["Weak credentials", "Unpatched web server"]},
            "443": {"service": "HTTPS", "common_vulns": ["SSL misconfiguration", "Outdated TLS"]},
            "23": {"service": "Telnet", "common_vulns": ["Unencrypted traffic", "Default passwords"]},
            "21": {"service": "FTP", "common_vulns": ["Anonymous access", "Weak passwords"]},
            "22": {"service": "SSH", "common_vulns": ["Weak SSH keys", "Outdated SSH version"]},
            "8080": {"service": "HTTP-Alt", "common_vulns": ["Misconfigured proxy", "Unpatched server"]},
            "1883": {"service": "MQTT", "common_vulns": ["Unauthenticated access", "Unencrypted data"]},
            "5683": {"service": "CoAP", "common_vulns": ["Unauthenticated endpoints", "DoS vulnerability"]}
        }

    def get_ip_range(self) -> List[str]:
        base_ip, prefix = self.network.split('/')
        prefix = int(prefix)
        ip_parts = base_ip.split('.')
        base = (int(ip_parts[0]) << 24) + (int(ip_parts[1]) << 16) + (int(ip_parts[2]) << 8)
        num_ips = 2 ** (32 - prefix)
        return [f"{base_ip.rsplit('.', 1)[0]}.{i}" for i in range(1, min(num_ips, 255))]

    def ping_device(self, ip: str) -> Optional[Dict]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            start_time = time.time()
            sock.connect((ip, 80))
            latency = (time.time() - start_time) * 1000
            sock.close()
            return {"ip": ip, "status": "up", "latency_ms": round(latency, 2)}
        except (socket.timeout, socket.error):
            return None

    def scan_ports(self, ip: str) -> Dict:
        open_ports = []
        for port in self.common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append({"port": port, "service": self.vulnerability_db.get(str(port), {}).get("service", "Unknown")})
                sock.close()
            except socket.error:
                continue
        return {"ip": ip, "open_ports": open_ports}

    def assess_vulnerabilities(self, device: Dict) -> Dict:
        vulnerabilities = []
        for port_info in device.get("open_ports", []):
            port = str(port_info["port"])
            if port in self.vulnerability_db:
                vulnerabilities.extend(self.vulnerability_db[port]["common_vulns"])
        return {"ip": device["ip"], "vulnerabilities": vulnerabilities}

    def scan_network(self, max_threads: int = 20):
        ip_list = self.get_ip_range()
        for ip in ip_list:
            self.scan_queue.put(ip)

        def worker():
            while not self.scan_queue.empty():
                ip = self.scan_queue.get()
                device = self.ping_device(ip)
                if device:
                    port_info = self.scan_ports(ip)
                    device.update(port_info)
                    vulnerabilities = self.assess_vulnerabilities(device)
                    device.update(vulnerabilities)
                    self.devices.append(device)
                self.scan_queue.task_done()

        with ThreadPoolExecutor(max_threads) as executor:
            for _ in range(min(max_threads, len(ip_list))):
                executor.submit(worker)

    def generate_report(self) -> str:
        report = "# IoT Network Scan Report\n\n"
        report += f"Scanned Network: {self.network}\n"
        report += f"Scan Time: {time.ctime()}\n"
        report += f"Total Devices Found: {len(self.devices)}\n\n"

        for device in self.devices:
            report += f"## Device: {device['ip']}\n"
            report += f"- Status: {device['status']}\n"
            report += f"- Latency: {device['latency_ms']} ms\n"
            report += "- Open Ports:\n"
            for port_info in device.get("open_ports", []):
                report += f"  - Port {port_info['port']} ({port_info['service']})\n"
            report += "- Potential Vulnerabilities:\n"
            for vuln in device.get("vulnerabilities", []):
                report += f"  - {vuln}\n"
            report += "\n"
        return report

class IoTScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("IoT Network Scanner")
        self.root.geometry("600x500")
        
        # Network input
        ttk.Label(root, text="Network (e.g., 192.168.1.0/24):").pack(pady=5)
        self.network_entry = ttk.Entry(root)
        self.network_entry.insert(0, "192.168.1.0/24")
        self.network_entry.pack(pady=5)
        
        # Timeout input
        ttk.Label(root, text="Timeout (seconds):").pack(pady=5)
        self.timeout_entry = ttk.Entry(root)
        self.timeout_entry.insert(0, "0.5")
        self.timeout_entry.pack(pady=5)
        
        # Scan button
        self.scan_button = ttk.Button(root, text="Start Scan", command=self.start_scan)
        self.scan_button.pack(pady=10)
        
        # Progress label
        self.progress_label = ttk.Label(root, text="")
        self.progress_label.pack(pady=5)
        
        # Result text area
        self.result_text = scrolledtext.ScrolledText(root, height=20, width=60, wrap=tk.WORD)
        self.result_text.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)
        
    def start_scan(self):
        self.scan_button.config(state="disabled")
        self.progress_label.config(text="Scanning... Please wait.")
        self.result_text.delete(1.0, tk.END)
        
        network = self.network_entry.get()
        try:
            timeout = float(self.timeout_entry.get())
        except ValueError:
            self.result_text.insert(tk.END, "Error: Timeout must be a number.\n")
            self.scan_button.config(state="normal")
            self.progress_label.config(text="")
            return
        
        # Run scan in a separate thread to keep GUI responsive
        def scan_thread():
            scanner = IoTScanner(network=network, timeout=timeout)
            scanner.scan_network()
            report = scanner.generate_report()
            self.root.after(0, self.update_results, report)
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def update_results(self, report):
        self.result_text.insert(tk.END, report)
        self.progress_label.config(text="Scan complete.")
        self.scan_button.config(state="normal")

def main():
    root = tk.Tk()
    app = IoTScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()