import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import threading
import ipaddress
import requests
from urllib.parse import urlparse

class CCTVScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Public CCTV Scanner")
        self.root.geometry("900x700")
        
        # Variables
        self.scanning = False
        self.target_range = tk.StringVar(value="192.168.1.1/24")
        self.ports = tk.StringVar(value="80,554,37777")
        self.timeout = tk.DoubleVar(value=1.0)
        self.threads = tk.IntVar(value=10)
        self.common_urls = ["/video.mjpg", "/stream", "/cameras", "/viewer/live/index.html"]
        
        # Create UI
        self.create_widgets()
        
    def create_widgets(self):
        # Top Frame (Controls)
        top_frame = ttk.LabelFrame(self.root, text="Scan Configuration", padding=10)
        top_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Target range
        ttk.Label(top_frame, text="IP Range:").grid(row=0, column=0, sticky=tk.W)
        self.target_entry = ttk.Entry(top_frame, textvariable=self.target_range, width=25)
        self.target_entry.grid(row=0, column=1, padx=5, sticky=tk.W)
        
        # Ports
        ttk.Label(top_frame, text="Ports:").grid(row=0, column=2, sticky=tk.W)
        self.ports_entry = ttk.Entry(top_frame, textvariable=self.ports, width=25)
        self.ports_entry.grid(row=0, column=3, padx=5, sticky=tk.W)
        
        # Timeout
        ttk.Label(top_frame, text="Timeout (s):").grid(row=1, column=0, sticky=tk.W)
        self.timeout_spin = ttk.Spinbox(top_frame, from_=0.1, to=10, increment=0.1, 
                                      textvariable=self.timeout, width=5)
        self.timeout_spin.grid(row=1, column=1, padx=5, sticky=tk.W)
        
        # Threads
        ttk.Label(top_frame, text="Threads:").grid(row=1, column=2, sticky=tk.W)
        self.threads_spin = ttk.Spinbox(top_frame, from_=1, to=100, increment=1, 
                                       textvariable=self.threads, width=5)
        self.threads_spin.grid(row=1, column=3, padx=5, sticky=tk.W)
        
        # Buttons
        self.start_btn = ttk.Button(top_frame, text="Start Scan", command=self.start_scan)
        self.start_btn.grid(row=0, column=4, padx=5, rowspan=2)
        self.stop_btn = ttk.Button(top_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_btn.grid(row=0, column=5, padx=5, rowspan=2)
        
        # Middle Frame (Results)
        mid_frame = ttk.LabelFrame(self.root, text="Discovered Cameras", padding=10)
        mid_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Treeview for results
        self.result_tree = ttk.Treeview(mid_frame, columns=("IP", "Port", "Type", "URL", "Auth"), show="headings")
        self.result_tree.heading("IP", text="IP Address")
        self.result_tree.heading("Port", text="Port")
        self.result_tree.heading("Type", text="Type")
        self.result_tree.heading("URL", text="Stream URL")
        self.result_tree.heading("Auth", text="Authentication")
        
        self.result_tree.column("IP", width=150)
        self.result_tree.column("Port", width=80)
        self.result_tree.column("Type", width=120)
        self.result_tree.column("URL", width=250)
        self.result_tree.column("Auth", width=100)
        
        self.result_tree.pack(fill=tk.BOTH, expand=True)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(mid_frame, orient="vertical", command=self.result_tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.result_tree.configure(yscrollcommand=scrollbar.set)
        
        # Bottom Frame (Log)
        bot_frame = ttk.LabelFrame(self.root, text="Scan Log", padding=10)
        bot_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.scan_log = scrolledtext.ScrolledText(bot_frame, wrap=tk.WORD)
        self.scan_log.pack(fill=tk.BOTH, expand=True)
        
        # Context menu for results
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Open in Browser", command=self.open_in_browser)
        self.context_menu.add_command(label="Copy URL", command=self.copy_url)
        self.result_tree.bind("<Button-3>", self.show_context_menu)
        
    def start_scan(self):
        """Start the scanning process"""
        try:
            ip_network = ipaddress.ip_network(self.target_range.get(), strict=False)
        except ValueError:
            messagebox.showerror("Error", "Invalid IP range format")
            return
            
        try:
            port_list = [int(p.strip()) for p in self.ports.get().split(",")]
        except ValueError:
            messagebox.showerror("Error", "Invalid port list format")
            return
            
        self.scanning = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        
        # Clear previous results
        self.result_tree.delete(*self.result_tree.get_children())
        self.scan_log.delete(1.0, tk.END)
        
        self.log_message(f"Starting scan on {self.target_range.get()} for ports {self.ports.get()}")
        
        # Create and start scanner threads
        self.scan_threads = []
        ip_list = list(ip_network.hosts())
        
        # Distribute IPs among threads
        chunk_size = len(ip_list) // self.threads.get() + 1
        for i in range(0, len(ip_list), chunk_size):
            chunk = ip_list[i:i + chunk_size]
            thread = threading.Thread(
                target=self.scan_ips,
                args=(chunk, port_list),
                daemon=True
            )
            self.scan_threads.append(thread)
            thread.start()
            
        # Start thread to monitor completion
        self.monitor_thread = threading.Thread(target=self.monitor_scan, daemon=True)
        self.monitor_thread.start()
        
    def stop_scan(self):
        """Stop the scanning process"""
        self.scanning = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.log_message("Scan stopped by user")
        
    def scan_ips(self, ip_list, port_list):
        """Scan a list of IP addresses for open ports"""
        for ip in ip_list:
            if not self.scanning:
                break
                
            ip_str = str(ip)
            self.log_message(f"Scanning {ip_str}...")
            
            for port in port_list:
                if not self.scanning:
                    break
                    
                if self.check_port(ip_str, port):
                    self.log_message(f"Found open port {port} on {ip_str}")
                    self.check_cctv(ip_str, port)
                    
    def check_port(self, ip, port):
        """Check if a port is open on an IP"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout.get())
                result = s.connect_ex((ip, port))
                return result == 0
        except Exception:
            return False
            
    def check_cctv(self, ip, port):
        """Check if an open port is a CCTV camera"""
        # Check common CCTV URLs
        base_url = f"http://{ip}:{port}"
        
        for url in self.common_urls:
            if not self.scanning:
                break
                
            full_url = base_url + url
            try:
                response = requests.get(full_url, timeout=self.timeout.get())
                if response.status_code == 200:
                    # Check if response looks like a video stream
                    if "image" in response.headers.get("Content-Type", "") or \
                       "video" in response.headers.get("Content-Type", "") or \
                       "mjpg" in response.headers.get("Content-Type", ""):
                        self.add_camera(ip, port, "HTTP Stream", full_url, "None" if response.status_code == 200 else "Required")
                        return
            except requests.RequestException:
                continue
                
        # Check RTSP (common port 554)
        if port == 554:
            rtsp_url = f"rtsp://{ip}:554/stream1"
            try:
                response = requests.get(f"http://{ip}:{port}", timeout=self.timeout.get())
                if response.status_code == 200:
                    self.add_camera(ip, port, "RTSP", rtsp_url, "None" if response.status_code == 200 else "Required")
            except requests.RequestException:
                pass
                
    def add_camera(self, ip, port, cam_type, url, auth):
        """Add a discovered camera to the results tree"""
        self.root.after(0, lambda: self.result_tree.insert(
            "", tk.END, values=(ip, port, cam_type, url, auth)
        ))
        
    def monitor_scan(self):
        """Monitor scan threads for completion"""
        while any(t.is_alive() for t in self.scan_threads) and self.scanning:
            time.sleep(0.5)
            
        self.root.after(0, self.stop_scan)
        self.log_message("Scan completed")
        
    def log_message(self, message):
        """Log a message to the scan log"""
        self.scan_log.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {message}\n")
        self.scan_log.see(tk.END)
        
    def show_context_menu(self, event):
        """Show context menu for result tree"""
        item = self.result_tree.identify_row(event.y)
        if item:
            self.result_tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)
            
    def open_in_browser(self):
        """Open selected URL in default browser"""
        selected = self.result_tree.selection()
        if selected:
            item = self.result_tree.item(selected[0])
            url = item['values'][3]
            import webbrowser
            webbrowser.open(url)
            
    def copy_url(self):
        """Copy selected URL to clipboard"""
        selected = self.result_tree.selection()
        if selected:
            item = self.result_tree.item(selected[0])
            url = item['values'][3]
            self.root.clipboard_clear()
            self.root.clipboard_append(url)
            self.log_message(f"Copied to clipboard: {url}")

def main():
    root = tk.Tk()
    app = CCTVScannerApp(root)
    root.mainloop()

if __name__ == "__main__":
    import time
    main()
    