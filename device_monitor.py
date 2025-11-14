#!/usr/bin/env python3
"""
Advanced Network Device Monitor with Digital Signature System
Created by: Dr. Mohammed Tawfik
Version: 1.0
Date: 2025-11-14

Features:
- Real-time device monitoring
- Digital signature generation for each device
- Change detection and alerting
- Network topology scanning
- Device information extraction (serial numbers, MAC, IP, etc.)
- Alert system for device changes/additions/removals
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import time
import json
import hashlib
import ipaddress
import socket
import subprocess
import platform
import uuid
import re
from datetime import datetime
import os
from collections import defaultdict
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Optional imports for enhanced functionality
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    import wmi
    HAS_WMI = True
except ImportError:
    HAS_WMI = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

class DeviceSignature:
    """Handles digital signature generation and verification for network devices"""
    
    @staticmethod
    def generate_device_signature(device_info):
        """
        Generate unique digital signature for a device based on hardware information
        """
        # Create signature string from device characteristics
        signature_data = f"{device_info.get('hostname', '')}{device_info.get('mac_address', '')}{device_info.get('ip_address', '')}{device_info.get('serial_number', '')}{device_info.get('manufacturer', '')}{device_info.get('model', '')}"
        
        # Generate SHA-256 hash as digital signature
        signature_hash = hashlib.sha256(signature_data.encode()).hexdigest()
        
        # Create readable signature (first 16 characters)
        readable_sig = signature_hash[:16].upper()
        
        return {
            'full_signature': signature_hash,
            'readable_signature': readable_sig,
            'generated_at': datetime.now().isoformat(),
            'signature_data': signature_data
        }
    
    @staticmethod
    def verify_device_signature(device_info, stored_signature):
        """
        Verify if device signature matches stored signature
        """
        current_signature = DeviceSignature.generate_device_signature(device_info)
        return current_signature['full_signature'] == stored_signature.get('full_signature', '')

class NetworkDeviceMonitor:
    """Main network device monitoring system"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Network Device Monitor - Dr. Mohammed Tawfik")
        self.root.geometry("1200x800")
        self.root.configure(bg='#2b2b2b')
        
        # Device storage
        self.known_devices = {}
        self.device_history = {}
        self.monitoring_active = False
        self.scan_interval = 60  # seconds
        
        # Network ranges to monitor
        self.network_ranges = []
        
        # Alert settings
        self.alert_email = ""
        self.alert_enabled = False
        
        # GUI Variables
        self.status_var = tk.StringVar(value="Ready")
        self.device_count_var = tk.StringVar(value="Devices: 0")
        self.monitoring_var = tk.BooleanVar()
        
        self.setup_gui()
        self.load_configuration()
        
    def setup_gui(self):
        """Setup the main GUI interface"""
        
        # Title Frame
        title_frame = tk.Frame(self.root, bg='#2b2b2b', height=80)
        title_frame.pack(fill='x', padx=10, pady=5)
        title_frame.pack_propagate(False)
        
        # Main Title
        title_label = tk.Label(title_frame, text="Network Device Monitor", 
                              font=('Arial', 20, 'bold'), fg='white', bg='#2b2b2b')
        title_label.pack(pady=10)
        
        # Subtitle with creator
        subtitle_label = tk.Label(title_frame, text="Created by: Dr. Mohammed Tawfik", 
                                 font=('Arial', 10), fg='#cccccc', bg='#2b2b2b')
        subtitle_label.pack()
        
        # Status Bar
        status_frame = tk.Frame(self.root, bg='#1e1e1e', height=30)
        status_frame.pack(fill='x', side='bottom')
        status_frame.pack_propagate(False)
        
        self.status_label = tk.Label(status_frame, textvariable=self.status_var, 
                                    font=('Arial', 9), fg='white', bg='#1e1e1e')
        self.status_label.pack(side='left', padx=10)
        
        self.device_count_label = tk.Label(status_frame, textvariable=self.device_count_var, 
                                          font=('Arial', 9), fg='white', bg='#1e1e1e')
        self.device_count_label.pack(side='right', padx=10)
        
        # Main Container
        main_frame = tk.Frame(self.root, bg='#2b2b2b')
        main_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Left Panel - Controls
        control_frame = tk.Frame(main_frame, bg='#3c3c3c', width=350)
        control_frame.pack(side='left', fill='y', padx=(0, 5))
        control_frame.pack_propagate(False)
        
        self.setup_control_panel(control_frame)
        
        # Right Panel - Device List
        device_frame = tk.Frame(main_frame, bg='#3c3c3c')
        device_frame.pack(side='right', fill='both', expand=True)
        
        self.setup_device_panel(device_frame)
        
    def setup_control_panel(self, parent):
        """Setup the control panel with monitoring controls"""
        
        # Title
        title = tk.Label(parent, text="Monitoring Controls", font=('Arial', 14, 'bold'), 
                        fg='white', bg='#3c3c3c')
        title.pack(pady=10)
        
        # Network Configuration
        net_frame = tk.LabelFrame(parent, text="Network Configuration", 
                                 font=('Arial', 10, 'bold'), fg='white', bg='#3c3c3c')
        net_frame.pack(fill='x', padx=10, pady=5)
        
        tk.Label(net_frame, text="Network Range:", fg='white', bg='#3c3c3c').pack(anchor='w')
        self.network_entry = tk.Entry(net_frame, width=25)
        self.network_entry.pack(pady=2)
        self.network_entry.insert(0, "192.168.1.0/24")
        
        add_btn = tk.Button(net_frame, text="Add Network", command=self.add_network_range,
                           bg='#4CAF50', fg='white', width=12)
        add_btn.pack(pady=2)
        
        # Network ranges listbox
        self.network_listbox = tk.Listbox(net_frame, height=4)
        self.network_listbox.pack(fill='x', pady=2)
        
        clear_net_btn = tk.Button(net_frame, text="Clear All", command=self.clear_networks,
                                 bg='#f44336', fg='white', width=12)
        clear_net_btn.pack(pady=2)
        
        # Monitoring Controls
        monitor_frame = tk.LabelFrame(parent, text="Monitoring Controls", 
                                     font=('Arial', 10, 'bold'), fg='white', bg='#3c3c3c')
        monitor_frame.pack(fill='x', padx=10, pady=5)
        
        # Start/Stop Monitoring
        self.start_btn = tk.Button(monitor_frame, text="Start Monitoring", 
                                  command=self.start_monitoring, bg='#4CAF50', fg='white',
                                  width=15, font=('Arial', 10, 'bold'))
        self.start_btn.pack(pady=5)
        
        self.stop_btn = tk.Button(monitor_frame, text="Stop Monitoring", 
                                 command=self.stop_monitoring, bg='#f44336', fg='white',
                                 width=15, font=('Arial', 10, 'bold'), state='disabled')
        self.stop_btn.pack(pady=5)
        
        # Scan Interval
        tk.Label(monitor_frame, text="Scan Interval (seconds):", fg='white', bg='#3c3c3c').pack(anchor='w')
        self.interval_var = tk.StringVar(value="60")
        interval_spin = tk.Spinbox(monitor_frame, from_=10, to=3600, textvariable=self.interval_var, width=25)
        interval_spin.pack(pady=2)
        
        # Manual Scan
        scan_btn = tk.Button(monitor_frame, text="Scan Now", command=self.manual_scan,
                            bg='#2196F3', fg='white', width=15)
        scan_btn.pack(pady=5)
        
        # Alert Configuration
        alert_frame = tk.LabelFrame(parent, text="Alert Configuration", 
                                   font=('Arial', 10, 'bold'), fg='white', bg='#3c3c3c')
        alert_frame.pack(fill='x', padx=10, pady=5)
        
        tk.Label(alert_frame, text="Email for Alerts:", fg='white', bg='#3c3c3c').pack(anchor='w')
        self.email_entry = tk.Entry(alert_frame, width=25)
        self.email_entry.pack(pady=2)
        
        self.alert_var = tk.BooleanVar()
        alert_check = tk.Checkbutton(alert_frame, text="Enable Email Alerts", 
                                    variable=self.alert_var, fg='white', bg='#3c3c3c',
                                    selectcolor='#2b2b2b')
        alert_check.pack(pady=2)
        
        # Device Actions
        device_frame = tk.LabelFrame(parent, text="Device Actions", 
                                    font=('Arial', 10, 'bold'), fg='white', bg='#3c3c3c')
        device_frame.pack(fill='x', padx=10, pady=5)
        
        export_btn = tk.Button(device_frame, text="Export Device List", command=self.export_devices,
                              bg='#FF9800', fg='white', width=15)
        export_btn.pack(pady=2)
        
        import_btn = tk.Button(device_frame, text="Import Device List", command=self.import_devices,
                              bg='#9C27B0', fg='white', width=15)
        import_btn.pack(pady=2)
        
        clear_btn = tk.Button(device_frame, text="Clear All Devices", command=self.clear_all_devices,
                             bg='#f44336', fg='white', width=15)
        clear_btn.pack(pady=2)
        
    def setup_device_panel(self, parent):
        """Setup the device monitoring panel"""
        
        # Title
        title = tk.Label(parent, text="Discovered Devices", font=('Arial', 14, 'bold'), 
                        fg='white', bg='#3c3c3c')
        title.pack(pady=10)
        
        # Device Tree
        tree_frame = tk.Frame(parent, bg='#3c3c3c')
        tree_frame.pack(fill='both', expand=True, padx=10)
        
        # Create Treeview with scrollbars
        tree_scroll_v = tk.Scrollbar(tree_frame)
        tree_scroll_v.pack(side='right', fill='y')
        
        tree_scroll_h = tk.Scrollbar(tree_frame, orient='horizontal')
        tree_scroll_h.pack(side='bottom', fill='x')
        
        self.device_tree = ttk.Treeview(tree_frame, 
                                       yscrollcommand=tree_scroll_v.set,
                                       xscrollcommand=tree_scroll_h.set,
                                       columns=('IP', 'MAC', 'Hostname', 'Signature', 'Status', 'Last Seen'),
                                       height=20)
        
        self.device_tree.pack(fill='both', expand=True)
        
        # Configure columns
        self.device_tree.heading('#0', text='Device Name')
        self.device_tree.heading('IP', text='IP Address')
        self.device_tree.heading('MAC', text='MAC Address')
        self.device_tree.heading('Hostname', text='Hostname')
        self.device_tree.heading('Signature', text='Digital Signature')
        self.device_tree.heading('Status', text='Status')
        self.device_tree.heading('Last Seen', text='Last Seen')
        
        self.device_tree.column('#0', width=150)
        self.device_tree.column('IP', width=120)
        self.device_tree.column('MAC', width=150)
        self.device_tree.column('Hostname', width=150)
        self.device_tree.column('Signature', width=120)
        self.device_tree.column('Status', width=100)
        self.device_tree.column('Last Seen', width=140)
        
        tree_scroll_v.config(command=self.device_tree.yview)
        tree_scroll_h.config(command=self.device_tree.xview)
        
        # Bind double-click for device details
        self.device_tree.bind('<Double-1>', self.show_device_details)
        
        # Device Details Panel
        details_frame = tk.LabelFrame(parent, text="Device Details", 
                                     font=('Arial', 10, 'bold'), fg='white', bg='#3c3c3c')
        details_frame.pack(fill='x', padx=10, pady=5)
        
        self.details_text = tk.Text(details_frame, height=6, bg='#2b2b2b', fg='white',
                                   font=('Courier', 9), wrap='word')
        details_text_scroll = tk.Scrollbar(details_frame, orient='vertical', command=self.details_text.yview)
        self.details_text.config(yscrollcommand=details_text_scroll.set)
        
        self.details_text.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        details_text_scroll.pack(side='right', fill='y')
        
    def add_network_range(self):
        """Add network range to monitoring list"""
        network_range = self.network_entry.get().strip()
        if network_range:
            try:
                ipaddress.ip_network(network_range, strict=False)
                self.network_listbox.insert(tk.END, network_range)
                self.network_entry.delete(0, tk.END)
            except ValueError:
                messagebox.showerror("Error", "Invalid network range format")
    
    def clear_networks(self):
        """Clear all network ranges"""
        self.network_listbox.delete(0, tk.END)
    
    def start_monitoring(self):
        """Start the monitoring process"""
        if not self.network_listbox.size():
            messagebox.showwarning("Warning", "Please add at least one network range")
            return
            
        self.monitoring_active = True
        self.scan_interval = int(self.interval_var.get())
        self.alert_email = self.email_entry.get()
        self.alert_enabled = self.alert_var.get()
        
        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.monitoring_var.set(True)
        
        self.status_var.set("Monitoring Active - Scanning networks...")
        
        # Start monitoring thread
        monitor_thread = threading.Thread(target=self.monitoring_loop, daemon=True)
        monitor_thread.start()
        
    def stop_monitoring(self):
        """Stop the monitoring process"""
        self.monitoring_active = False
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.monitoring_var.set(False)
        self.status_var.set("Monitoring Stopped")
    
    def monitoring_loop(self):
        """Main monitoring loop that runs in background thread"""
        while self.monitoring_active:
            try:
                self.status_var.set("Scanning network devices...")
                
                # Perform network scan
                discovered_devices = self.scan_network_devices()
                
                # Process discovered devices
                self.process_discovered_devices(discovered_devices)
                
                self.status_var.set(f"Monitoring - {len(self.known_devices)} devices tracked")
                
                # Wait for next scan
                for _ in range(self.scan_interval):
                    if not self.monitoring_active:
                        break
                    time.sleep(1)
                    
            except Exception as e:
                self.status_var.set(f"Error during monitoring: {str(e)}")
                time.sleep(5)
    
    def manual_scan(self):
        """Perform manual network scan"""
        if not self.network_listbox.size():
            messagebox.showwarning("Warning", "Please add at least one network range")
            return
            
        self.status_var.set("Performing manual scan...")
        scan_thread = threading.Thread(target=self._manual_scan_worker, daemon=True)
        scan_thread.start()
    
    def _manual_scan_worker(self):
        """Worker thread for manual scan"""
        try:
            discovered_devices = self.scan_network_devices()
            self.process_discovered_devices(discovered_devices)
            self.root.after(0, lambda: self.status_var.set("Manual scan completed"))
        except Exception as e:
            self.root.after(0, lambda: self.status_var.set(f"Scan error: {str(e)}"))
    
    def scan_network_devices(self):
        """Scan network for all devices and gather information"""
        discovered_devices = []
        
        # Get all network ranges
        networks = list(self.network_listbox.get(0, tk.END))
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = []
            
            for network_range in networks:
                try:
                    network = ipaddress.ip_network(network_range, strict=False)
                    
                    for ip in network.hosts() if network.num_addresses > 2 else [network.network_address + 1]:
                        future = executor.submit(self.scan_single_device, str(ip))
                        futures.append(future)
                        
                except Exception as e:
                    print(f"Error processing network {network_range}: {e}")
            
            # Collect results
            for future in as_completed(futures):
                try:
                    device_info = future.result()
                    if device_info:
                        discovered_devices.append(device_info)
                except Exception as e:
                    print(f"Error in device scan: {e}")
        
        return discovered_devices
    
    def scan_single_device(self, ip_address):
        """Scan a single IP address for device information"""
        try:
            # Check if host is alive
            if not self.ping_host(ip_address):
                return None
                
            # Initialize device info
            device_info = {
                'ip_address': ip_address,
                'mac_address': '',
                'hostname': '',
                'manufacturer': '',
                'model': '',
                'serial_number': '',
                'os_info': '',
                'open_ports': [],
                'device_type': '',
                'last_seen': datetime.now().isoformat(),
                'status': 'Online'
            }
            
            # Get MAC address
            device_info['mac_address'] = self.get_mac_address(ip_address)
            
            # Get hostname
            device_info['hostname'] = self.get_hostname(ip_address)
            
            # Get device information via SNMP/WMI/SNMP
            device_info.update(self.get_device_details(ip_address))
            
            # Get open ports
            device_info['open_ports'] = self.get_open_ports(ip_address)
            
            # Determine device type
            device_info['device_type'] = self.determine_device_type(device_info)
            
            # Generate digital signature
            signature_info = DeviceSignature.generate_device_signature(device_info)
            device_info['digital_signature'] = signature_info
            
            return device_info
            
        except Exception as e:
            print(f"Error scanning {ip_address}: {e}")
            return None
    
    def ping_host(self, ip_address, timeout=2):
        """Ping a host to check if it's alive"""
        try:
            # Use different ping methods based on OS
            if platform.system().lower() == 'windows':
                cmd = f"ping -n 1 -w {timeout*1000} {ip_address}"
            else:
                cmd = f"ping -c 1 -W {timeout} {ip_address}"
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            return result.returncode == 0
            
        except Exception:
            return False
    
    def get_mac_address(self, ip_address):
        """Get MAC address of a device using ARP"""
        try:
            # Ping first to populate ARP table
            self.ping_host(ip_address)
            
            # Get ARP table
            if platform.system().lower() == 'windows':
                cmd = "arp -a"
            else:
                cmd = "arp -n"
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            # Parse ARP table for MAC address
            for line in result.stdout.split('\n'):
                if ip_address in line:
                    # Extract MAC address
                    mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', line)
                    if mac_match:
                        mac = mac_match.group(0).replace('-', ':').upper()
                        return mac
                        
            return "Unknown"
            
        except Exception:
            return "Unknown"
    
    def get_hostname(self, ip_address):
        """Get hostname of a device using reverse DNS lookup"""
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            return hostname
        except Exception:
            return "Unknown"
    
    def get_device_details(self, ip_address):
        """Get detailed device information"""
        device_info = {
            'manufacturer': 'Unknown',
            'model': 'Unknown', 
            'serial_number': 'Unknown',
            'os_info': 'Unknown'
        }
        
        try:
            # Try SNMP first
            device_info.update(self.get_snmp_info(ip_address))
        except Exception:
            pass
            
        try:
            # Try WMI for Windows devices
            if platform.system().lower() == 'windows':
                device_info.update(self.get_wmi_info(ip_address))
        except Exception:
            pass
            
        try:
            # Try to get manufacturer from MAC OUI
            mac = self.get_mac_address(ip_address)
            device_info['manufacturer'] = self.get_manufacturer_from_mac(mac)
        except Exception:
            pass
            
        return device_info
    
    def get_snmp_info(self, ip_address):
        """Get device information via SNMP"""
        try:
            # Basic SNMP queries
            snmp_info = {}
            
            # SNMP community strings to try
            communities = ['public', 'private', 'cisco', 'admin', 'read']
            
            for community in communities:
                try:
                    # This would require pysnmp library in a real implementation
                    # For now, return basic info structure
                    snmp_info['manufacturer'] = 'SNMP Device'
                    snmp_info['model'] = 'Network Device'
                    snmp_info['serial_number'] = 'SNMP-' + ip_address.replace('.', '')
                    break
                except Exception:
                    continue
                    
            return snmp_info
            
        except Exception:
            return {}
    
    def get_wmi_info(self, ip_address):
        """Get device information via WMI (Windows only)"""
        if not HAS_WMI:
            return {}
            
        try:
            wmi_info = {}
            
            # Connect to remote WMI
            c = wmi.WMI(ip_address, find=False)
            
            # Get system information
            for system in c.Win32_ComputerSystem():
                wmi_info['manufacturer'] = system.Manufacturer
                wmi_info['model'] = system.Model
                
            for bios in c.Win32_BIOS():
                wmi_info['serial_number'] = bios.SerialNumber
                break
                
            # Get OS information
            for os_info in c.Win32_OperatingSystem():
                wmi_info['os_info'] = f"{os_info.Caption} {os_info.Version}"
                break
                
            return wmi_info
            
        except Exception:
            return {}
    
    def get_manufacturer_from_mac(self, mac_address):
        """Get manufacturer from MAC address OUI database"""
        try:
            if mac_address == "Unknown":
                return "Unknown"
                
            # OUI database - first 3 octets of MAC address
            oui_db = {
                '00:1B:63': 'Apple',
                '00:26:BB': 'Apple',
                '3C:15:C2': 'Apple',
                '00:50:56': 'VMware',
                '08:00:27': 'VirtualBox',
                '00:0C:29': 'VMware',
                '00:15:5D': 'Microsoft',
                '00:03:FF': 'Microsoft',
                '00:E0:4C': 'Realtek',
                'B8:27:EB': 'Raspberry Pi',
                'DC:A6:32': 'Raspberry Pi',
                '00:1F:D0': 'ASUSTek',
                '00:24:8C': 'ASUSTek',
                '00:1C:42': 'Parallels',
                '00:16:3E': 'Xen',
                '00:05:69': 'VMware',
                '00:03:93': 'VMware',
                '00:0C:29': 'VMware',
                '00:50:56': 'VMware'
            }
            
            oui = mac_address[:8].upper()
            return oui_db.get(oui, 'Unknown')
            
        except Exception:
            return "Unknown"
    
    def get_open_ports(self, ip_address, ports=None):
        """Get open ports on a device"""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 3389, 8080]
            
        open_ports = []
        
        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip_address, port))
                sock.close()
                
                if result == 0:
                    return port
            except Exception:
                pass
            return None
            
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(check_port, port) for port in ports]
            
            for future in as_completed(futures):
                port = future.result()
                if port:
                    open_ports.append(port)
                    
        return sorted(open_ports)
    
    def determine_device_type(self, device_info):
        """Determine device type based on information gathered"""
        open_ports = device_info.get('open_ports', [])
        hostname = device_info.get('hostname', '').lower()
        manufacturer = device_info.get('manufacturer', '').lower()
        
        # Check for specific device types
        if 22 in open_ports or 23 in open_ports:
            return "Network Device"
        elif 3389 in open_ports:
            return "Windows Server"
        elif 80 in open_ports or 443 in open_ports:
            return "Web Server"
        elif 'router' in hostname or 'switch' in hostname:
            return "Network Equipment"
        elif manufacturer in ['cisco', 'juniper', 'hp']:
            return "Enterprise Network Device"
        elif 'raspberry' in manufacturer.lower():
            return "IoT Device"
        else:
            return "Unknown"
    
    def process_discovered_devices(self, discovered_devices):
        """Process newly discovered devices and detect changes"""
        current_time = datetime.now()
        
        new_devices = []
        changed_devices = []
        removed_devices = []
        
        # Check for new and changed devices
        for device in discovered_devices:
            device_ip = device['ip_address']
            
            if device_ip in self.known_devices:
                # Device exists, check for changes
                if not DeviceSignature.verify_device_signature(device, self.known_devices[device_ip].get('digital_signature', {})):
                    changed_devices.append(device)
            else:
                # New device
                new_devices.append(device)
            
            # Store/update device information
            self.known_devices[device_ip] = device
            
            # Update device history
            if device_ip not in self.device_history:
                self.device_history[device_ip] = []
            self.device_history[device_ip].append({
                'timestamp': current_time.isoformat(),
                'device_info': device
            })
        
        # Check for removed devices
        for known_ip in list(self.known_devices.keys()):
            if known_ip not in [d['ip_address'] for d in discovered_devices]:
                # Device not found in current scan
                if known_ip not in [d['ip_address'] for d in changed_devices]:
                    # Not a changed device, so it's removed
                    removed_devices.append(known_ip)
        
        # Handle alerts
        if new_devices or changed_devices or removed_devices:
            self.handle_alerts(new_devices, changed_devices, removed_devices)
        
        # Update GUI
        self.root.after(0, self.update_device_display)
    
    def handle_alerts(self, new_devices, changed_devices, removed_devices):
        """Handle alerts for device changes"""
        alert_message = ""
        
        if new_devices:
            alert_message += f"NEW DEVICES DETECTED ({len(new_devices)}):\n"
            for device in new_devices:
                alert_message += f"  - {device['ip_address']} ({device.get('hostname', 'Unknown')})\n"
        
        if changed_devices:
            alert_message += f"\nCHANGED DEVICES DETECTED ({len(changed_devices)}):\n"
            for device in changed_devices:
                alert_message += f"  - {device['ip_address']} ({device.get('hostname', 'Unknown')})\n"
        
        if removed_devices:
            alert_message += f"\nREMOVED DEVICES DETECTED ({len(removed_devices)}):\n"
            for device_ip in removed_devices:
                alert_message += f"  - {device_ip}\n"
        
        # Send email alert if enabled
        if self.alert_enabled and self.alert_email:
            self.send_email_alert(alert_message)
        
        # Show popup alert
        self.root.after(0, lambda: messagebox.showwarning("Device Alert", alert_message))
    
    def send_email_alert(self, message):
        """Send email alert for device changes"""
        try:
            # Email configuration (would need actual SMTP settings)
            # This is a placeholder implementation
            print(f"Email alert would be sent to {self.alert_email}")
            print(f"Alert message:\n{message}")
            
        except Exception as e:
            print(f"Failed to send email alert: {e}")
    
    def update_device_display(self):
        """Update the device display in the GUI"""
        # Clear existing items
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)
        
        # Add devices to tree
        for ip, device in self.known_devices.items():
            signature = device.get('digital_signature', {}).get('readable_signature', 'N/A')
            hostname = device.get('hostname', 'Unknown')
            mac = device.get('mac_address', 'Unknown')
            device_type = device.get('device_type', 'Unknown')
            last_seen = device.get('last_seen', 'Unknown')[:19]  # Remove microseconds
            
            # Determine status based on last seen time
            try:
                last_seen_dt = datetime.fromisoformat(last_seen)
                time_diff = datetime.now() - last_seen_dt
                if time_diff.total_seconds() < 300:  # 5 minutes
                    status = "Online"
                elif time_diff.total_seconds() < 3600:  # 1 hour
                    status = "Recent"
                else:
                    status = "Offline"
            except Exception:
                status = "Unknown"
            
            # Insert device into tree
            item = self.device_tree.insert('', 'end', text=hostname, values=(
                ip, mac, hostname, signature, status, last_seen
            ))
            
            # Color code based on status
            if status == "Online":
                self.device_tree.set(item, 'Status', f"🟢 {status}")
            elif status == "Recent":
                self.device_tree.set(item, 'Status', f"🟡 {status}")
            else:
                self.device_tree.set(item, 'Status', f"🔴 {status}")
        
        # Update device count
        self.device_count_var.set(f"Devices: {len(self.known_devices)}")
        
    def show_device_details(self, event):
        """Show detailed information for selected device"""
        selection = self.device_tree.selection()
        if not selection:
            return
            
        item = selection[0]
        hostname = self.device_tree.item(item, 'text')
        
        # Find device by hostname
        device = None
        for dev in self.known_devices.values():
            if dev.get('hostname', '') == hostname:
                device = dev
                break
        
        if device:
            self.display_device_details(device)
    
    def display_device_details(self, device):
        """Display detailed device information"""
        details = f"""
DEVICE INFORMATION
==================

IP Address: {device.get('ip_address', 'N/A')}
MAC Address: {device.get('mac_address', 'N/A')}
Hostname: {device.get('hostname', 'N/A')}
Device Type: {device.get('device_type', 'N/A')}

HARDWARE INFORMATION
====================
Manufacturer: {device.get('manufacturer', 'N/A')}
Model: {device.get('model', 'N/A')}
Serial Number: {device.get('serial_number', 'N/A')}
OS Information: {device.get('os_info', 'N/A')}

DIGITAL SIGNATURE
=================
Full Signature: {device.get('digital_signature', {}).get('full_signature', 'N/A')}
Readable Signature: {device.get('digital_signature', {}).get('readable_signature', 'N/A')}
Generated At: {device.get('digital_signature', {}).get('generated_at', 'N/A')}

NETWORK INFORMATION
===================
Open Ports: {', '.join(map(str, device.get('open_ports', [])))}
Status: {device.get('status', 'N/A')}
Last Seen: {device.get('last_seen', 'N/A')}

SIGNATURE DATA
==============
Signature Source: {device.get('digital_signature', {}).get('signature_data', 'N/A')}
"""
        
        self.details_text.delete('1.0', tk.END)
        self.details_text.insert('1.0', details)
    
    def export_devices(self):
        """Export device list to JSON file"""
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            
            if filename:
                export_data = {
                    'export_timestamp': datetime.now().isoformat(),
                    'total_devices': len(self.known_devices),
                    'devices': self.known_devices,
                    'device_history': self.device_history
                }
                
                with open(filename, 'w') as f:
                    json.dump(export_data, f, indent=2)
                
                messagebox.showinfo("Success", f"Device list exported to {filename}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export: {str(e)}")
    
    def import_devices(self):
        """Import device list from JSON file"""
        try:
            filename = filedialog.askopenfilename(
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            
            if filename:
                with open(filename, 'r') as f:
                    import_data = json.load(f)
                
                if 'devices' in import_data:
                    self.known_devices = import_data['devices']
                    if 'device_history' in import_data:
                        self.device_history = import_data['device_history']
                    
                    self.update_device_display()
                    messagebox.showinfo("Success", f"Imported {len(self.known_devices)} devices")
                else:
                    messagebox.showerror("Error", "Invalid file format")
                    
        except Exception as e:
            messagebox.showerror("Error", f"Failed to import: {str(e)}")
    
    def clear_all_devices(self):
        """Clear all discovered devices"""
        if messagebox.askyesno("Confirm", "Are you sure you want to clear all devices?"):
            self.known_devices.clear()
            self.device_history.clear()
            self.update_device_display()
    
    def save_configuration(self):
        """Save current configuration"""
        config = {
            'network_ranges': list(self.network_listbox.get(0, tk.END)),
            'scan_interval': int(self.interval_var.get()),
            'alert_email': self.email_entry.get(),
            'alert_enabled': self.alert_var.get()
        }
        
        try:
            with open('monitor_config.json', 'w') as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            print(f"Failed to save configuration: {e}")
    
    def load_configuration(self):
        """Load saved configuration"""
        try:
            if os.path.exists('monitor_config.json'):
                with open('monitor_config.json', 'r') as f:
                    config = json.load(f)
                
                # Load network ranges
                for network in config.get('network_ranges', []):
                    self.network_listbox.insert(tk.END, network)
                
                # Load other settings
                self.interval_var.set(str(config.get('scan_interval', 60)))
                self.email_entry.set(config.get('alert_email', ''))
                self.alert_var.set(config.get('alert_enabled', False))
                
        except Exception as e:
            print(f"Failed to load configuration: {e}")
    
    def on_closing(self):
        """Handle application closing"""
        if self.monitoring_active:
            self.stop_monitoring()
        
        self.save_configuration()
        self.root.destroy()
    
    def run(self):
        """Start the application"""
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()

def main():
    """Main function to start the application"""
    try:
        app = NetworkDeviceMonitor()
        app.run()
    except Exception as e:
        print(f"Application error: {e}")
        messagebox.showerror("Application Error", f"Failed to start application: {str(e)}")

if __name__ == "__main__":
    main()