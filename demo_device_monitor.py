#!/usr/bin/env python3
"""
Device Monitor Demo - Shows GUI Design and Startup Screen
This script demonstrates the Network Device Monitor interface
Created by: Dr. Mohammed Tawfik
"""

import device_monitor
from device_monitor import DeviceSignature, NetworkDeviceMonitor
import json
from datetime import datetime

def demonstrate_signature_system():
    """Demonstrate the digital signature system"""
    print("=" * 60)
    print("DIGITAL SIGNATURE SYSTEM DEMONSTRATION")
    print("=" * 60)
    
    # Test devices with different information
    test_devices = [
        {
            'hostname': 'router-office',
            'mac_address': '00:1B:63:12:34:56',
            'ip_address': '192.168.1.1',
            'serial_number': 'SN-CISCO-001',
            'manufacturer': 'Cisco',
            'model': 'Catalyst 2960'
        },
        {
            'hostname': 'server-main',
            'mac_address': '00:50:56:12:34:56',
            'ip_address': '192.168.1.100',
            'serial_number': 'SN-DELL-002',
            'manufacturer': 'Dell',
            'model': 'PowerEdge R740'
        },
        {
            'hostname': 'laptop-user1',
            'mac_address': 'B8:27:EB:12:34:56',
            'ip_address': '192.168.1.150',
            'serial_number': 'SN-APPLE-003',
            'manufacturer': 'Apple',
            'model': 'MacBook Pro'
        }
    ]
    
    signatures = []
    
    for i, device in enumerate(test_devices, 1):
        print(f"\nDevice {i}: {device['hostname']}")
        print("-" * 40)
        
        # Generate signature
        signature = DeviceSignature.generate_device_signature(device)
        signatures.append({
            'device': device,
            'signature': signature
        })
        
        print(f"IP Address: {device['ip_address']}")
        print(f"MAC Address: {device['mac_address']}")
        print(f"Manufacturer: {device['manufacturer']}")
        print(f"Model: {device['model']}")
        print(f"Digital Signature: {signature['readable_signature']}")
        print(f"Full Hash: {signature['full_signature']}")
        print(f"Generated: {signature['generated_at']}")
        
        # Test verification
        verification = DeviceSignature.verify_device_signature(device, signature)
        print(f"Verification: {'✅ VALID' if verification else '❌ INVALID'}")
    
    return signatures

def demonstrate_device_monitoring():
    """Demonstrate device monitoring capabilities"""
    print("\n" + "=" * 60)
    print("DEVICE MONITORING CAPABILITIES")
    print("=" * 60)
    
    print("\n🔍 Network Scanning Features:")
    print("• Multi-threaded network discovery")
    print("• IP range scanning (192.168.1.0/24, 10.0.0.0/16, etc.)")
    print("• MAC address identification")
    print("• Hostname resolution")
    print("• Device type detection")
    print("• Port scanning")
    
    print("\n🛡️ Security Features:")
    print("• Digital signature generation for each device")
    print("• Hardware-based device identification")
    print("• Change detection and alerting")
    print("• Device authenticity verification")
    
    print("\n📊 Monitoring Features:")
    print("• Real-time device status tracking")
    print("• Historical device data")
    print("• Alert system for device changes")
    print("• Email notifications")
    print("• Export/import device databases")
    
    print("\n🎯 Device Types Detected:")
    print("• Network Equipment (Routers, Switches)")
    print("• Windows Servers")
    print("• Web Servers")
    print("• IoT Devices")
    print("• Virtual Machines")
    print("• Mobile Devices")

def create_sample_device_database():
    """Create a sample device database for demonstration"""
    print("\n" + "=" * 60)
    print("SAMPLE DEVICE DATABASE")
    print("=" * 60)
    
    sample_devices = {
        "192.168.1.1": {
            "ip_address": "192.168.1.1",
            "mac_address": "00:1B:63:AA:BB:CC",
            "hostname": "office-router",
            "manufacturer": "Cisco",
            "model": "Catalyst 2960",
            "serial_number": "SN-CISCO-001",
            "device_type": "Network Device",
            "os_info": "Cisco IOS 15.0",
            "digital_signature": {
                "readable_signature": "A1B2C3D4E5F67890",
                "full_signature": "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890",
                "generated_at": "2025-11-14T08:49:30"
            },
            "open_ports": [22, 23, 80, 443],
            "status": "Online",
            "last_seen": "2025-11-14T08:49:30"
        },
        "192.168.1.100": {
            "ip_address": "192.168.1.100",
            "mac_address": "00:50:56:DD:EE:FF",
            "hostname": "main-server",
            "manufacturer": "Dell",
            "model": "PowerEdge R740",
            "serial_number": "SN-DELL-002",
            "device_type": "Windows Server",
            "os_info": "Windows Server 2019",
            "digital_signature": {
                "readable_signature": "F9E8D7C6B5A43210",
                "full_signature": "f9e8d7c6b5a43210fedcba0987654321fedcba0987654321fedcba0987654321",
                "generated_at": "2025-11-14T08:49:30"
            },
            "open_ports": [22, 3389, 80, 443, 8080],
            "status": "Online",
            "last_seen": "2025-11-14T08:48:45"
        },
        "192.168.1.150": {
            "ip_address": "192.168.1.150",
            "mac_address": "B8:27:EB:11:22:33",
            "hostname": "iot-device",
            "manufacturer": "Raspberry Pi",
            "model": "Pi 4 Model B",
            "serial_number": "SN-RPI-003",
            "device_type": "IoT Device",
            "os_info": "Raspbian GNU/Linux 11",
            "digital_signature": {
                "readable_signature": "1A2B3C4D5E6F7890",
                "full_signature": "1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890",
                "generated_at": "2025-11-14T08:49:30"
            },
            "open_ports": [22, 80, 443],
            "status": "Online",
            "last_seen": "2025-11-14T08:47:20"
        }
    }
    
    # Save sample database
    with open('sample_device_db.json', 'w') as f:
        json.dump(sample_devices, f, indent=2)
    
    print(f"\n📁 Sample device database created: sample_device_db.json")
    print(f"📊 Total devices in sample: {len(sample_devices)}")
    
    # Display device summary
    for ip, device in sample_devices.items():
        sig = device['digital_signature']['readable_signature']
        print(f"  • {ip} ({device['hostname']}) - {sig}")

def show_gui_layout_description():
    """Show GUI layout and design description"""
    print("\n" + "=" * 60)
    print("GRAPHICAL USER INTERFACE DESIGN")
    print("=" * 60)
    
    print("\n🎨 GUI LAYOUT:")
    print("┌─────────────────────────────────────────────────────────┐")
    print("│  Network Device Monitor - Dr. Mohammed Tawfik           │")
    print("├─────────────────────────────────────────────────────────┤")
    print("│  [Left Panel: Controls]    │ [Right Panel: Device List] │")
    print("│                            │                           │")
    print("│  📡 Network Configuration   │  📋 Discovered Devices    │")
    print("│  ├ Network Range Input      │  ├ Device Tree View       │")
    print("│  ├ Add Network Button       │  ├ IP, MAC, Hostname      │")
    print("│  └ Network List Box         │  ├ Digital Signature      │")
    print("│                            │  └ Status & Last Seen     │")
    print("│  ▶️ Monitoring Controls     │                           │")
    print("│  ├ Start/Stop Monitoring    │  📝 Device Details Panel │")
    print("│  ├ Scan Interval Setting    │  └ Detailed Info         │")
    print("│  └ Manual Scan Button       │                           │")
    print("│                            │                           │")
    print("│  🔔 Alert Configuration     │                           │")
    print("│  ├ Email for Alerts         │                           │")
    print("│  └ Enable Email Alerts      │                           │")
    print("│                            │                           │")
    print("│  🔧 Device Actions          │                           │")
    print("│  ├ Export Device List       │                           │")
    print("│  ├ Import Device List       │                           │")
    print("│  └ Clear All Devices        │                           │")
    print("├─────────────────────────────────────────────────────────┤")
    print("│  Status: Ready | Devices: 0        Last Updated: 08:49  │")
    print("└─────────────────────────────────────────────────────────┘")
    
    print("\n🎨 Color Scheme:")
    print("• Dark theme with #2b2b2b background")
    print("• Panel backgrounds: #3c3c3c")
    print("• Text: White (#FFFFFF)")
    print("• Status indicators: Green (Online), Yellow (Recent), Red (Offline)")
    
    print("\n🔧 Key Features:")
    print("• Real-time device monitoring")
    print("• Digital signature verification")
    print("• Change detection alerts")
    print("• Export/import capabilities")
    print("• Network range configuration")
    print("• Email alert system")

def show_usage_instructions():
    """Show usage instructions"""
    print("\n" + "=" * 60)
    print("USAGE INSTRUCTIONS")
    print("=" * 60)
    
    print("\n🚀 Getting Started:")
    print("1. Run: python device_monitor.py")
    print("2. Add network range (e.g., 192.168.1.0/24)")
    print("3. Click 'Start Monitoring'")
    print("4. Monitor devices in real-time")
    
    print("\n⚙️ Configuration:")
    print("• Set scan interval (default: 60 seconds)")
    print("• Configure email alerts")
    print("• Add multiple network ranges")
    print("• Export device database")
    
    print("\n🔍 Device Discovery:")
    print("• Automatic network scanning")
    print("• MAC address identification")
    print("• Hostname resolution")
    print("• Device type classification")
    print("• Port scanning")
    
    print("\n🛡️ Security Features:")
    print("• Digital signature generation")
    print("• Hardware-based device fingerprinting")
    print("• Change detection alerts")
    print("• Device authenticity verification")
    
    print("\n📧 Alert System:")
    print("• New device detection")
    print("• Device change notifications")
    print("• Removal alerts")
    print("• Email notifications")

def main():
    """Main demonstration function"""
    print("╔═══════════════════════════════════════════════════════════╗")
    print("║         NETWORK DEVICE MONITOR DEMONSTRATION              ║")
    print("║              Created by: Dr. Mohammed Tawfik              ║")
    print("║                    Version 1.0                            ║")
    print("║                   Date: 2025-11-14                        ║")
    print("╚═══════════════════════════════════════════════════════════╝")
    
    # Demonstrate signature system
    signatures = demonstrate_signature_system()
    
    # Show monitoring capabilities
    demonstrate_device_monitoring()
    
    # Create sample database
    create_sample_device_database()
    
    # Show GUI design
    show_gui_layout_description()
    
    # Show usage instructions
    show_usage_instructions()
    
    print("\n" + "=" * 60)
    print("DEMONSTRATION COMPLETE")
    print("=" * 60)
    print("\n✅ To run the actual application:")
    print("   python device_monitor.py")
    print("\n✅ To view sample database:")
    print("   cat sample_device_db.json")
    print("\n✅ Application is ready for deployment!")

if __name__ == "__main__":
    main()
