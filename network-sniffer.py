import argparse
import logging
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from collections import defaultdict
import json
import os
from datetime import datetime

class NetworkSniffer:
    def __init__(self, interface=None, output_dir='network_logs', 
                 capture_duration=None, protocols=None):
        """
        Initialize the Network Sniffer with configurable parameters.
        
        :param interface: Network interface to sniff on (None for default)
        :param output_dir: Directory to save log files
        :param capture_duration: Maximum duration of capture in seconds
        :param protocols: List of protocols to filter (e.g., ['TCP', 'UDP'])
        """
        self.interface = interface
        self.output_dir = output_dir
        self.capture_duration = capture_duration
        self.protocols = protocols or ['TCP', 'UDP', 'ICMP']
        
        # Store packets for PCAP export
        self.captured_packets = []
        
        # Logging configuration
        logging.basicConfig(
            level=logging.INFO, 
            format='%(asctime)s - %(levelname)s: %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Statistics tracking
        self.packet_stats = defaultdict(int)
        self.connection_tracking = defaultdict(list)
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)

    def packet_callback(self, packet):
        """
        Callback function for processing captured packets.
        
        :param packet: Scapy packet object
        """
        # Store packet for PCAP export
        self.captured_packets.append(packet)
        
        # Ignore packets that don't have IP layer
        if not packet.haslayer(IP):
            return

        # Protocol filtering
        protocol = packet[IP].proto
        protocol_name = {
            6: 'TCP', 
            17: 'UDP', 
            1: 'ICMP'
        }.get(protocol, 'Unknown')
        
        if protocol_name not in self.protocols:
            return

        # Basic packet information
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Update packet statistics
        self.packet_stats['total'] += 1
        self.packet_stats[protocol_name] += 1
        
        # Connection tracking
        connection_key = f"{src_ip}:{dst_ip}"
        self.connection_tracking[connection_key].append({
            'timestamp': datetime.now().isoformat(),
            'protocol': protocol_name,
            'packet_length': len(packet)
        })
        
        # Optional: Detailed logging for specific protocols
        if protocol_name == 'TCP' and packet.haslayer(TCP):
            self._log_tcp_details(packet)
        
        # Verbose logging
        self.logger.info(
            f"Packet: {src_ip} -> {dst_ip} | "
            f"Protocol: {protocol_name} | "
            f"Length: {len(packet)} bytes"
        )

    def _log_tcp_details(self, packet):
        """
        Log detailed information for TCP packets.
        
        :param packet: TCP packet
        """
        tcp_layer = packet[TCP]
        tcp_info = {
            'sport': tcp_layer.sport,
            'dport': tcp_layer.dport,
            'flags': tcp_layer.flags
        }
        
        # Log specific flags
        if tcp_layer.flags & 0x02:  # SYN flag
            self.logger.info(f"TCP Connection Request: {tcp_info}")

    def start_capture(self):
        """
        Start packet capture with optional duration limit.
        """
        self.logger.info(f"Starting network capture on {self.interface or 'default interface'}")
        
        try:
            # Capture packets
            sniff(
                iface=self.interface, 
                prn=self.packet_callback,
                store=1,  # Store packets in memory for PCAP export
                timeout=self.capture_duration
            )
        except Exception as e:
            self.logger.error(f"Capture error: {e}")
        finally:
            self.save_capture_summary()
            self.save_pcap()

    def save_capture_summary(self):
        """
        Save capture statistics and connection tracking to files.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Packet Statistics
        stats_file = os.path.join(
            self.output_dir, 
            f'packet_stats_{timestamp}.json'
        )
        with open(stats_file, 'w') as f:
            json.dump(dict(self.packet_stats), f, indent=4)
        
        # Connection Tracking
        connections_file = os.path.join(
            self.output_dir, 
            f'connection_tracking_{timestamp}.json'
        )
        with open(connections_file, 'w') as f:
            json.dump(
                {k: v for k, v in self.connection_tracking.items()}, 
                f, 
                indent=4
            )
        
        self.logger.info(f"Capture summary saved to {stats_file}")
        self.logger.info(f"Connection tracking saved to {connections_file}")

    def save_pcap(self):
        """
        Save captured packets to a PCAP file.
        """
        if not self.captured_packets:
            self.logger.warning("No packets captured for PCAP export")
            return
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pcap_file = os.path.join(
            self.output_dir, 
            f'capture_{timestamp}.pcap'
        )
        
        wrpcap(pcap_file, self.captured_packets)
        self.logger.info(f"Packet capture saved to {pcap_file}")

def main():
    parser = argparse.ArgumentParser(description='Network Traffic Sniffer')
    parser.add_argument(
        '-i', '--interface', 
        help='Network interface to sniff on'
    )
    parser.add_argument(
        '-d', '--duration', 
        type=int, 
        help='Capture duration in seconds'
    )
    parser.add_argument(
        '-p', '--protocols', 
        nargs='+', 
        default=['TCP', 'UDP', 'ICMP'],
        help='Protocols to capture (TCP UDP ICMP)'
    )
    
    args = parser.parse_args()
    
    sniffer = NetworkSniffer(
        interface=args.interface,
        capture_duration=args.duration,
        protocols=args.protocols
    )
    
    sniffer.start_capture()

if __name__ == '__main__':
    main()

# README/Usage Instructions
"""
Network Sniffer Usage Instructions:

IMPORTANT: This script requires root/administrator privileges to capture packets.

Prerequisites:
1. Install Scapy: pip install scapy
2. Run with sudo/admin rights

Basic Usage:
- Capture on default interface: 
  sudo python network_sniffer.py

- Specify interface and duration:
  sudo python network_sniffer.py -i eth0 -d 60

- Filter specific protocols:
  sudo python network_sniffer.py -p TCP UDP

Output:
- Saves packet capture to network_logs/capture_[timestamp].pcap (Wireshark compatible)
- Logs packet statistics to network_logs/packet_stats_[timestamp].json
- Saves connection tracking details to network_logs/connection_tracking_[timestamp].json

Ethical Use Warning:
- Only capture packets on networks you own or have explicit permission to monitor
- Respect privacy and legal regulations
"""
