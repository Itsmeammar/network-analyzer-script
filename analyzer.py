#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.http import HTTP
from scapy.layers.dns import DNS
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from collections import defaultdict
import argparse
import time
import threading
import os
from datetime import datetime
import socket
import matplotlib.gridspec as gridspec

# ANSI Color Codes
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
    # Custom colors
    NEON_BLUE = '\033[38;5;81m'
    NEON_CYAN = '\033[38;5;51m'
    NEON_PURPLE = '\033[38;5;135m'
    NEON_GREEN = '\033[38;5;82m'
    NEON_PINK = '\033[38;5;213m'
    NEON_YELLOW = '\033[38;5;226m'
    DARK_GRAY = '\033[38;5;240m'
    LIGHT_GRAY = '\033[38;5;250m'

def display_banner():
    banner = f"""
{Colors.NEON_PURPLE}╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║  {Colors.NEON_BLUE}███████╗███╗   ██╗██████╗ ███████╗██████╗                                  {Colors.NEON_PURPLE}║
║  {Colors.NEON_BLUE}██╔════╝████╗  ██║██╔══██╗██╔════╝██╔══██╗                                 {Colors.NEON_PURPLE}║
║  {Colors.NEON_BLUE}█████╗  ██╔██╗ ██║██║  ██║█████╗  ██████╔╝                                 {Colors.NEON_PURPLE}║
║  {Colors.NEON_BLUE}██╔══╝  ██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗                                 {Colors.NEON_PURPLE}║
║  {Colors.NEON_BLUE}███████╗██║ ╚████║██████╔╝███████╗██║  ██║                                 {Colors.NEON_PURPLE}║
║  {Colors.NEON_BLUE}╚══════╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝                                 {Colors.NEON_PURPLE}║
║                                                                              ║
║  {Colors.NEON_PINK}█████╗ ███╗   ███╗███╗   ███╗ █████╗ ██████╗ ██╗  ██╗ ██████╗ ██╗  ██╗   {Colors.NEON_PURPLE}║
║  {Colors.NEON_PINK}██╔══██╗████╗ ████║████╗ ████║██╔══██╗██╔══██╗██║  ██║██╔═████╗██║  ██║   {Colors.NEON_PURPLE}║
║  {Colors.NEON_PINK}███████║██╔████╔██║██╔████╔██║███████║██████╔╝███████║██║██╔██║███████║   {Colors.NEON_PURPLE}║
║  {Colors.NEON_PINK}██╔══██║██║╚██╔╝██║██║╚██╔╝██║██╔══██║██╔══██╗╚════██║████╔╝██║╚════██║   {Colors.NEON_PURPLE}║
║  {Colors.NEON_PINK}██║  ██║██║ ╚═╝ ██║██║ ╚═╝ ██║██║  ██║██║  ██║     ██║╚██████╔╝     ██║   {Colors.NEON_PURPLE}║
║  {Colors.NEON_PINK}╚═╝  ╚═╝╚═╝     ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝     ╚═╝ ╚═════╝      ╚═╝   {Colors.NEON_PURPLE}║
║                                                                              ║
║  {Colors.NEON_CYAN}┌────────────────────────────────────────────────────────────────────────┐  {Colors.NEON_PURPLE}║
║  {Colors.NEON_CYAN}│                    NETWORK TRAFFIC ANALYZER                            │  {Colors.NEON_PURPLE}║
║  {Colors.NEON_CYAN}│                   Advanced Packet Analysis Tool                        │  {Colors.NEON_PURPLE}║
║  {Colors.NEON_CYAN}└────────────────────────────────────────────────────────────────────────┘  {Colors.NEON_PURPLE}║
║                                                                              ║
║  {Colors.OKGREEN}CAPABILITIES:{Colors.ENDC}                                                            ║
║  {Colors.NEON_GREEN}▸{Colors.ENDC} Real-time packet capture and protocol analysis                        ║
║  {Colors.NEON_GREEN}▸{Colors.ENDC} Traffic pattern identification and visualization                      ║
║  {Colors.NEON_GREEN}▸{Colors.ENDC} Network performance metrics and reporting                             ║
║  {Colors.NEON_GREEN}▸{Colors.ENDC} Security awareness and anomaly detection                              ║
║  {Colors.NEON_GREEN}▸{Colors.ENDC} Historical data analysis with graphical reports                       ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝{Colors.ENDC}
"""
    print(banner)

class NetworkTrafficAnalyzer:
    def __init__(self, interface, duration=60, save_pcap=False):
        self.interface = interface
        self.duration = duration
        self.save_pcap = save_pcap
        self.packets = []
        self.protocol_stats = defaultdict(int)
        self.ip_stats = defaultdict(int)
        self.port_stats = defaultdict(int)
        self.alerts = []
        self.running = False
        self.start_time = None
        
    def packet_handler(self, packet):
        if not self.running:
            return
            
        self.packets.append(packet)
        
        # Protocol analysis
        if packet.haslayer(TCP):
            self.protocol_stats['TCP'] += 1
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            self.port_stats[dst_port] += 1
            
            if packet.haslayer(HTTP):
                self.protocol_stats['HTTP'] += 1
                self.inspect_http(packet)
                
        elif packet.haslayer(UDP):
            self.protocol_stats['UDP'] += 1
            if packet.haslayer(DNS):
                self.protocol_stats['DNS'] += 1
                self.inspect_dns(packet)
                
        elif packet.haslayer(ICMP):
            self.protocol_stats['ICMP'] += 1
            
        # IP analysis
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            self.ip_stats[src_ip] += 1
            self.ip_stats[dst_ip] += 1
            
        # Minimal security check - only for obvious threats
        self.detect_obvious_threats(packet)
        
    def inspect_http(self, packet):
        try:
            if packet.haslayer(HTTP) and packet[HTTP].Method:
                method = packet[HTTP].Method.decode('utf-8')
                host = packet[HTTP].Host.decode('utf-8') if packet[HTTP].Host else "Unknown"
                path = packet[HTTP].Path.decode('utf-8') if packet[HTTP].Path else "/"
                print(f"{Colors.NEON_CYAN}[HTTP]{Colors.ENDC} Request: {Colors.NEON_YELLOW}{method}{Colors.ENDC} http://{Colors.NEON_GREEN}{host}{path}{Colors.ENDC}")
        except:
            pass
            
    def inspect_dns(self, packet):
        try:
            if packet.haslayer(DNS) and packet[DNS].qd:
                domain = packet[DNS].qd.qname.decode('utf-8').rstrip('.')
                print(f"{Colors.NEON_PURPLE}[DNS]{Colors.ENDC} Query: {Colors.NEON_BLUE}{domain}{Colors.ENDC}")
        except:
            pass
            
    def detect_obvious_threats(self, packet):
        # Only detect very obvious threats - high threshold to avoid false positives
        if packet.haslayer(TCP) and packet[TCP].flags == 2:  # SYN flag
            src_ip = packet[IP].src
            # Very high threshold for port scan (100 packets to same port)
            if self.port_stats.get(packet[TCP].dport, 0) > 100:
                self.alerts.append(f"Possible port scan from {src_ip}")
                
        # Only flag extremely large packets (over 50KB)
        if len(packet) > 50000:
            src_ip = packet[IP].src
            self.alerts.append(f"Very large packet ({len(packet)} bytes) from {src_ip}")
            
    def start_capture(self):
        print(f"\n{Colors.OKBLUE}[*]{Colors.ENDC} Initiating packet capture on interface: {Colors.NEON_GREEN}{self.interface}{Colors.ENDC}")
        print(f"{Colors.OKBLUE}[*]{Colors.ENDC} Capture duration: {Colors.NEON_YELLOW}{self.duration}{Colors.ENDC} seconds")
        print(f"{Colors.OKBLUE}[*]{Colors.ENDC} Generating network traffic will enhance analysis results")
        self.running = True
        self.start_time = time.time()
        
        # Create pcap filename if saving
        pcap_filename = None
        if self.save_pcap:
            pcap_filename = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
            print(f"{Colors.OKBLUE}[*]{Colors.ENDC} Saving packets to: {Colors.NEON_CYAN}{pcap_filename}{Colors.ENDC}")
            
        # Start sniffing in a separate thread
        sniff_thread = threading.Thread(
            target=sniff,
            kwargs={
                'iface': self.interface,
                'prn': self.packet_handler,
                'timeout': self.duration,
                'store': False
            }
        )
        sniff_thread.start()
        
        # Wait for capture to complete
        sniff_thread.join()
        self.running = False
        
        # Save packets if requested
        if self.save_pcap and pcap_filename and self.packets:
            wrpcap(pcap_filename, self.packets)
            print(f"{Colors.OKGREEN}[+]{Colors.ENDC} Successfully saved {Colors.NEON_GREEN}{len(self.packets)}{Colors.ENDC} packets to {Colors.NEON_CYAN}{pcap_filename}{Colors.ENDC}")
            
        print(f"\n{Colors.OKGREEN}[+]{Colors.ENDC} Packet capture completed")
        
    def analyze_traffic(self):
        print(f"\n{Colors.NEON_PURPLE}{'='*80}{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.NEON_BLUE}NETWORK TRAFFIC ANALYSIS REPORT{Colors.ENDC}")
        print(f"{Colors.NEON_PURPLE}{'='*80}{Colors.ENDC}")
        
        # Executive Summary
        print(f"\n{Colors.NEON_CYAN}{Colors.BOLD}EXECUTIVE SUMMARY:{Colors.ENDC}")
        print(f"{Colors.DARK_GRAY}{'-'*40}{Colors.ENDC}")
        print(f"Total packets analyzed: {Colors.NEON_GREEN}{len(self.packets)}{Colors.ENDC}")
        print(f"Analysis duration: {Colors.NEON_YELLOW}{self.duration}{Colors.ENDC} seconds")
        print(f"Average packet rate: {Colors.NEON_PINK}{len(self.packets)/self.duration:.2f}{Colors.ENDC} packets/second")
        
        # Security Assessment (minimal focus)
        print(f"\n{Colors.NEON_CYAN}{Colors.BOLD}SECURITY AWARENESS:{Colors.ENDC}")
        print(f"{Colors.DARK_GRAY}{'-'*40}{Colors.ENDC}")
        if self.alerts:
            print(f"{Colors.WARNING}Note: {len(set(self.alerts))} unusual pattern(s) observed{Colors.ENDC}")
            for i, alert in enumerate(set(self.alerts), 1):
                print(f"  {Colors.NEON_YELLOW}{i}.{Colors.ENDC} {alert}")
            print(f"{Colors.LIGHT_GRAY}Note: These may be legitimate activities{Colors.ENDC}")
        else:
            print(f"{Colors.OKGREEN}No unusual patterns detected{Colors.ENDC}")
            print(f"{Colors.LIGHT_GRAY}Network traffic appears normal{Colors.ENDC}")
        
        # Protocol Analysis (main focus)
        print(f"\n{Colors.NEON_CYAN}{Colors.BOLD}PROTOCOL ANALYSIS:{Colors.ENDC}")
        print(f"{Colors.DARK_GRAY}{'-'*40}{Colors.ENDC}")
        for proto, count in sorted(self.protocol_stats.items()):
            percentage = count/len(self.packets)*100 if self.packets else 0
            print(f"{Colors.NEON_BLUE}{proto.upper()}:{Colors.ENDC} {Colors.NEON_GREEN}{count}{Colors.ENDC} packets ({Colors.NEON_PINK}{percentage:.1f}%{Colors.ENDC})")
        
        # Network Topology (main focus)
        print(f"\n{Colors.NEON_CYAN}{Colors.BOLD}NETWORK TOPOLOGY:{Colors.ENDC}")
        print(f"{Colors.DARK_GRAY}{'-'*40}{Colors.ENDC}")
        print(f"{Colors.NEON_YELLOW}Most Active Devices:{Colors.ENDC}")
        sorted_ips = sorted(self.ip_stats.items(), key=lambda x: x[1], reverse=True)[:5]
        for i, (ip, count) in enumerate(sorted_ips, 1):
            print(f"  {Colors.NEON_GREEN}{i}.{Colors.ENDC} {Colors.NEON_BLUE}{ip}{Colors.ENDC}: {Colors.NEON_PINK}{count}{Colors.ENDC} packets")
        
        # Service Analysis (main focus)
        print(f"\n{Colors.NEON_CYAN}{Colors.BOLD}SERVICE ANALYSIS:{Colors.ENDC}")
        print(f"{Colors.DARK_GRAY}{'-'*40}{Colors.ENDC}")
        print(f"{Colors.NEON_YELLOW}Most Active Services:{Colors.ENDC}")
        sorted_ports = sorted(self.port_stats.items(), key=lambda x: x[1], reverse=True)[:5]
        for i, (port, count) in enumerate(sorted_ports, 1):
            try:
                service = socket.getservbyport(port, 'tcp') if port < 65536 else "unknown"
                print(f"  {Colors.NEON_GREEN}{i}.{Colors.ENDC} Port {Colors.NEON_BLUE}{port}{Colors.ENDC} ({Colors.NEON_PURPLE}{service}{Colors.ENDC}): {Colors.NEON_PINK}{count}{Colors.ENDC} packets")
            except:
                print(f"  {Colors.NEON_GREEN}{i}.{Colors.ENDC} Port {Colors.NEON_BLUE}{port}{Colors.ENDC} ({Colors.LIGHT_GRAY}unknown{Colors.ENDC}): {Colors.NEON_PINK}{count}{Colors.ENDC} packets")
        
    def generate_report(self):
        # Create output directory
        output_dir = "Network_analysis"
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            print(f"{Colors.OKGREEN}[+]{Colors.ENDC} Created output directory: {Colors.NEON_CYAN}{output_dir}{Colors.ENDC}")
        
        # Create figure with professional layout
        plt.style.use('seaborn-v0_8-whitegrid')
        fig = plt.figure(figsize=(20, 16))
        gs = gridspec.GridSpec(3, 2, figure=fig, height_ratios=[1.2, 1, 1])
        
        # Professional color palette
        colors = ['#2E86AB', '#A23B72', '#F18F01', '#C73E1D', '#592E83']
        
        # 1. Protocol Distribution - Stacked Bar Chart
        ax1 = fig.add_subplot(gs[0, 0])
        if self.protocol_stats:
            protocols = list(self.protocol_stats.keys())
            counts = list(self.protocol_stats.values())
            total = sum(counts)
            
            # Create stacked bar
            bottom = 0
            for i, (proto, count) in enumerate(zip(protocols, counts)):
                percentage = count/total * 100
                ax1.bar(0, percentage, bottom=bottom, color=colors[i % len(colors)], 
                       label=f"{proto.upper()} ({count})")
                bottom += percentage
            
            ax1.set_title('Protocol Distribution', fontsize=14, fontweight='bold', pad=20)
            ax1.set_ylabel('Percentage of Total Traffic', fontsize=12)
            ax1.set_xticks([])
            ax1.legend(loc='upper right', fontsize=10)
            
            # Add percentage labels
            bottom = 0
            for i, (proto, count) in enumerate(zip(protocols, counts)):
                percentage = count/total * 100
                ax1.text(0, bottom + percentage/2, f'{percentage:.1f}%', 
                        ha='center', va='center', color='white', fontweight='bold', fontsize=12)
                bottom += percentage
        
        # 2. Traffic Timeline - Area Chart
        ax2 = fig.add_subplot(gs[0, 1])
        if self.packets:
            timestamps = [float(packet.time) for packet in self.packets]
            if timestamps:
                # Create time bins (5-second intervals)
                start_time = min(timestamps)
                end_time = max(timestamps)
                time_bins = np.linspace(start_time, end_time, 12)  # 12 bins = ~5s each
                
                # Count packets in each bin
                hist, _ = np.histogram(timestamps, bins=time_bins)
                
                # Create time labels
                time_labels = []
                for i in range(len(time_bins)-1):
                    bin_center = (time_bins[i] + time_bins[i+1]) / 2
                    rel_time = bin_center - start_time
                    time_labels.append(f"{rel_time:.0f}s")
                
                # Plot as area chart
                ax2.fill_between(range(len(hist)), hist, alpha=0.7, color=colors[1])
                ax2.plot(range(len(hist)), hist, color=colors[1], linewidth=2)
                ax2.set_title('Packet Distribution Over Time', fontsize=14, fontweight='bold', pad=20)
                ax2.set_xlabel('Time Elapsed (seconds)', fontsize=12)
                ax2.set_ylabel('Packet Count', fontsize=12)
                ax2.set_xticks(range(len(time_labels)))
                ax2.set_xticklabels(time_labels)
                ax2.grid(True, linestyle='--', alpha=0.7)
                
                # Add value labels on peaks
                max_idx = np.argmax(hist)
                ax2.text(max_idx, hist[max_idx], f'{hist[max_idx]}', 
                        ha='center', va='bottom', fontweight='bold', fontsize=10)
        
        # 3. Top IP Addresses - Horizontal Bar Chart
        ax3 = fig.add_subplot(gs[1, :])
        if self.ip_stats:
            top_ips = sorted(self.ip_stats.items(), key=lambda x: x[1], reverse=True)[:10]
            ips, counts = zip(*top_ips)
            
            # Create horizontal bars
            bars = ax3.barh(range(len(ips)), counts, color=colors[2])
            ax3.set_yticks(range(len(ips)))
            ax3.set_yticklabels(ips)
            ax3.set_title('Most Active Network Devices', fontsize=14, fontweight='bold', pad=20)
            ax3.set_xlabel('Packet Count', fontsize=12)
            
            # Add value labels
            for i, (bar, count) in enumerate(zip(bars, counts)):
                ax3.text(bar.get_width() + max(counts)*0.01, bar.get_y() + bar.get_height()/2,
                        f'{count}', va='center', fontweight='bold', fontsize=10)
            
            # Highlight local vs external IPs
            for i, ip in enumerate(ips):
                if ip.startswith(('192.168.', '10.', '172.')):
                    bars[i].set_color(colors[0])  # Local network
                else:
                    bars[i].set_color(colors[3])  # External
        
        # 4. Port Analysis - Grouped Bar Chart
        ax4 = fig.add_subplot(gs[2, :])
        if self.port_stats:
            top_ports = sorted(self.port_stats.items(), key=lambda x: x[1], reverse=True)[:8]
            ports, counts = zip(*top_ports)
            
            # Get service names and categories
            port_labels = []
            port_colors = []
            for port in ports:
                try:
                    service = socket.getservbyport(port, 'tcp')
                    if port in [80, 443, 8080]:
                        category = "Web"
                        color = colors[0]
                    elif port in [20, 21, 22, 23]:
                        category = "Remote"
                        color = colors[1]
                    elif port == 53:
                        category = "DNS"
                        color = colors[2]
                    else:
                        category = "Other"
                        color = colors[3]
                    port_labels.append(f"{port}\n({service})\n[{category}]")
                    port_colors.append(color)
                except:
                    port_labels.append(f"{port}\n(unknown)\n[Other]")
                    port_colors.append(colors[4])
            
            # Create bars
            bars = ax4.bar(range(len(ports)), counts, color=port_colors)
            ax4.set_title('Destination Port Analysis', fontsize=14, fontweight='bold', pad=20)
            ax4.set_xlabel('Port Number (Service) [Category]', fontsize=12)
            ax4.set_ylabel('Packet Count', fontsize=12)
            ax4.set_xticks(range(len(port_labels)))
            ax4.set_xticklabels(port_labels, rotation=45, ha='right')
            
            # Add value labels
            for bar in bars:
                height = bar.get_height()
                ax4.text(bar.get_x() + bar.get_width()/2., height,
                        f'{int(height)}', ha='center', va='bottom', fontweight='bold', fontsize=9)
        
        # Add main title and timestamp
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        fig.suptitle(f'Network Traffic Analysis Report\n{timestamp}', 
                    fontsize=18, fontweight='bold', y=0.98)
        
        # Adjust layout
        plt.tight_layout(rect=[0, 0, 1, 0.95])  # Make room for suptitle
        
        # Save report
        report_filename = f"network_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        report_path = os.path.join(output_dir, report_filename)
        plt.savefig(report_path, dpi=300, bbox_inches='tight', facecolor='white')
        print(f"\n{Colors.OKGREEN}[+]{Colors.ENDC} Visual report saved to: {Colors.NEON_CYAN}{report_path}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+]{Colors.ENDC} Report resolution: {Colors.NEON_YELLOW}300 DPI{Colors.ENDC} (print quality)")
        
        # Save summary text file
        summary_filename = f"analysis_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        summary_path = os.path.join(output_dir, summary_filename)
        with open(summary_path, 'w') as f:
            f.write("NETWORK TRAFFIC ANALYSIS SUMMARY\n")
            f.write("="*50 + "\n\n")
            f.write(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Interface: {self.interface}\n")
            f.write(f"Duration: {self.duration} seconds\n")
            f.write(f"Total Packets: {len(self.packets)}\n\n")
            
            f.write("PROTOCOL DISTRIBUTION:\n")
            for proto, count in sorted(self.protocol_stats.items()):
                percentage = count/len(self.packets)*100 if self.packets else 0
                f.write(f"- {proto.upper()}: {count} packets ({percentage:.1f}%)\n")
            
            f.write("\nMOST ACTIVE IPs:\n")
            sorted_ips = sorted(self.ip_stats.items(), key=lambda x: x[1], reverse=True)[:5]
            for i, (ip, count) in enumerate(sorted_ips, 1):
                f.write(f"{i}. {ip}: {count} packets\n")
            
            f.write("\nSECURITY AWARENESS:\n")
            if self.alerts:
                f.write(f"- {len(set(self.alerts))} unusual pattern(s) observed\n")
                for alert in set(self.alerts):
                    f.write(f"  - {alert}\n")
            else:
                f.write("- No unusual patterns detected\n")
                f.write("- Network traffic appears normal\n")
        
        print(f"{Colors.OKGREEN}[+]{Colors.ENDC} Text summary saved to: {Colors.NEON_CYAN}{summary_path}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+]{Colors.ENDC} All reports available in: {Colors.NEON_PURPLE}{output_dir}/{Colors.ENDC}")

def check_privileges():
    if os.name == 'posix':  # Linux/Mac
        if os.geteuid() != 0:
            print(f"{Colors.FAIL}[!] Error: This script requires root privileges for packet capture{Colors.ENDC}")
            print(f"    Execute with: {Colors.NEON_CYAN}sudo python3 analyzer.py [options]{Colors.ENDC}")
            return False
    return True

if __name__ == "__main__":
    display_banner()
    
    parser = argparse.ArgumentParser(description="Network Traffic Analyzer")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to capture on")
    parser.add_argument("-d", "--duration", type=int, default=60, help="Capture duration in seconds")
    parser.add_argument("-s", "--save", action="store_true", help="Save captured packets to PCAP file")
    parser.add_argument("-l", "--load", help="Load and analyze existing PCAP file")
    args = parser.parse_args()
    
    if not check_privileges() and not args.load:
        sys.exit(1)
    
    try:
        if args.load:
            # Load existing PCAP file
            print(f"{Colors.OKBLUE}[*]{Colors.ENDC} Loading PCAP file: {Colors.NEON_CYAN}{args.load}{Colors.ENDC}")
            packets = rdpcap(args.load)
            analyzer = NetworkTrafficAnalyzer(args.interface, duration=0)
            analyzer.packets = packets
            
            # Process loaded packets
            for packet in packets:
                analyzer.packet_handler(packet)
                
            analyzer.analyze_traffic()
            analyzer.generate_report()
        else:
            # Live capture
            analyzer = NetworkTrafficAnalyzer(args.interface, args.duration, args.save)
            analyzer.start_capture()
            analyzer.analyze_traffic()
            analyzer.generate_report()
                
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Analysis interrupted by user{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error: {str(e)}{Colors.ENDC}")
