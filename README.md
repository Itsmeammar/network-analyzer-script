# 🔥 ENDER - Network Traffic Analyzer

<div align="center">

![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

**A powerful, professional network traffic analysis tool with real-time monitoring and advanced visualization**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Documentation](#-documentation)

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Usage](#-usage)
- [Examples](#-examples)
- [Output](#-output)
- [Contributing](#-contributing)
- [License](#-license)
- [Author](#-author)

---

## 🎯 Overview

**ENDER** is an advanced network traffic analyzer designed for network administrators, security professionals, and developers. It provides comprehensive packet analysis with beautiful visualizations and real-time monitoring capabilities.

### Why ENDER?

- 🚀 **Real-time Analysis**: Live packet capture and instant protocol detection
- 📊 **Visual Reports**: Professional charts and graphs for easy interpretation
- 🔍 **Deep Inspection**: HTTP, DNS, TCP, UDP, ICMP protocol analysis
- 🎨 **Beautiful Interface**: Color-coded terminal output for enhanced readability
- 💾 **Export Capabilities**: Save captures in PCAP format for later analysis
- 🔒 **Security Awareness**: Basic threat detection and anomaly identification

---

## ✨ Features

### Core Capabilities

- **Real-time Packet Capture**: Monitor network traffic as it happens
- **Protocol Analysis**: Automatic detection and analysis of:
  - TCP/UDP traffic
  - HTTP requests and responses
  - DNS queries
  - ICMP packets
- **Traffic Statistics**: Detailed metrics on:
  - Protocol distribution
  - IP address activity
  - Port usage and services
  - Packet rates and volumes
- **Visual Reporting**: Auto-generated charts including:
  - Protocol distribution charts
  - Traffic timeline graphs
  - Top active devices
  - Port and service analysis
- **PCAP Support**: Save and load packet captures
- **Security Monitoring**: Detection of unusual patterns
- **Professional Output**: Color-coded terminal interface

---

## 🔧 Requirements

### System Requirements

- **Operating System**: Linux or macOS (root/sudo access required)
- **Python**: 3.8 or higher
- **Network Interface**: Active network interface for packet capture

### Python Dependencies
```
scapy>=2.4.5
matplotlib>=3.5.0
pandas>=1.3.0
numpy>=1.21.0
```

---

## 📦 Installation

### Step 1: Clone the Repository
```bash
git clone https://github.com/YOUR_GITHUB_USERNAME/ender-network-analyzer.git
cd ender-network-analyzer
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 3: Verify Installation
```bash
python3 analyzer.py --help
```

---

## 🚀 Usage

### Basic Syntax
```bash
sudo python3 analyzer.py -i <interface> [options]
```

### Command Line Arguments

| Argument | Short | Description | Required |
|----------|-------|-------------|----------|
| `--interface` | `-i` | Network interface to capture on (e.g., eth0, wlan0) | ✅ Yes |
| `--duration` | `-d` | Capture duration in seconds (default: 60) | ❌ No |
| `--save` | `-s` | Save captured packets to PCAP file | ❌ No |
| `--load` | `-l` | Load and analyze existing PCAP file | ❌ No |

---

## 💡 Examples

### Example 1: Basic 60-Second Capture
```bash
sudo python3 analyzer.py -i eth0
```

Captures traffic on `eth0` for 60 seconds and generates a report.

### Example 2: Custom Duration with PCAP Save
```bash
sudo python3 analyzer.py -i wlan0 -d 120 -s
```

Captures traffic on `wlan0` for 120 seconds and saves packets to a PCAP file.

### Example 3: Analyze Existing PCAP File
```bash
sudo python3 analyzer.py -i eth0 -l capture_20241016_153045.pcap
```

Analyzes a previously saved PCAP file.

### Example 4: Quick 30-Second Scan
```bash
sudo python3 analyzer.py -i eth0 -d 30
```

Quick network scan for 30 seconds.

---

## 📊 Output

### Terminal Output

The tool provides color-coded terminal output including:

- **Executive Summary**: Total packets, duration, packet rate
- **Protocol Analysis**: Distribution of TCP, UDP, HTTP, DNS, ICMP
- **Network Topology**: Most active IP addresses
- **Service Analysis**: Most active ports and services
- **Security Awareness**: Unusual pattern detection

### Generated Files

All output files are saved in the `Network_analysis/` directory:

1. **Visual Report** (`network_analysis_YYYYMMDD_HHMMSS.png`)
   - High-resolution (300 DPI) charts
   - Protocol distribution
   - Traffic timeline
   - Top devices and ports

2. **Text Summary** (`analysis_summary_YYYYMMDD_HHMMSS.txt`)
   - Detailed statistics
   - Complete analysis report
   - Timestamp and metadata

3. **PCAP File** (if `-s` flag used)
   - Raw packet capture
   - Compatible with Wireshark
   - Replayable for future analysis

---

## 📖 Documentation

### Finding Your Network Interface

#### Linux:
```bash
ip link show
```

Common interfaces: `eth0`, `wlan0`, `enp0s3`

#### macOS:
```bash
ifconfig
```

Common interfaces: `en0`, `en1`

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/AmazingFeature`
3. Commit your changes: `git commit -m 'Add some AmazingFeature'`
4. Push to the branch: `git push origin feature/AmazingFeature`
5. Open a Pull Request

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

**Ammar404**

- GitHub: [@YOUR_GITHUB_USERNAME](https://github.com/YOUR_GITHUB_USERNAME)

---

## ⚠️ Disclaimer

This tool is intended for educational purposes and authorized network analysis only. Always ensure you have permission before monitoring network traffic. The author is not responsible for any misuse of this tool.

---

## 🙏 Acknowledgments

- Built with [Scapy](https://scapy.net/) - Powerful packet manipulation library
- Visualization powered by [Matplotlib](https://matplotlib.org/)
- Inspired by the need for accessible network analysis tools

---

<div align="center">

**⭐ Star this repository if you find it helpful! ⭐**

Made with ❤️ by Ammar404

</div>
