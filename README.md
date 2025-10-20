# 🔍 ENDER - Basic Network Traffic Analyzer

A simple Python script to capture and analyze network traffic.
Built for learning and practicing basic packet analysis using **Scapy**.

This script was generated with the help of AI, guided by thoughtful prompts and design decisions by the author.

---

## ⚙️ Features

* Capture live network packets
* Analyze basic protocols (TCP, UDP, ICMP, DNS, HTTP)
* Display stats (top IPs, ports, packet count, etc.)
* Option to save captures as `.pcap` for Wireshark (if `-s` is used)

---

## 🧰 Requirements

* Linux (root/sudo access required)
* Python 3.8+
* Install dependencies:

  ```bash
  pip install -r requirements.txt
  ```

---

## 🚀 Usage

Run the script with:

```bash
sudo python3 analyzer.py -i <interface>
```

Example:

```bash
sudo python3 analyzer.py -i eth0
```

Save capture to a PCAP file:

```bash
sudo python3 analyzer.py -i eth0 -s
```

Notes:

* `-s` enables saving captured packets to a `.pcap` file (compatible with Wireshark).

---

## 🧑‍💻 Author

**Ammar404**
[GitHub](https://github.com/Itsmeammar)

---

## ⚠️ Disclaimer

For **educational and authorized use only.**
Always analyze traffic on networks you own or have permission to test.

---

