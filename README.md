# PRODIGY_CS_05 – Network Packet Analyzer

## Project Overview
This Python program captures and analyzes network packets in real time.  
It shows:
- Capture **time** for each packet  
- **Source and destination IP addresses**  
- **Protocol** (TCP, UDP, ICMP, or other)  
- **Ports** for TCP/UDP packets  
- A short **payload summary** if data is present  

Created as **Task-05** of my **Cyber Security Internship at Prodigy InfoTech**.

## Features
- Captures live traffic on your own network interface  
- Displays packet details in a clean table format  
- Works with encrypted traffic (payload will appear as raw bytes)  
- Stops automatically after a set number of packets (default 10)

## How to Run
1. Install Python and Scapy:
   ```bash
   pip install scapy
   ```
2. Save the code as `packet_analyzer.py`.
3. Run with administrator/root rights:
   ```bash
   python packet_analyzer.py
   ```
   (Use **sudo** on Linux/Mac or **Run as Administrator** on Windows.)
4. Open a website or create network traffic while the program is running.  
   Press **Ctrl + C** to stop early.

## Example Output
```
--------------------------------------------------
| Time: 14:22:31.145                             |
| Protocol: TCP                                   |
| Source IP: 192.168.0.10                         |
| Destination IP: 142.250.190.78                  |
| Src Port: 52344 | Dst Port: 443                 |
| Payload Summary: <Raw load=b'\x17\x03...>       |
--------------------------------------------------
```

## Tech Used
- Python  
- [Scapy](https://scapy.net/) library for packet capture

## ⚠️ Disclaimer
This tool is for **educational use only**.  
Run it **only on networks you own or have explicit permission to monitor**.  
Capturing traffic on unauthorized networks may be illegal.
