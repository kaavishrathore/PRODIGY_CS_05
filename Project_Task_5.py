from scapy.all import sniff, IP, TCP, UDP, ICMP
import datetime, sys, os

#capture settings
interface = None    
packet_count = 10    

def log_packet(pkt):
    time_now = datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]

    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = "Unknown"
        info = ""
        payload = "N/A"

        if TCP in pkt:
            proto = "TCP"
            info = f"Src Port: {pkt[TCP].sport} | Dst Port: {pkt[TCP].dport}"
            if pkt[TCP].payload:
                payload = repr(pkt[TCP].payload)[:50] + "..."
        elif UDP in pkt:
            proto = "UDP"
            info = f"Src Port: {pkt[UDP].sport} | Dst Port: {pkt[UDP].dport}"
            if pkt[UDP].payload:
                payload = repr(pkt[UDP].payload)[:50] + "..."
        elif ICMP in pkt:
            proto = "ICMP"
            info = f"Type: {pkt[ICMP].type} | Code: {pkt[ICMP].code}"
        else:
            info = f"Protocol Code: {pkt[IP].proto}"

        print("-" * 50)
        print(f"| Time: {time_now:<42}|")
        print(f"| Protocol: {proto:<40}|")
        print(f"| Source IP: {src_ip:<39}|")
        print(f"| Destination IP: {dst_ip:<34}|")
        print(f"| {info:<48}|")
        print(f"| Payload Summary: {payload:<34}|")
        print("-" * 50)
    else:
        print(f"[{time_now}] Non-IP Packet: {pkt.summary()}")

def main():
    print(f"[{datetime.datetime.now():%Y-%m-%d %H:%M:%S}] Packet Analyzer Started.")
    print(f"Capturing {packet_count} packets... open a website or run some network traffic.\n")

    try:
        sniff(prn=log_packet, count=packet_count, iface=interface, store=0)
        print("\n[INFO] Capture finished. Exiting.")
    except PermissionError:
        print("\n[ERROR] Permission denied! Run as admin (Windows) or use sudo (Linux/Mac).")
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {e}")

if __name__ == "__main__":
    if sys.platform.startswith('linux') or sys.platform == 'darwin':
        if os.geteuid() != 0:
            print("WARNING: You might need root/sudo privileges for sniffing.")
    main()
