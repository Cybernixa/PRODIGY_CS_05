from scapy.all import *
import sys

def process_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        proto = packet[IP].proto
        proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        proto_name = proto_map.get(proto, f"Unknown ({proto})")

        payload = None
        if packet.haslayer(TCP):
            payload = bytes(packet[TCP].payload)
        elif packet.haslayer(UDP):
            payload = bytes(packet[UDP].payload)
        elif packet.haslayer(ICMP):
            payload = bytes(packet[ICMP].payload)

        hex_str = decoded_str = ""
        if payload:
            # Truncate payload to first 100 bytes
            truncated_payload = payload[:100]
            # Convert to hex
            hex_str = truncated_payload.hex()
            if len(payload) > 100:
                hex_str += "..."
            # Attempt to decode as UTF-8 text
            try:
                decoded_str = truncated_payload.decode('utf-8', errors='replace')
                decoded_str = decoded_str.replace('\n', '\\n').replace('\r', '\\r')  # Escape newlines
                if len(payload) > 100:
                    decoded_str += "..."
            except:
                decoded_str = "[Non-text data]"

        print(f"[+] {src_ip} -> {dst_ip} | Proto: {proto_name}")
        print(f"    Hex: {hex_str}")
        print(f"    Decoded: {decoded_str}\n")

def ethical_warning():
    print("""
    ███████╗████████╗██╗  ██╗██╗ ██████╗ █████╗ ██╗         
    ██╔════╝╚══██╔══╝██║  ██║██║██╔════╝██╔══██╗██║         
    █████╗     ██║   ███████║██║██║     ███████║██║         
    ██╔══╝     ██║   ██╔══██║██║██║     ██╔══██║██║         
    ███████╗   ██║   ██║  ██║██║╚██████╗██║  ██║███████╗    
    ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝    
                                                            
    This tool is for EDUCATIONAL USE ONLY.
    Unauthorized network sniffing is ILLEGAL.
    Use only on networks you have EXPLICIT PERMISSION to monitor.
    """)
    input("Press ENTER to confirm you agree to use this tool ethically: ")

if __name__ == "__main__":
    ethical_warning()
    print("\nStarting packet sniffer (Press Ctrl+C to stop)...\n")
    try:
        sniff(prn=process_packet, store=0)
    except PermissionError:
        print("[!] Permission denied. Run with sudo/administrator privileges.")
    except KeyboardInterrupt:
        print("\n[!] Sniffer stopped by user.")
