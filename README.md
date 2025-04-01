# PRODIGY_CS_05
NETWORK PACKET ANALYZER

Breakdown of the Code:
1. Ethical Warning
The script starts by displaying a clear ethical warning, emphasizing that the tool is for educational purposes only.

It advises the user to only use the tool on networks they have explicit permission to monitor, as unauthorized sniffing is illegal.

The user must confirm by pressing Enter to continue, acknowledging that they understand the ethical use of the tool.

2. Processing Packets
The process_packet function is called every time a packet is captured by scapy.

The function checks if the packet contains an IP layer (packet.haslayer(IP)).

If the packet contains an IP layer, it retrieves:

Source IP (packet[IP].src)

Destination IP (packet[IP].dst)

Protocol (packet[IP].proto), and maps it to a human-readable name (ICMP, TCP, UDP).

It checks if the packet contains payload data and processes it accordingly:

For TCP, UDP, and ICMP packets, the payload (if any) is extracted.

If a payload is found, it's truncated to the first 100 bytes for easier inspection.

The payload is then converted to a hexadecimal string and decoded as UTF-8 text (if possible). If decoding fails, it marks the payload as non-text data.

The following information is printed for each packet:

Source and destination IP addresses

Protocol name (e.g., ICMP, TCP, UDP)

Hexadecimal representation of the payload

Decoded (UTF-8) representation of the payload (or a message indicating that the data is non-text)

3. Start Sniffing
The sniff function from scapy is used to capture network packets.

prn=process_packet: This tells scapy to call process_packet for every captured packet.

store=0: This prevents storing the sniffed packets in memory, which is useful for large-scale packet sniffing where you don’t want to accumulate packets.

4. Error Handling
The script contains a try-except block to handle errors:

If the script is run without sufficient permissions (e.g., without sudo on Linux or administrator privileges on Windows), it will print a PermissionError message.

The script gracefully handles a KeyboardInterrupt (which occurs when the user presses Ctrl+C to stop the sniffer) and prints a message indicating that the sniffer was stopped by the user.

Example Output:
When running this script on a network with traffic, the output might look something like this:

vbnet
Copy
WARNING: This tool is for EDUCATIONAL USE ONLY.
Unauthorized network sniffing is ILLEGAL.
Use only on networks you have EXPLICIT PERMISSION to monitor.

Press ENTER to confirm you agree to use this tool ethically: 
Starting packet sniffer (Press Ctrl+C to stop)...

[+] 192.168.1.1 -> 192.168.1.100 | Proto: TCP
    Hex: 48656c6c6f2c20576f726c6421
    Decoded: Hello, World!

[+] 192.168.1.1 -> 192.168.1.200 | Proto: ICMP
    Hex: 000000000000000000000000
    Decoded: [Non-text data]

[+] 192.168.1.100 -> 192.168.1.1 | Proto: UDP
    Hex: 68656c6c6f
    Decoded: hello
Key Points:
Educational Use: This tool is intended for use in an educational or ethical hacking context, and only on networks where you have permission to sniff traffic.

Ethical Usage: Unauthorized network sniffing is illegal and unethical. Always get explicit consent before capturing traffic on any network that is not your own.

Network Security Testing: The script provides a basic method for inspecting network traffic, which can be useful for monitoring, debugging, or learning about network protocols.

Additional Notes:
Root/Administrator Privileges: In order to capture network packets, the script requires elevated privileges. On Linux or macOS, this means running the script with sudo, and on Windows, you need to run it as an administrator.

Scapy Installation: Ensure that you have the scapy library installed. You can install it via pip:

bash
Copy
pip install scapy
Security Considerations: If you're using this script in a penetration testing scenario, be sure to obtain written permission and follow ethical guidelines. Unauthorized sniffing of sensitive data could have serious legal consequences.

Conclusion:
This script demonstrates how to use the scapy library to sniff and analyze network traffic in real-time. It is a powerful educational tool for understanding network protocols like TCP, UDP, and ICMP, and it provides a simple way to log packet information such as source and destination IPs, protocol type, and the packet payload. However, ethical considerations and legal guidelines must always be followed when using this tool.
