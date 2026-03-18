from scapy.all import sniff, IP, TCP, UDP, ICMP
PROTOCOL_MAP = {
    1:  "ICMP",  
    6:  "TCP",
    17: "UDP"     
}


def process_packet(packet):

    # First, check if this packet has an IP layer.
    # Not all packets do (e.g., ARP packets are Layer 2 only).
    # The 'in' keyword checks if a layer exists inside the packet.
    if IP not in packet:
        return  # Skip non-IP packets silently

    # Extract the IP layer from the packet.
    # This gives us access to source IP, destination IP, and protocol.
    ip_layer = packet[IP]

    src_ip   = ip_layer.src    # Source IP — where the packet came FROM
    dst_ip   = ip_layer.dst    # Destination IP — where the packet is GOING
    proto_num = ip_layer.proto  # Protocol number (1, 6, or 17)

    # Convert the protocol number to a human-readable name.
    # If it's not in our map, label it "OTHER".
    protocol = PROTOCOL_MAP.get(proto_num, f"OTHER({proto_num})")

    # ── PORT EXTRACTION ─────────────────────────────────────
    # Ports only exist in TCP and UDP — not in ICMP.
    # So we check which layer is present before reading ports.
    src_port = "N/A"
    dst_port = "N/A"

    if TCP in packet:
        # TCP layer contains source and destination ports.
        # Common TCP ports: 80 (HTTP), 443 (HTTPS), 22 (SSH)
        src_port = packet[TCP].sport  # sport = source port
        dst_port = packet[TCP].dport  # dport = destination port

    elif UDP in packet:
        # UDP layer also has ports.
        # Common UDP ports: 53 (DNS), 67/68 (DHCP)
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    # ICMP packets (like ping) don't use ports — they use
    # "type" and "code" fields instead. We skip those here.

    # ── DISPLAY OUTPUT ──────────────────────────────────────
    # Print everything in a clean, readable format.
    # The separator line makes it easy to distinguish packets.
    print("=" * 55)
    print(f"  Protocol   : {protocol}")
    print(f"  Source IP  : {src_ip}  →  Port: {src_port}")
    print(f"  Dest IP    : {dst_ip}  →  Port: {dst_port}")
    print("=" * 55)


# ── MAIN ENTRY POINT ────────────────────────────────────────
if __name__ == "__main__":

    print("\n[*] Network Sniffer Started — Press Ctrl+C to stop\n")

    # sniff() is Scapy's core capture function.
    #
    # Parameters explained:
    #   prn     = the function to call for each captured packet
    #   store   = False means don't store packets in memory
    #             (important — otherwise RAM fills up fast)
    #   count   = 0 means capture forever (until Ctrl+C)
    #
    # Note: On Linux, run with: sudo python3 sniffer.py
    # On Windows, run as Administrator in Command Prompt
    sniff(prn=process_packet, store=False, count=0)