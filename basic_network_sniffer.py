from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

# Map protocol numbers to names
PROTOCOL_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP"
}

# Packet counter
packet_count = 0


def process_packet(packet):
    global packet_count

    # Only process IP packets
    if IP not in packet:
        return

    packet_count += 1

    # Extract IP info
    ip_layer = packet[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    proto_num = ip_layer.proto
    protocol = PROTOCOL_MAP.get(proto_num, f"OTHER({proto_num})")

    # Timestamp
    timestamp = datetime.now().strftime("%H:%M:%S")

    # Default ports
    src_port = "N/A"
    dst_port = "N/A"

    # Extract ports
    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    # Extract payload
    # Extract payload (safe hex display)
    # Extract payload (safe hex display)
    if packet.haslayer("Raw"):

        raw_payload = bytes(packet["Raw"].load)
        payload_display = raw_payload[:50].hex()
    else:
        payload_display = "None"

    # Print output
    print("=" * 50)
    print(f"Packet #{packet_count}")
    print(f"Time: {timestamp}")
    print(f"Protocol: {protocol}")
    print(f"Source IP: {src_ip}")
    print(f"Destination IP: {dst_ip}")
    print(f"Source Port: {src_port}")
    print(f"Destination Port: {dst_port}")
    print(f"Payload: {payload_display}")
    print("=" * 50)

    # Save to file
    with open("capture_log.txt", "a") as f:
        f.write(f"""
Packet #{packet_count}
Time: {timestamp}
Protocol: {protocol}
Source IP: {src_ip}
Destination IP: {dst_ip}
Source Port: {src_port}
Destination Port: {dst_port}
Payload: {payload_display}
---------------------------------------
""")


def main():
    print("Starting Basic Network Sniffer...")
    print("Press CTRL+C to stop\n")

    sniff(prn=process_packet, store=False, count=20)


if __name__ == "__main__":
    main()