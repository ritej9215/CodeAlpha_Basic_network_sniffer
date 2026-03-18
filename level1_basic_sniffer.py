from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

PROTOCOL_MAP = {
    1:  "ICMP",
    6:  "TCP",
    17: "UDP"
}

packet_count = 0

def process_packet(packet):
    global packet_count

    if IP not in packet:
        return

    packet_count += 1
    ip_layer  = packet[IP]
    src_ip    = ip_layer.src
    dst_ip    = ip_layer.dst
    proto_num = ip_layer.proto
    protocol  = PROTOCOL_MAP.get(proto_num, f"OTHER({proto_num})")
    timestamp = datetime.now().strftime("%H:%M:%S")

    src_port = "N/A"
    dst_port = "N/A"

    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    # Payload extraction
    if packet.haslayer("Raw"):
        raw_payload = packet["Raw"].load
        try:
            decoded = raw_payload.decode("utf-8", errors="replace")
            payload_display = decoded[:80] + "..." if len(decoded) > 80 else decoded
        except:
            payload_display = str(raw_payload[:80])
    else:
        payload_display = "None"

    print("=" * 55)
    print(f"  Packet     : #{packet_count}  |  Time: {timestamp}")
    print(f"  Protocol   : {protocol}")
    print(f"  Source IP  : {src_ip}  →  Port: {src_port}")
    print(f"  Dest IP    : {dst_ip}  →  Port: {dst_port}")
    print(f"  Payload    : {payload_display}")
    print("=" * 55)

    with open("capture_log.txt", "a") as f:
        f.write(f"{timestamp} | #{packet_count} | {protocol} | {src_ip}:{src_port} → {dst_ip}:{dst_port} | Payload: {payload_display}\n")

if __name__ == "__main__":
    print("\n[*] Network Sniffer Started — Press Ctrl+C to stop\n")
    sniff(prn=process_packet, store=False, count=0)