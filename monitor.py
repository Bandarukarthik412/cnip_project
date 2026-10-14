
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

packet_count = 0
tcp_count = 0
udp_count = 0
icmp_count = 0
other_count = 0


def show_packet(packet):
    global packet_count, tcp_count
    global udp_count, icmp_count, other_count

    if IP not in packet:
        return

    packet_count += 1
    source = packet[IP].src
    destination = packet[IP].dst

    if TCP in packet:
        protocol = "TCP"
        tcp_count += 1
    elif UDP in packet:
        protocol = "UDP"
        udp_count += 1
    elif ICMP in packet:
        protocol = "ICMP"
        icmp_count += 1
    else:
        protocol = "Other"
        other_count += 1

    message = (
        f"Packet: {packet_count} | "
        f"Source: {source} | "
        f"Destination: {destination} | "
        f"Protocol: {protocol}"
    )

    print(message, flush=True)

    with open("traffic_log.txt", "a") as file:
        file.write(f"{datetime.now()} | {message}\n")

    print(
        f"LIVE STATS | Total: {packet_count} | "
        f"TCP: {tcp_count} | UDP: {udp_count} | "
        f"ICMP: {icmp_count} | Other: {other_count}",
        flush=True
    )


def show_stats():
    print("\n--- FINAL TRAFFIC STATISTICS ---")
    print(f"Total IP packets: {packet_count}")
    print(f"TCP packets: {tcp_count}")
    print(f"UDP packets: {udp_count}")
    print(f"ICMP packets: {icmp_count}")
    print(f"Other packets: {other_count}")
    print("Monitoring stopped.")


print("NETWORK TRAFFIC MONITOR")
print("Live statistics enabled.")
print("Press Ctrl+C to stop monitoring.")

try:
    sniff(prn=show_packet, store=False)
except KeyboardInterrupt:
    show_stats()
finally:
    print("Program ended.")
