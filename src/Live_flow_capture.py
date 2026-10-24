from scapy.all import sniff, IP, TCP
import socket
import time


# ==========================================
# 1. GET IP ADDRESS OF THE DOMAIN
# ==========================================

domain = input("Enter domain: ")

try:
    target_ip = socket.gethostbyname(domain)
    print("Target IP:", target_ip)

except socket.gaierror:
    print("Could not resolve domain")
    exit()


# ==========================================
# 2. START TIME
# ==========================================

start_time = time.time()

forward_packets = 0
backward_packets = 0

forward_bytes = 0
backward_bytes = 0

syn_count = 0
ack_count = 0
fin_count = 0


# ==========================================
# 3. PACKET PROCESSING FUNCTION
# ==========================================

def process_packet(packet):

    global forward_packets
    global backward_packets
    global forward_bytes
    global backward_bytes
    global syn_count
    global ack_count
    global fin_count

    if IP not in packet:
        return

    src = packet[IP].src
    dst = packet[IP].dst

    packet_size = len(packet)

    # --------------------------------------
    # Forward traffic
    # Our computer → target
    # --------------------------------------

    if dst == target_ip:

        forward_packets += 1
        forward_bytes += packet_size

    # --------------------------------------
    # Backward traffic
    # Target → our computer
    # --------------------------------------

    elif src == target_ip:

        backward_packets += 1
        backward_bytes += packet_size


    # ======================================
    # TCP FLAGS
    # ======================================

    if TCP in packet:

        flags = packet[TCP].flags

        if flags & 0x02:       # SYN
            syn_count += 1

        if flags & 0x10:       # ACK
            ack_count += 1

        if flags & 0x01:       # FIN
            fin_count += 1


# ==========================================
# 4. CAPTURE PACKETS
# ==========================================

print("\nCapturing traffic to/from", domain)
print("Press Ctrl+C to stop...\n")

try:

    sniff(
        filter=f"host {target_ip}",
        prn=process_packet,
        store=False,
        timeout=30
    )

except PermissionError:

    print("Packet capture requires administrator/root privileges.")
    exit()


# ==========================================
# 5. CALCULATE FLOW FEATURES
# ==========================================

end_time = time.time()

duration = end_time - start_time

total_packets = forward_packets + backward_packets
total_bytes = forward_bytes + backward_bytes

if duration > 0:

    bytes_per_second = total_bytes / duration
    packets_per_second = total_packets / duration

else:

    bytes_per_second = 0
    packets_per_second = 0


# ==========================================
# 6. DISPLAY FLOW
# ==========================================

print("\n========== FLOW INFORMATION ==========")

print("Destination:", domain)
print("IP:", target_ip)

print("Duration:", duration)

print("Forward packets:", forward_packets)
print("Backward packets:", backward_packets)

print("Forward bytes:", forward_bytes)
print("Backward bytes:", backward_bytes)

print("Total packets:", total_packets)
print("Total bytes:", total_bytes)

print("Bytes/sec:", bytes_per_second)
print("Packets/sec:", packets_per_second)

print("SYN count:", syn_count)
print("ACK count:", ack_count)
print("FIN count:", fin_count)