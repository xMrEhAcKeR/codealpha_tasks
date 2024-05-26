import socket
import struct

def main(packet_count):
    # Create a raw socket to capture packets
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    count = 0

    while count < packet_count:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print(f'Destination MAC: {dest_mac}, Source MAC: {src_mac}, Protocol: {eth_proto}')

        # Check if the packet is IPv4
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            print(f'\t- IPv4 Packet:')
            print(f'\t\t- Version: {version}, Header Length: {header_length}, TTL: {ttl}')
            print(f'\t\t- Protocol: {proto}, Source: {src}, Target: {target}')

            # Check for ICMP
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(f'\t\t- ICMP Packet:')
                print(f'\t\t\t- Type: {icmp_type}, Code: {code}, Checksum: {checksum}')

            # Check for TCP
            elif proto == 6:
                (src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)
                print(f'\t\t- TCP Segment:')
                print(f'\t\t\t- Source Port: {src_port}, Destination Port: {dest_port}')
                print(f'\t\t\t- Sequence: {sequence}, Acknowledgment: {acknowledgment}')
                print(f'\t\t\t- Flags:')
                print(f'\t\t\t\t- URG: {flag_urg}, ACK: {flag_ack}, PSH: {flag_psh}')
                print(f'\t\t\t\t- RST: {flag_rst}, SYN: {flag_syn}, FIN: {flag_fin}')
                
            # Check for UDP
            elif proto == 17:
                src_port, dest_port, size, data = udp_segment(data)
                print(f'\t\t- UDP Segment:')
                print(f'\t\t\t- Source Port: {src_port}, Destination Port: {dest_port}, Length: {size}')

        count += 1

# Unpack Ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Return properly formatted MAC address (i.e AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

# Unpack IPv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

# Returns properly formatted IPv4 address
def ipv4(addr):
    return '.'.join(map(str, addr))

# Unpack ICMP packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpack TCP segment
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

# Unpack UDP segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

# Set the number of packets to capture
PACKET_COUNT = 10
main(PACKET_COUNT)
