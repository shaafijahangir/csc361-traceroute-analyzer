import sys
import struct

# GlobalHeader class to parse pcap global header
class GlobalHeader:
    def __init__(self, buffer):
        self.magic_number, self.version_minor, self.version_major, self.thiszone, self.sigfigs, self.snaplen, self.network = struct.unpack('IHHiIII', buffer)

# PacketHeader class to parse packet headers
class PacketHeader:
    def __init__(self):
        self.ts_sec, self.ts_usec, self.incl_len, self.orig_len = 0, 0, 0, 0

    def set_header(self, buffer):
        self.ts_sec, self.ts_usec, self.incl_len, self.orig_len = struct.unpack('IIII', buffer)

# IPV4Header class to parse IPv4 headers
class IPV4Header:
    def __init__(self):
        self.ihl, self.total_length, self.identification, self.flags, self.fragment_offset, self.ttl, self.protocol = 0, 0, 0, 0, 0, 0, 0
        self.src_ip, self.dst_ip = '', ''

    def set_ihl(self, value):
        self.ihl = (struct.unpack('B', value)[0] & 15) * 4

    def set_total_len(self, buffer):
        num1, num2 = struct.unpack('BB', buffer)
        self.total_length = ((num1 >> 4) * 16 * 16 * 16) + ((num1 & 15) * 16 * 16) + ((num2 >> 4) * 16) + (num2 & 15)

    def set_ip(self, buffer1, buffer2):
        src_addr = struct.unpack('BBBB', buffer1)
        dst_addr = struct.unpack('BBBB', buffer2)
        self.src_ip = '.'.join(map(str, src_addr))
        self.dst_ip = '.'.join(map(str, dst_addr))

    def set_identification(self, buffer):
        result = struct.unpack('BB', buffer)
        self.identification = (result[0] << 8) + result[1]

    def set_fragment_offset(self, buffer):
        if len(buffer) >= 4:
            num0, num1, num2, num3 = struct.unpack('BBBB', buffer)
            self.flags = (num0 >> 5)
            self.fragment_offset = ((num0 & 31) << 8) + num1 + (num2 << 4) + num3
        else:
            self.flags = 0
            self.fragment_offset = 0

    def set_ttl(self, buffer):
        self.ttl = struct.unpack('B', buffer)[0]

    def set_protocol(self, buffer):
        self.protocol = struct.unpack('B', buffer)[0]

# UDPHeader class to parse UDP headers
class UDPHeader:
    def __init__(self):
        self.src_port, self.dst_port, self.udp_length, self.checksum = 0, 0, 0, ''

    def set_src_port(self, buffer):
        result = struct.unpack('BB', buffer)
        self.src_port = (result[0] << 8) + result[1]

    def set_dst_port(self, buffer):
        result = struct.unpack('BB', buffer)
        self.dst_port = (result[0] << 8) + result[1]

    def set_udp_len(self, buffer):
        result = struct.unpack('BB', buffer)
        self.udp_length = (result[0] << 8) + result[1]

    def set_checksum(self, buffer):
        result = struct.unpack('BB', buffer)
        self.checksum = f'{result[0]:02x}{result[1]:02x}'

# ICMPHeader class to parse ICMP headers
class ICMPHeader:
    def __init__(self):
        self.type_num, self.code, self.src_port, self.dst_port, self.sequence = 0, 0, 0, 0, 0

    def set_type(self, buffer):
        self.type_num = struct.unpack('B', buffer)[0]

    def set_code(self, buffer):
        self.code = struct.unpack('B', buffer)[0]

    def set_src_port(self, buffer):
        result = struct.unpack('BB', buffer)
        self.src_port = (result[0] << 8) + result[1]

    def set_dst_port(self, buffer):
        result = struct.unpack('BB', buffer)
        self.dst_port = (result[0] << 8) + result[1]

    def set_sequence(self, buffer):
        result = struct.unpack('BB', buffer)
        self.sequence = (result[0] << 8) + result[1]

# Packet class to represent packets and parse packet data
class Packet:
    def __init__(self):
        self.header = PacketHeader()
        self.ipv4 = IPV4Header()
        self.icmp = ICMPHeader()
        self.udp = UDPHeader()
        self.data = b''
        self.timestamp = 0

    def set_header(self, buffer):
        self.header.set_header(buffer)

    def set_data(self, buffer):
        self.data = buffer

    def set_number(self, value):
        self.number = value

    def set_rtt(self, p):
        rtt = p.timestamp - self.timestamp
        self.RTT_value = round(rtt, 8)

    def set_timestamp(self, orig_time):
        seconds = self.header.ts_sec
        microseconds = self.header.ts_usec
        self.timestamp = 1000 * round(seconds + microseconds * 0.000000001 - orig_time, 6)

    def set_ipv4(self):
        offset = 14
        self.ipv4.set_ihl(self.data[offset: offset+1])
        self.ipv4.set_total_len(self.data[offset+2: offset+4])
        self.ipv4.set_identification(self.data[offset+4: offset+6])
        self.ipv4.set_fragment_offset(self.data[offset+6: offset+8])
        self.ipv4.set_ttl(self.data[offset+8: offset+9])
        self.ipv4.set_protocol(self.data[offset+9: offset+10])
        self.ipv4.set_ip(self.data[offset+12: offset+16], self.data[offset+16: offset+20])

    def set_icmp(self):
        offset = 14 + self.ipv4.ihl
        self.icmp.set_type(self.data[offset: offset+1])
        self.icmp.set_code(self.data[offset+1: offset+2])
        if self.icmp.type_num == 8 or self.icmp.type_num == 0:
            self.icmp.set_sequence(self.data[offset+6: offset+8])
        offset += 8 + self.ipv4.ihl
        if offset+4 <= self.header.incl_len:
            if self.icmp.type_num != 8 and self.icmp.type_num != 0:
                self.icmp.set_sequence(self.data[offset+6: offset+8])
            self.icmp.set_src_port(self.data[offset: offset+2])
            self.icmp.set_dst_port(self.data[offset+2: offset+4])
        else:
            self.icmp.src_port = 0
            self.icmp.dst_port = 0

    def set_udp(self):
        offset = 14 + self.ipv4.ihl
        self.udp.set_src_port(self.data[offset: offset+2])
        self.udp.set_dst_port(self.data[offset+2: offset+4])
        self.udp.set_udp_len(self.data[offset+4: offset+6])
        self.udp.set_checksum(self.data[offset+6: offset+8])

def parse_pcap(input_file):
    # Open the input file in binary read mode
    f = open(input_file, 'rb')
    
    # Read and ignore the global header of the PCAP file (first 24 bytes)
    global_header = GlobalHeader(f.read(24))
    
    # Define a mapping of IP protocol numbers to protocol names
    protocol_map = {1: 'ICMP', 17: 'UDP'}
    
    # Initialize dictionaries and lists to store parsed data
    protocol_used = {} 
    src, dst = [], []  
    pcap_start_time = None 
    packet_counter = 0  
    
    while True:
        packet_counter += 1 
        
        # Read the next 16 bytes of the packet (packet header)
        stream = f.read(16)
        
        # If the stream is empty, break the loop (end of file)
        if stream == b'':
            break
        
        # Create a Packet object and set its header and packet number
        packet = Packet()
        packet.set_header(stream)
        packet.set_number(packet_counter)
        incl_len = packet.header.incl_len
        
        # If the start time is not set, calculate it from the packet's timestamp
        if pcap_start_time is None:
            seconds = packet.header.ts_sec
            microseconds = packet.header.ts_usec
            pcap_start_time = round(seconds + microseconds * 0.000001, 6)
        
        # Read the packet data and set IPv4 information
        packet.set_data(f.read(incl_len))
        packet.set_ipv4()
        
        # Determine the protocol and process the packet accordingly
        if packet.ipv4.protocol == 1:  # ICMP protocol
            packet.set_icmp()
            dst.append(packet)
            protocol_used[1] = 'ICMP'
        elif packet.ipv4.protocol == 17:  # UDP protocol
            packet.set_udp()
            src.append(packet)
            if 33434 <= packet.udp.dst_port <= 33529:
                protocol_used[17] = 'UDP'
        elif packet.ipv4.protocol not in protocol_map:
            continue  # Skip packets with unrecognized protocols
    
    # Process ICMP packets if any ICMP type 8 (echo request) packets are found
    if any(p.icmp.type_num == 8 for p in dst):
        icmp_all = dst
        src, dst = [], []  # Reset src and dst lists
        
        # Separate ICMP type 8 (echo request) and type 11 or 0 (time exceeded or echo reply) packets
        for p in icmp_all:
            if p.icmp.type_num == 8:
                src.append(p)
            if p.icmp.type_num == 11 or p.icmp.type_num == 0:
                dst.append(p)
        
        intermediate = []  
        intermediate_packets = []  
        rtt_dict = {}  
        
        # Calculate round-trip times for ICMP packets
        for p1 in src:
            for p2 in dst:
                if p1.icmp.sequence == p2.icmp.sequence:
                    if p2.ipv4.src_ip not in intermediate:
                        intermediate.append(p2.ipv4.src_ip)
                        intermediate_packets.append(p2)
                        rtt_dict[p2.ipv4.src_ip] = []  # Initialize RTT list for the IP address
                    
                    p1.set_timestamp(pcap_start_time)
                    p2.set_timestamp(pcap_start_time)
                    rtt_dict[p2.ipv4.src_ip].append(p2.timestamp - p1.timestamp)
    else:  # Process UDP packets
        intermediate = []  # Reset intermediate list
        intermediate_packets = []  # Reset intermediate packets list
        rtt_dict = {}  # Reset RTT dictionary
        
        # Calculate round-trip times for UDP packets
        for p1 in src:
            for p2 in dst:
                if p1.udp.src_port == p2.icmp.src_port:
                    if p2.ipv4.src_ip not in intermediate:
                        intermediate.append(p2.ipv4.src_ip)
                        intermediate_packets.append(p2)
                        rtt_dict[p2.ipv4.src_ip] = []  # Initialize RTT list for the IP address
                    
                    p1.set_timestamp(pcap_start_time)
                    p2.set_timestamp(pcap_start_time)
                    rtt_dict[p2.ipv4.src_ip].append(p2.timestamp - p1.timestamp)
    
    identity_dict = {}  # Dictionary to store packets with the same IP identification
    
    # Group packets by IP identification
    for packet in src:
        if packet.ipv4.identification not in identity_dict:
            identity_dict[packet.ipv4.identification] = []
        
        identity_dict[packet.ipv4.identification].append(packet)
    
    frag_count = 0  # Initialize the fragment count
    
    # Count the number of fragmented packets
    for identity in identity_dict:
        if len(identity_dict[identity]) > 1:
            frag_count += 1
    
    # Return parsed data
    return src, intermediate, protocol_used, frag_count, identity_dict, rtt_dict

def generate_output(src, intermediate, protocol_used, frag_count, identity_dict, rtt_dict):
    # Print the IP address of the source node
    print('The IP address of the source node:', src[0].ipv4.src_ip)
    
    # Print the IP address of the ultimate destination node
    print('The IP address of the ultimate destination node:', src[0].ipv4.dst_ip)
    
    # Print the IP addresses of the intermediate destination nodes
    print('The IP addresses of the intermediate destination nodes:')
    for i in range(len(intermediate) - 1):
        print(f'\trouter {i + 1}: {intermediate[i]}')
    
    print()  # Add a blank line for better readability
    
    # Print the values in the protocol field of IP headers
    print('The values in the protocol field of IP headers:')
    for protocol, protocol_name in sorted(protocol_used.items()):
        print(f'\t{protocol}: {protocol_name}')
    
    print()  # Add a blank line for better readability
    
    if frag_count == 0:
        # If there are no fragments, print this information
        print('The number of fragments created from the original datagram is:', frag_count)
        print('The offset of the last fragment is:', frag_count, '\n')
    else:
        # If there are fragments, iterate through the identity_dict and print information for each identity
        for identity, packets in identity_dict.items():
            if len(packets) > 1:
                print(f'The number of fragments created from the original datagram {identity} is:', len(packets))
                # Find the maximum fragment offset among packets with the same identity
                offset = max(packet.ipv4.fragment_offset for packet in packets)
                print('The offset of the last fragment is:', offset, '\n')
    
    # Print RTT information for intermediate nodes
    for i in range(len(intermediate)):
        avg = round(sum(rtt_dict[intermediate[i]]) / len(rtt_dict[intermediate[i]]), 6)
        std = round((sum(pow(x - avg, 2) for x in rtt_dict[intermediate[i]]) / len(rtt_dict[intermediate[i]])) ** (1 / 2), 6)
        print(f'The avg RTT between {src[0].ipv4.src_ip} and {intermediate[i]} is:', avg, 'ms, the s.d. is:', std, 'ms')

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print('Unexpected input. Usage: python3 TraceRouteAnalyzer.py <sample_trace_file.cap>')
        exit()

    input_file = sys.argv[1]
    src, intermediate, protocol_used, frag_count, identity_dict, rtt_dict = parse_pcap(input_file)
    generate_output(src, intermediate, protocol_used, frag_count, identity_dict, rtt_dict)
