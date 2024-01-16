import ctypes
import struct
import argparse
import ipaddress

'''
'''
class Header(ctypes.BigEndianStructure):
    _fields_ = [
        ('version', ctypes.c_uint, 4),
        ('trafficClass', ctypes.c_uint, 8),
        ('flowLabel', ctypes.c_uint, 20),
        ('payloadLength', ctypes.c_uint, 16),
        ('nextHeader', ctypes.c_uint, 8),
        ('hopLimit', ctypes.c_uint, 8),
        ('srcAddr', ctypes.c_ubyte * 16),
        ('destAddr', ctypes.c_ubyte * 16)
    ]
 
def init_argparse():
    parser = argparse.ArgumentParser(
        usage="%(prog)s [OPTION] [FILE]...",
        description="Tool to view ipv6 packet headers."
    )
    
    parser.add_argument(
        "-p", 
        "--packet",
        required=True
    )

    return parser   

def format_input(packet):
    if packet[:2] == '0x':
        packet = packet[2:]
    return bytes.fromhex(packet)

def capture_header(packet):
    f_packet = format_input(packet)
    ipv6_header = Header()
    struct.pack_into('!40s', ipv6_header, 0, f_packet)
    return ipv6_header

def format_ipv6(addr):
    int_ipv6 = int(''.join([format(i, '02x') for i in list(addr)]), 16)
    return ipaddress.ip_address(int_ipv6)


def print_table(header):
    print(f'''
    Version: {header.version},
    Traffic Class: {header.trafficClass},
    Flow Label: {header.flowLabel},
    Payload Length: {header.payloadLength},
    Next Header: {header.nextHeader},
    Hop Limit: {header.hopLimit},
    Source Address: {format_ipv6(header.srcAddr)},
    Destination Address: {format_ipv6(header.destAddr)}
    ''')

if __name__ == '__main__':
    parser = init_argparse()
    args = parser.parse_args()
    packet = args.packet
    ipv6_header = capture_header(packet) 
    print_table(ipv6_header)
