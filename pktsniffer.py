import argparse
import dpkt
import socket
import struct


def mac_addr(address):
    """Convert MAC address to human-readable format"""
    return ':'.join('%02x' % b for b in address)


def ip_addr(address):
    """Convert IP address to human-readable format"""
    return socket.inet_ntoa(address)


def parse_ethernet(packet):
    """Parse Ethernet header"""
    eth = dpkt.ethernet.Ethernet(packet)
    print(f"Ethernet Frame: {len(packet)} bytes")
    print(f"Destination: {mac_addr(eth.dst)}, Source: {mac_addr(eth.src)}, Type: {eth.type}")
    return eth


def parse_ip(ip):
    """Parse IP header"""
    print(f"IP Packet: Version {ip.v}, Header Length {ip.hl * 4} bytes, Type of Service {ip.tos}")
    print(f"Total Length: {ip.len}, Identification: {ip.id}")
    print(f"Flags: {ip.off >> 13}, Fragment Offset: {ip.off & 0x1FFF}")
    print(f"Time to Live: {ip.ttl}, Protocol: {ip.p}, Checksum: {ip.sum}")
    print(f"Source: {ip_addr(ip.src)}, Destination: {ip_addr(ip.dst)}")
    return ip


def parse_tcp(tcp):
    """Parse TCP header"""
    print(f"TCP Segment: Source Port {tcp.sport}, Destination Port {tcp.dport}")
    print(f"Sequence Number: {tcp.seq}, Acknowledgment: {tcp.ack}")
    print(f"Header Length: {(tcp.off * 4)} bytes, Flags: {tcp.flags}")


def parse_udp(udp):
    """Parse UDP header"""
    print(f"UDP Datagram: Source Port {udp.sport}, Destination Port {udp.dport}")
    print(f"Length: {udp.ulen}, Checksum: {udp.sum}")


def parse_icmp(icmp):
    """Parse ICMP header"""
    print(f"ICMP Packet: Type {icmp.type}, Code {icmp.code}, Checksum {icmp.sum}")


def process_pcap(file_path, filter_opts, count):
    with open(file_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for i, (ts, buf) in enumerate(pcap):
            if count and i >= count:
                break
            eth = parse_ethernet(buf)
            if isinstance(eth.data, dpkt.ip.IP):
                ip = parse_ip(eth.data)
                if isinstance(ip.data, dpkt.tcp.TCP):
                    parse_tcp(ip.data)
                elif isinstance(ip.data, dpkt.udp.UDP):
                    parse_udp(ip.data)
                elif isinstance(ip.data, dpkt.icmp.ICMP):
                    parse_icmp(ip.data)
            print("-" * 50)


def main():
    parser = argparse.ArgumentParser(description="Packet Sniffer")
    parser.add_argument("-r", required=True, help="PCAP file to read")
    parser.add_argument("-c", type=int, help="Limit the number of packets to analyze")
    parser.add_argument("host", nargs="?", help="Filter packets by host IP")
    parser.add_argument("port", nargs="?", help="Filter packets by port number")
    parser.add_argument("net", nargs="?", help="Filter packets by network")
    args = parser.parse_args()
    
    process_pcap(args.r, args, args.c)


if __name__ == "__main__":
    main()
