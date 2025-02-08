import argparse
import dpkt
import socket
import os
import ipaddress
import warnings

# Suppress warnings from dpkt
warnings.filterwarnings("ignore", category=UserWarning, module="dpkt")


def mac_addr(address):
    """Convert MAC address to human-readable format"""
    return ':'.join('%02x' % b for b in address)


def ip_addr(address):
    """Convert IP address to human-readable format"""
    return socket.inet_ntoa(address)


def ip6_addr(address):
    """Convert IPv6 address to human-readable format"""
    return socket.inet_ntop(socket.AF_INET6, address)


def parse_ethernet(packet):
    """Parse Ethernet header"""
    eth = dpkt.ethernet.Ethernet(packet)
    print(f"- Ethernet Frame (Packet Size): {len(packet)} bytes")
    print(f" Destination: {mac_addr(eth.dst)}, Source: {mac_addr(eth.src)}")
    print(f" Type: {eth.type}")
    return eth


def parse_ip(ip):
    """Parse IP header"""
    print("- IP Header: ")
    print(f" Version {ip.v}, Header Length {ip.hl * 4} bytes, Type of Service {ip.tos}")
    print(f" Total Length: {ip.len}, Identification: {ip.id}")
    print(f" Flags: {ip.off >> 13}, Fragment Offset: {ip.off & 0x1FFF}")
    print(f" Time to Live: {ip.ttl}, Protocol: {ip.p}, Checksum: {ip.sum}")
    print(f" Source: {ip_addr(ip.src)}, Destination: {ip_addr(ip.dst)}")
    return ip


def parse_ip6(ip6):
    """Parse IPv6 header"""
    print("- IPv6 Header: ")
    print(f" Version: {ip6.v}, Traffic Class: {ip6.fc >> 4}, Flow Label: {ip6.flow}")
    print(f" Payload Length: {ip6.plen}, Next Header: {ip6.nxt}, Hop Limit: {ip6.hlim}")
    print(f" Source: {ip6_addr(ip6.src)}, Destination: {ip6_addr(ip6.dst)}")
    return ip6


def parse_tcp(tcp):
    """Parse TCP header"""
    print("- TCP Header:")
    print(f" Source Port {tcp.sport}, Destination Port {tcp.dport}")
    print(f" Header Length: {(tcp.off * 4)} bytes, Flags: {tcp.flags}")


def parse_udp(udp):
    """Parse UDP header"""
    print("- UDP Header:")
    print(f" Source Port {udp.sport}, Destination Port {udp.dport}")
    print(f" Length: {udp.ulen}, Checksum: {udp.sum}")


def parse_icmp(icmp):
    """Parse ICMP header"""
    print("- ICMP Header:")
    print(f" Type {icmp.type}, Code {icmp.code}, Checksum {icmp.sum}")


def filter_packet(ip, filter_opts):
    """Filter packets based on the provided options"""
    """filtering by IP protocol"""
    if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
        return False
    if filter_opts.ip:
        try:
            protocol_num = int(filter_opts.ip)
        except ValueError:
            protocol_num = socket.getprotobyname(filter_opts.ip)
        if ip.p != protocol_num:
            return False
    """filtering by host address"""
    if filter_opts.host:
        if isinstance(ip, dpkt.ip.IP):
            src_ip = ip_addr(ip.src)
            dst_ip = ip_addr(ip.dst)
        elif isinstance(ip, dpkt.ip6.IP6):
            src_ip = ip6_addr(ip.src)
            dst_ip = ip6_addr(ip.dst)
        if src_ip != filter_opts.host and dst_ip != filter_opts.host:
            return False
    """filtering by network address"""
    if filter_opts.net:
        net_parts = filter_opts.net.split('.')
        if net_parts[-1] == '0':
            net_parts[-1] = '0/24'
        network = ipaddress.ip_network('.'.join(net_parts), strict=False)
        if isinstance(ip, dpkt.ip.IP):
            src_ip = ipaddress.ip_address(ip.src)
            dst_ip = ipaddress.ip_address(ip.dst)
        elif isinstance(ip, dpkt.ip6.IP6):
            src_ip = ipaddress.ip_address(ip6_addr(ip.src))
            dst_ip = ipaddress.ip_address(ip6_addr(ip.dst))
        if not (src_ip in network or dst_ip in network):
            return False
    """filtering by port"""
    if filter_opts.port:
        if isinstance(ip.data, dpkt.tcp.TCP):
            if not hasattr(ip.data, 'sport') or not hasattr(ip.data, 'dport'):
                return False
            if ip.data.sport != filter_opts.port and ip.data.dport != filter_opts.port:
                return False
        elif isinstance(ip.data, dpkt.udp.UDP):
            if not hasattr(ip.data, 'sport') or not hasattr(ip.data, 'dport'):
                return False
            if ip.data.sport != filter_opts.port and ip.data.dport != filter_opts.port:
                return False
        else:
            return False
    return True


def process_pcap(file_path, filter_opts, count):
    packets = []
    packets_no = []
    with open(file_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for i, (ts, buf) in enumerate(pcap):
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            """filter packets based on the provided options"""
            if not filter_packet(ip, filter_opts):
                continue
            packets.append((ts, buf))
            packets_no.append(i + 1)
    """limit the number of packets to analyze"""
    if count and count < 0:
        packets = packets[count:]
        packets_no = packets_no[count:]

    co = 0  # limitation counter
    for i, (ts, buf) in enumerate(packets):
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        """counter for limiting the number of packets to analyze"""
        if count and co >= abs(count):
            print(f"--- limit reached ({abs(count)}) ---")
            break
        """print packet details"""
        print("-" * 50)
        print(f"Packet {packets_no[i]}:")
        parse_ethernet(buf)
        if isinstance(eth.data, dpkt.ip.IP):
            parse_ip(ip)
            if isinstance(ip.data, dpkt.tcp.TCP):
                parse_tcp(ip.data)
            elif isinstance(ip.data, dpkt.udp.UDP):
                parse_udp(ip.data)
            elif isinstance(ip.data, dpkt.icmp.ICMP):
                parse_icmp(ip.data)
        elif isinstance(eth.data, dpkt.ip6.IP6):
            parse_ip6(ip)
            if ip.nxt == dpkt.ip.IP_PROTO_TCP:
                parse_tcp(ip.data)
            elif ip.nxt == dpkt.ip.IP_PROTO_UDP:
                parse_udp(ip.data)
            elif ip.nxt == dpkt.ip.IP_PROTO_ICMP:
                parse_icmp(ip.data)
        co += 1
    print("-" * 50)


def main():
    """Main function to parse command line arguments and process pcap file"""

    parser = argparse.ArgumentParser(description="Packet Sniffer")
    parser.add_argument(
        "-r", required=True, help="PCAP file to read")
    parser.add_argument(
        "-c", type=int, help="Limit the number of packets to analyze")
    parser.add_argument(
        "--host", nargs="?", help="Filter packets by host IP")
    parser.add_argument(
        "--port", type=int, help="Filter packets by port number")
    parser.add_argument(
        "--net", help="Filter packets by network")
    parser.add_argument(
        "--ip", help="Filter packets by IP protocol")
    args = parser.parse_args()

    if not os.path.exists(args.r):
        print(f"Error: The file {args.r} does not exist.")
        return

    process_pcap(args.r, args, args.c)


if __name__ == "__main__":
    main()
