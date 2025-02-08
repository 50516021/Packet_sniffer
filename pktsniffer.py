import argparse
import dpkt
import os
import warnings
from modules.filter_packet import filter_packet
from modules.parse_mssg import (
    parse_ethernet,
    parse_ip,
    parse_ip6,
    parse_tcp,
    parse_udp,
    parse_icmp
)

# Suppress warnings from dpkt
warnings.filterwarnings("ignore", category=UserWarning, module="dpkt")


def process_pcap(file_path, filter_opts, count):
    """Process the pcap file and print packet details
    
    :param name: input file, filter_opts, count
    :returns: N/A
    :rtype: N/A 
    """
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
