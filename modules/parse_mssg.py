import dpkt
from modules.addres_conv import mac_addr, ip_addr, ip6_addr


def parse_ethernet(packet):
    """Parse Ethernet header"""
    eth = dpkt.ethernet.Ethernet(packet)
    print(f"- Ethernet Frame (Packet Size): {len(packet)} bytes")
    print(f" Destination: {mac_addr(eth.dst)}, Source: {mac_addr(eth.src)}")
    print(f" Type: {eth.type}")
    return eth


def parse_ip(ip):
    """Parse IP header
    
    :param name: ip
    :returns: ip
    :rtype: ip packet
    """
    print("- IP Header: ")
    print(f" Version {ip.v}, Header Length {ip.hl * 4} bytes, Type of Service {ip.tos}")
    print(f" Total Length: {ip.len}, Identification: {ip.id}")
    print(f" Flags: {ip.off >> 13}, Fragment Offset: {ip.off & 0x1FFF}")
    print(f" Time to Live: {ip.ttl}, Protocol: {ip.p}, Checksum: {ip.sum}")
    print(f" Source: {ip_addr(ip.src)}, Destination: {ip_addr(ip.dst)}")
    return ip


def parse_ip6(ip6):
    """Parse IPv6 header
    
    :param name: ip6
    :returns: ip6
    :rtype: ip6 packet"""
    print("- IPv6 Header: ")
    print(f" Version: {ip6.v}, Traffic Class: {ip6.fc >> 4}, Flow Label: {ip6.flow}")
    print(f" Payload Length: {ip6.plen}, Next Header: {ip6.nxt}, Hop Limit: {ip6.hlim}")
    print(f" Source: {ip6_addr(ip6.src)}, Destination: {ip6_addr(ip6.dst)}")
    return ip6


def parse_tcp(tcp):
    """Parse TCP header
    
    :param name: tcp
    :returns: N/A
    :rtype: N/A
    """
    print("- TCP Header:")
    print(f" Source Port {tcp.sport}, Destination Port {tcp.dport}")
    print(f" Header Length: {(tcp.off * 4)} bytes, Flags: {tcp.flags}")


def parse_udp(udp):
    """Parse UDP header
    
    :param name: udp
    :returns: N/A
    :rtype: N/A
    """
    print("- UDP Header:")
    print(f" Source Port {udp.sport}, Destination Port {udp.dport}")
    print(f" Length: {udp.ulen}, Checksum: {udp.sum}")


def parse_icmp(icmp):
    """Parse ICMP header
    
    :param name: icmp
    :returns: N/A
    :rtype: N/A
    """
    print("- ICMP Header:")
    print(f" Type {icmp.type}, Code {icmp.code}, Checksum {icmp.sum}")
