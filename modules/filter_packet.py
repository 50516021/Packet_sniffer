import dpkt
import socket
import ipaddress
from modules.addres_conv import ip_addr, ip6_addr


def filter_packet(ip, filter_opts):
    """Filter packets based on the provided options
    
    :param name: ip, filter_opts
    :returns: bool (if the packet passes filter or not)
    :rtype: bool 
    """
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