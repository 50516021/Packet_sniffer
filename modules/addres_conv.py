import socket


def mac_addr(address):
    """Convert MAC address to human-readable format
    
    :param name: address
    :returns: mac address
    :rtype: str 
    """
    return ':'.join('%02x' % b for b in address)


def ip_addr(address):
    """Convert IP address to human-readable format
    
    :param name: address
    :returns: ip address
    :rtype: str 
    """
    return socket.inet_ntoa(address)


def ip6_addr(address):
    """Convert IPv6 address to human-readable format
    
    :param name: address
    :returns: ip6 address
    :rtype: str 
    """
    return socket.inet_ntop(socket.AF_INET6, address)
