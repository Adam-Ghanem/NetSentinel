import datetime
import ipaddress

def get_timestamp():
    """ Returns the current UTC timestamp in ISO format. """
    return datetime.datetime.utcnow().isoformat()

def is_private_ip(ip_address):
    """ Checks if an IP address is private. """
    try:
        ip = ipaddress.ip_address(ip_address)
        return ip.is_private
    except ValueError:
        return False

def is_public_ip(ip_address):
    """ Checks if an IP address is public. """
    try:
        ip = ipaddress.ip_address(ip_address)
        return not ip.is_private and not ip.is_loopback and not ip.is_unspecified
    except ValueError:
        return False
