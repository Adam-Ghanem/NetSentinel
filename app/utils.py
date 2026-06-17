import datetime
import ipaddress
import logging
import sys
from app.config import Config

# Configure logging
logging.basicConfig(
    level=Config.LOG_LEVEL,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("netsentinel.log")
    ]
)

def get_logger(name):
    return logging.getLogger(name)

def get_timestamp():
    """ Returns the current UTC timestamp in ISO format """
    return datetime.datetime.utcnow().isoformat()

def is_private_ip(ip_address):
    """ Checks if an IP address is private """
    try:
        return ipaddress.ip_address(ip_address).is_private
    except ValueError:
        return False

def is_public_ip(ip_address):
    """ Checks if an IP address is public """
    try:
        ip = ipaddress.ip_address(ip_address)
        return not (ip.is_private or ip.is_loopback or ip.is_unspecified)
    except ValueError:
        return False
