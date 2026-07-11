import datetime
import ipaddress
import logging
import sys

from app.config import Config

handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
if Config.LOG_FILE:
    handlers.append(logging.FileHandler(Config.LOG_FILE))

logging.basicConfig(
    level=Config.LOG_LEVEL,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=handlers,
)


def get_logger(name):
    return logging.getLogger(name)


def get_timestamp():
    """Return the current UTC timestamp in ISO format."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def is_private_ip(ip_address):
    """Return whether a value is a private IP address."""
    try:
        return ipaddress.ip_address(ip_address).is_private
    except (TypeError, ValueError):
        return False


def is_public_ip(ip_address):
    """Return whether a value is a globally routable IP address."""
    try:
        return ipaddress.ip_address(ip_address).is_global
    except (TypeError, ValueError):
        return False
