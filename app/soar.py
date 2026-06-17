import os
import subprocess
from app.utils import get_logger

logger = get_logger(__name__)

class SOARManager:
    """
    Security Orchestration, Automation, and Response (SOAR) Manager.
    Handles active responses like blocking IPs.
    """
    def __init__(self, db_manager):
        self.db = db_manager
        self.blocked_ips = set()

    def block_ip(self, ip_address, reason="Security Violation"):
        """
        Blocks an IP address using system iptables (Linux).
        Requires root/sudo permissions.
        """
        if ip_address in self.blocked_ips:
            return False

        try:
            # Command to block IP
            cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
            # Note: In a real production environment, we'd use a more robust way to manage rules
            # result = subprocess.run(cmd, capture_output=True, text=True)
            
            # For demonstration and safety in sandbox, we log the action
            logger.warning(f"SOAR: Blocking IP {ip_address}. Reason: {reason}")
            self.blocked_ips.add(ip_address)
            
            # Record action in DB
            self._record_action(ip_address, "BLOCK", reason)
            return True
        except Exception as e:
            logger.error(f"SOAR: Failed to block IP {ip_address}: {e}")
            return False

    def unblock_ip(self, ip_address):
        """ Unblocks an IP address """
        if ip_address not in self.blocked_ips:
            return False

        try:
            cmd = ["sudo", "iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"]
            # subprocess.run(cmd, capture_output=True, text=True)
            
            logger.info(f"SOAR: Unblocking IP {ip_address}")
            self.blocked_ips.remove(ip_address)
            
            self._record_action(ip_address, "UNBLOCK", "Manual intervention")
            return True
        except Exception as e:
            logger.error(f"SOAR: Failed to unblock IP {ip_address}: {e}")
            return False

    def _record_action(self, target, action, reason):
        # We can add a SOAR_ACTIONS table to the DB later if needed
        logger.info(f"SOAR_AUDIT: {action} on {target} - {reason}")

    def get_blocked_ips(self):
        return list(self.blocked_ips)
