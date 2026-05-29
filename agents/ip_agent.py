"""IP Intelligence Agent - reverse DNS and WHOIS enrichment for bare IP addresses."""
import socket
import whois
from utils.helpers import log_info, log_success, log_warn


class IPAgent:
    def run(self, ip: str) -> dict:
        log_info(f"[IPAgent] Gathering intelligence for {ip}")
        result = {"ip": ip, "hostname": None, "whois": {}}

        # Reverse DNS
        try:
            hostname = socket.getfqdn(ip)
            result["hostname"] = hostname if hostname != ip else None
            if result["hostname"]:
                log_success(f"[IPAgent] Reverse DNS: {hostname}")
        except Exception as e:
            log_warn(f"[IPAgent] Reverse DNS failed: {e}")

        # WHOIS
        try:
            w = whois.whois(ip)
            result["whois"] = {
                "org":        getattr(w, "org",        None) or "",
                "country":    getattr(w, "country",    None) or "",
                "registrar":  getattr(w, "registrar",  None) or "",
                "nets":       getattr(w, "nets",        []) or [],
            }
            log_success(f"[IPAgent] WHOIS: {result['whois'].get('org','unknown')}")
        except Exception as e:
            log_warn(f"[IPAgent] WHOIS failed: {e}")

        return result
