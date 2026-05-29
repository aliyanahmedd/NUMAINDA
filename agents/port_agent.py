"""Port Scanning Agent - Shodan host lookup with socket fallback."""
import socket
from utils.helpers import log_info, log_success, log_warn
from config.settings import SHODAN_API_KEY

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017: "MongoDB",
}

DANGEROUS_PORTS = {23, 21, 3389, 445, 6379, 27017, 9200}


class PortAgent:
    def run(self, subdomains: list[dict]) -> list[dict]:
        unique_ips = {}
        for s in subdomains:
            ip = s.get("ip", "")
            if ip and ip not in unique_ips:
                unique_ips[ip] = s["subdomain"]

        if not unique_ips:
            log_warn("[PortAgent] No IPs to scan")
            return []

        log_info(f"[PortAgent] Scanning {len(unique_ips)} IPs")
        results = []

        if SHODAN_API_KEY:
            results = self._shodan_scan(unique_ips)
        else:
            results = self._socket_scan(unique_ips)

        dangerous = sum(
            1 for r in results
            for p in r.get("ports", [])
            if p in DANGEROUS_PORTS
        )
        log_success(
            f"[PortAgent] Scan complete - {len(results)} hosts | {dangerous} dangerous port(s)"
        )
        return results

    @staticmethod
    def _shodan_scan(ip_map: dict) -> list[dict]:
        try:
            import shodan
            api = shodan.Shodan(SHODAN_API_KEY)
            results = []
            for ip, hostname in ip_map.items():
                try:
                    host = api.host(ip)
                    ports = [item["port"] for item in host.get("data", [])]
                    services = {
                        item["port"]: item.get("_shodan", {}).get("module", "")
                        for item in host.get("data", [])
                    }
                    results.append({
                        "ip": ip,
                        "hostname": hostname,
                        "ports": ports,
                        "services": services,
                        "dangerous": [p for p in ports if p in DANGEROUS_PORTS],
                        "source": "shodan",
                    })
                except Exception:
                    pass
            return results
        except Exception as e:
            log_warn(f"[PortAgent] Shodan failed: {e}, falling back to socket scan")
            return PortAgent._socket_scan(ip_map)

    @staticmethod
    def _socket_scan(ip_map: dict) -> list[dict]:
        results = []
        for ip, hostname in ip_map.items():
            open_ports = []
            for port in COMMON_PORTS:
                try:
                    with socket.create_connection((ip, port), timeout=0.5):
                        open_ports.append(port)
                except (socket.timeout, ConnectionRefusedError, OSError):
                    pass

            if open_ports:
                results.append({
                    "ip": ip,
                    "hostname": hostname,
                    "ports": open_ports,
                    "services": {p: COMMON_PORTS[p] for p in open_ports},
                    "dangerous": [p for p in open_ports if p in DANGEROUS_PORTS],
                    "source": "socket",
                })

        return results
