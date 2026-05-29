"""SSL Certificate Agent - checks expiry, issuer, and SANs using Python stdlib."""
import ssl
import socket
from datetime import datetime
from utils.helpers import log_info, log_success, log_warn


class SSLAgent:
    def run(self, domain: str, subdomains: list[dict]) -> dict:
        log_info(f"[SSLAgent] Checking SSL certificates")
        results = {"main": self._check(domain), "subdomains": []}

        risky_subs = [s["subdomain"] for s in subdomains if s.get("risk_flag")]
        for sub in risky_subs[:5]:
            cert = self._check(sub)
            if cert:
                results["subdomains"].append(cert)

        if results["main"]:
            days = results["main"].get("days_left")
            if days is None:
                log_warn(f"[SSLAgent] {domain} certificate expiry unknown")
            elif days < 0:
                log_warn(f"[SSLAgent] {domain} certificate EXPIRED {abs(days)} days ago")
            elif days < 30:
                log_warn(f"[SSLAgent] {domain} certificate expires in {days} days")
            else:
                log_success(f"[SSLAgent] {domain} cert valid for {days} days")

        return results

    @staticmethod
    def _check(hostname: str) -> dict | None:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

            expiry_str = cert.get("notAfter", "")
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))
            sans = [v for (t, v) in cert.get("subjectAltName", []) if t == "DNS"]

            expiry_dt = None
            days_left = None
            if expiry_str:
                expiry_dt = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry_dt - datetime.utcnow()).days

            return {
                "hostname": hostname,
                "valid": True,
                "expires": expiry_dt.strftime("%Y-%m-%d") if expiry_dt else "",
                "days_left": days_left,
                "issuer": issuer.get("organizationName", issuer.get("commonName", "")),
                "subject": subject.get("commonName", hostname),
                "sans": sans[:10],
                "expired": days_left is not None and days_left < 0,
                "expiring_soon": days_left is not None and 0 <= days_left < 30,
            }
        except ssl.SSLCertVerificationError:
            return {
                "hostname": hostname,
                "valid": False,
                "expires": "",
                "days_left": None,
                "issuer": "",
                "subject": "",
                "sans": [],
                "expired": False,
                "expiring_soon": False,
                "error": "Certificate verification failed",
            }
        except Exception as e:
            log_warn(f"[SSLAgent] {hostname}: {e}")
            return None
