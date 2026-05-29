"""DNS & IP Intelligence Agent - WHOIS, A/MX/TXT/NS records."""
import whois
import dns.resolver
from utils.helpers import log_info, log_success, log_warn
from database.db import insert_dns_records

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


class DNSAgent:
    def run(self, target_id: int, domain: str) -> dict:
        log_info(f"[DNSAgent] Gathering DNS & WHOIS for {domain}")
        records = []

        for rtype in RECORD_TYPES:
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=5)
                for rdata in answers:
                    records.append({"record_type": rtype, "value": str(rdata)})
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                pass
            except Exception as e:
                log_warn(f"[DNSAgent] {rtype} lookup failed: {e}")

        whois_data = self._whois(domain)

        if records:
            insert_dns_records(target_id, records)
            log_success(f"[DNSAgent] {len(records)} DNS records saved")

        return {"records": records, "whois": whois_data}

    @staticmethod
    def _whois(domain: str) -> dict:
        try:
            w = whois.whois(domain)
            return {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers,
                "country": w.country,
                "org": w.org,
            }
        except Exception as e:
            log_warn(f"[DNSAgent] WHOIS failed: {e}")
            return {}
