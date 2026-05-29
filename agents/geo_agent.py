"""IP Geolocation Agent — enriches IPs using ip-api.com (free, no key required)."""
import requests
from utils.helpers import log_info, log_success, log_warn
from config.settings import REQUEST_TIMEOUT

_BATCH_URL = "http://ip-api.com/batch"
_FIELDS = "status,country,countryCode,city,org,isp,lat,lon,query"


class GeoAgent:
    def run(self, subdomains: list[dict], dns_data: dict) -> list[dict]:
        ips = self._collect_ips(subdomains, dns_data)
        if not ips:
            log_warn("[GeoAgent] No IPs to geolocate")
            return []

        log_info(f"[GeoAgent] Geolocating {len(ips)} unique IPs")
        results = []

        for batch_start in range(0, len(ips), 100):
            batch = list(ips)[batch_start:batch_start + 100]
            results += self._lookup_batch(batch)

        log_success(f"[GeoAgent] Geolocated {len(results)} IPs")
        return results

    @staticmethod
    def _collect_ips(subdomains: list[dict], dns_data: dict) -> set:
        ips = set()
        for s in subdomains:
            ip = s.get("ip", "")
            if ip and not ip.startswith("10.") and not ip.startswith("192.168."):
                ips.add(ip)
        for rec in dns_data.get("records", []):
            if rec.get("record_type") == "A":
                ips.add(rec["value"])
        return ips

    @staticmethod
    def _lookup_batch(ips: list) -> list[dict]:
        try:
            payload = [{"query": ip, "fields": _FIELDS} for ip in ips]
            r = requests.post(_BATCH_URL, json=payload, timeout=REQUEST_TIMEOUT)
            if r.status_code != 200:
                return []
            results = []
            for entry in r.json():
                if entry.get("status") == "success":
                    results.append({
                        "ip": entry.get("query", ""),
                        "country": entry.get("country", ""),
                        "country_code": entry.get("countryCode", ""),
                        "city": entry.get("city", ""),
                        "org": entry.get("org", ""),
                        "isp": entry.get("isp", ""),
                        "lat": entry.get("lat"),
                        "lon": entry.get("lon"),
                    })
            return results
        except Exception as e:
            log_warn(f"[GeoAgent] Batch lookup failed: {e}")
            return []
