"""Threat Intelligence Agent — VirusTotal + URLhaus + ThreatFox + AbuseIPDB."""
import requests
from utils.api_client import virustotal_check_domain, virustotal_check_ip
from utils.helpers import log_info, log_success, log_warn
from database.db import insert_threat_intel
from config.settings import ABUSEIPDB_API_KEY, REQUEST_TIMEOUT


class ThreatAgent:
    def run(self, target_id: int, domain: str, subdomains: list[dict]) -> list[dict]:
        log_info("[ThreatAgent] Running multi-source threat checks")
        findings = []

        # ── VirusTotal — domain ───────────────────────────────────────────────
        vt = self._vt_domain(domain)
        if vt: findings.append(vt)

        # ── URLhaus — domain (free, no key) ───────────────────────────────────
        uh = self._urlhaus(domain)
        if uh: findings.append(uh)

        # ── ThreatFox — domain (free, no key) ─────────────────────────────────
        tf = self._threatfox(domain)
        if tf: findings.append(tf)

        # ── Per-IP checks ─────────────────────────────────────────────────────
        seen_ips: set = set()
        for sub in subdomains:
            ip = sub.get("ip")
            if not ip or ip in seen_ips:
                continue
            seen_ips.add(ip)

            vt_ip = self._vt_ip(ip)
            if vt_ip: findings.append(vt_ip)

            ab = self._abuseipdb(ip)
            if ab: findings.append(ab)

            uh_ip = self._urlhaus(ip)
            if uh_ip: findings.append(uh_ip)

        if findings:
            insert_threat_intel(target_id, findings)
            malicious = [f for f in findings if f["malicious"]]
            log_success(
                f"[ThreatAgent] {len(findings)} indicators | {len(malicious)} malicious"
            )

        return findings

    # ── VirusTotal ─────────────────────────────────────────────────────────────

    def _vt_domain(self, domain: str) -> dict | None:
        data = virustotal_check_domain(domain)
        return self._parse_vt(domain, "domain", data) if data else None

    def _vt_ip(self, ip: str) -> dict | None:
        data = virustotal_check_ip(ip)
        return self._parse_vt(ip, "ip", data) if data else None

    @staticmethod
    def _parse_vt(indicator: str, itype: str, data: dict) -> dict:
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        hits = stats.get("malicious", 0)
        return {
            "indicator": indicator, "indicator_type": itype,
            "malicious": int(hits > 0), "engine_hits": hits,
            "source": "virustotal",
            "vt_link": f"https://www.virustotal.com/gui/{itype}/{indicator}",
        }

    # ── URLhaus (abuse.ch) ────────────────────────────────────────────────────

    @staticmethod
    def _urlhaus(indicator: str) -> dict | None:
        try:
            r = requests.post(
                "https://urlhaus-api.abuse.ch/v1/host/",
                data={"host": indicator},
                timeout=REQUEST_TIMEOUT,
            )
            data = r.json()
            status = data.get("query_status", "")
            urls_count = len(data.get("urls", []))
            is_malicious = status == "is_host" and urls_count > 0
            if status in ("is_host", "no_results"):
                return {
                    "indicator": indicator, "indicator_type": "domain",
                    "malicious": int(is_malicious),
                    "engine_hits": urls_count,
                    "source": "urlhaus",
                    "vt_link": f"https://urlhaus.abuse.ch/browse.php?search={indicator}",
                }
        except Exception as e:
            log_warn(f"[ThreatAgent] URLhaus failed for {indicator}: {e}")
        return None

    # ── ThreatFox (abuse.ch) ──────────────────────────────────────────────────

    @staticmethod
    def _threatfox(indicator: str) -> dict | None:
        try:
            r = requests.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "search_ioc", "search_term": indicator},
                timeout=REQUEST_TIMEOUT,
            )
            data = r.json()
            iocs = data.get("data") or []
            is_malicious = data.get("query_status") == "ok" and len(iocs) > 0
            if data.get("query_status") in ("ok", "no_result"):
                return {
                    "indicator": indicator, "indicator_type": "domain",
                    "malicious": int(is_malicious),
                    "engine_hits": len(iocs),
                    "source": "threatfox",
                    "vt_link": f"https://threatfox.abuse.ch/browse.php?search={indicator}",
                }
        except Exception as e:
            log_warn(f"[ThreatAgent] ThreatFox failed for {indicator}: {e}")
        return None

    # ── AbuseIPDB ─────────────────────────────────────────────────────────────

    @staticmethod
    def _abuseipdb(ip: str) -> dict | None:
        if not ABUSEIPDB_API_KEY:
            return None
        try:
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                timeout=REQUEST_TIMEOUT,
            )
            data = r.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            return {
                "indicator": ip, "indicator_type": "ip",
                "malicious": int(score > 25),
                "engine_hits": score,
                "source": "abuseipdb",
                "vt_link": f"https://www.abuseipdb.com/check/{ip}",
            }
        except Exception as e:
            log_warn(f"[ThreatAgent] AbuseIPDB failed for {ip}: {e}")
        return None
