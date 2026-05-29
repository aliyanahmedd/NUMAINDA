"""CVE Lookup Agent — queries NIST NVD API for known vulnerabilities in detected tech."""
import time
import requests
from utils.helpers import log_info, log_success, log_warn
from config.settings import REQUEST_TIMEOUT

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}


class CVEAgent:
    def run(self, tech_data: dict) -> list[dict]:
        technologies = tech_data.get("technologies", [])
        versioned = tech_data.get("versioned", {})

        targets = []
        for tech in technologies[:5]:
            version = versioned.get(tech)
            targets.append((tech, version))

        if not targets:
            log_warn("[CVEAgent] No technologies to look up")
            return []

        log_info(f"[CVEAgent] Looking up CVEs for: {[t[0] for t in targets]}")
        all_cves = []

        for tech, version in targets:
            query = f"{tech} {version}" if version else tech
            cves = self._lookup(query, tech)
            if cves:
                all_cves.append({"tech": tech, "version": version or "unknown", "cves": cves})
            time.sleep(0.7)

        total = sum(len(e["cves"]) for e in all_cves)
        critical = sum(
            1 for e in all_cves for c in e["cves"]
            if c.get("severity") in ("CRITICAL", "HIGH")
        )
        log_success(f"[CVEAgent] {total} CVE(s) found | {critical} critical/high")
        return all_cves

    @staticmethod
    def _lookup(keyword: str, tech: str) -> list[dict]:
        try:
            r = requests.get(
                _NVD_URL,
                params={"keywordSearch": keyword, "resultsPerPage": 5},
                headers={"User-Agent": "OSINT-Agent/1.0"},
                timeout=REQUEST_TIMEOUT,
            )
            if r.status_code != 200:
                return []

            cves = []
            for item in r.json().get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                desc = next(
                    (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
                    "No description available",
                )
                metrics = cve.get("metrics", {})
                score = None
                severity = "UNKNOWN"
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if key in metrics and metrics[key]:
                        m = metrics[key][0].get("cvssData", {})
                        score = m.get("baseScore")
                        severity = m.get("baseSeverity", "UNKNOWN")
                        break

                cves.append({
                    "id": cve_id,
                    "score": score,
                    "severity": severity,
                    "description": desc[:200] + ("…" if len(desc) > 200 else ""),
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                })

            cves.sort(key=lambda c: _SEVERITY_ORDER.get(c["severity"], 99))
            return cves

        except Exception as e:
            log_warn(f"[CVEAgent] NVD lookup failed for '{keyword}': {e}")
            return []
