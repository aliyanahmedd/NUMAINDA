"""Risk Scoring Agent - aggregates all findings into a 0-10 attack surface score."""
from database.db import upsert_risk_score
from utils.helpers import log_info, log_success

DANGEROUS_PORTS = {23, 21, 3389, 445, 6379, 27017, 9200}


class ScoringAgent:
    def run(self, target_id: int, findings: dict) -> dict:
        log_info("[ScoringAgent] Computing risk scores")

        email_score     = self._email_score(findings.get("emails", []))
        subdomain_score = self._subdomain_score(findings.get("subdomains", []))
        breach_score    = self._breach_score(findings.get("breaches", []))
        threat_score    = self._threat_score(findings.get("threat_intel", []))
        ssl_score       = self._ssl_score(findings.get("ssl", {}))
        cve_score       = self._cve_score(findings.get("cves", []))
        port_score      = self._port_score(findings.get("ports", []))
        paste_score     = self._paste_score(findings.get("pastes", []))

        total = round(
            email_score     * 0.15 +
            subdomain_score * 0.20 +
            breach_score    * 0.25 +
            threat_score    * 0.10 +
            ssl_score       * 0.08 +
            cve_score       * 0.10 +
            port_score      * 0.07 +
            paste_score     * 0.05,
            2,
        )

        scores = {
            "total":     total,
            "email":     email_score,
            "subdomain": subdomain_score,
            "breach":    breach_score,
            "threat":    threat_score,
            "ssl":       ssl_score,
            "cve":       cve_score,
            "port":      port_score,
            "paste":     paste_score,
        }

        upsert_risk_score(target_id, scores)
        log_success(f"[ScoringAgent] Total attack surface risk: {total}/10")
        return scores

    @staticmethod
    def _email_score(emails: list) -> float:
        count = len(emails)
        if count == 0:  return 0.0
        if count < 5:   return 2.0
        if count < 20:  return 5.0
        return min(10.0, 5.0 + (count - 20) * 0.1)

    @staticmethod
    def _subdomain_score(subdomains: list) -> float:
        risky = sum(1 for s in subdomains if s.get("risk_flag"))
        total = len(subdomains)
        base  = min(5.0, total * 0.2)
        bonus = min(5.0, risky * 1.5)
        return round(min(10.0, base + bonus), 2)

    @staticmethod
    def _breach_score(breaches: list) -> float:
        count = len(breaches)
        if count == 0:   return 0.0
        if count < 3:    return 4.0
        if count < 10:   return 7.0
        return 10.0

    @staticmethod
    def _threat_score(intel: list) -> float:
        malicious = sum(1 for i in intel if i.get("malicious"))
        if malicious == 0: return 0.0
        return min(10.0, malicious * 3.5)

    @staticmethod
    def _ssl_score(ssl_data: dict) -> float:
        main = ssl_data.get("main")
        if not main: return 0.0
        if not main.get("valid"): return 8.0
        if main.get("expired"):   return 10.0
        days = main.get("days_left")
        if days is None: return 0.0
        if days < 7:   return 9.0
        if days < 14:  return 7.0
        if days < 30:  return 5.0
        return 0.0

    @staticmethod
    def _cve_score(cves: list) -> float:
        total_critical = sum(
            1 for e in cves for c in e.get("cves", [])
            if c.get("severity") in ("CRITICAL", "HIGH")
        )
        total_medium = sum(
            1 for e in cves for c in e.get("cves", [])
            if c.get("severity") == "MEDIUM"
        )
        score = total_critical * 2.5 + total_medium * 1.0
        return round(min(10.0, score), 2)

    @staticmethod
    def _port_score(ports: list) -> float:
        dangerous = sum(
            1 for h in ports for p in h.get("dangerous", [])
        )
        return round(min(10.0, dangerous * 2.0), 2)

    @staticmethod
    def _paste_score(pastes: list) -> float:
        count = len(pastes)
        if count == 0:  return 0.0
        if count < 3:   return 4.0
        if count < 10:  return 7.0
        return 10.0
