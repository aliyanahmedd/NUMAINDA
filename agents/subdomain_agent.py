"""Subdomain Enumeration Agent — crt.sh + HackerTarget + RapidDNS + wordlist brute-force."""
import requests
import dns.resolver
from utils.api_client import crt_sh_subdomains
from utils.helpers import log_info, log_success, log_warn
from database.db import insert_subdomains
from config.settings import REQUEST_TIMEOUT

RISKY_KEYWORDS = {
    "admin", "dev", "staging", "test", "api", "internal", "vpn",
    "secret", "beta", "debug", "backup", "old", "legacy", "temp",
    "private", "manage", "dashboard", "portal", "cpanel", "ftp",
}

# Top common subdomains to brute-force via DNS
WORDLIST = [
    "www", "mail", "email", "webmail", "smtp", "pop", "imap",
    "ftp", "sftp", "ssh", "vpn", "remote",
    "admin", "portal", "dashboard", "cp", "panel", "manage",
    "api", "api2", "rest", "ws", "app", "apps",
    "dev", "test", "staging", "uat", "qa", "demo", "beta", "sandbox",
    "cdn", "static", "assets", "media", "img", "images",
    "blog", "news", "forum", "support", "help", "docs", "wiki", "status",
    "mobile", "m", "secure", "login", "auth", "sso",
    "ns1", "ns2", "mx", "mx1", "mx2",
    "db", "mysql", "redis", "mongo",
    "git", "jenkins", "ci", "jira", "confluence",
    "intranet", "internal", "corp",
    "shop", "store", "billing", "files", "download", "cloud",
    "crm", "erp", "hr", "finance", "lms", "elearn", "student",
    "staff", "faculty", "library", "research",
]


class SubdomainAgent:
    def run(self, target_id: int, domain: str) -> list[dict]:
        log_info(f"[SubdomainAgent] Enumerating subdomains for {domain}")
        found_subs: set = set()

        # Source 1: Certificate Transparency (crt.sh)
        ct = crt_sh_subdomains(domain)
        found_subs.update(ct)
        log_success(f"[SubdomainAgent] crt.sh: {len(ct)} subdomains")

        # Source 2: HackerTarget
        ht = self._hackertarget(domain)
        found_subs.update(ht)
        log_success(f"[SubdomainAgent] HackerTarget: {len(ht)} subdomains")

        # Source 3: RapidDNS (free, no key)
        rd = self._rapiddns(domain)
        found_subs.update(rd)
        log_success(f"[SubdomainAgent] RapidDNS: {len(rd)} subdomains")

        # Source 4: AlienVault OTX (free, no key)
        otx = self._alienvault(domain)
        found_subs.update(otx)
        log_success(f"[SubdomainAgent] AlienVault OTX: {len(otx)} subdomains")

        # Source 5: Wordlist DNS brute-force
        bf = self._bruteforce(domain, found_subs)
        found_subs.update(bf)
        log_success(f"[SubdomainAgent] Brute-force: {len(bf)} new subdomains")

        subdomains = []
        for sub in sorted(found_subs):
            ip = self._resolve_ip(sub)
            keyword = sub.split(".")[0].lower()
            risk = any(kw in keyword for kw in RISKY_KEYWORDS)
            subdomains.append({
                "subdomain": sub,
                "ip": ip or "",
                "open_ports": [],
                "technology": [],
                "risk_flag": int(risk),
            })

        if subdomains:
            insert_subdomains(target_id, subdomains)
            risky = [s for s in subdomains if s["risk_flag"]]
            log_success(f"[SubdomainAgent] {len(subdomains)} total | {len(risky)} risky")

        return subdomains

    @staticmethod
    def _hackertarget(domain: str) -> list[str]:
        try:
            r = requests.get(
                "https://api.hackertarget.com/hostsearch/",
                params={"q": domain}, timeout=REQUEST_TIMEOUT,
            )
            if r.status_code != 200 or "error" in r.text.lower():
                return []
            subs = []
            for line in r.text.strip().splitlines():
                parts = line.split(",")
                if parts and parts[0].endswith(f".{domain}"):
                    subs.append(parts[0].strip().lower())
            return subs
        except Exception as e:
            log_warn(f"[SubdomainAgent] HackerTarget failed: {e}")
            return []

    @staticmethod
    def _rapiddns(domain: str) -> list[str]:
        try:
            r = requests.get(
                f"https://rapiddns.io/subdomain/{domain}?full=1",
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=REQUEST_TIMEOUT,
            )
            if r.status_code != 200:
                return []
            import re
            pattern = re.compile(r'([a-zA-Z0-9\-\.]+\.' + re.escape(domain) + r')')
            subs = list({m.lower() for m in pattern.findall(r.text)
                         if m.lower().endswith(f".{domain}") and m.lower() != domain})
            return subs
        except Exception as e:
            log_warn(f"[SubdomainAgent] RapidDNS failed: {e}")
            return []

    @staticmethod
    def _alienvault(domain: str) -> list[str]:
        try:
            r = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=REQUEST_TIMEOUT,
            )
            if r.status_code != 200:
                return []
            subs = []
            for entry in r.json().get("passive_dns", []):
                hostname = entry.get("hostname", "").lower()
                if hostname.endswith(f".{domain}") and hostname not in subs:
                    subs.append(hostname)
            return subs
        except Exception as e:
            log_warn(f"[SubdomainAgent] AlienVault OTX failed: {e}")
            return []

    @staticmethod
    def _bruteforce(domain: str, existing: set) -> list[str]:
        found = []
        for word in WORDLIST:
            sub = f"{word}.{domain}"
            if sub in existing:
                continue
            ip = SubdomainAgent._resolve_ip(sub)
            if ip:
                found.append(sub)
        return found

    @staticmethod
    def _resolve_ip(hostname: str) -> str | None:
        try:
            answers = dns.resolver.resolve(hostname, "A", lifetime=3)
            return str(answers[0])
        except Exception:
            return None
