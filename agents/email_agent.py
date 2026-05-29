"""Email Discovery Agent — Hunter.io + web crawler + pattern generator."""
import re
import requests
from bs4 import BeautifulSoup
from utils.api_client import hunter_domain_search
from utils.helpers import log_info, log_success, log_warn
from database.db import insert_emails
from config.settings import REQUEST_TIMEOUT

_EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
_OBFUSCATED_RE = re.compile(
    r'([a-zA-Z0-9._%+\-]+)\s*[\[\(]at[\]\)]\s*([a-zA-Z0-9.\-]+)\s*[\[\(]dot[\]\)]\s*([a-zA-Z]{2,})',
    re.IGNORECASE
)

_CRAWL_PATHS = [
    "/", "/contact", "/contact-us", "/about", "/about-us",
    "/team", "/staff", "/faculty", "/people", "/directory",
    "/employees", "/our-team", "/leadership", "/management",
]

_HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}


class EmailAgent:
    def run(self, target_id: int, domain: str) -> list[dict]:
        log_info(f"[EmailAgent] Searching emails for {domain}")
        seen: set = set()
        emails: list = []

        # ── Source 1: Hunter.io ───────────────────────────────────────────────
        hunter_emails = self._hunter(domain)
        for e in hunter_emails:
            if e["email"] not in seen:
                seen.add(e["email"])
                emails.append(e)
        log_success(f"[EmailAgent] Hunter.io: {len(hunter_emails)} emails")

        # ── Source 2: Web crawler ─────────────────────────────────────────────
        scraped = self._crawl(domain, seen)
        emails += scraped
        for e in scraped:
            seen.add(e["email"])
        log_success(f"[EmailAgent] Web crawler: {len(scraped)} new emails")

        # ── Source 3: Pattern generator (from Hunter pattern + names) ─────────
        generated = self._generate_patterns(domain, hunter_emails, seen)
        emails += generated
        log_success(f"[EmailAgent] Pattern generator: {len(generated)} new emails")

        if emails:
            insert_emails(target_id, emails)
            log_success(f"[EmailAgent] Total: {len(emails)} unique emails saved")

        return emails

    @staticmethod
    def _hunter(domain: str) -> list[dict]:
        data = hunter_domain_search(domain)
        if not data or "data" not in data:
            return []
        emails = []
        for e in data["data"].get("emails", []):
            emails.append({
                "email":      e.get("value", "").lower(),
                "first_name": e.get("first_name", ""),
                "last_name":  e.get("last_name", ""),
                "position":   e.get("position", ""),
                "confidence": e.get("confidence", 0),
                "source":     "hunter.io",
            })
        return emails

    @staticmethod
    def _crawl(domain: str, seen: set) -> list[dict]:
        found = []
        for path in _CRAWL_PATHS:
            for scheme in ("https", "http"):
                try:
                    r = requests.get(
                        f"{scheme}://{domain}{path}",
                        headers=_HEADERS, timeout=REQUEST_TIMEOUT,
                        allow_redirects=True,
                    )
                    if r.status_code != 200:
                        continue

                    text = r.text

                    # Normal emails
                    for match in _EMAIL_RE.findall(text):
                        email = match.lower()
                        if domain in email and email not in seen:
                            seen.add(email)
                            found.append({
                                "email": email, "first_name": "", "last_name": "",
                                "position": "", "confidence": 70, "source": f"web:{path}",
                            })

                    # Obfuscated: name [at] domain [dot] com
                    for m in _OBFUSCATED_RE.finditer(text):
                        email = f"{m.group(1)}@{m.group(2)}.{m.group(3)}".lower()
                        if domain in email and email not in seen:
                            seen.add(email)
                            found.append({
                                "email": email, "first_name": "", "last_name": "",
                                "position": "", "confidence": 60, "source": f"web-obfuscated:{path}",
                            })

                    # Also follow links on the page to find sub-pages
                    soup = BeautifulSoup(text, "html.parser")
                    for a in soup.find_all("a", href=True):
                        href = a["href"]
                        if "mailto:" in href:
                            email = href.replace("mailto:", "").split("?")[0].lower().strip()
                            if domain in email and email not in seen:
                                seen.add(email)
                                found.append({
                                    "email": email, "first_name": "", "last_name": "",
                                    "position": "", "confidence": 90, "source": f"mailto:{path}",
                                })
                    break
                except Exception:
                    continue
        return found

    @staticmethod
    def _generate_patterns(domain: str, hunter_emails: list, seen: set) -> list[dict]:
        """Generate likely emails from Hunter pattern + names found."""
        if not hunter_emails:
            return []
        # Derive pattern from existing emails
        patterns = []
        for e in hunter_emails:
            fn = e.get("first_name", "").lower().strip()
            ln = e.get("last_name", "").lower().strip()
            if not fn or not ln:
                continue
            patterns += [
                f"{fn}.{ln}@{domain}",
                f"{fn[0]}{ln}@{domain}",
                f"{fn}{ln[0]}@{domain}",
                f"{fn}@{domain}",
            ]

        new_emails = []
        for email in set(patterns):
            if email not in seen:
                seen.add(email)
                new_emails.append({
                    "email": email, "first_name": "", "last_name": "",
                    "position": "", "confidence": 40, "source": "pattern-generated",
                })
        return new_emails[:50]  # cap to avoid noise
