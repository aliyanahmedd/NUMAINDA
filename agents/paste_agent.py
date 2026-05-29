"""Paste Search Agent — searches psbdmp.ws for domain/email mentions in public pastes."""
import requests
from utils.helpers import log_info, log_success, log_warn
from config.settings import REQUEST_TIMEOUT

_SEARCH_URL = "https://psbdmp.ws/api/v3/search/{keyword}"


class PasteAgent:
    def run(self, domain: str, emails: list[dict]) -> list[dict]:
        log_info(f"[PasteAgent] Searching pastes for {domain}")
        results = []

        results += self._search(domain)

        company = domain.split(".")[0]
        if company != domain:
            results += self._search(company)

        for entry in emails[:3]:
            email = entry.get("email", "")
            if email:
                results += self._search(email)

        seen = set()
        unique = []
        for r in results:
            if r["id"] not in seen:
                seen.add(r["id"])
                unique.append(r)

        log_success(f"[PasteAgent] Found {len(unique)} paste(s) mentioning target")
        return unique[:20]

    @staticmethod
    def _search(keyword: str) -> list[dict]:
        try:
            r = requests.get(
                _SEARCH_URL.format(keyword=keyword),
                timeout=REQUEST_TIMEOUT,
                headers={"User-Agent": "OSINT-Agent/1.0"},
            )
            if r.status_code != 200:
                return []

            data = r.json()
            if not isinstance(data, list):
                return []

            pastes = []
            for item in data[:5]:
                paste_id = item.get("id", "")
                if not paste_id:
                    continue
                pastes.append({
                    "id": paste_id,
                    "date": item.get("time", ""),
                    "snippet": item.get("text", "")[:300],
                    "url": f"https://pastebin.com/{paste_id}",
                    "keyword": keyword,
                })
            return pastes

        except Exception as e:
            log_warn(f"[PasteAgent] Search failed for '{keyword}': {e}")
            return []
