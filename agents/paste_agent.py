"""Paste Search Agent — searches multiple paste indexers for domain/email leaks."""
import requests
from utils.helpers import log_info, log_success, log_warn
from config.settings import REQUEST_TIMEOUT

_HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}


class PasteAgent:
    def run(self, domain: str, emails: list[dict]) -> list[dict]:
        log_info(f"[PasteAgent] Searching pastes for {domain}")
        results = []
        seen: set = set()
        company = domain.split(".")[0]

        keywords = [domain, company] + [e.get("email", "") for e in emails[:3]]

        for keyword in keywords:
            if not keyword:
                continue
            results += self._psbdmp(keyword, seen)
            results += self._leakix(keyword, seen)

        # Deduplicate
        unique = [r for r in results if r["id"] not in seen or not seen.add(r["id"])]
        log_success(f"[PasteAgent] {len(unique)} paste(s) found across all sources")
        return unique[:30]

    @staticmethod
    def _psbdmp(keyword: str, seen: set) -> list[dict]:
        """psbdmp.ws — indexes Pastebin pastes."""
        try:
            r = requests.get(
                f"https://psbdmp.ws/api/v3/search/{keyword}",
                headers=_HEADERS, timeout=REQUEST_TIMEOUT,
            )
            if r.status_code != 200:
                return []
            data = r.json()
            if not isinstance(data, list):
                return []
            pastes = []
            for item in data[:5]:
                pid = item.get("id", "")
                if not pid or pid in seen:
                    continue
                seen.add(pid)
                pastes.append({
                    "id": pid,
                    "date": item.get("time", ""),
                    "snippet": item.get("text", "")[:300],
                    "url": f"https://pastebin.com/{pid}",
                    "keyword": keyword,
                    "source": "psbdmp.ws",
                })
            return pastes
        except Exception as e:
            log_warn(f"[PasteAgent] psbdmp failed for '{keyword}': {e}")
            return []

    @staticmethod
    def _leakix(keyword: str, seen: set) -> list[dict]:
        """LeakIX — indexes exposed services and leaks (free, no key for basic search)."""
        try:
            r = requests.get(
                "https://leakix.net/search",
                params={"q": keyword, "scope": "leak"},
                headers={**_HEADERS, "Accept": "application/json"},
                timeout=REQUEST_TIMEOUT,
            )
            if r.status_code != 200:
                return []
            results = r.json() if isinstance(r.json(), list) else []
            pastes = []
            for item in results[:5]:
                event_id = item.get("event_fingerprint", item.get("ip", ""))
                if not event_id or event_id in seen:
                    continue
                seen.add(event_id)
                pastes.append({
                    "id": event_id,
                    "date": item.get("time", ""),
                    "snippet": item.get("summary", item.get("data", ""))[:300],
                    "url": f"https://leakix.net/host/{item.get('ip','')}",
                    "keyword": keyword,
                    "source": "leakix",
                })
            return pastes
        except Exception as e:
            log_warn(f"[PasteAgent] LeakIX failed for '{keyword}': {e}")
            return []
