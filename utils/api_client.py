"""Thin wrappers around third-party API endpoints."""
import time
import requests
from config.settings import (
    HUNTER_API_KEY,
    VIRUSTOTAL_API_KEY,
    GITHUB_TOKEN,
    BREACHDIRECTORY_API_KEY,
    REQUEST_TIMEOUT,
    RATE_LIMIT_DELAY,
)


def _get(url: str, params: dict = None, headers: dict = None) -> dict | None:
    try:
        r = requests.get(url, params=params, headers=headers, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except requests.RequestException as e:
        print(f"[API ERROR] {url}: {e}")
        return None
    finally:
        time.sleep(RATE_LIMIT_DELAY)


# ── Hunter.io ─────────────────────────────────────────────────────────────────

def hunter_domain_search(domain: str) -> dict | None:
    """Return all emails found for a domain."""
    return _get(
        "https://api.hunter.io/v2/domain-search",
        params={"domain": domain, "api_key": HUNTER_API_KEY, "limit": 100},
    )


def hunter_email_verify(email: str) -> dict | None:
    return _get(
        "https://api.hunter.io/v2/email-verifier",
        params={"email": email, "api_key": HUNTER_API_KEY},
    )



# ── VirusTotal ────────────────────────────────────────────────────────────────

def virustotal_check_domain(domain: str) -> dict | None:
    return _get(
        f"https://www.virustotal.com/api/v3/domains/{domain}",
        headers={"x-apikey": VIRUSTOTAL_API_KEY},
    )


def virustotal_check_ip(ip: str) -> dict | None:
    return _get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"x-apikey": VIRUSTOTAL_API_KEY},
    )


# ── BreachDirectory ───────────────────────────────────────────────────────────

def breachdirectory_check_email(email: str) -> dict | None:
    return _get(
        "https://breachdirectory.p.rapidapi.com/",
        params={"func": "auto", "term": email},
        headers={
            "X-RapidAPI-Key": BREACHDIRECTORY_API_KEY,
            "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com",
        },
    )


# ── GitHub ────────────────────────────────────────────────────────────────────

def github_search_users(query: str) -> dict | None:
    headers = {"Authorization": f"token {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}
    return _get(
        "https://api.github.com/search/users",
        params={"q": query, "per_page": 10},
        headers=headers,
    )


def github_user_repos(username: str) -> list | None:
    headers = {"Authorization": f"token {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}
    return _get(
        f"https://api.github.com/users/{username}/repos",
        params={"per_page": 30, "sort": "updated"},
        headers=headers,
    )


# ── Blockchain / Crypto wallet (Blockchair - free, no key) ────────────────────

def btc_address_info(address: str) -> dict | None:
    """Bitcoin address data via blockchain.info (free, no key)."""
    return _get(f"https://blockchain.info/rawaddr/{address}", params={"limit": 10})


def eth_address_info(address: str) -> dict | None:
    """Ethereum address data via Ethplorer (free 'freekey', no signup)."""
    return _get(
        f"https://api.ethplorer.io/getAddressInfo/{address}",
        params={"apiKey": "freekey"},
    )


# ── DNS (no API key needed) ───────────────────────────────────────────────────

def crt_sh_subdomains(domain: str) -> list[str]:
    """Certificate Transparency log - free, no key required."""
    data = _get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"})
    if not data:
        return []
    seen = set()
    results = []
    for entry in data:
        name = entry.get("name_value", "")
        for sub in name.splitlines():
            sub = sub.strip().lower()
            if sub.endswith(f".{domain}") and sub not in seen:
                seen.add(sub)
                results.append(sub)
    return results
