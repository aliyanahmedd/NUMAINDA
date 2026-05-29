"""Username OSINT Agent — checks username existence across major platforms concurrently.

Only platforms where existence can be reliably determined without JavaScript rendering
or authentication are included. SPAs (Twitch, Kaggle, TikTok, YouTube, Instagram,
Twitter/X, Pinterest) are excluded because they return HTTP 200 for all URLs.
"""
import re
import concurrent.futures
import requests
from utils.helpers import log_info, log_success, log_warn

# (display_name, url_template, check_type, check_value)
#
# check_type:
#   "status"        — found if HTTP 200, not found if HTTP == check_value (404)
#   "not_in"        — found if check_value string is NOT in response body (case-insensitive)
#   "json_null"     — found if response body is not "null" / empty
#   "title_has"     — found if username appears in <title> tag (case-insensitive)

PLATFORMS = [
    # Server-side rendered — 404 is definitive
    ("GitHub",      "https://github.com/{}",                               "status",    404),
    ("Dev.to",      "https://dev.to/{}",                                   "status",    404),
    ("Keybase",     "https://keybase.io/{}",                               "status",    404),
    ("DockerHub",   "https://hub.docker.com/u/{}/",                        "status",    404),
    ("HuggingFace", "https://huggingface.co/{}",                           "status",    404),
    ("Bitbucket",   "https://bitbucket.org/{}/",                           "status",    404),
    ("Dribbble",    "https://dribbble.com/{}",                             "status",    404),
    ("Pastebin",    "https://pastebin.com/u/{}",                           "status",    404),
    ("Fiverr",      "https://www.fiverr.com/{}",                           "status",    404),
    # JSON API — null body means user doesn't exist
    ("HackerNews",  "https://hacker-news.firebaseio.com/v0/user/{}.json",  "json_null", None),
    # Content checks — platform returns 200 but body reveals existence
    ("Steam",       "https://steamcommunity.com/id/{}",                    "not_in",    "The specified profile could not be found"),
    # Title checks — username in <title> only when profile exists
    ("GitLab",      "https://gitlab.com/{}",                               "title_has", None),
    ("npm",         "https://www.npmjs.com/~{}",                           "title_has", None),
    ("CodePen",     "https://codepen.io/{}",                               "title_has", None),
    # Reddit via JSON API
    ("Reddit",      "https://www.reddit.com/user/{}/about.json",           "status",    404),
]

# Cloudflare challenge page indicators — treat as "unknown" to avoid false positives
_CF_INDICATORS = ("just a moment", "client challenge", "_cf_chl", "cf-browser-verification")

_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}
_TIMEOUT = 8
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


class UsernameAgent:
    def run(self, username: str) -> dict:
        username = username.lstrip("@").strip()
        log_info(f"[UsernameAgent] Checking '{username}' across {len(PLATFORMS)} platforms")

        found, not_found, errors = [], [], []

        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
            futures = {
                executor.submit(self._check, username, name, url_tpl, check_type, check_val): name
                for name, url_tpl, check_type, check_val in PLATFORMS
            }
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result["status"] == "found":
                    found.append(result)
                elif result["status"] == "not_found":
                    not_found.append(result)
                else:
                    errors.append(result)

        found.sort(key=lambda x: x["platform"])
        log_success(f"[UsernameAgent] Found on {len(found)}/{len(PLATFORMS)} platforms")

        return {
            "username": username,
            "found": found,
            "not_found": not_found,
            "total_checked": len(PLATFORMS),
        }

    @staticmethod
    def _is_cloudflare(r) -> bool:
        snippet = r.text[:1000].lower()
        return any(ind in snippet for ind in _CF_INDICATORS)

    @staticmethod
    def _check(username: str, name: str, url_tpl: str, check_type: str, check_val) -> dict:
        url = url_tpl.format(username)
        try:
            r = requests.get(url, headers=_HEADERS, timeout=_TIMEOUT, allow_redirects=True)

            # Cloudflare challenge pages always return "not_found" to avoid false positives
            if UsernameAgent._is_cloudflare(r):
                return {"platform": name, "url": url, "status": "not_found", "status_code": r.status_code}

            if check_type == "status":
                exists = r.status_code == 200

            elif check_type == "not_in":
                exists = r.status_code == 200 and check_val.lower() not in r.text.lower()

            elif check_type == "json_null":
                exists = r.status_code == 200 and r.text.strip() not in ("null", "", "null\n")

            elif check_type == "title_has":
                m = _TITLE_RE.search(r.text)
                title = m.group(1).strip() if m else ""
                exists = r.status_code == 200 and username.lower() in title.lower()

            else:
                exists = r.status_code == 200

            return {
                "platform": name,
                "url": url,
                "status": "found" if exists else "not_found",
                "status_code": r.status_code,
            }
        except Exception as e:
            return {"platform": name, "url": url, "status": "error", "error": str(e)}
