"""Tech Stack Detection Agent — HTTP headers, HTML patterns, and version extraction."""
import re
import requests
from utils.helpers import log_info, log_success, log_warn
from config.settings import REQUEST_TIMEOUT

HEADER_SIGNATURES = {
    "x-powered-by": lambda v: v,
    "server": lambda v: v,
    "x-generator": lambda v: v,
    "x-drupal-cache": lambda _: "Drupal",
    "x-wp-total": lambda _: "WordPress",
    "x-shopify-stage": lambda _: "Shopify",
    "x-aspnet-version": lambda v: f"ASP.NET {v}",
    "x-aspnetmvc-version": lambda v: f"ASP.NET MVC {v}",
}

HTML_SIGNATURES = {
    r'wp-content|wp-includes':    "WordPress",
    r'Drupal\.settings':          "Drupal",
    r'Joomla':                    "Joomla",
    r'__NEXT_DATA__':             "Next.js",
    r'ng-version':                "Angular",
    r'data-reactroot|__reactFiber': "React",
    r'id="__nuxt"':               "Vue/Nuxt",
    r'laravel_session':           "Laravel",
    r'csrfmiddlewaretoken':       "Django",
    r'railsenv':                  "Ruby on Rails",
    r'cdn\.shopify\.com':         "Shopify",
    r'static\.cloudflareinsights\.com': "Cloudflare",
}

# Regex to extract name + version from common headers
_VERSION_RE = re.compile(r'^([A-Za-z][A-Za-z0-9._-]*)[/ ]([0-9]+\.[0-9]+(?:\.[0-9]+)?).*$')


_PROBE_PATHS = [
    "/", "/robots.txt", "/sitemap.xml",
    "/wp-login.php", "/wp-admin/",
    "/admin", "/admin/login", "/login",
    "/phpmyadmin/", "/joomla/", "/drupal/",
]


class TechAgent:
    def run(self, domain: str) -> dict:
        log_info(f"[TechAgent] Detecting tech stack for {domain}")
        tech = {
            "technologies": [],
            "versioned": {},
            "headers": {},
            "cms": None,
            "server": None,
            "waf": None,
        }

        base_url = None
        for scheme in ("https", "http"):
            try:
                r = requests.get(
                    f"{scheme}://{domain}", timeout=REQUEST_TIMEOUT,
                    allow_redirects=True, headers={"User-Agent": "Mozilla/5.0"},
                )
                tech["headers"] = dict(r.headers)
                tech["status_code"] = r.status_code
                self._parse_headers(r.headers, tech)
                self._parse_html(r.text, tech)
                self._detect_waf(r.headers, tech)
                base_url = f"{scheme}://{domain}"
                break
            except requests.RequestException as e:
                log_warn(f"[TechAgent] {scheme}://{domain} failed: {e}")

        # Probe additional paths to detect CMS / admin panels
        if base_url:
            for path in _PROBE_PATHS[1:]:
                try:
                    r = requests.get(
                        f"{base_url}{path}", timeout=5,
                        allow_redirects=True, headers={"User-Agent": "Mozilla/5.0"},
                    )
                    self._parse_headers(r.headers, tech)
                    self._parse_html(r.text, tech)
                    self._check_path_clues(path, r.status_code, tech)
                except Exception:
                    pass

        log_success(f"[TechAgent] Detected: {tech['technologies']}")
        return tech

    def _parse_headers(self, headers, tech: dict):
        for header, extractor in HEADER_SIGNATURES.items():
            value = headers.get(header)
            if not value:
                continue
            detected = extractor(value)
            if not detected:
                continue

            # Extract versioned info
            m = _VERSION_RE.match(value.strip())
            if m:
                name, version = m.group(1), m.group(2)
                # Normalise common names
                norm = name.lower()
                if "nginx" in norm:
                    tech["versioned"]["nginx"] = version
                    detected = "nginx"
                elif "apache" in norm:
                    tech["versioned"]["Apache"] = version
                    detected = "Apache"
                elif "php" in norm:
                    tech["versioned"]["PHP"] = version
                    detected = f"PHP/{version}"
                elif "express" in norm:
                    tech["versioned"]["Express"] = version
                    detected = f"Express/{version}"

            if header == "server":
                tech["server"] = detected

            if detected not in tech["technologies"]:
                tech["technologies"].append(detected)

    def _parse_html(self, html: str, tech: dict):
        for pattern, name in HTML_SIGNATURES.items():
            if re.search(pattern, html, re.IGNORECASE):
                if name not in tech["technologies"]:
                    tech["technologies"].append(name)
                if tech["cms"] is None and name not in ("Cloudflare",):
                    tech["cms"] = name

        # WordPress version detection
        wp_ver = re.search(r'content=["\']WordPress ([0-9.]+)["\']', html, re.IGNORECASE)
        if wp_ver:
            tech["versioned"]["WordPress"] = wp_ver.group(1)

        # jQuery version
        jq_ver = re.search(r'jquery[.-]([0-9]+\.[0-9]+\.[0-9]+)', html, re.IGNORECASE)
        if jq_ver:
            tech["versioned"]["jQuery"] = jq_ver.group(1)
            if "jQuery" not in tech["technologies"]:
                tech["technologies"].append("jQuery")

    @staticmethod
    def _check_path_clues(path: str, status: int, tech: dict):
        clues = {
            "/wp-login.php":   ("WordPress",  "cms"),
            "/wp-admin/":      ("WordPress",  "cms"),
            "/phpmyadmin/":    ("phpMyAdmin", None),
            "/joomla/":        ("Joomla",     "cms"),
            "/drupal/":        ("Drupal",     "cms"),
            "/admin/login":    ("Admin Panel","none"),
        }
        if path in clues and status in (200, 301, 302):
            name, ctype = clues[path]
            if name not in tech["technologies"]:
                tech["technologies"].append(name)
            if ctype == "cms" and not tech["cms"]:
                tech["cms"] = name

    @staticmethod
    def _detect_waf(headers, tech: dict):
        waf_signatures = {
            "cf-ray": "Cloudflare",
            "x-sucuri-id": "Sucuri",
            "x-fw-hash": "Wordfence",
            "x-protected-by": None,
            "x-datadome-cid": "DataDome",
            "x-imperva-id": "Imperva",
        }
        for header, waf_name in waf_signatures.items():
            if headers.get(header):
                name = waf_name or headers[header]
                tech["waf"] = name
                if name and name not in tech["technologies"]:
                    tech["technologies"].append(name)
                break
