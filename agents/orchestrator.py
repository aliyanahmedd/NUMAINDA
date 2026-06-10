"""
Orchestrator Agent - routes to domain, IP, or username scan flows.
"""
import anthropic
from config.settings import ANTHROPIC_API_KEY
from utils.validators import detect_input_type, normalize_domain, extract_domain_from_email, detect_wallet_chain
from utils.helpers import log_info, log_success, log_warn, print_section
from database.models import init_db
from database.db import (
    create_target, insert_geo_data, insert_ssl_certs,
    insert_cve_findings, insert_paste_findings, insert_port_findings,
    insert_analysis,
)

from agents.email_agent import EmailAgent
from agents.subdomain_agent import SubdomainAgent
from agents.breach_agent import BreachAgent
from agents.dns_agent import DNSAgent
from agents.tech_agent import TechAgent
from agents.threat_agent import ThreatAgent
from agents.social_agent import SocialAgent
from agents.scoring_agent import ScoringAgent
from agents.geo_agent import GeoAgent
from agents.ssl_agent import SSLAgent
from agents.port_agent import PortAgent
from agents.cve_agent import CVEAgent
from agents.paste_agent import PasteAgent
from agents.ip_agent import IPAgent
from agents.wallet_agent import WalletAgent


_NO_AI_MESSAGE = (
    "AI analysis was not generated because no ANTHROPIC_API_KEY is configured. "
    "All other OSINT findings above are complete. Set the key to enable the "
    "Claude-written intelligence report."
)


class OSINTOrchestrator:
    def __init__(self, progress_cb=None):
        # Only build the Anthropic client when a key is present; the AI report
        # is skipped gracefully otherwise.
        self.client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY) if ANTHROPIC_API_KEY else None
        self._emit = progress_cb or (lambda msg: None)
        init_db()

    # ── Entry point ────────────────────────────────────────────────────────────

    def run(self, raw_input: str) -> dict:
        # Crypto wallet addresses are checked first - they never match the
        # domain/email/ip patterns but would otherwise fall through to "domain".
        wallet_chain = detect_wallet_chain(raw_input)
        if wallet_chain != "unknown":
            self._emit(f"[*] {wallet_chain.title()} wallet detected: {raw_input.strip()}")
            target_id = create_target(raw_input.strip(), "wallet")
            return self._run_wallet(raw_input.strip(), target_id)

        input_type = detect_input_type(raw_input)

        if input_type == "email":
            domain = extract_domain_from_email(raw_input)
            self._emit(f"[*] Email detected - scanning domain: {domain}")
            target_id = create_target(raw_input, input_type)
            return self._run_domain(domain, target_id)

        elif input_type == "domain":
            domain = normalize_domain(raw_input)
            self._emit(f"[*] Domain detected: {domain}")
            target_id = create_target(raw_input, input_type)
            return self._run_domain(domain, target_id)

        elif input_type == "ip":
            ip = raw_input.strip()
            self._emit(f"[*] IP address detected: {ip}")
            target_id = create_target(raw_input, input_type)
            return self._run_ip(ip, target_id)

        else:
            log_warn(f"Unrecognized input: {raw_input!r} - treating as domain")
            domain = normalize_domain(raw_input)
            target_id = create_target(raw_input, "domain")
            return self._run_domain(domain, target_id)

    # ── Domain / Email flow (14 phases) ───────────────────────────────────────

    def _run_domain(self, domain: str, target_id: int) -> dict:
        findings: dict = {"scan_type": "domain", "domain": domain, "target_id": target_id}

        print_section("Phase 1 - DNS & WHOIS")
        self._emit("[DNS] Phase 1/14 - DNS & WHOIS reconnaissance...")
        dns_data = DNSAgent().run(target_id, domain)
        findings["dns"] = dns_data
        self._emit(f"[+] DNS complete - {len(dns_data.get('records', []))} records found")

        print_section("Phase 2 - Email Discovery")
        self._emit("[EMAIL] Phase 2/14 - Email discovery via Hunter.io...")
        emails = EmailAgent().run(target_id, domain)
        findings["emails"] = emails
        self._emit(f"[+] Email discovery complete - {len(emails)} emails found")

        print_section("Phase 3 - Subdomain Enumeration")
        self._emit("[SUB] Phase 3/14 - Subdomain enumeration (crt.sh + HackerTarget)...")
        subdomains = SubdomainAgent().run(target_id, domain)
        findings["subdomains"] = subdomains
        risky = sum(1 for s in subdomains if s.get("risk_flag"))
        self._emit(f"[+] Subdomains complete - {len(subdomains)} found, {risky} flagged risky")

        print_section("Phase 4 - IP Geolocation")
        self._emit("[GEO] Phase 4/14 - Geolocating discovered IPs...")
        geo = GeoAgent().run(subdomains, dns_data)
        findings["geo"] = geo
        insert_geo_data(target_id, geo)
        countries = list({g["country"] for g in geo if g.get("country")})
        self._emit(f"[+] Geolocation complete - {len(geo)} IPs across {len(countries)} country/ies")

        print_section("Phase 5 - Port Scanning")
        self._emit("[PORT] Phase 5/14 - Scanning for open ports...")
        ports = PortAgent().run(subdomains)
        findings["ports"] = ports
        insert_port_findings(target_id, ports)
        dangerous = sum(len(h.get("dangerous", [])) for h in ports)
        self._emit(f"[+] Port scan complete - {len(ports)} hosts scanned, {dangerous} dangerous port(s)")

        print_section("Phase 6 - Breach Intelligence")
        self._emit("[BREACH] Phase 6/14 - Checking breach databases...")
        breaches = BreachAgent().run(target_id, emails)
        findings["breaches"] = breaches
        self._emit(f"[+] Breach check complete - {len(breaches)} record(s) found")

        print_section("Phase 7 - Tech Stack Detection")
        self._emit("[TECH] Phase 7/14 - Fingerprinting tech stack & versions...")
        tech = TechAgent().run(domain)
        findings["tech"] = tech
        techs = tech.get("technologies", [])
        versioned = tech.get("versioned", {})
        self._emit(f"[+] Tech stack detected - {', '.join(techs[:5]) or 'unknown'} | {len(versioned)} versioned")

        print_section("Phase 8 - SSL Certificate Check")
        self._emit("[SSL] Phase 8/14 - Checking SSL certificate expiry...")
        ssl_data = SSLAgent().run(domain, subdomains)
        findings["ssl"] = ssl_data
        insert_ssl_certs(target_id, ssl_data)
        main_cert = ssl_data.get("main")
        if main_cert:
            days = main_cert.get("days_left")
            day_str = f"{days} days" if days is not None else "unknown"
            self._emit(f"[+] SSL complete - expires in {day_str} via {main_cert.get('issuer','unknown')}")
        else:
            self._emit("[!] SSL check - no certificate data retrieved")

        print_section("Phase 9 - CVE Lookup")
        self._emit("[CVE] Phase 9/14 - Looking up CVEs for detected technologies...")
        cves = CVEAgent().run(tech)
        findings["cves"] = cves
        insert_cve_findings(target_id, cves)
        total_cves = sum(len(e["cves"]) for e in cves)
        critical = sum(1 for e in cves for c in e["cves"] if c.get("severity") in ("CRITICAL", "HIGH"))
        self._emit(f"[+] CVE lookup complete - {total_cves} CVE(s) found, {critical} critical/high")

        print_section("Phase 10 - Threat Intelligence")
        self._emit("[THREAT] Phase 10/14 - Querying VirusTotal...")
        threat_intel = ThreatAgent().run(target_id, domain, subdomains)
        findings["threat_intel"] = threat_intel
        malicious = sum(1 for t in threat_intel if t.get("malicious"))
        self._emit(f"[+] Threat scan complete - {malicious} malicious indicator(s)")

        print_section("Phase 11 - Paste Search")
        self._emit("[PASTE] Phase 11/14 - Searching Pastebin for leaks...")
        pastes = PasteAgent().run(domain, emails)
        findings["pastes"] = pastes
        if pastes:
            insert_paste_findings(target_id, pastes)
        self._emit(f"[+] Paste search complete - {len(pastes)} paste(s) found")

        print_section("Phase 12 - Social Media Intelligence")
        self._emit("[SOCIAL] Phase 12/14 - GitHub intelligence gathering...")
        social = SocialAgent().run(domain)
        findings["social"] = social
        repos = len(social.get("repositories", []))
        self._emit(f"[+] Social scan complete - {repos} GitHub repo(s) found")

        print_section("Phase 13 - Risk Scoring")
        self._emit("[SCORE] Phase 13/14 - Calculating risk scores...")
        scores = ScoringAgent().run(target_id, findings)
        findings["scores"] = scores
        self._emit(f"[+] Risk scoring complete - Overall: {scores.get('total', 0):.1f}/10")

        print_section("Phase 14 - AI Analysis")
        if ANTHROPIC_API_KEY:
            self._emit("[AI] Phase 14/14 - Claude AI analyzing findings...")
            analysis = self._claude_domain_analysis(domain, findings)
            findings["analysis"] = analysis
            insert_analysis(target_id, analysis)
            self._emit("[+] AI analysis complete")
        else:
            findings["analysis"] = _NO_AI_MESSAGE
            self._emit("[!] AI analysis skipped - no ANTHROPIC_API_KEY configured")

        return findings

    # ── IP flow (6 phases) ────────────────────────────────────────────────────

    def _run_ip(self, ip: str, target_id: int) -> dict:
        findings: dict = {"scan_type": "ip", "domain": ip, "target_id": target_id}

        print_section("Phase 1 - Reverse DNS & WHOIS")
        self._emit("[RDNS] Phase 1/6 - Reverse DNS & WHOIS lookup...")
        ip_data = IPAgent().run(ip)
        findings["ip_data"] = ip_data
        self._emit(f"[+] Reverse DNS: {ip_data.get('hostname') or 'none'} | Org: {ip_data.get('whois', {}).get('org','unknown')}")

        print_section("Phase 2 - Geolocation")
        self._emit("[GEO] Phase 2/6 - Geolocating IP...")
        geo = GeoAgent().run([], {"records": [{"record_type": "A", "value": ip}]})
        findings["geo"] = geo
        insert_geo_data(target_id, geo)
        if geo:
            g = geo[0]
            self._emit(f"[+] Geolocation: {g.get('city','')}, {g.get('country','')} - {g.get('org','')}")
        else:
            self._emit("[!] Geolocation returned no data")

        print_section("Phase 3 - Port Scanning")
        self._emit("[PORT] Phase 3/6 - Scanning open ports...")
        ports = PortAgent().run([{"subdomain": ip, "ip": ip}])
        findings["ports"] = ports
        insert_port_findings(target_id, ports)
        open_ports = ports[0].get("ports", []) if ports else []
        self._emit(f"[+] Port scan complete - {len(open_ports)} open port(s)")

        print_section("Phase 4 - Threat Intelligence")
        self._emit("[THREAT] Phase 4/6 - VirusTotal IP check...")
        threat_intel = ThreatAgent().run(target_id, ip, [])
        findings["threat_intel"] = threat_intel
        malicious = sum(1 for t in threat_intel if t.get("malicious"))
        self._emit(f"[+] Threat check complete - {malicious} malicious indicator(s)")

        print_section("Phase 5 - Risk Scoring")
        self._emit("[SCORE] Phase 5/6 - Calculating risk scores...")
        scores = ScoringAgent().run(target_id, findings)
        findings["scores"] = scores
        self._emit(f"[+] Risk scoring complete - Overall: {scores.get('total', 0):.1f}/10")

        print_section("Phase 6 - AI Analysis")
        if ANTHROPIC_API_KEY:
            self._emit("[AI] Phase 6/6 - Claude AI analyzing findings...")
            analysis = self._claude_ip_analysis(ip, findings)
            findings["analysis"] = analysis
            insert_analysis(target_id, analysis)
            self._emit("[+] AI analysis complete")
        else:
            findings["analysis"] = _NO_AI_MESSAGE
            self._emit("[!] AI analysis skipped - no ANTHROPIC_API_KEY configured")

        return findings


    # ── Wallet flow (2 phases) ─────────────────────────────────────────────────

    def _run_wallet(self, address: str, target_id: int) -> dict:
        findings: dict = {"scan_type": "wallet", "domain": address, "target_id": target_id}

        print_section("Phase 1 - On-chain Lookup")
        self._emit("[WALLET] Phase 1/2 - Fetching public on-chain data...")
        wallet = WalletAgent().run(address)
        findings["wallet"] = wallet

        if not wallet.get("found"):
            self._emit("[!] No on-chain data found for this address")
            findings["analysis"] = "No on-chain activity found for this wallet address."
            return findings

        bal = wallet.get("balance", 0)
        sym = wallet.get("symbol", "")
        self._emit(f"[+] On-chain data retrieved - {bal} {sym} | {wallet.get('tx_count', 0)} txs")

        print_section("Phase 2 - AI Analysis")
        analysis = wallet.get("analysis") or "AI analysis not available."
        findings["analysis"] = analysis
        if ANTHROPIC_API_KEY:
            insert_analysis(target_id, analysis)
            self._emit("[+] AI analysis complete")
        else:
            self._emit("[!] AI analysis skipped - no ANTHROPIC_API_KEY configured")

        return findings


    # ── Claude analysis variants ───────────────────────────────────────────────

    def _claude_domain_analysis(self, domain: str, findings: dict) -> str:
        emails       = len(findings.get("emails", []))
        subdomains   = len(findings.get("subdomains", []))
        risky_subs   = [s["subdomain"] for s in findings.get("subdomains", []) if s.get("risk_flag")]
        breaches     = len(findings.get("breaches", []))
        malicious    = [t["indicator"] for t in findings.get("threat_intel", []) if t.get("malicious")]
        tech         = findings.get("tech", {}).get("technologies", [])
        versioned    = findings.get("tech", {}).get("versioned", {})
        scores       = findings.get("scores", {})
        ssl          = findings.get("ssl", {}).get("main", {})
        cves         = findings.get("cves", [])
        ports        = findings.get("ports", [])
        pastes       = findings.get("pastes", [])
        geo          = findings.get("geo", [])
        total_cves   = sum(len(e["cves"]) for e in cves)
        critical_cve = sum(1 for e in cves for c in e["cves"] if c.get("severity") in ("CRITICAL","HIGH"))
        dangerous_ports = [p for h in ports for p in h.get("dangerous", [])]
        countries    = list({g["country"] for g in geo if g.get("country")})
        ssl_status   = "unknown"
        if ssl:
            if ssl.get("expired"):         ssl_status = "EXPIRED"
            elif ssl.get("expiring_soon"): ssl_status = f"expiring in {ssl.get('days_left')} days"
            else:                          ssl_status = f"valid ({ssl.get('days_left')} days left)"

        prompt = f"""You are a senior cybersecurity analyst reviewing OSINT findings for: {domain}

DATA:
- Emails: {emails} | Subdomains: {subdomains} ({len(risky_subs)} risky: {risky_subs or 'none'})
- Breaches: {breaches} | Malicious indicators: {malicious or 'none'}
- Tech: {tech} | Versioned: {versioned}
- SSL: {ssl_status} | CVEs: {total_cves} total, {critical_cve} critical/high
- Dangerous ports: {dangerous_ports or 'none'} | Pastes: {len(pastes)}
- Infrastructure: {countries} | Risk scores: {scores}

Write a concise intelligence report:
1. EXECUTIVE SUMMARY (2-3 sentences)
2. KEY FINDINGS (bullet points, most critical first)
3. ATTACK SURFACE ANALYSIS
4. RECOMMENDATIONS (prioritized by risk)"""

        msg = self.client.messages.create(
            model="claude-sonnet-4-6", max_tokens=1800,
            messages=[{"role": "user", "content": prompt}],
        )
        log_success("[Orchestrator] Claude domain analysis complete")
        return msg.content[0].text

    def _claude_ip_analysis(self, ip: str, findings: dict) -> str:
        ip_data  = findings.get("ip_data", {})
        geo      = findings.get("geo", [{}])[0] if findings.get("geo") else {}
        ports    = findings.get("ports", [{}])[0] if findings.get("ports") else {}
        malicious = [t["indicator"] for t in findings.get("threat_intel", []) if t.get("malicious")]

        prompt = f"""You are a cybersecurity analyst reviewing OSINT for IP: {ip}

DATA:
- Hostname: {ip_data.get('hostname','none')}
- Org: {ip_data.get('whois',{}).get('org','unknown')}
- Location: {geo.get('city','')}, {geo.get('country','')}
- ISP: {geo.get('isp','')}
- Open ports: {ports.get('ports',[])}
- Dangerous ports: {ports.get('dangerous',[])}
- Malicious (VirusTotal): {malicious or 'none'}

Write:
1. SUMMARY - what is this IP, who owns it
2. RISK ASSESSMENT - what the open ports and threat data indicate
3. RECOMMENDATIONS"""

        msg = self.client.messages.create(
            model="claude-sonnet-4-6", max_tokens=800,
            messages=[{"role": "user", "content": prompt}],
        )
        log_success("[Orchestrator] Claude IP analysis complete")
        return msg.content[0].text

