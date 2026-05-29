# OSINT Agent

An AI-powered Open Source Intelligence agent built with Claude (Anthropic) and Python. It autonomously gathers, correlates, and analyzes publicly available intelligence about a target domain or email address, then produces a risk-scored report with a network visualization.

## What It Does

| Phase | Agent | Data Sources |
|-------|-------|-------------|
| 1 | DNS Agent | WHOIS, A/MX/NS/TXT records |
| 2 | Email Agent | Hunter.io |
| 3 | Subdomain Agent | crt.sh (cert transparency), Shodan |
| 4 | Breach Agent | Have I Been Pwned |
| 5 | Tech Agent | HTTP headers, HTML fingerprinting |
| 6 | Threat Agent | VirusTotal |
| 7 | Social Agent | GitHub API |
| 8 | Scoring Agent | Weighted risk model (0-10) |
| 9 | AI Analysis | Claude Sonnet - correlates all findings |

**Output:** plain-text report, interactive HTML report, interactive network graph, JSON export.

## Demo Output

```
=== OSINT INTELLIGENCE REPORT ===
Target: example.com

[RISK SCORES]
  Overall Attack Surface Risk : 6.8 / 10
  Email Exposure              : 5.0 / 10
  Subdomain Exposure          : 7.2 / 10
  Breach Risk                 : 7.0 / 10
  Threat Intelligence         : 0.0 / 10

[EMAIL INTELLIGENCE]
  14 emails discovered
  • cto@example.com (CTO, confidence=92%)
  • security@example.com (-, confidence=78%)

[SUBDOMAIN ENUMERATION]
  27 subdomains found | 4 flagged as risky
  ⚠  admin.example.com (IP: 93.184.216.34)
  ⚠  staging.example.com (IP: 93.184.216.35)

[BREACH INTELLIGENCE]
  3 breach record(s) found
  • dev@example.com in LinkedIn (2021-06-29)
```

## Setup

### 1. Clone & install

```bash
git clone https://github.com/YOUR_USERNAME/osint-agent.git
cd osint-agent
pip install -r requirements.txt
```

### 2. Configure API keys

```bash
cp .env.example .env
# Edit .env and fill in your keys
```

| API | Free Tier | Get Key At |
|-----|-----------|------------|
| Anthropic | - | console.anthropic.com |
| Hunter.io | 100 searches/month | hunter.io |
| Shodan | 1 query/month | shodan.io |
| VirusTotal | Unlimited | virustotal.com |
| GitHub | Unlimited | github.com/settings/tokens |
| Have I Been Pwned | Unlimited | haveibeenpwned.com/API |

### 3. Run

```bash
python main.py example.com
python main.py john@example.com
```

Reports are saved to `output/reports/` and `output/graphs/`.

## Project Structure

```
osint-agent/
├── agents/
│   ├── orchestrator.py      # Claude-powered coordinator
│   ├── email_agent.py       # Hunter.io email discovery
│   ├── subdomain_agent.py   # crt.sh + Shodan enumeration
│   ├── breach_agent.py      # HIBP breach lookup
│   ├── dns_agent.py         # WHOIS + DNS records
│   ├── tech_agent.py        # Tech stack fingerprinting
│   ├── threat_agent.py      # VirusTotal threat intel
│   ├── social_agent.py      # GitHub intelligence
│   └── scoring_agent.py     # Risk scoring (0-10)
├── config/settings.py       # Config & API keys loader
├── database/                # SQLite persistence
├── output/
│   ├── report_generator.py  # Text + HTML reports
│   ├── graph_visualizer.py  # Interactive Plotly graph
│   └── templates/report.html
├── utils/                   # API clients, validators, helpers
├── main.py                  # Entry point
├── requirements.txt
└── .env.example
```

## Tech Stack

- **AI:** Anthropic Claude (claude-sonnet-4-6)
- **Orchestration:** Custom multi-agent pipeline
- **APIs:** Hunter.io, Shodan, VirusTotal, HIBP, GitHub, crt.sh
- **Storage:** SQLite
- **Visualization:** Plotly + NetworkX
- **CLI:** Rich

---

## ⚠️ Legal & Ethical Disclaimer

This tool is for **AUTHORIZED** reconnaissance only:

- ✅ Test on domains you own
- ✅ Test with explicit written permission from the target
- ✅ Use for bug bounty programs within their defined scope
- ✅ Use for CTF challenges and security research
- ❌ Do NOT target individuals without consent
- ❌ Do NOT attempt to access private systems or bypass authentication
- ❌ Do NOT use to facilitate harassment or stalking

Unauthorized use may violate **CFAA** (US), **GDPR** (EU), **PECA** (Pakistan), and other applicable laws. The author is not liable for misuse.

---

*Built as a portfolio project demonstrating multi-agent AI orchestration for cybersecurity.*
