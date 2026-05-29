"""Generate HTML and plain-text OSINT reports from findings."""
from pathlib import Path
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from config.settings import REPORTS_DIR
from utils.helpers import safe_json_loads

REPORTS_DIR.mkdir(parents=True, exist_ok=True)

_TEMPLATE_DIR = Path(__file__).parent / "templates"
_env = Environment(loader=FileSystemLoader(str(_TEMPLATE_DIR)), autoescape=True)


def generate_text_report(findings: dict) -> str:
    domain = findings.get("domain", "unknown")
    scores = findings.get("scores", {})
    emails = findings.get("emails", [])
    subdomains = findings.get("subdomains", [])
    breaches = findings.get("breaches", [])
    threat_intel = findings.get("threat_intel", [])
    tech = findings.get("tech", {})
    analysis = findings.get("analysis", "")

    risky_subs = [s for s in subdomains if s.get("risk_flag")]
    malicious = [t for t in threat_intel if t.get("malicious")]

    lines = [
        "=" * 60,
        "      OSINT INTELLIGENCE REPORT",
        f"      Target: {domain}",
        f"      Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 60,
        "",
        "[RISK SCORES]",
        f"  Overall Attack Surface Risk : {scores.get('total', 0):.1f} / 10",
        f"  Email Exposure              : {scores.get('email', 0):.1f} / 10",
        f"  Subdomain Exposure          : {scores.get('subdomain', 0):.1f} / 10",
        f"  Breach Risk                 : {scores.get('breach', 0):.1f} / 10",
        f"  Threat Intelligence         : {scores.get('threat', 0):.1f} / 10",
        "",
        "[EMAIL INTELLIGENCE]",
        f"  {len(emails)} emails discovered",
    ]

    for e in emails[:10]:
        lines.append(f"  • {e['email']} ({e.get('position','–')}, confidence={e.get('confidence',0)}%)")
    if len(emails) > 10:
        lines.append(f"  ... and {len(emails) - 10} more")

    lines += [
        "",
        "[SUBDOMAIN ENUMERATION]",
        f"  {len(subdomains)} subdomains found | {len(risky_subs)} flagged as risky",
    ]
    for s in risky_subs:
        lines.append(f"  ⚠  {s['subdomain']} (IP: {s.get('ip','–')})")

    lines += [
        "",
        "[BREACH INTELLIGENCE]",
        f"  {len(breaches)} breach record(s) found",
    ]
    for b in breaches:
        lines.append(f"  • {b['email']} in {b['breach_name']} ({b.get('breach_date','–')})")

    lines += [
        "",
        "[THREAT INTELLIGENCE]",
        f"  {len(malicious)} malicious indicator(s) detected",
    ]
    for t in malicious:
        lines.append(f"  ✗ {t['indicator']} — {t.get('engine_hits',0)} engines flagged")

    lines += [
        "",
        "[TECH STACK]",
        f"  {', '.join(tech.get('technologies', [])) or 'Unknown'}",
        "",
        "[AI ANALYSIS]",
        analysis,
        "",
        "=" * 60,
        "  ⚠  For authorized use only. Do not share without consent.",
        "=" * 60,
    ]

    return "\n".join(lines)


def save_text_report(findings: dict) -> Path:
    domain = findings.get("domain", "unknown")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = REPORTS_DIR / f"{domain}_{ts}.txt"
    report = generate_text_report(findings)
    path.write_text(report, encoding="utf-8")
    return path


def generate_html_report(findings: dict) -> str:
    template = _env.get_template("report.html")
    return template.render(
        domain=findings.get("domain", "unknown"),
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        scores=findings.get("scores", {}),
        emails=findings.get("emails", [])[:20],
        subdomains=findings.get("subdomains", []),
        breaches=findings.get("breaches", []),
        threat_intel=findings.get("threat_intel", []),
        tech=findings.get("tech", {}),
        analysis=findings.get("analysis", ""),
        social=findings.get("social", {}),
    )


def save_html_report(findings: dict) -> Path:
    domain = findings.get("domain", "unknown")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = REPORTS_DIR / f"{domain}_{ts}.html"
    path.write_text(generate_html_report(findings), encoding="utf-8")
    return path


def save_pdf_report(findings: dict) -> Path | None:
    try:
        from weasyprint import HTML as WP_HTML
        domain = findings.get("domain", "unknown")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = REPORTS_DIR / f"{domain}_{ts}.pdf"
        html_content = generate_html_report(findings)
        WP_HTML(string=html_content).write_pdf(str(path))
        return path
    except Exception as e:
        from utils.helpers import log_warn
        log_warn(f"PDF generation failed: {e}")
        return None
