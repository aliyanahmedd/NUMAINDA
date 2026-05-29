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
        lines.append(f"  • {e['email']} ({e.get('position','-')}, confidence={e.get('confidence',0)}%)")
    if len(emails) > 10:
        lines.append(f"  ... and {len(emails) - 10} more")

    lines += [
        "",
        "[SUBDOMAIN ENUMERATION]",
        f"  {len(subdomains)} subdomains found | {len(risky_subs)} flagged as risky",
    ]
    for s in risky_subs:
        lines.append(f"  ⚠  {s['subdomain']} (IP: {s.get('ip','-')})")

    lines += [
        "",
        "[BREACH INTELLIGENCE]",
        f"  {len(breaches)} breach record(s) found",
    ]
    for b in breaches:
        lines.append(f"  • {b['email']} in {b['breach_name']} ({b.get('breach_date','-')})")

    lines += [
        "",
        "[THREAT INTELLIGENCE]",
        f"  {len(malicious)} malicious indicator(s) detected",
    ]
    for t in malicious:
        lines.append(f"  ✗ {t['indicator']} - {t.get('engine_hits',0)} engines flagged")

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


def _ascii(text: str) -> str:
    """Replace common non-latin-1 glyphs so fpdf core fonts can render them."""
    repl = {
        "•": "-", "◦": "-", "·": "-", "→": "->", "⚠": "[!]", "✗": "x",
        "✓": "v", "★": "*", "└": "+", "├": "+", "─": "-", "│": "|",
        "≥": ">=", "≤": "<=", "“": '"', "”": '"', "’": "'", "‘": "'",
    }
    for k, v in repl.items():
        text = text.replace(k, v)
    return text.encode("latin-1", "replace").decode("latin-1")


def save_pdf_report(findings: dict) -> Path | None:
    """Render a clean structured PDF using fpdf2 (pure Python, no system libs)."""
    try:
        from fpdf import FPDF
    except ImportError:
        from utils.helpers import log_warn
        log_warn("fpdf2 not installed; run: pip install fpdf2")
        return None

    try:
        domain = findings.get("domain", "unknown")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = REPORTS_DIR / f"{domain}_{ts}.pdf"

        scores       = findings.get("scores", {})
        emails       = findings.get("emails", [])
        subdomains   = findings.get("subdomains", [])
        breaches     = findings.get("breaches", [])
        threat_intel = findings.get("threat_intel", [])
        tech         = findings.get("tech", {})
        analysis     = findings.get("analysis", "")

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        # Header
        pdf.set_fill_color(47, 159, 222)
        pdf.rect(0, 0, 210, 26, "F")
        pdf.set_xy(12, 7)
        pdf.set_font("Helvetica", "B", 18)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(0, 12, "OSINT Intelligence Report", ln=1)
        pdf.set_text_color(30, 30, 30)
        pdf.set_xy(pdf.l_margin, 32)

        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 8, _ascii(f"Target: {domain}"), ln=1)
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(110, 110, 110)
        pdf.cell(0, 6, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=1)
        pdf.set_text_color(30, 30, 30)
        pdf.ln(4)

        def heading(t):
            pdf.ln(2)
            pdf.set_x(pdf.l_margin)
            pdf.set_font("Helvetica", "B", 12)
            pdf.set_text_color(47, 159, 222)
            pdf.multi_cell(pdf.epw, 8, _ascii(t))
            pdf.set_text_color(30, 30, 30)
            pdf.set_font("Helvetica", "", 10)

        def line(t):
            pdf.set_x(pdf.l_margin)
            pdf.set_font("Helvetica", "", 10)
            pdf.multi_cell(pdf.epw, 5.5, _ascii(t))

        # Risk scores
        heading("Risk Scores")
        for label, key in [
            ("Overall Attack Surface", "total"), ("Email Exposure", "email"),
            ("Subdomain Exposure", "subdomain"), ("Breach Risk", "breach"),
            ("Threat Intelligence", "threat"), ("SSL", "ssl"),
            ("CVEs", "cve"), ("Open Ports", "port"),
        ]:
            if key in scores:
                line(f"  {label:<26}: {scores.get(key, 0):.1f} / 10")

        heading(f"Email Intelligence ({len(emails)})")
        for e in emails[:25]:
            line(f"  - {e.get('email','')}  ({e.get('position') or '-'}, conf={e.get('confidence',0)}%)")
        if not emails: line("  None discovered")

        risky = [s for s in subdomains if s.get("risk_flag")]
        heading(f"Subdomains ({len(subdomains)} total, {len(risky)} risky)")
        for s in subdomains[:40]:
            flag = "  [RISKY]" if s.get("risk_flag") else ""
            line(f"  - {s.get('subdomain','')}  {s.get('ip','')}{flag}")
        if not subdomains: line("  None found")

        heading(f"Breach Records ({len(breaches)})")
        for b in breaches:
            line(f"  - {b.get('email','')} in {b.get('breach_name','')}")
        if not breaches: line("  None found")

        malicious = [t for t in threat_intel if t.get("malicious")]
        heading(f"Threat Intelligence ({len(malicious)} malicious)")
        for t in threat_intel[:20]:
            status = "MALICIOUS" if t.get("malicious") else "clean"
            line(f"  - {t.get('indicator','')}  [{status}]  ({t.get('source','')})")
        if not threat_intel: line("  No data")

        heading("Tech Stack")
        line("  " + (", ".join(tech.get("technologies", [])) or "Unknown"))

        if analysis:
            heading("AI Analysis")
            line(analysis)

        pdf.output(str(path))
        return path
    except Exception as e:
        from utils.helpers import log_warn
        log_warn(f"PDF generation failed: {e}")
        return None
