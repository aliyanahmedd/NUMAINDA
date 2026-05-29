"""Database helper functions for inserting and querying OSINT findings."""
import json
from database.models import get_connection
import sqlite3


def create_target(input_value: str, input_type: str) -> int:
    conn = get_connection()
    cur = conn.execute(
        "INSERT INTO targets (input, input_type) VALUES (?, ?)",
        (input_value, input_type),
    )
    target_id = cur.lastrowid
    conn.commit()
    conn.close()
    return target_id


def insert_emails(target_id: int, emails: list[dict]):
    conn = get_connection()
    conn.executemany(
        """INSERT INTO emails (target_id, email, first_name, last_name, position, confidence, source)
           VALUES (:target_id, :email, :first_name, :last_name, :position, :confidence, :source)""",
        [{**e, "target_id": target_id} for e in emails],
    )
    conn.commit()
    conn.close()


def insert_subdomains(target_id: int, subdomains: list[dict]):
    conn = get_connection()
    conn.executemany(
        """INSERT INTO subdomains (target_id, subdomain, ip, open_ports, technology, risk_flag)
           VALUES (:target_id, :subdomain, :ip, :open_ports, :technology, :risk_flag)""",
        [
            {
                **s,
                "target_id": target_id,
                "open_ports": json.dumps(s.get("open_ports", [])),
                "technology": json.dumps(s.get("technology", [])),
            }
            for s in subdomains
        ],
    )
    conn.commit()
    conn.close()


def insert_breaches(target_id: int, breaches: list[dict]):
    conn = get_connection()
    conn.executemany(
        """INSERT INTO breaches (target_id, email, breach_name, breach_date, data_types)
           VALUES (:target_id, :email, :breach_name, :breach_date, :data_types)""",
        [
            {
                **b,
                "target_id": target_id,
                "data_types": json.dumps(b.get("data_types", [])),
            }
            for b in breaches
        ],
    )
    conn.commit()
    conn.close()


def insert_threat_intel(target_id: int, findings: list[dict]):
    conn = get_connection()
    conn.executemany(
        """INSERT INTO threat_intel (target_id, indicator, indicator_type, malicious, engine_hits, vt_link)
           VALUES (:target_id, :indicator, :indicator_type, :malicious, :engine_hits, :vt_link)""",
        [{**f, "target_id": target_id} for f in findings],
    )
    conn.commit()
    conn.close()


def insert_dns_records(target_id: int, records: list[dict]):
    conn = get_connection()
    conn.executemany(
        "INSERT INTO dns_records (target_id, record_type, value) VALUES (:target_id, :record_type, :value)",
        [{**r, "target_id": target_id} for r in records],
    )
    conn.commit()
    conn.close()


def upsert_risk_score(target_id: int, scores: dict):
    conn = get_connection()
    conn.execute(
        """INSERT INTO risk_scores
               (target_id, total_score, email_score, subdomain_score, breach_score,
                threat_score, ssl_score, cve_score, port_score)
           VALUES (:target_id, :total, :email, :subdomain, :breach, :threat,
                   :ssl, :cve, :port)
           ON CONFLICT(target_id) DO UPDATE SET
               total_score=excluded.total_score,
               email_score=excluded.email_score,
               subdomain_score=excluded.subdomain_score,
               breach_score=excluded.breach_score,
               threat_score=excluded.threat_score,
               ssl_score=excluded.ssl_score,
               cve_score=excluded.cve_score,
               port_score=excluded.port_score,
               computed_at=CURRENT_TIMESTAMP""",
        {
            "target_id": target_id,
            "total":     scores.get("total", 0),
            "email":     scores.get("email", 0),
            "subdomain": scores.get("subdomain", 0),
            "breach":    scores.get("breach", 0),
            "threat":    scores.get("threat", 0),
            "ssl":       scores.get("ssl", 0),
            "cve":       scores.get("cve", 0),
            "port":      scores.get("port", 0),
        },
    )
    conn.commit()
    conn.close()


def insert_geo_data(target_id: int, entries: list[dict]):
    conn = get_connection()
    conn.executemany(
        """INSERT INTO geo_data (target_id, ip, country, country_code, city, org, isp, lat, lon)
           VALUES (:target_id, :ip, :country, :country_code, :city, :org, :isp, :lat, :lon)""",
        [{**e, "target_id": target_id} for e in entries],
    )
    conn.commit()
    conn.close()


def insert_ssl_certs(target_id: int, certs: list[dict]):
    conn = get_connection()
    rows = []
    if certs.get("main"):
        rows.append(certs["main"])
    rows += certs.get("subdomains", [])
    conn.executemany(
        """INSERT INTO ssl_certs
           (target_id, hostname, valid, expires, days_left, issuer, subject, expired, expiring_soon)
           VALUES (:target_id, :hostname, :valid, :expires, :days_left, :issuer, :subject, :expired, :expiring_soon)""",
        [{**r, "target_id": target_id} for r in rows if r],
    )
    conn.commit()
    conn.close()


def insert_cve_findings(target_id: int, findings: list[dict]):
    conn = get_connection()
    rows = []
    for entry in findings:
        for cve in entry.get("cves", []):
            rows.append({
                "target_id": target_id,
                "tech": entry["tech"],
                "version": entry.get("version", ""),
                "cve_id": cve["id"],
                "score": cve.get("score"),
                "severity": cve.get("severity", ""),
                "description": cve.get("description", ""),
                "url": cve.get("url", ""),
            })
    if rows:
        conn.executemany(
            """INSERT INTO cve_findings
               (target_id, tech, version, cve_id, score, severity, description, url)
               VALUES (:target_id, :tech, :version, :cve_id, :score, :severity, :description, :url)""",
            rows,
        )
    conn.commit()
    conn.close()


def insert_paste_findings(target_id: int, pastes: list[dict]):
    conn = get_connection()
    conn.executemany(
        """INSERT INTO paste_findings (target_id, paste_id, paste_date, snippet, url, keyword)
           VALUES (:target_id, :id, :date, :snippet, :url, :keyword)""",
        [{**p, "target_id": target_id} for p in pastes],
    )
    conn.commit()
    conn.close()


def insert_port_findings(target_id: int, findings: list[dict]):
    conn = get_connection()
    conn.executemany(
        """INSERT INTO port_findings (target_id, ip, hostname, ports, services, dangerous, source)
           VALUES (:target_id, :ip, :hostname, :ports, :services, :dangerous, :source)""",
        [
            {
                **f,
                "target_id": target_id,
                "ports": json.dumps(f.get("ports", [])),
                "services": json.dumps(f.get("services", {})),
                "dangerous": json.dumps(f.get("dangerous", [])),
            }
            for f in findings
        ],
    )
    conn.commit()
    conn.close()


def insert_scan_files(target_id: int, graph_path: str = None, html_path: str = None,
                      txt_path: str = None, json_path: str = None):
    conn = get_connection()
    conn.execute(
        """INSERT INTO scan_files (target_id, graph_path, html_path, txt_path, json_path)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(target_id) DO UPDATE SET
               graph_path=excluded.graph_path,
               html_path=excluded.html_path,
               txt_path=excluded.txt_path,
               json_path=excluded.json_path""",
        (target_id, graph_path, html_path, txt_path, json_path),
    )
    conn.commit()
    conn.close()


def get_scan_files(target_id: int) -> dict:
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM scan_files WHERE target_id=?", (target_id,)).fetchone()
    conn.close()
    return dict(row) if row else {}


def insert_analysis(target_id: int, content: str):
    conn = get_connection()
    conn.execute(
        """INSERT INTO analysis (target_id, content) VALUES (?, ?)
           ON CONFLICT(target_id) DO UPDATE SET content=excluded.content""",
        (target_id, content),
    )
    conn.commit()
    conn.close()


def get_all_records() -> list[dict]:
    conn = get_connection()
    conn.row_factory = __import__('sqlite3').Row
    rows = conn.execute("""
        SELECT t.id, t.input, t.input_type, t.created_at,
               rs.total_score,
               (SELECT COUNT(*) FROM emails WHERE target_id=t.id) AS email_count,
               (SELECT COUNT(*) FROM subdomains WHERE target_id=t.id) AS subdomain_count,
               (SELECT COUNT(*) FROM breaches WHERE target_id=t.id) AS breach_count,
               (SELECT COUNT(*) FROM threat_intel WHERE target_id=t.id AND malicious=1) AS threat_count
        FROM targets t
        LEFT JOIN risk_scores rs ON rs.target_id = t.id
        ORDER BY t.created_at DESC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_record_detail(target_id: int) -> dict:
    conn = get_connection()
    conn.row_factory = __import__('sqlite3').Row

    def fetch(table, cols="*"):
        return [dict(r) for r in conn.execute(
            f"SELECT {cols} FROM {table} WHERE target_id=?", (target_id,)
        ).fetchall()]

    target = conn.execute("SELECT * FROM targets WHERE id=?", (target_id,)).fetchone()
    if not target:
        conn.close()
        return {}

    score_row = conn.execute(
        "SELECT * FROM risk_scores WHERE target_id=?", (target_id,)
    ).fetchone()

    record = {
        "target_id":  target_id,
        "input":      target["input"],
        "input_type": target["input_type"],
        "created_at": target["created_at"],
        "domain":     target["input"],
        "scan_type":  target["input_type"],
        "scores": {
            "total":     score_row["total_score"]     if score_row else 0,
            "email":     score_row["email_score"]     if score_row else 0,
            "subdomain": score_row["subdomain_score"] if score_row else 0,
            "breach":    score_row["breach_score"]    if score_row else 0,
            "threat":    score_row["threat_score"]    if score_row else 0,
            "ssl":       (score_row["ssl_score"]  if score_row and "ssl_score"  in score_row.keys() else 0),
            "cve":       (score_row["cve_score"]  if score_row and "cve_score"  in score_row.keys() else 0),
            "port":      (score_row["port_score"] if score_row and "port_score" in score_row.keys() else 0),
            "paste":     0,
        } if score_row else {},
        "emails":     fetch("emails"),
        "subdomains": fetch("subdomains"),
        "breaches":   fetch("breaches"),
        "threat_intel": fetch("threat_intel"),
        "dns":        {"records": fetch("dns_records", "record_type, value"), "whois": {}},
        "geo":        fetch("geo_data"),
        "ssl":        {},
        "cves":       [],
        "pastes":     fetch("paste_findings", "paste_id AS id, paste_date AS date, snippet, url, keyword"),
        "ports":      fetch("port_findings"),
        "tech":       {"technologies": [], "versioned": {}, "cms": None, "server": None, "waf": None},
        "social":     {"repositories": [], "github_users": []},
        "analysis":   (conn.execute("SELECT content FROM analysis WHERE target_id=?", (target_id,)).fetchone() or [""])[0],
    }

    ssl_rows = fetch("ssl_certs")
    if ssl_rows:
        main = ssl_rows[0]
        record["ssl"] = {
            "main": {
                "hostname":      main.get("hostname"),
                "valid":         bool(main.get("valid")),
                "expires":       main.get("expires"),
                "days_left":     main.get("days_left"),
                "issuer":        main.get("issuer"),
                "subject":       main.get("subject"),
                "expired":       bool(main.get("expired")),
                "expiring_soon": bool(main.get("expiring_soon")),
            },
            "subdomains": []
        }

    cve_rows = fetch("cve_findings")
    cve_map: dict = {}
    for c in cve_rows:
        t = c.get("tech", "unknown")
        if t not in cve_map:
            cve_map[t] = {"tech": t, "version": c.get("version", ""), "cves": []}
        cve_map[t]["cves"].append({
            "id": c.get("cve_id"), "score": c.get("score"),
            "severity": c.get("severity"), "description": c.get("description"),
            "url": c.get("url"),
        })
    record["cves"] = list(cve_map.values())

    port_rows = fetch("port_findings")
    import json as _json
    record["ports"] = []
    for p in port_rows:
        record["ports"].append({
            "ip":       p.get("ip"),
            "hostname": p.get("hostname"),
            "ports":    _json.loads(p.get("ports", "[]")),
            "services": _json.loads(p.get("services", "{}")),
            "dangerous": _json.loads(p.get("dangerous", "[]")),
        })

    # Fix subdomains open_ports/technology fields
    for s in record["subdomains"]:
        for key in ("open_ports", "technology"):
            if isinstance(s.get(key), str):
                try:
                    s[key] = _json.loads(s[key])
                except Exception:
                    s[key] = []

    conn.close()
    return record


def get_full_report(target_id: int) -> dict:
    conn = get_connection()
    conn.row_factory = sqlite3.Row

    def fetch(table, cols="*"):
        return [dict(r) for r in conn.execute(
            f"SELECT {cols} FROM {table} WHERE target_id=?", (target_id,)
        ).fetchall()]

    import sqlite3
    conn.row_factory = sqlite3.Row
    target = dict(conn.execute("SELECT * FROM targets WHERE id=?", (target_id,)).fetchone())
    report = {
        "target": target,
        "emails": fetch("emails"),
        "subdomains": fetch("subdomains"),
        "breaches": fetch("breaches"),
        "threat_intel": fetch("threat_intel"),
        "dns_records": fetch("dns_records"),
        "risk_scores": fetch("risk_scores"),
    }
    conn.close()
    return report
