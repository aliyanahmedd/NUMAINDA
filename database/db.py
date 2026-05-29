"""Database helper functions for inserting and querying OSINT findings."""
import json
from database.models import get_connection


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
