"""SQLite schema for storing OSINT findings."""
import sqlite3
from config.settings import DATABASE_PATH


SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    input       TEXT NOT NULL,
    input_type  TEXT NOT NULL,   -- domain | email | person | company
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS emails (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER REFERENCES targets(id),
    email       TEXT NOT NULL,
    first_name  TEXT,
    last_name   TEXT,
    position    TEXT,
    confidence  INTEGER,
    source      TEXT
);

CREATE TABLE IF NOT EXISTS subdomains (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER REFERENCES targets(id),
    subdomain   TEXT NOT NULL,
    ip          TEXT,
    open_ports  TEXT,            -- JSON array
    technology  TEXT,            -- JSON array
    risk_flag   INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS breaches (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER REFERENCES targets(id),
    email       TEXT,
    breach_name TEXT,
    breach_date TEXT,
    data_types  TEXT             -- JSON array (passwords, emails, etc.)
);

CREATE TABLE IF NOT EXISTS threat_intel (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER REFERENCES targets(id),
    indicator   TEXT,
    indicator_type TEXT,         -- domain | ip | url
    malicious   INTEGER DEFAULT 0,
    engine_hits INTEGER DEFAULT 0,
    vt_link     TEXT
);

CREATE TABLE IF NOT EXISTS dns_records (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER REFERENCES targets(id),
    record_type TEXT,
    value       TEXT
);

CREATE TABLE IF NOT EXISTS risk_scores (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER REFERENCES targets(id) UNIQUE,
    total_score REAL,
    email_score REAL,
    subdomain_score REAL,
    breach_score REAL,
    threat_score REAL,
    ssl_score   REAL DEFAULT 0,
    cve_score   REAL DEFAULT 0,
    port_score  REAL DEFAULT 0,
    computed_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS geo_data (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id    INTEGER REFERENCES targets(id),
    ip           TEXT,
    country      TEXT,
    country_code TEXT,
    city         TEXT,
    org          TEXT,
    isp          TEXT,
    lat          REAL,
    lon          REAL
);

CREATE TABLE IF NOT EXISTS ssl_certs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id    INTEGER REFERENCES targets(id),
    hostname     TEXT,
    valid        INTEGER,
    expires      TEXT,
    days_left    INTEGER,
    issuer       TEXT,
    subject      TEXT,
    expired      INTEGER DEFAULT 0,
    expiring_soon INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS cve_findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id    INTEGER REFERENCES targets(id),
    tech         TEXT,
    version      TEXT,
    cve_id       TEXT,
    score        REAL,
    severity     TEXT,
    description  TEXT,
    url          TEXT
);

CREATE TABLE IF NOT EXISTS paste_findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id    INTEGER REFERENCES targets(id),
    paste_id     TEXT,
    paste_date   TEXT,
    snippet      TEXT,
    url          TEXT,
    keyword      TEXT
);

CREATE TABLE IF NOT EXISTS port_findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id    INTEGER REFERENCES targets(id),
    ip           TEXT,
    hostname     TEXT,
    ports        TEXT,
    services     TEXT,
    dangerous    TEXT,
    source       TEXT
);
"""


def init_db():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH)
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


def get_connection():
    return sqlite3.connect(DATABASE_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
