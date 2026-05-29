import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).parent.parent

# API Keys
HUNTER_API_KEY = os.getenv("HUNTER_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
BREACHDIRECTORY_API_KEY = os.getenv("BREACHDIRECTORY_API_KEY", "")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
SHODAN_API_KEY    = os.getenv("SHODAN_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

# Timeouts & rate limits
REQUEST_TIMEOUT = 15           # seconds per HTTP request
RATE_LIMIT_DELAY = 1.0        # seconds between API calls
MAX_EMAILS_PER_DOMAIN = 100
MAX_SUBDOMAINS = 500

# Database
DATABASE_PATH = BASE_DIR / "database" / "osint.db"

# Output
REPORTS_DIR = BASE_DIR / "output" / "reports"
GRAPHS_DIR = BASE_DIR / "output" / "graphs"

# Risk thresholds (0–10 scale)
RISK_HIGH = 7.0
RISK_MEDIUM = 4.0
