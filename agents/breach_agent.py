"""Breach Intelligence Agent - checks BreachDirectory (free via RapidAPI)."""
from utils.api_client import breachdirectory_check_email
from utils.helpers import log_info, log_success, log_warn
from database.db import insert_breaches


class BreachAgent:
    def run(self, target_id: int, emails: list[dict]) -> list[dict]:
        log_info(f"[BreachAgent] Checking {len(emails)} emails against BreachDirectory")
        all_breaches = []

        for entry in emails:
            email = entry.get("email", "")
            if not email:
                continue

            data = breachdirectory_check_email(email)
            if not data or not data.get("success"):
                log_warn(f"[BreachAgent] No data returned for {email}")
                continue

            results = data.get("result", [])
            if not results:
                continue

            sources = set()
            for r in results:
                for source in r.get("sources", []):
                    sources.add(source)

            for source in sources:
                all_breaches.append({
                    "email": email,
                    "breach_name": source,
                    "breach_date": "",
                    "data_types": ["email", "password"],
                })
                log_warn(f"[BreachAgent] {email} found in breach: {source}")

        if all_breaches:
            insert_breaches(target_id, all_breaches)
            log_success(f"[BreachAgent] {len(all_breaches)} breach records saved")
        else:
            log_success("[BreachAgent] No breaches found for discovered emails")

        return all_breaches
