#!/usr/bin/env python3
"""
OSINT Agent - Entry Point

Usage:
    python main.py <target>

Examples:
    python main.py example.com
    python main.py john@example.com
"""
import sys
import json
from pathlib import Path

from utils.helpers import print_banner, log_success, log_error, print_section
from agents.orchestrator import OSINTOrchestrator
from output.report_generator import save_text_report, save_html_report
from output.graph_visualizer import save_graph


def main():
    print_banner()

    if len(sys.argv) < 2:
        log_error("Usage: python main.py <domain|email>")
        log_error("Example: python main.py example.com")
        sys.exit(1)

    target = sys.argv[1].strip()
    orchestrator = OSINTOrchestrator()

    try:
        findings = orchestrator.run(target)
    except KeyboardInterrupt:
        log_error("Interrupted by user.")
        sys.exit(0)
    except Exception as e:
        log_error(f"Agent failed: {e}")
        raise

    # ── Save outputs ───────────────────────────────────────────────────────────
    print_section("Generating Reports")

    txt_path = save_text_report(findings)
    log_success(f"Text report : {txt_path}")

    html_path = save_html_report(findings)
    log_success(f"HTML report : {html_path}")

    graph_path = save_graph(findings)
    log_success(f"Network graph: {graph_path}")

    # JSON dump for programmatic use
    json_path = txt_path.with_suffix(".json")
    serializable = {k: v for k, v in findings.items() if isinstance(v, (str, int, float, list, dict))}
    json_path.write_text(json.dumps(serializable, indent=2, default=str), encoding="utf-8")
    log_success(f"JSON export : {json_path}")

    print_section("Done")
    scores = findings.get("scores", {})
    print(f"\n  Overall Attack Surface Risk: {scores.get('total', 0):.1f} / 10\n")


if __name__ == "__main__":
    main()
