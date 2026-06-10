#!/usr/bin/env python3
"""
Crypto Wallet Scraper - Entry Point

Usage:
    python scrape_wallet.py <wallet_address>

Examples:
    python scrape_wallet.py 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa        # Bitcoin
    python scrape_wallet.py 0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe  # Ethereum
"""
import sys
import json

from utils.helpers import log_error, print_section
from agents.wallet_agent import WalletAgent


def main():
    if len(sys.argv) < 2:
        log_error("Usage: python scrape_wallet.py <wallet_address>")
        sys.exit(1)

    address = sys.argv[1].strip()
    result = WalletAgent().run(address)

    print_section("Wallet Intelligence")
    print(json.dumps(result, indent=2, default=str))

    if not result.get("valid"):
        sys.exit(1)


if __name__ == "__main__":
    main()
