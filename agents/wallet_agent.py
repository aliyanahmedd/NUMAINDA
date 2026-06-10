"""Crypto Wallet Intelligence Agent - public on-chain data for a wallet address.

Pulls balance, transaction history, and activity from public explorers
(blockchain.info for BTC, Ethplorer for ETH - both free, no signup).
Supports Bitcoin and Ethereum addresses.

All data is publicly visible on the blockchain. For authorized OSINT only.
"""
from datetime import datetime, timezone

import anthropic

from config.settings import ANTHROPIC_API_KEY
from utils.api_client import btc_address_info, eth_address_info
from utils.validators import detect_wallet_chain
from utils.helpers import log_info, log_success, log_warn, log_error

SATOSHI = 1e8

_NO_AI_MESSAGE = (
    "AI analysis not generated - no ANTHROPIC_API_KEY configured. "
    "On-chain findings above are complete."
)


class WalletAgent:
    def __init__(self):
        self.client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY) if ANTHROPIC_API_KEY else None

    def run(self, address: str) -> dict:
        address = address.strip()
        chain = detect_wallet_chain(address)

        if chain == "bitcoin":
            result = self._bitcoin(address)
        elif chain == "ethereum":
            result = self._ethereum(address)
        else:
            log_error(f"[WalletAgent] Unrecognized wallet address: {address}")
            return {"address": address, "chain": "unknown", "valid": False}

        if result.get("found"):
            result["analysis"] = self._analyze(result)
        return result

    # ── Bitcoin (blockchain.info) ──────────────────────────────────────────────

    def _bitcoin(self, address: str) -> dict:
        log_info(f"[WalletAgent] Scraping bitcoin address {address}")
        data = btc_address_info(address)
        if not data:
            log_warn(f"[WalletAgent] No data for {address}")
            return {"address": address, "chain": "bitcoin", "valid": True, "found": False}

        txs = data.get("txs", []) or []
        result = {
            "address": address,
            "chain": "bitcoin",
            "symbol": "BTC",
            "valid": True,
            "found": True,
            "balance": round(data.get("final_balance", 0) / SATOSHI, 8),
            "total_received": round(data.get("total_received", 0) / SATOSHI, 8),
            "total_spent": round(data.get("total_sent", 0) / SATOSHI, 8),
            "tx_count": data.get("n_tx", len(txs)),
            "last_seen": self._ts(max((t.get("time", 0) for t in txs), default=0)),
            "recent_txs": [t.get("hash") for t in txs[:10]],
            "explorer": f"https://blockchain.info/address/{address}",
        }
        log_success(
            f"[WalletAgent] BTC balance={result['balance']} | {result['tx_count']} txs"
        )
        return result

    # ── Ethereum (Ethplorer) ───────────────────────────────────────────────────

    def _ethereum(self, address: str) -> dict:
        log_info(f"[WalletAgent] Scraping ethereum address {address}")
        data = eth_address_info(address)
        if not data or "error" in data:
            log_warn(f"[WalletAgent] No data for {address}")
            return {"address": address, "chain": "ethereum", "valid": True, "found": False}

        eth = data.get("ETH", {})
        tokens = data.get("tokens", []) or []
        result = {
            "address": address,
            "chain": "ethereum",
            "symbol": "ETH",
            "valid": True,
            "found": True,
            "balance": round(float(eth.get("balance", 0)), 8),
            "tx_count": data.get("countTxs", 0),
            "tokens": [
                {
                    "symbol": t.get("tokenInfo", {}).get("symbol"),
                    "name": t.get("tokenInfo", {}).get("name"),
                    "balance": self._token_balance(t),
                }
                for t in tokens[:25]
            ],
            "explorer": f"https://etherscan.io/address/{address}",
        }
        log_success(
            f"[WalletAgent] ETH balance={result['balance']} "
            f"| {len(result['tokens'])} tokens"
        )
        return result

    # ── Claude AI analysis ─────────────────────────────────────────────────────

    def _analyze(self, w: dict) -> str:
        if not self.client:
            log_warn("[WalletAgent] AI analysis skipped - no ANTHROPIC_API_KEY")
            return _NO_AI_MESSAGE

        log_info("[WalletAgent] Claude analyzing wallet...")
        if w["chain"] == "bitcoin":
            data = (
                f"- Balance: {w['balance']} BTC\n"
                f"- Total received: {w['total_received']} BTC | Total spent: {w['total_spent']} BTC\n"
                f"- Transaction count: {w['tx_count']}\n"
                f"- Last activity: {w.get('last_seen') or 'unknown'}\n"
                f"- Recent tx hashes: {w.get('recent_txs', [])[:5]}"
            )
        else:
            tokens = ", ".join(
                f"{t['symbol']}={t['balance']}" for t in w.get("tokens", []) if t.get("symbol")
            )
            data = (
                f"- Balance: {w['balance']} ETH\n"
                f"- Transaction count: {w['tx_count']}\n"
                f"- Token holdings ({len(w.get('tokens', []))}): {tokens or 'none'}"
            )

        prompt = f"""You are a blockchain intelligence analyst reviewing public on-chain data for a {w['chain']} wallet: {w['address']}

DATA:
{data}

Write a concise wallet intelligence report:
1. SUMMARY (2-3 sentences - what kind of wallet is this: exchange, whale, dormant, active trader, contract, etc.)
2. ACTIVITY PROFILE (balance significance, transaction behavior, holdings)
3. RISK / NOTABLE SIGNALS (dormancy, unusual tokens, mixing indicators, large flows - flag only what the data supports)
4. CAVEATS (what cannot be concluded from on-chain data alone)

Base claims only on the data given. Do not fabricate transaction details."""

        msg = self.client.messages.create(
            model="claude-sonnet-4-6", max_tokens=1200,
            messages=[{"role": "user", "content": prompt}],
        )
        log_success("[WalletAgent] AI analysis complete")
        return msg.content[0].text

    # ── helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _ts(unix: int):
        if not unix:
            return None
        return datetime.fromtimestamp(unix, tz=timezone.utc).strftime("%Y-%m-%d")

    @staticmethod
    def _token_balance(token: dict):
        try:
            decimals = int(token.get("tokenInfo", {}).get("decimals", 0))
            return round(float(token.get("balance", 0)) / (10 ** decimals), 6)
        except (TypeError, ValueError):
            return 0.0
