"""Input validation helpers."""
import re
import ipaddress


def is_valid_domain(value: str) -> bool:
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, value.strip()))


def is_valid_email(value: str) -> bool:
    pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
    return bool(re.match(pattern, value.strip()))


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def detect_input_type(value: str) -> str:
    """Return 'domain' | 'email' | 'ip' | 'unknown'."""
    value = value.strip()
    if is_valid_email(value):
        return "email"
    if is_valid_ip(value):
        return "ip"
    if is_valid_domain(value):
        return "domain"
    return "unknown"


def is_valid_eth_address(value: str) -> bool:
    return bool(re.match(r"^0x[a-fA-F0-9]{40}$", value.strip()))


def is_valid_btc_address(value: str) -> bool:
    value = value.strip()
    # Legacy P2PKH/P2SH (base58) or bech32 (segwit)
    if re.match(r"^(bc1)[a-z0-9]{25,90}$", value):
        return True
    return bool(re.match(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$", value))


def detect_wallet_chain(value: str) -> str:
    """Return 'ethereum' | 'bitcoin' | 'unknown'."""
    value = value.strip()
    if is_valid_eth_address(value):
        return "ethereum"
    if is_valid_btc_address(value):
        return "bitcoin"
    return "unknown"


def extract_domain_from_email(email: str) -> str:
    return email.split("@")[-1].lower().strip()


def normalize_domain(domain: str) -> str:
    return domain.lower().strip().removeprefix("http://").removeprefix("https://").split("/")[0]
