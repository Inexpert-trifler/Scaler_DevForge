"""HMAC-SHA256 keyed pseudonym generation.

Implements TR-PRV-1:
- Pseudonym = PSN- + 6 Crockford-base32 chars of HMAC-SHA256(secret, "psn|" + cluster_key)
- Crockford-base32 alphabet: "0123456789ABCDEFGHJKMNPQRSTVWXYZ" (excludes I, L, O, U)
- Fully deterministic, keyed on secret
"""
from __future__ import annotations
import hashlib
import hmac


CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def encode_crockford(data: bytes, length: int = 6) -> str:
    """Encode binary data into Crockford's Base32 string of fixed length."""
    # 6 characters * 5 bits = 30 bits
    val = int.from_bytes(data[:4], "big") >> 2
    chars = []
    for _ in range(length):
        chars.append(CROCKFORD_ALPHABET[val & 0x1F])
        val >>= 5
    return "".join(reversed(chars))


def pseudonym(cluster_key: str, secret: bytes, policy: dict) -> str:
    """Generate deterministic HMAC-SHA256 keyed Crockford-base32 pseudonym PSN-XXXXXX."""
    prefix = policy.get("psn_prefix", "PSN-")
    h = hmac.new(secret, f"psn|{cluster_key}".encode("utf-8"), hashlib.sha256).digest()
    token = encode_crockford(h, length=6)
    return f"{prefix}{token}"
