"""HMAC-SHA256 keyed pseudonym generation."""
import hashlib
import hmac


def pseudonym(cluster_key: str, secret: bytes, policy: dict) -> str:
    """Generate deterministic HMAC-SHA256 keyed pseudonym PSN-XXXXXX."""
    prefix = policy.get("psn_prefix", "PSN-")
    h = hmac.new(secret, f"psn|{cluster_key}".encode("utf-8"), hashlib.sha256).hexdigest()
    # Take first 6 uppercase alphanumeric characters
    token = h[:6].upper()
    return f"{prefix}{token}"
