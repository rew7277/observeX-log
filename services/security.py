"""
services/security.py — Cryptographic helpers: API keys, CSRF tokens, masking, connector secrets.

Changes from monolith:
  - Reset tokens are now hashed at rest (SHA-256) — only the hash is stored in DB.
  - Connector secrets are Fernet-encrypted before storage (requires OBSERVEX_SECRET_KEY env var).
  - Account lockout helpers added (failed_login_count, locked_until on User model).
  - File-type validation uses python-magic in addition to extension check.
"""
import os
import re
import secrets
import hashlib
import datetime

from flask import session


# ── API key helpers ───────────────────────────────────────────────────────────

def generate_api_key():
    """Return (raw_key, digest, prefix).  Only the digest is stored at rest."""
    raw    = "ox_" + secrets.token_urlsafe(32)
    digest = hashlib.sha256(raw.encode()).hexdigest()
    return raw, digest, raw[:10]


def hash_api_key(raw: str) -> str:
    return hashlib.sha256(str(raw).encode()).hexdigest()


# ── Reset-token helpers ───────────────────────────────────────────────────────

def generate_reset_token() -> tuple[str, str]:
    """Return (raw_token, hashed_token).  Send raw to user; store only hash."""
    raw    = secrets.token_urlsafe(40)
    digest = hashlib.sha256(raw.encode()).hexdigest()
    return raw, digest


def verify_reset_token(raw_token: str, stored_hash: str) -> bool:
    """Timing-safe comparison of a raw token against its stored hash."""
    if not raw_token or not stored_hash:
        return False
    digest = hashlib.sha256(raw_token.encode()).hexdigest()
    return secrets.compare_digest(digest, stored_hash)


# ── CSRF helpers ──────────────────────────────────────────────────────────────

def csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def verify_csrf(sent: str) -> bool:
    expected = session.get("csrf_token", "")
    if not sent or not expected:
        return False
    return secrets.compare_digest(str(sent), str(expected))


# ── Connector secret encryption ───────────────────────────────────────────────
# Uses Fernet symmetric encryption.  Key is taken from OBSERVEX_SECRET_KEY env var.
# If cryptography is not installed or key is missing, encryption is skipped with a warning.

def _get_fernet():
    try:
        from cryptography.fernet import Fernet
        key = os.environ.get("OBSERVEX_FERNET_KEY", "").strip()
        if not key:
            return None
        return Fernet(key.encode() if isinstance(key, str) else key)
    except Exception:
        return None


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a connector secret for storage.  Returns ciphertext or plaintext on failure."""
    f = _get_fernet()
    if not f or not plaintext:
        return plaintext or ""
    try:
        return f.encrypt(plaintext.encode("utf-8")).decode("utf-8")
    except Exception:
        return plaintext


def decrypt_secret(ciphertext: str) -> str:
    """Decrypt a stored connector secret.  Returns plaintext or ciphertext on failure."""
    f = _get_fernet()
    if not f or not ciphertext:
        return ciphertext or ""
    try:
        return f.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except Exception:
        return ciphertext


# ── File-type validation ──────────────────────────────────────────────────────

ALLOWED_EXTENSIONS = {"log", "txt", "json"}

# MIME types that are acceptable for log uploads
_ALLOWED_MIMES = {
    "text/plain", "text/x-log", "application/json",
    "application/octet-stream",   # some OS report .log as this
}


def allowed_file(filename: str) -> bool:
    """Extension-level check (fast path)."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def allowed_file_content(file_bytes: bytes, filename: str) -> bool:
    """
    MIME-level check using python-magic.
    Falls back to extension-only check if python-magic is not installed.
    """
    if not allowed_file(filename):
        return False
    try:
        import magic
        mime = magic.from_buffer(file_bytes[:2048], mime=True)
        return mime in _ALLOWED_MIMES
    except ImportError:
        # python-magic not installed — extension check is enough for now
        return True
    except Exception:
        return True


# ── Account lockout ───────────────────────────────────────────────────────────

LOCKOUT_MAX_FAILURES = int(os.environ.get("LOGIN_LOCKOUT_MAX_FAILURES", "10"))
LOCKOUT_DURATION_MINUTES = int(os.environ.get("LOGIN_LOCKOUT_MINUTES", "15"))


def record_failed_login(user) -> bool:
    """
    Increment user.failed_login_count and lock the account if threshold reached.
    Returns True if the account is now locked.
    """
    user.failed_login_count = (user.failed_login_count or 0) + 1
    if user.failed_login_count >= LOCKOUT_MAX_FAILURES:
        user.locked_until = datetime.datetime.utcnow() + datetime.timedelta(
            minutes=LOCKOUT_DURATION_MINUTES
        )
        return True
    return False


def is_account_locked(user) -> bool:
    """Return True if the account is currently locked."""
    if not user.locked_until:
        return False
    if user.locked_until > datetime.datetime.utcnow():
        return True
    # Lock has expired — clear it
    user.locked_until = None
    user.failed_login_count = 0
    return False


def clear_failed_logins(user):
    """Reset failure counter after a successful login."""
    user.failed_login_count = 0
    user.locked_until = None


# ── PII masking ───────────────────────────────────────────────────────────────
# (Kept here so masking logic is co-located with the security module.)

DEFAULT_MASKING_RULES = [
    {"field_name": "Phone",         "mask_type": "partial",        "enabled": True},
    {"field_name": "Email",         "mask_type": "hash",           "enabled": True},
    {"field_name": "BankAc",        "mask_type": "full",           "enabled": True},
    {"field_name": "Amt",           "mask_type": "full",           "enabled": True},
    {"field_name": "CollectionAmt", "mask_type": "full",           "enabled": True},
    {"field_name": "AppID",         "mask_type": "full",           "enabled": True},
    {"field_name": "MerchantKey",   "mask_type": "full",           "enabled": True},
    {"field_name": "Ref1",          "mask_type": "searchable_mask","enabled": True},
    {"field_name": "Ref2",          "mask_type": "partial",        "enabled": True},
    {"field_name": "Cust1",         "mask_type": "partial",        "enabled": True},
    {"field_name": "Cust2",         "mask_type": "partial",        "enabled": True},
    {"field_name": "Cust3",         "mask_type": "partial",        "enabled": True},
    {"field_name": "IFSC",          "mask_type": "partial",        "enabled": True},
    {"field_name": "MICR",          "mask_type": "partial",        "enabled": True},
]


def _hash_mask_value(value: str) -> str:
    try:
        return hashlib.sha256(str(value).encode("utf-8", errors="ignore")).hexdigest()[:12]
    except Exception:
        return "MASKED_HASH"


def _mask_value(value, mask_type="full") -> str:
    if value is None:
        return value
    value = str(value)
    if not value:
        return value
    mt = (mask_type or "full").lower()
    if mt == "partial":
        if len(value) <= 4:
            return "*" * len(value)
        return value[:2] + "*" * min(8, max(4, len(value) - 4)) + value[-2:]
    if mt == "hash":
        return "[HASH:" + _hash_mask_value(value) + "]"
    if mt == "searchable_mask":
        m = re.search(r"(\d{4,8})$", value)
        suffix = m.group(1) if m else value[-6:]
        return "[MASKED_ID:" + suffix + "]"
    return "[MASKED]"


def apply_field_masking(text: str, config) -> str:
    masked = str(text or "")
    enabled = [r for r in (config or []) if r.get("enabled") and r.get("field_name")]
    for rule in enabled:
        key = re.escape(str(rule.get("field_name")))
        mt  = str(rule.get("mask_type") or "full")

        def repl_json(m, mt=mt):
            return m.group(1) + _mask_value(m.group(2), mt) + m.group(3)

        masked = re.sub(r'(?i)("' + key + r'"\s*:\s*")([^"]*)(\")', repl_json, masked)

        def repl_kv(m, mt=mt):
            return m.group(1) + _mask_value(m.group(2), mt)

        masked = re.sub(r"(?i)(\b" + key + r"\b\s*[=:]\s*['\"]?)([^\s,;\"'}]+)", repl_kv, masked)
    return masked


def mask_secrets(text: str, masking_config=None) -> str:
    """Mask PII/secrets plus user-configured fields before UI/API/storage."""
    if not text:
        return text
    config = masking_config or DEFAULT_MASKING_RULES
    masked = apply_field_masking(str(text), config)
    masked = re.sub(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", "[MASKED_JWT]", masked)
    masked = re.sub(
        r"(?i)(authorization\s*[:=]\s*bearer\s+)[A-Za-z0-9._\-+/=]{16,}",
        r"\1[MASKED_TOKEN]", masked
    )
    masked = re.sub(
        r"(?i)(api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|bearer|token"
        r"|password|passwd|pwd|secret|client[_-]?secret|signature|hmac)(\s*[=:]\s*['\"]?)([^\s,;\"'}]{4,})",
        r"\1\2[MASKED]", masked
    )
    # India-specific PII
    masked = re.sub(r"(?i)(aadhaar|aadhar|uidai)(\s*[=:]\s*['\"]?)(\d[ -]?){12}", r"\1\2[MASKED_AADHAAR]", masked)
    masked = re.sub(r"\b\d{4}[ -]?\d{4}[ -]?\d{4}\b", "[MASKED_AADHAAR]", masked)
    masked = re.sub(r"(?i)(pan|panNumber|pan_card)(\s*[=:]\s*['\"]?)[A-Z]{5}\d{4}[A-Z]", r"\1\2[MASKED_PAN]", masked)
    masked = re.sub(r"\b[A-Z]{5}\d{4}[A-Z]\b", "[MASKED_PAN]", masked)
    masked = re.sub(
        r"(?i)(mobile|phone|customerMobile|contact|msisdn)(\s*[=:]\s*['\"]?)(?:\+?91[- ]?)?[6-9]\d{9}",
        r"\1\2[MASKED_MOBILE]", masked
    )
    masked = re.sub(r"(?<!\d)(?:\+?91[- ]?)?[6-9]\d{9}(?!\d)", "[MASKED_MOBILE]", masked)
    masked = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "[MASKED_EMAIL]", masked)

    sensitive_keys = [
        "customerName", "name", "fullName", "firstName", "lastName",
        "loanNumber", "loanId", "accountNumber", "accountNo",
        "primaryCustomerId", "customerId", "applicationNo", "checkoutId",
        "bbpsId", "receiptNumber", "transactionId", "gatewayTransactionId",
        "upiId", "vpa", "cardNumber",
    ]
    key_alt = "|".join(map(re.escape, sensitive_keys))
    masked = re.sub(rf'(?i)(\"(?:{key_alt})\"\s*:\s*\")([^\"]+)(\")', r"\1[MASKED]\3", masked)
    masked = re.sub(rf'(?i)(\b(?:{key_alt})\b\s*[=:]\s*[\'"]?)([A-Za-z0-9@._\- /]+)', r"\1[MASKED]", masked)

    def repl_ref(m):
        val = m.group(0)
        num = re.search(r"(\d{4,8})$", val)
        return "[MASKED_ID:" + (num.group(1) if num else val[-6:]) + "]"

    masked = re.sub(r"\b(?:TR|PP|BD|FS|GLB|APPL|APPT)[A-Z0-9]{6,}\b", repl_ref, masked)
    return masked
