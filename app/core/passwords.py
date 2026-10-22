import hashlib
import hmac
import secrets

# PBKDF2-SHA256 from the standard library, stored as
# "pbkdf2_sha256$<iterations>$<salt hex>$<hash hex>".
ALGORITHM = "pbkdf2_sha256"
ITERATIONS = 390_000

# Seed data written before real hashing stored "hash_<password>".
LEGACY_PREFIX = "hash_"


def hash_password(password: str, *, iterations: int = ITERATIONS) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"{ALGORITHM}${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, iterations, salt_hex, digest_hex = stored.split("$")
        if algorithm != ALGORITHM:
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations)
        )
    except (ValueError, AttributeError):
        return False
    return hmac.compare_digest(digest.hex(), digest_hex)


def is_legacy_hash(stored: str) -> bool:
    return isinstance(stored, str) and stored.startswith(LEGACY_PREFIX)
