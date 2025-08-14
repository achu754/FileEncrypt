import hmac
import hashlib


class IntegrityVerifier:
    """Handles integrity verification using HMAC."""
    
    @staticmethod
    def generate_hmac(data: bytes, key: bytes) -> bytes:
        """Generate HMAC-SHA256 for data."""
        return hmac.new(key, data, hashlib.sha256).digest()
    
    @staticmethod
    def verify_hmac(data: bytes, key: bytes, expected_hmac: bytes) -> bool:
        """Verify HMAC-SHA256 for data."""
        computed_hmac = IntegrityVerifier.generate_hmac(data, key)
        return hmac.compare_digest(computed_hmac, expected_hmac)
    
    @staticmethod
    def generate_hmac_key(master_key: bytes) -> bytes:
        """Derive HMAC key from master key."""
        return hashlib.sha256(master_key + b"HMAC_KEY").digest()