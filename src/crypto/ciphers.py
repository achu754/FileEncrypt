import os
from abc import ABC, abstractmethod
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend
from .utils import generate_iv


class CipherType:
    AES_256_GCM = "aes-256-gcm"
    AES_256_CBC = "aes-256-cbc"
    CHACHA20_POLY1305 = "chacha20-poly1305"


class BaseCipher(ABC):
    """Abstract base class for encryption ciphers."""
    
    @abstractmethod
    def encrypt(self, plaintext: bytes, key: bytes, iv: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """Encrypt plaintext and return (ciphertext, iv)."""
        pass
    
    @abstractmethod
    def decrypt(self, ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        """Decrypt ciphertext using key and IV."""
        pass
    
    @abstractmethod
    def get_iv_size(self) -> int:
        """Get IV size for this cipher."""
        pass


class AES256GCM(BaseCipher):
    """AES-256 in GCM mode (authenticated encryption)."""
    
    def encrypt(self, plaintext: bytes, key: bytes, iv: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        if iv is None:
            iv = generate_iv(12)  # GCM uses 96-bit nonce
        
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(iv, plaintext, None)
        return ciphertext, iv
    
    def decrypt(self, ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(iv, ciphertext, None)
    
    def get_iv_size(self) -> int:
        return 12


class AES256CBC(BaseCipher):
    """AES-256 in CBC mode."""
    
    def encrypt(self, plaintext: bytes, key: bytes, iv: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        if iv is None:
            iv = generate_iv(16)  # AES block size
        
        # PKCS7 padding
        pad_len = 16 - (len(plaintext) % 16)
        padded = plaintext + bytes([pad_len] * pad_len)
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        
        return ciphertext, iv
    
    def decrypt(self, ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove PKCS7 padding
        pad_len = padded_plaintext[-1]
        return padded_plaintext[:-pad_len]
    
    def get_iv_size(self) -> int:
        return 16


class ChaCha20Poly1305Cipher(BaseCipher):
    """ChaCha20-Poly1305 authenticated encryption."""
    
    def encrypt(self, plaintext: bytes, key: bytes, iv: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        if iv is None:
            iv = generate_iv(12)  # ChaCha20 uses 96-bit nonce
        
        chacha = ChaCha20Poly1305(key)
        ciphertext = chacha.encrypt(iv, plaintext, None)
        return ciphertext, iv
    
    def decrypt(self, ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        chacha = ChaCha20Poly1305(key)
        return chacha.decrypt(iv, ciphertext, None)
    
    def get_iv_size(self) -> int:
        return 12


class CipherFactory:
    """Factory class for creating cipher instances."""
    
    _ciphers = {
        CipherType.AES_256_GCM: AES256GCM,
        CipherType.AES_256_CBC: AES256CBC,
        CipherType.CHACHA20_POLY1305: ChaCha20Poly1305Cipher,
    }
    
    @classmethod
    def create_cipher(cls, cipher_type: str) -> BaseCipher:
        """Create cipher instance by type."""
        if cipher_type not in cls._ciphers:
            raise ValueError(f"Unsupported cipher type: {cipher_type}")
        
        return cls._ciphers[cipher_type]()
    
    @classmethod
    def list_ciphers(cls) -> list:
        """List available cipher types."""
        return list(cls._ciphers.keys())