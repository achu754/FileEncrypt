import hashlib
from typing import Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from argon2 import PasswordHasher, Type
from argon2.low_level import hash_secret_raw


class KDFType:
    PBKDF2 = "pbkdf2"
    SCRYPT = "scrypt"
    ARGON2ID = "argon2id"


class KeyDerivation:
    @staticmethod
    def derive_key_pbkdf2(
        password: bytes,
        salt: bytes,
        iterations: int = 100000,
        key_length: int = 32
    ) -> bytes:
        """Derive key using PBKDF2-HMAC-SHA256."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            iterations=iterations,
        )
        return kdf.derive(password)
    
    @staticmethod
    def derive_key_scrypt(
        password: bytes,
        salt: bytes,
        n: int = 32768,
        r: int = 8,
        p: int = 1,
        key_length: int = 32
    ) -> bytes:
        """Derive key using Scrypt."""
        kdf = Scrypt(
            length=key_length,
            salt=salt,
            n=n,
            r=r,
            p=p,
        )
        return kdf.derive(password)
    
    @staticmethod
    def derive_key_argon2id(
        password: bytes,
        salt: bytes,
        time_cost: int = 3,
        memory_cost: int = 65536,
        parallelism: int = 1,
        key_length: int = 32
    ) -> bytes:
        """Derive key using Argon2id."""
        return hash_secret_raw(
            password,
            salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=key_length,
            type=Type.ID
        )
    
    @staticmethod
    def derive_key(
        password: bytes,
        salt: bytes,
        kdf_type: str = KDFType.PBKDF2,
        **kwargs
    ) -> bytes:
        """Derive key using specified KDF type."""
        if kdf_type == KDFType.PBKDF2:
            return KeyDerivation.derive_key_pbkdf2(password, salt, **kwargs)
        elif kdf_type == KDFType.SCRYPT:
            return KeyDerivation.derive_key_scrypt(password, salt, **kwargs)
        elif kdf_type == KDFType.ARGON2ID:
            return KeyDerivation.derive_key_argon2id(password, salt, **kwargs)
        else:
            raise ValueError(f"Unsupported KDF type: {kdf_type}")