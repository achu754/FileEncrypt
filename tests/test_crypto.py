import unittest
import os
import tempfile
from src.crypto.ciphers import CipherFactory, CipherType
from src.crypto.kdf import KeyDerivation, KDFType
from src.crypto.utils import generate_salt, generate_iv
from src.integrity import IntegrityVerifier


class TestCiphers(unittest.TestCase):
    """Test encryption ciphers."""
    
    def setUp(self):
        self.test_data = b"Hello, World! This is a test message for encryption."
        self.key = os.urandom(32)  # 256-bit key
    
    def test_aes_256_gcm(self):
        """Test AES-256-GCM encryption/decryption."""
        cipher = CipherFactory.create_cipher(CipherType.AES_256_GCM)
        
        ciphertext, iv = cipher.encrypt(self.test_data, self.key)
        decrypted = cipher.decrypt(ciphertext, self.key, iv)
        
        self.assertEqual(decrypted, self.test_data)
        self.assertNotEqual(ciphertext, self.test_data)
        self.assertEqual(len(iv), cipher.get_iv_size())
    
    def test_aes_256_cbc(self):
        """Test AES-256-CBC encryption/decryption."""
        cipher = CipherFactory.create_cipher(CipherType.AES_256_CBC)
        
        ciphertext, iv = cipher.encrypt(self.test_data, self.key)
        decrypted = cipher.decrypt(ciphertext, self.key, iv)
        
        self.assertEqual(decrypted, self.test_data)
        self.assertNotEqual(ciphertext, self.test_data)
        self.assertEqual(len(iv), cipher.get_iv_size())
    
    def test_chacha20_poly1305(self):
        """Test ChaCha20-Poly1305 encryption/decryption."""
        cipher = CipherFactory.create_cipher(CipherType.CHACHA20_POLY1305)
        
        ciphertext, iv = cipher.encrypt(self.test_data, self.key)
        decrypted = cipher.decrypt(ciphertext, self.key, iv)
        
        self.assertEqual(decrypted, self.test_data)
        self.assertNotEqual(ciphertext, self.test_data)
        self.assertEqual(len(iv), cipher.get_iv_size())
    
    def test_invalid_cipher(self):
        """Test invalid cipher type."""
        with self.assertRaises(ValueError):
            CipherFactory.create_cipher("invalid-cipher")


class TestKDF(unittest.TestCase):
    """Test key derivation functions."""
    
    def setUp(self):
        self.password = b"test_password_123"
        self.salt = generate_salt()
    
    def test_pbkdf2(self):
        """Test PBKDF2 key derivation."""
        key1 = KeyDerivation.derive_key_pbkdf2(self.password, self.salt)
        key2 = KeyDerivation.derive_key_pbkdf2(self.password, self.salt)
        
        self.assertEqual(key1, key2)
        self.assertEqual(len(key1), 32)
        
        # Different salt should produce different key
        different_salt = generate_salt()
        key3 = KeyDerivation.derive_key_pbkdf2(self.password, different_salt)
        self.assertNotEqual(key1, key3)
    
    def test_scrypt(self):
        """Test Scrypt key derivation."""
        key1 = KeyDerivation.derive_key_scrypt(self.password, self.salt)
        key2 = KeyDerivation.derive_key_scrypt(self.password, self.salt)
        
        self.assertEqual(key1, key2)
        self.assertEqual(len(key1), 32)
    
    def test_argon2id(self):
        """Test Argon2id key derivation."""
        key1 = KeyDerivation.derive_key_argon2id(self.password, self.salt)
        key2 = KeyDerivation.derive_key_argon2id(self.password, self.salt)
        
        self.assertEqual(key1, key2)
        self.assertEqual(len(key1), 32)
    
    def test_kdf_factory(self):
        """Test KDF factory method."""
        key_pbkdf2 = KeyDerivation.derive_key(self.password, self.salt, KDFType.PBKDF2)
        key_scrypt = KeyDerivation.derive_key(self.password, self.salt, KDFType.SCRYPT)
        key_argon2id = KeyDerivation.derive_key(self.password, self.salt, KDFType.ARGON2ID)
        
        self.assertEqual(len(key_pbkdf2), 32)
        self.assertEqual(len(key_scrypt), 32)
        self.assertEqual(len(key_argon2id), 32)
        
        # Different KDFs should produce different keys
        self.assertNotEqual(key_pbkdf2, key_scrypt)
        self.assertNotEqual(key_pbkdf2, key_argon2id)
        self.assertNotEqual(key_scrypt, key_argon2id)


class TestIntegrity(unittest.TestCase):
    """Test integrity verification."""
    
    def setUp(self):
        self.data = b"Test data for HMAC verification"
        self.key = os.urandom(32)
    
    def test_hmac_generation_and_verification(self):
        """Test HMAC generation and verification."""
        hmac_value = IntegrityVerifier.generate_hmac(self.data, self.key)
        
        self.assertTrue(IntegrityVerifier.verify_hmac(self.data, self.key, hmac_value))
        self.assertEqual(len(hmac_value), 32)  # SHA-256 produces 32-byte hash
    
    def test_hmac_tamper_detection(self):
        """Test HMAC tamper detection."""
        hmac_value = IntegrityVerifier.generate_hmac(self.data, self.key)
        
        # Modify data
        tampered_data = self.data + b"tampered"
        self.assertFalse(IntegrityVerifier.verify_hmac(tampered_data, self.key, hmac_value))
        
        # Modify key
        wrong_key = os.urandom(32)
        self.assertFalse(IntegrityVerifier.verify_hmac(self.data, wrong_key, hmac_value))
    
    def test_hmac_key_derivation(self):
        """Test HMAC key derivation."""
        master_key = os.urandom(32)
        hmac_key1 = IntegrityVerifier.generate_hmac_key(master_key)
        hmac_key2 = IntegrityVerifier.generate_hmac_key(master_key)
        
        self.assertEqual(hmac_key1, hmac_key2)
        self.assertEqual(len(hmac_key1), 32)


if __name__ == '__main__':
    unittest.main()