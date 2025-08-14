import unittest
import tempfile
import os
from pathlib import Path
from src.file_handler import FileEncryptor, EncryptedFileHeader
from src.crypto.ciphers import CipherType
from src.crypto.kdf import KDFType


class TestEncryptedFileHeader(unittest.TestCase):
    """Test encrypted file header serialization/deserialization."""
    
    def test_header_serialization(self):
        """Test header serialization and deserialization."""
        cipher_type = CipherType.AES_256_GCM
        kdf_type = KDFType.PBKDF2
        salt = os.urandom(32)
        iv = os.urandom(12)
        hmac = os.urandom(32)
        kdf_params = {"iterations": 100000, "key_length": 32}
        
        header = EncryptedFileHeader(cipher_type, kdf_type, salt, iv, hmac, kdf_params)
        serialized = header.serialize()
        
        deserialized = EncryptedFileHeader.deserialize(serialized)
        
        self.assertEqual(deserialized.cipher_type, cipher_type)
        self.assertEqual(deserialized.kdf_type, kdf_type)
        self.assertEqual(deserialized.salt, salt)
        self.assertEqual(deserialized.iv[:12], iv)  # IV is padded/truncated to 32 bytes
        self.assertEqual(deserialized.hmac, hmac)
        self.assertEqual(deserialized.kdf_params, kdf_params)


class TestFileEncryptor(unittest.TestCase):
    """Test file encryption and decryption."""
    
    def setUp(self):
        self.password = b"test_password_123"
        self.test_content = b"This is a test file content for encryption testing.\n" * 100
        self.encryptor = FileEncryptor()
    
    def test_single_file_encryption_decryption(self):
        """Test single file encryption and decryption."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test file
            input_file = Path(temp_dir) / "test.txt"
            encrypted_file = Path(temp_dir) / "test.txt.enc"
            decrypted_file = Path(temp_dir) / "test_decrypted.txt"
            
            with open(input_file, 'wb') as f:
                f.write(self.test_content)
            
            # Encrypt
            self.encryptor.encrypt_file(
                str(input_file), str(encrypted_file), self.password, show_progress=False
            )
            
            self.assertTrue(encrypted_file.exists())
            self.assertGreater(encrypted_file.stat().st_size, len(self.test_content))
            
            # Decrypt
            self.encryptor.decrypt_file(
                str(encrypted_file), str(decrypted_file), self.password, show_progress=False
            )
            
            with open(decrypted_file, 'rb') as f:
                decrypted_content = f.read()
            
            self.assertEqual(decrypted_content, self.test_content)
    
    def test_different_ciphers(self):
        """Test encryption with different cipher types."""
        ciphers = [CipherType.AES_256_GCM, CipherType.AES_256_CBC, CipherType.CHACHA20_POLY1305]
        
        for cipher_type in ciphers:
            with self.subTest(cipher=cipher_type):
                encryptor = FileEncryptor(cipher_type=cipher_type)
                
                with tempfile.TemporaryDirectory() as temp_dir:
                    input_file = Path(temp_dir) / "test.txt"
                    encrypted_file = Path(temp_dir) / "test.txt.enc"
                    decrypted_file = Path(temp_dir) / "test_decrypted.txt"
                    
                    with open(input_file, 'wb') as f:
                        f.write(self.test_content)
                    
                    encryptor.encrypt_file(
                        str(input_file), str(encrypted_file), self.password, show_progress=False
                    )
                    encryptor.decrypt_file(
                        str(encrypted_file), str(decrypted_file), self.password, show_progress=False
                    )
                    
                    with open(decrypted_file, 'rb') as f:
                        decrypted_content = f.read()
                    
                    self.assertEqual(decrypted_content, self.test_content)
    
    def test_different_kdfs(self):
        """Test encryption with different KDF types."""
        kdfs = [KDFType.PBKDF2, KDFType.SCRYPT, KDFType.ARGON2ID]
        
        for kdf_type in kdfs:
            with self.subTest(kdf=kdf_type):
                encryptor = FileEncryptor(kdf_type=kdf_type)
                
                with tempfile.TemporaryDirectory() as temp_dir:
                    input_file = Path(temp_dir) / "test.txt"
                    encrypted_file = Path(temp_dir) / "test.txt.enc"
                    decrypted_file = Path(temp_dir) / "test_decrypted.txt"
                    
                    with open(input_file, 'wb') as f:
                        f.write(self.test_content)
                    
                    encryptor.encrypt_file(
                        str(input_file), str(encrypted_file), self.password, show_progress=False
                    )
                    encryptor.decrypt_file(
                        str(encrypted_file), str(decrypted_file), self.password, show_progress=False
                    )
                    
                    with open(decrypted_file, 'rb') as f:
                        decrypted_content = f.read()
                    
                    self.assertEqual(decrypted_content, self.test_content)
    
    def test_wrong_password(self):
        """Test decryption with wrong password."""
        with tempfile.TemporaryDirectory() as temp_dir:
            input_file = Path(temp_dir) / "test.txt"
            encrypted_file = Path(temp_dir) / "test.txt.enc"
            decrypted_file = Path(temp_dir) / "test_decrypted.txt"
            
            with open(input_file, 'wb') as f:
                f.write(self.test_content)
            
            self.encryptor.encrypt_file(
                str(input_file), str(encrypted_file), self.password, show_progress=False
            )
            
            # Try to decrypt with wrong password
            with self.assertRaises(ValueError):
                self.encryptor.decrypt_file(
                    str(encrypted_file), str(decrypted_file), b"wrong_password", show_progress=False
                )
    
    def test_directory_encryption(self):
        """Test directory encryption and decryption."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test directory structure
            input_dir = Path(temp_dir) / "input"
            input_dir.mkdir()
            
            (input_dir / "file1.txt").write_bytes(b"Content of file 1")
            (input_dir / "file2.txt").write_bytes(b"Content of file 2")
            
            subdir = input_dir / "subdir"
            subdir.mkdir()
            (subdir / "file3.txt").write_bytes(b"Content of file 3")
            
            encrypted_dir = Path(temp_dir) / "encrypted"
            decrypted_dir = Path(temp_dir) / "decrypted"
            
            # Encrypt directory
            self.encryptor.encrypt_directory(
                str(input_dir), str(encrypted_dir), self.password, 
                recursive=True, show_progress=False
            )
            
            # Verify encrypted files exist
            self.assertTrue((encrypted_dir / "file1.txt.enc").exists())
            self.assertTrue((encrypted_dir / "file2.txt.enc").exists())
            self.assertTrue((encrypted_dir / "subdir" / "file3.txt.enc").exists())
            
            # Decrypt directory
            self.encryptor.decrypt_directory(
                str(encrypted_dir), str(decrypted_dir), self.password,
                recursive=True, show_progress=False
            )
            
            # Verify decrypted content
            self.assertEqual((decrypted_dir / "file1.txt").read_bytes(), b"Content of file 1")
            self.assertEqual((decrypted_dir / "file2.txt").read_bytes(), b"Content of file 2")
            self.assertEqual((decrypted_dir / "subdir" / "file3.txt").read_bytes(), b"Content of file 3")


if __name__ == '__main__':
    unittest.main()