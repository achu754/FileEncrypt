#!/usr/bin/env python3
"""
Demonstration script for FileEncrypt utility.
Shows various encryption capabilities and security features.
"""

import os
import sys
import tempfile
from pathlib import Path

# Add src to path for imports
sys.path.append('src')

from src.file_handler import FileEncryptor
from src.crypto.ciphers import CipherType
from src.crypto.kdf import KDFType


def demo_single_file_encryption():
    """Demonstrate single file encryption with different ciphers."""
    print("=== Single File Encryption Demo ===")
    
    # Create test file
    test_data = b"This is a confidential document that needs encryption.\n" * 10
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        original_file = temp_path / "confidential.txt"
        
        with open(original_file, 'wb') as f:
            f.write(test_data)
        
        password = b"secure_password_123"
        
        # Test different ciphers
        ciphers = [CipherType.AES_256_GCM, CipherType.AES_256_CBC, CipherType.CHACHA20_POLY1305]
        
        for cipher in ciphers:
            print(f"\n  Testing {cipher}:")
            encryptor = FileEncryptor(cipher_type=cipher)
            
            encrypted_file = temp_path / f"confidential_{cipher}.enc"
            decrypted_file = temp_path / f"decrypted_{cipher}.txt"
            
            # Encrypt
            encryptor.encrypt_file(
                str(original_file), str(encrypted_file), password, show_progress=False
            )
            
            # Decrypt
            encryptor.decrypt_file(
                str(encrypted_file), str(decrypted_file), password, show_progress=False
            )
            
            # Verify
            with open(decrypted_file, 'rb') as f:
                decrypted_data = f.read()
            
            if decrypted_data == test_data:
                print(f"    ✓ {cipher} encryption/decryption successful")
                print(f"    ✓ Original: {len(test_data)} bytes, Encrypted: {encrypted_file.stat().st_size} bytes")
            else:
                print(f"    ✗ {cipher} encryption/decryption failed")


def demo_kdf_types():
    """Demonstrate different key derivation functions."""
    print("\n=== Key Derivation Function Demo ===")
    
    test_data = b"Sensitive data requiring strong key derivation."
    password = b"strong_password_456"
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        original_file = temp_path / "sensitive.txt"
        
        with open(original_file, 'wb') as f:
            f.write(test_data)
        
        kdfs = [KDFType.PBKDF2, KDFType.SCRYPT, KDFType.ARGON2ID]
        
        for kdf in kdfs:
            print(f"\n  Testing {kdf}:")
            encryptor = FileEncryptor(kdf_type=kdf)
            
            encrypted_file = temp_path / f"sensitive_{kdf}.enc"
            decrypted_file = temp_path / f"decrypted_{kdf}.txt"
            
            # Encrypt with custom KDF params
            kdf_params = {}
            if kdf == KDFType.PBKDF2:
                kdf_params = {"iterations": 50000, "key_length": 32}
            elif kdf == KDFType.SCRYPT:
                kdf_params = {"n": 16384, "r": 8, "p": 1, "key_length": 32}
            elif kdf == KDFType.ARGON2ID:
                kdf_params = {"time_cost": 2, "memory_cost": 32768, "parallelism": 1, "key_length": 32}
            
            encryptor.encrypt_file(
                str(original_file), str(encrypted_file), password, 
                kdf_params=kdf_params, show_progress=False
            )
            
            # Decrypt
            encryptor.decrypt_file(
                str(encrypted_file), str(decrypted_file), password, show_progress=False
            )
            
            # Verify
            with open(decrypted_file, 'rb') as f:
                decrypted_data = f.read()
            
            if decrypted_data == test_data:
                print(f"    ✓ {kdf} key derivation successful")
                print(f"    ✓ Parameters: {kdf_params}")
            else:
                print(f"    ✗ {kdf} key derivation failed")


def demo_security_features():
    """Demonstrate security features like tampering detection."""
    print("\n=== Security Features Demo ===")
    
    test_data = b"Important data that must maintain integrity."
    password = b"security_test_789"
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        original_file = temp_path / "important.txt"
        encrypted_file = temp_path / "important.txt.enc"
        tampered_file = temp_path / "tampered.txt.enc"
        
        with open(original_file, 'wb') as f:
            f.write(test_data)
        
        encryptor = FileEncryptor()
        
        # Encrypt file
        encryptor.encrypt_file(
            str(original_file), str(encrypted_file), password, show_progress=False
        )
        print("  ✓ File encrypted with HMAC integrity verification")
        
        # Copy and tamper with encrypted file
        with open(encrypted_file, 'rb') as f:
            encrypted_data = bytearray(f.read())
        
        # Modify a byte in the middle (corrupt the data)
        if len(encrypted_data) > 200:
            encrypted_data[200] = (encrypted_data[200] + 1) % 256
        
        with open(tampered_file, 'wb') as f:
            f.write(encrypted_data)
        
        # Try to decrypt tampered file
        try:
            encryptor.decrypt_file(
                str(tampered_file), str(temp_path / "should_fail.txt"), 
                password, show_progress=False
            )
            print("  ✗ Tampering detection failed!")
        except ValueError as e:
            print(f"  ✓ Tampering detected: {e}")
        
        # Test wrong password
        try:
            encryptor.decrypt_file(
                str(encrypted_file), str(temp_path / "should_fail2.txt"), 
                b"wrong_password", show_progress=False
            )
            print("  ✗ Wrong password detection failed!")
        except ValueError as e:
            print(f"  ✓ Wrong password detected: {e}")


def demo_directory_encryption():
    """Demonstrate recursive directory encryption."""
    print("\n=== Directory Encryption Demo ===")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create test directory structure
        test_dir = temp_path / "test_project"
        test_dir.mkdir()
        
        (test_dir / "README.md").write_text("# Test Project\nThis is a test project.")
        (test_dir / "config.json").write_text('{"version": "1.0", "debug": true}')
        
        src_dir = test_dir / "src"
        src_dir.mkdir()
        (src_dir / "main.py").write_text("#!/usr/bin/env python3\nprint('Hello World')")
        (src_dir / "utils.py").write_text("def helper(): return 42")
        
        docs_dir = test_dir / "docs"
        docs_dir.mkdir()
        (docs_dir / "guide.txt").write_text("User guide content")
        
        encrypted_dir = temp_path / "encrypted_project"
        decrypted_dir = temp_path / "decrypted_project"
        
        password = b"directory_password_abc"
        encryptor = FileEncryptor()
        
        print(f"  Original directory: {len(list(test_dir.rglob('*')))} items")
        
        # Encrypt directory
        encryptor.encrypt_directory(
            str(test_dir), str(encrypted_dir), password, 
            recursive=True, show_progress=False
        )
        
        encrypted_files = list(encrypted_dir.rglob('*.enc'))
        print(f"  ✓ Encrypted directory: {len(encrypted_files)} .enc files")
        
        # Decrypt directory
        encryptor.decrypt_directory(
            str(encrypted_dir), str(decrypted_dir), password,
            recursive=True, show_progress=False
        )
        
        decrypted_files = list(decrypted_dir.rglob('*'))
        original_files = list(test_dir.rglob('*'))
        
        # Count only files (not directories)
        decrypted_file_count = len([f for f in decrypted_files if f.is_file()])
        original_file_count = len([f for f in original_files if f.is_file()])
        
        if decrypted_file_count == original_file_count:
            print(f"  ✓ Decrypted directory: {decrypted_file_count} files restored")
            
            # Verify content of one file
            original_content = (test_dir / "README.md").read_text()
            decrypted_content = (decrypted_dir / "README.md").read_text()
            
            if original_content == decrypted_content:
                print("  ✓ File contents verified identical")
            else:
                print("  ✗ File contents differ")
        else:
            print(f"  ✗ File count mismatch: {original_file_count} vs {decrypted_file_count}")


def main():
    """Run all demonstrations."""
    print("FileEncrypt Utility Demonstration")
    print("=" * 50)
    
    demo_single_file_encryption()
    demo_kdf_types()
    demo_security_features()
    demo_directory_encryption()
    
    print("\n" + "=" * 50)
    print("All demonstrations completed!")
    print("\nFileEncrypt provides:")
    print("✓ Multiple encryption algorithms (AES-256-GCM, AES-256-CBC, ChaCha20-Poly1305)")
    print("✓ Multiple key derivation functions (PBKDF2, Scrypt, Argon2id)")
    print("✓ HMAC integrity verification")
    print("✓ Single file and directory encryption")
    print("✓ Tampering and wrong password detection")
    print("✓ Secure file format with versioning")


if __name__ == '__main__':
    main()