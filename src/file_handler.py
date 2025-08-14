import os
import json
import struct
from pathlib import Path
from typing import Dict, Any, Optional, Iterator
from tqdm import tqdm
from .crypto.ciphers import CipherFactory, CipherType
from .crypto.kdf import KeyDerivation, KDFType
from .crypto.utils import generate_salt, generate_iv
from .integrity import IntegrityVerifier


class EncryptedFileHeader:
    """Handles encrypted file header format."""
    
    MAGIC = b"FENC"
    VERSION = 1
    
    def __init__(self, cipher_type: str, kdf_type: str, salt: bytes, iv: bytes, 
                 hmac: bytes, kdf_params: Dict[str, Any]):
        self.cipher_type = cipher_type
        self.kdf_type = kdf_type
        self.salt = salt
        self.iv = iv
        self.hmac = hmac
        self.kdf_params = kdf_params
    
    def serialize(self) -> bytes:
        """Serialize header to bytes."""
        params_json = json.dumps(self.kdf_params).encode('utf-8')
        
        # Ensure IV is exactly 32 bytes
        iv_padded = self.iv[:32].ljust(32, b'\x00') if len(self.iv) < 32 else self.iv[:32]
        
        header = struct.pack(
            '<4sII32s32s32sI',
            self.MAGIC,
            self.VERSION,
            len(self.cipher_type),
            self.salt,
            iv_padded,
            self.hmac,
            len(params_json)
        )
        
        header += self.cipher_type.encode('utf-8')
        header += self.kdf_type.encode('utf-8').ljust(16, b'\x00')  # Fixed 16 bytes
        header += params_json
        
        return header
    
    @classmethod
    def deserialize(cls, data: bytes) -> 'EncryptedFileHeader':
        """Deserialize header from bytes."""
        if len(data) < 112:
            raise ValueError("Invalid header: too short")
        
        magic, version, cipher_len, salt, iv, hmac, params_len = struct.unpack(
            '<4sII32s32s32sI', data[:112]
        )
        
        if magic != cls.MAGIC:
            raise ValueError("Invalid file format")
        
        if version != cls.VERSION:
            raise ValueError("Unsupported file version")
        
        offset = 112
        cipher_type = data[offset:offset + cipher_len].decode('utf-8')
        offset += cipher_len
        
        kdf_type = data[offset:offset + 16].rstrip(b'\x00').decode('utf-8')
        offset += 16
        
        params_json = data[offset:offset + params_len].decode('utf-8')
        kdf_params = json.loads(params_json)
        
        return cls(cipher_type, kdf_type, salt, iv, hmac, kdf_params)
    
    def get_header_size(self) -> int:
        """Get total header size."""
        params_json = json.dumps(self.kdf_params).encode('utf-8')
        return 112 + len(self.cipher_type) + 16 + len(params_json)


class FileEncryptor:
    """Handles file encryption and decryption operations."""
    
    def __init__(self, cipher_type: str = CipherType.AES_256_GCM, 
                 kdf_type: str = KDFType.PBKDF2, chunk_size: int = 64 * 1024):
        self.cipher_type = cipher_type
        self.kdf_type = kdf_type
        self.chunk_size = chunk_size
        self.cipher = CipherFactory.create_cipher(cipher_type)
    
    def encrypt_file(self, input_path: str, output_path: str, password: bytes, 
                    kdf_params: Optional[Dict[str, Any]] = None, 
                    show_progress: bool = True) -> None:
        """Encrypt a single file."""
        if kdf_params is None:
            kdf_params = self._get_default_kdf_params()
        
        salt = generate_salt()
        key = KeyDerivation.derive_key(password, salt, self.kdf_type, **kdf_params)
        hmac_key = IntegrityVerifier.generate_hmac_key(key)
        
        input_file_size = os.path.getsize(input_path)
        
        with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
            iv = generate_iv(self.cipher.get_iv_size())
            
            encrypted_data = bytearray()
            
            progress_bar = None
            if show_progress:
                progress_bar = tqdm(total=input_file_size, unit='B', unit_scale=True, 
                                  desc="Encrypting")
            
            try:
                while True:
                    chunk = infile.read(self.chunk_size)
                    if not chunk:
                        break
                    
                    if len(encrypted_data) == 0:
                        # First chunk, encrypt with IV
                        encrypted_chunk, _ = self.cipher.encrypt(chunk, key, iv)
                    else:
                        # Subsequent chunks
                        encrypted_chunk, _ = self.cipher.encrypt(chunk, key)
                    
                    encrypted_data.extend(encrypted_chunk)
                    
                    if progress_bar:
                        progress_bar.update(len(chunk))
                
                # Generate HMAC for encrypted data
                hmac_value = IntegrityVerifier.generate_hmac(bytes(encrypted_data), hmac_key)
                
                # Create and write header
                header = EncryptedFileHeader(
                    self.cipher_type, self.kdf_type, salt, iv, hmac_value, kdf_params
                )
                
                outfile.write(header.serialize())
                outfile.write(encrypted_data)
                
            finally:
                if progress_bar:
                    progress_bar.close()
    
    def decrypt_file(self, input_path: str, output_path: str, password: bytes,
                    show_progress: bool = True) -> None:
        """Decrypt a single file."""
        with open(input_path, 'rb') as infile:
            # Read and parse header
            header_data = infile.read(1024)  # Read enough for header
            header = EncryptedFileHeader.deserialize(header_data)
            
            # Seek to start of encrypted data
            infile.seek(header.get_header_size())
            
            # Derive key
            key = KeyDerivation.derive_key(
                password, header.salt, header.kdf_type, **header.kdf_params
            )
            hmac_key = IntegrityVerifier.generate_hmac_key(key)
            
            # Read encrypted data
            encrypted_data = infile.read()
            
            # Verify HMAC
            if not IntegrityVerifier.verify_hmac(encrypted_data, hmac_key, header.hmac):
                raise ValueError("HMAC verification failed - file may be corrupted or tampered with")
            
            # Decrypt
            cipher = CipherFactory.create_cipher(header.cipher_type)
            
            # Get the actual IV size for this cipher and trim the padded IV
            actual_iv_size = cipher.get_iv_size()
            actual_iv = header.iv[:actual_iv_size]
            
            with open(output_path, 'wb') as outfile:
                if show_progress:
                    progress_bar = tqdm(total=len(encrypted_data), unit='B', unit_scale=True,
                                      desc="Decrypting")
                
                try:
                    decrypted_data = cipher.decrypt(encrypted_data, key, actual_iv)
                    outfile.write(decrypted_data)
                    
                    if show_progress:
                        progress_bar.update(len(encrypted_data))
                
                finally:
                    if show_progress:
                        progress_bar.close()
    
    def encrypt_directory(self, input_dir: str, output_dir: str, password: bytes,
                         recursive: bool = True, show_progress: bool = True) -> None:
        """Encrypt all files in a directory."""
        input_path = Path(input_dir)
        output_path = Path(output_dir)
        
        output_path.mkdir(parents=True, exist_ok=True)
        
        if recursive:
            files = list(input_path.rglob('*'))
        else:
            files = list(input_path.iterdir())
        
        files = [f for f in files if f.is_file()]
        
        for file_path in tqdm(files, desc="Processing files"):
            relative_path = file_path.relative_to(input_path)
            output_file = output_path / (str(relative_path) + '.enc')
            
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            self.encrypt_file(
                str(file_path), str(output_file), password, 
                show_progress=False
            )
    
    def decrypt_directory(self, input_dir: str, output_dir: str, password: bytes,
                         recursive: bool = True, show_progress: bool = True) -> None:
        """Decrypt all .enc files in a directory."""
        input_path = Path(input_dir)
        output_path = Path(output_dir)
        
        output_path.mkdir(parents=True, exist_ok=True)
        
        if recursive:
            files = list(input_path.rglob('*.enc'))
        else:
            files = [f for f in input_path.iterdir() if f.suffix == '.enc']
        
        for file_path in tqdm(files, desc="Processing files"):
            relative_path = file_path.relative_to(input_path)
            output_file = output_path / str(relative_path)[:-4]  # Remove .enc extension
            
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            self.decrypt_file(
                str(file_path), str(output_file), password,
                show_progress=False
            )
    
    def _get_default_kdf_params(self) -> Dict[str, Any]:
        """Get default KDF parameters."""
        if self.kdf_type == KDFType.PBKDF2:
            return {"iterations": 100000, "key_length": 32}
        elif self.kdf_type == KDFType.SCRYPT:
            return {"n": 32768, "r": 8, "p": 1, "key_length": 32}
        elif self.kdf_type == KDFType.ARGON2ID:
            return {"time_cost": 3, "memory_cost": 65536, "parallelism": 1, "key_length": 32}
        else:
            return {"key_length": 32}