# FileEncrypt

A robust command-line file encryption utility that supports multiple encryption algorithms and key derivation functions. The tool handles both individual files and directory structures securely with integrity verification.

## Features

### Encryption Algorithms
- **AES-256-GCM** - Authenticated encryption (default)
- **AES-256-CBC** - Block cipher with PKCS7 padding
- **ChaCha20-Poly1305** - Modern authenticated encryption

### Key Derivation Functions
- **PBKDF2-HMAC-SHA256** - Traditional, widely supported (default)
- **Scrypt** - Memory-hard function
- **Argon2id** - Modern, recommended for new applications

### Security Features
- HMAC-SHA256 integrity verification
- Secure random IV/nonce generation
- Memory-safe password handling
- Configurable KDF parameters
- File format versioning

### Additional Features
- Single file and directory encryption
- Recursive directory processing
- Progress indicators for large files
- Configuration file support
- Key file authentication
- Comprehensive error handling

## Installation

### From Source
```bash
git clone <repository>
cd FileEncrypt
pip install -r requirements.txt
pip install -e .
```

### Dependencies
- Python 3.8+
- cryptography>=41.0.0
- argon2-cffi>=23.1.0
- tqdm>=4.66.0

## Usage

### Basic Usage

#### Encrypt a File
```bash
python -m src.main encrypt input.txt output.txt.enc
```

#### Decrypt a File
```bash
python -m src.main decrypt output.txt.enc decrypted.txt
```

#### Encrypt Directory
```bash
python -m src.main encrypt -d /path/to/directory /path/to/encrypted --recursive
```

#### Decrypt Directory
```bash
python -m src.main decrypt -d /path/to/encrypted /path/to/decrypted --recursive
```

### Advanced Options

#### Use Different Cipher
```bash
python -m src.main encrypt -c chacha20-poly1305 input.txt output.txt.enc
```

#### Use Different KDF
```bash
python -m src.main encrypt -k argon2id input.txt output.txt.enc
```

#### Customize KDF Parameters
```bash
# PBKDF2 with custom iterations
python -m src.main encrypt --iterations 200000 input.txt output.txt.enc

# Argon2id with custom parameters
python -m src.main encrypt -k argon2id --memory-cost 131072 --time-cost 4 input.txt output.txt.enc

# Scrypt with custom N parameter
python -m src.main encrypt -k scrypt --scrypt-n 65536 input.txt output.txt.enc
```

#### Use Key File
```bash
# Generate key file
openssl rand -out keyfile.bin 32

# Encrypt with key file
python -m src.main encrypt --keyfile keyfile.bin input.txt output.txt.enc
```

### Command Reference

#### Global Options
- `-v, --verbose` - Enable verbose output
- `--keyfile FILE` - Use key from file instead of password
- `--no-progress` - Disable progress bars

#### Encrypt Command
```bash
python -m src.main encrypt [OPTIONS] INPUT OUTPUT
```

Options:
- `-c, --cipher {aes-256-gcm,aes-256-cbc,chacha20-poly1305}` - Encryption cipher
- `-k, --kdf {pbkdf2,scrypt,argon2id}` - Key derivation function
- `-d, --directory` - Encrypt directory instead of single file
- `-r, --recursive` - Process directories recursively
- `--iterations INT` - PBKDF2 iterations (default: 100000)
- `--memory-cost INT` - Argon2id memory cost (default: 65536)
- `--time-cost INT` - Argon2id time cost (default: 3)
- `--scrypt-n INT` - Scrypt N parameter (default: 32768)

#### Decrypt Command
```bash
python -m src.main decrypt [OPTIONS] INPUT OUTPUT
```

Options:
- `-d, --directory` - Decrypt directory instead of single file
- `-r, --recursive` - Process directories recursively

#### List Ciphers
```bash
python -m src.main list-ciphers
```

## File Format

Encrypted files use a custom format with the following structure:

```
[HEADER][ENCRYPTED_DATA]
```

### Header Format
- Magic bytes: "FENC" (4 bytes)
- Version: 1 (4 bytes)
- Cipher type length (4 bytes)
- Salt (32 bytes)
- IV/Nonce (32 bytes, padded/truncated)
- HMAC (32 bytes)
- KDF parameters length (4 bytes)
- Cipher type (variable)
- KDF type (16 bytes, padded)
- KDF parameters (variable, JSON)

## Configuration

FileEncrypt supports configuration files at `~/.fileencrypt.json`:

```json
{
  "cipher": "aes-256-gcm",
  "kdf": "pbkdf2",
  "chunk_size": 65536,
  "kdf_params": {
    "pbkdf2": {
      "iterations": 100000,
      "key_length": 32
    },
    "scrypt": {
      "n": 32768,
      "r": 8,
      "p": 1,
      "key_length": 32
    },
    "argon2id": {
      "time_cost": 3,
      "memory_cost": 65536,
      "parallelism": 1,
      "key_length": 32
    }
  }
}
```

## Security Considerations

1. **Password Security**: Use strong, unique passwords. Consider using key files for automated scenarios.

2. **Key Derivation**: Choose appropriate KDF parameters based on your security requirements and performance constraints.

3. **File Deletion**: Original files are not automatically deleted. Use secure deletion tools if needed.

4. **Memory**: Passwords and keys are handled securely in memory when possible.

5. **Integrity**: All encrypted files include HMAC verification to detect tampering.

## Testing

Run the test suite:
```bash
python -m pytest tests/
```

Or using unittest:
```bash
python -m unittest discover tests/
```

## License

MIT License - see LICENSE file for details.# FileEncrypt
