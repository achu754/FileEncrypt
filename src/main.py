#!/usr/bin/env python3
import argparse
import getpass
import sys
import logging
from pathlib import Path
from typing import Optional
from .file_handler import FileEncryptor
from .crypto.ciphers import CipherFactory, CipherType
from .crypto.kdf import KDFType
from .config import Config


def setup_logging(verbose: bool = False) -> None:
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )


def get_password(prompt: str = "Password: ") -> bytes:
    """Get password from user input."""
    password = getpass.getpass(prompt).encode('utf-8')
    if not password:
        raise ValueError("Password cannot be empty")
    return password


def read_key_file(key_file_path: str) -> bytes:
    """Read key from file."""
    try:
        with open(key_file_path, 'rb') as f:
            return f.read().strip()
    except IOError as e:
        raise ValueError(f"Failed to read key file: {e}")


def create_parser() -> argparse.ArgumentParser:
    """Create command line argument parser."""
    parser = argparse.ArgumentParser(
        description="FileEncrypt - Secure file encryption utility",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Encrypt a file
  %(prog)s encrypt input.txt output.txt.enc
  
  # Decrypt a file
  %(prog)s decrypt input.txt.enc output.txt
  
  # Encrypt directory recursively
  %(prog)s encrypt -d /path/to/dir /path/to/encrypted --recursive
  
  # Use different cipher
  %(prog)s encrypt -c chacha20-poly1305 input.txt output.txt.enc
  
  # Use key file instead of password
  %(prog)s encrypt --keyfile key.bin input.txt output.txt.enc
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Common arguments
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument('-v', '--verbose', action='store_true',
                             help='Enable verbose output')
    common_parser.add_argument('--keyfile', type=str,
                             help='Use key from file instead of password')
    common_parser.add_argument('--no-progress', action='store_true',
                             help='Disable progress bars')
    
    # Encrypt command
    encrypt_parser = subparsers.add_parser('encrypt', parents=[common_parser],
                                         help='Encrypt files or directories')
    encrypt_parser.add_argument('input', help='Input file or directory')
    encrypt_parser.add_argument('output', help='Output file or directory')
    encrypt_parser.add_argument('-c', '--cipher', choices=CipherFactory.list_ciphers(),
                               default=CipherType.AES_256_GCM,
                               help='Encryption cipher to use')
    encrypt_parser.add_argument('-k', '--kdf', choices=[KDFType.PBKDF2, KDFType.SCRYPT, KDFType.ARGON2ID],
                               default=KDFType.PBKDF2,
                               help='Key derivation function to use')
    encrypt_parser.add_argument('-d', '--directory', action='store_true',
                               help='Encrypt directory instead of single file')
    encrypt_parser.add_argument('-r', '--recursive', action='store_true',
                               help='Process directories recursively')
    encrypt_parser.add_argument('--iterations', type=int,
                               help='PBKDF2 iterations (default: 100000)')
    encrypt_parser.add_argument('--memory-cost', type=int,
                               help='Argon2id memory cost (default: 65536)')
    encrypt_parser.add_argument('--time-cost', type=int,
                               help='Argon2id time cost (default: 3)')
    encrypt_parser.add_argument('--scrypt-n', type=int,
                               help='Scrypt N parameter (default: 32768)')
    
    # Decrypt command
    decrypt_parser = subparsers.add_parser('decrypt', parents=[common_parser],
                                         help='Decrypt files or directories')
    decrypt_parser.add_argument('input', help='Input encrypted file or directory')
    decrypt_parser.add_argument('output', help='Output file or directory')
    decrypt_parser.add_argument('-d', '--directory', action='store_true',
                               help='Decrypt directory instead of single file')
    decrypt_parser.add_argument('-r', '--recursive', action='store_true',
                               help='Process directories recursively')
    
    # List ciphers command
    subparsers.add_parser('list-ciphers', help='List available encryption ciphers')
    
    return parser


def main() -> None:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    setup_logging(args.verbose if hasattr(args, 'verbose') else False)
    logger = logging.getLogger(__name__)
    
    try:
        if args.command == 'list-ciphers':
            print("Available ciphers:")
            for cipher in CipherFactory.list_ciphers():
                print(f"  {cipher}")
            return
        
        # Get password or key
        if hasattr(args, 'keyfile') and args.keyfile:
            password = read_key_file(args.keyfile)
        else:
            password = get_password()
        
        # Create encryptor
        cipher_type = getattr(args, 'cipher', CipherType.AES_256_GCM)
        kdf_type = getattr(args, 'kdf', KDFType.PBKDF2)
        
        config = Config()
        encryptor = FileEncryptor(cipher_type, kdf_type, config.get('chunk_size', 65536))
        
        # Build KDF parameters
        kdf_params = config.get_kdf_params(kdf_type)
        if hasattr(args, 'iterations') and args.iterations:
            kdf_params['iterations'] = args.iterations
        if hasattr(args, 'memory_cost') and args.memory_cost:
            kdf_params['memory_cost'] = args.memory_cost
        if hasattr(args, 'time_cost') and args.time_cost:
            kdf_params['time_cost'] = args.time_cost
        if hasattr(args, 'scrypt_n') and args.scrypt_n:
            kdf_params['n'] = args.scrypt_n
        
        show_progress = not getattr(args, 'no_progress', False)
        
        if args.command == 'encrypt':
            if args.directory:
                logger.info(f"Encrypting directory: {args.input}")
                encryptor.encrypt_directory(
                    args.input, args.output, password,
                    recursive=args.recursive,
                    show_progress=show_progress
                )
            else:
                logger.info(f"Encrypting file: {args.input}")
                encryptor.encrypt_file(
                    args.input, args.output, password,
                    kdf_params=kdf_params,
                    show_progress=show_progress
                )
            
            logger.info("Encryption completed successfully")
        
        elif args.command == 'decrypt':
            if args.directory:
                logger.info(f"Decrypting directory: {args.input}")
                encryptor.decrypt_directory(
                    args.input, args.output, password,
                    recursive=args.recursive,
                    show_progress=show_progress
                )
            else:
                logger.info(f"Decrypting file: {args.input}")
                encryptor.decrypt_file(
                    args.input, args.output, password,
                    show_progress=show_progress
                )
            
            logger.info("Decryption completed successfully")
    
    except KeyboardInterrupt:
        logger.error("Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error: {e}")
        if hasattr(args, 'verbose') and args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()