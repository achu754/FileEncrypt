import json
from pathlib import Path
from typing import Dict, Any, Optional
from .crypto.ciphers import CipherType
from .crypto.kdf import KDFType


class Config:
    """Configuration management for FileEncrypt."""
    
    DEFAULT_CONFIG = {
        "cipher": CipherType.AES_256_GCM,
        "kdf": KDFType.PBKDF2,
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
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or str(Path.home() / ".fileencrypt.json")
        self._config = self.DEFAULT_CONFIG.copy()
        self.load_config()
    
    def load_config(self) -> None:
        """Load configuration from file."""
        try:
            if Path(self.config_path).exists():
                with open(self.config_path, 'r') as f:
                    user_config = json.load(f)
                    self._config.update(user_config)
        except (json.JSONDecodeError, IOError):
            # Use default config if loading fails
            pass
    
    def save_config(self) -> None:
        """Save configuration to file."""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self._config, f, indent=2)
        except IOError:
            pass
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value."""
        return self._config.get(key, default)
    
    def set(self, key: str, value: Any) -> None:
        """Set configuration value."""
        self._config[key] = value
    
    def get_kdf_params(self, kdf_type: str) -> Dict[str, Any]:
        """Get KDF parameters for specified type."""
        kdf_params = self._config.get("kdf_params", {})
        return kdf_params.get(kdf_type, {})