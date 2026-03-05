"""
Global application configuration management.

Handles configuration loading, validation, and environment variable support.
"""

import logging
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


@dataclass
class ScanDefaults:
    """Default values for scan operations."""
    timeout: float = 5.0
    retries: int = 1
    concurrency: int = 10
    rate_limit: Optional[float] = None
    verbose: bool = False
    dns_lookup: bool = True
    ports: List[int] = field(
        default_factory=lambda: [22, 80, 443, 3306, 5432, 6379, 8080, 8443]
    )


@dataclass
class DatabaseConfig:
    """Database configuration."""
    engine: str = "sqlite"
    path: str = "aegisscan.db"
    url: Optional[str] = None
    pool_size: int = 10
    echo: bool = False


@dataclass
class LoggingConfig:
    """Logging configuration."""
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    log_file: Optional[str] = None
    console_output: bool = True


@dataclass
class APIConfig:
    """API-related configuration."""
    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 8000
    workers: int = 4
    timeout: float = 30.0


@dataclass
class CredentialConfig:
    """Credentials and secrets management."""
    ssh_key_path: Optional[str] = None
    api_keys_path: Optional[str] = None
    env_var_prefix: str = "AEGISSCAN_"


@dataclass
class AppConfig:
    """
    Main application configuration.
    
    Aggregates all configuration sections and provides unified interface
    for loading from YAML files and environment variables.
    """
    
    # Configuration sections
    scan_defaults: ScanDefaults = field(default_factory=ScanDefaults)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    api: APIConfig = field(default_factory=APIConfig)
    credentials: CredentialConfig = field(default_factory=CredentialConfig)
    
    # Metadata
    debug: bool = False
    app_name: str = "AegisScan"
    version: str = "0.1.0"
    
    def __post_init__(self) -> None:
        """Initialize and validate configuration."""
        self._setup_logging()
    
    def _setup_logging(self) -> None:
        """Configure logging based on configuration."""
        logger = logging.getLogger()
        logger.setLevel(getattr(logging, self.logging.level))
        
        # Console handler
        if self.logging.console_output:
            console_handler = logging.StreamHandler()
            formatter = logging.Formatter(self.logging.format)
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)
        
        # File handler
        if self.logging.log_file:
            file_handler = logging.FileHandler(self.logging.log_file)
            formatter = logging.Formatter(self.logging.format)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
    
    @classmethod
    def from_yaml(cls, path: str) -> "AppConfig":
        """
        Load configuration from YAML file.
        
        Args:
            path: Path to YAML configuration file
            
        Returns:
            AppConfig instance
            
        Raises:
            FileNotFoundError: If config file not found
            ValueError: If YAML parsing fails or validation fails
        """
        if not YAML_AVAILABLE:
            raise RuntimeError(
                "PyYAML is required to load YAML config. "
                "Install with: pip install pyyaml"
            )
        
        config_path = Path(path)
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
        
        try:
            with open(config_path) as f:
                config_data = yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in config file: {e}") from e
        
        return cls._from_dict(config_data)
    
    @classmethod
    def from_env(cls, prefix: str = "AEGISSCAN_") -> "AppConfig":
        """
        Load configuration from environment variables.
        
        Supports nested config via double underscores:
        AEGISSCAN_SCAN_DEFAULTS__TIMEOUT=10.0
        AEGISSCAN_DATABASE__ENGINE=postgresql
        
        Args:
            prefix: Environment variable prefix
            
        Returns:
            AppConfig instance
        """
        config_data: Dict[str, Any] = {}
        
        for env_var, value in os.environ.items():
            if not env_var.startswith(prefix):
                continue
            
            # Remove prefix and convert to lowercase
            key_path = env_var[len(prefix):].lower()
            
            # Split on double underscores for nested config
            keys = key_path.split("__")
            
            # Parse value (try int, float, bool, else string)
            parsed_value = cls._parse_env_value(value)
            
            # Build nested dict
            current = config_data
            for key in keys[:-1]:
                if key not in current:
                    current[key] = {}
                current = current[key]
            
            current[keys[-1]] = parsed_value
        
        return cls._from_dict(config_data)
    
    @classmethod
    def _parse_env_value(cls, value: str) -> Any:
        """
        Parse environment variable value to appropriate type.
        
        Args:
            value: String value from environment
            
        Returns:
            Parsed value (int, float, bool, or string)
        """
        # Try integer
        try:
            return int(value)
        except ValueError:
            pass
        
        # Try float
        try:
            return float(value)
        except ValueError:
            pass
        
        # Try boolean
        if value.lower() in ("true", "yes", "1"):
            return True
        if value.lower() in ("false", "no", "0"):
            return False
        
        # Return as string
        return value
    
    @classmethod
    def _from_dict(cls, config_dict: Dict[str, Any]) -> "AppConfig":
        """
        Create AppConfig from dictionary.
        
        Args:
            config_dict: Configuration dictionary
            
        Returns:
            AppConfig instance
        """
        # Extract known sections
        scan_defaults_dict = config_dict.get("scan_defaults", {})
        database_dict = config_dict.get("database", {})
        logging_dict = config_dict.get("logging", {})
        api_dict = config_dict.get("api", {})
        credentials_dict = config_dict.get("credentials", {})
        
        # Create section instances
        scan_defaults = ScanDefaults(**{
            k: v for k, v in scan_defaults_dict.items()
            if k in ScanDefaults.__dataclass_fields__
        })
        
        database = DatabaseConfig(**{
            k: v for k, v in database_dict.items()
            if k in DatabaseConfig.__dataclass_fields__
        })
        
        logging_config = LoggingConfig(**{
            k: v for k, v in logging_dict.items()
            if k in LoggingConfig.__dataclass_fields__
        })
        
        api = APIConfig(**{
            k: v for k, v in api_dict.items()
            if k in APIConfig.__dataclass_fields__
        })
        
        credentials = CredentialConfig(**{
            k: v for k, v in credentials_dict.items()
            if k in CredentialConfig.__dataclass_fields__
        })
        
        # Extract top-level config
        top_level_keys = {"debug", "app_name", "version"}
        top_level = {
            k: v for k, v in config_dict.items()
            if k in top_level_keys
        }
        
        return cls(
            scan_defaults=scan_defaults,
            database=database,
            logging=logging_config,
            api=api,
            credentials=credentials,
            **top_level
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert configuration to dictionary.
        
        Returns:
            Dictionary representation of config
        """
        return {
            "scan_defaults": asdict(self.scan_defaults),
            "database": asdict(self.database),
            "logging": asdict(self.logging),
            "api": asdict(self.api),
            "credentials": asdict(self.credentials),
            "debug": self.debug,
            "app_name": self.app_name,
            "version": self.version
        }
    
    def save_yaml(self, path: str) -> None:
        """
        Save configuration to YAML file.
        
        Args:
            path: Output file path
            
        Raises:
            RuntimeError: If PyYAML is not available
        """
        if not YAML_AVAILABLE:
            raise RuntimeError(
                "PyYAML is required to save YAML config. "
                "Install with: pip install pyyaml"
            )
        
        with open(path, "w") as f:
            yaml.dump(self.to_dict(), f, default_flow_style=False)
    
    def validate(self) -> List[str]:
        """
        Validate configuration and return list of errors.
        
        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []
        
        # Validate scan defaults
        if self.scan_defaults.timeout <= 0:
            errors.append("scan_defaults.timeout must be positive")
        if self.scan_defaults.retries < 0:
            errors.append("scan_defaults.retries cannot be negative")
        if self.scan_defaults.concurrency < 1:
            errors.append("scan_defaults.concurrency must be at least 1")
        
        # Validate database config
        if not self.database.engine:
            errors.append("database.engine is required")
        if not self.database.path and self.database.engine == "sqlite":
            errors.append("database.path required for SQLite engine")
        
        # Validate API config
        if self.api.enabled:
            if self.api.port < 1 or self.api.port > 65535:
                errors.append("api.port must be valid (1-65535)")
            if self.api.workers < 1:
                errors.append("api.workers must be at least 1")
        
        return errors


# Global configuration instance
_config: Optional[AppConfig] = None


def get_config() -> AppConfig:
    """
    Get global configuration instance (lazy initialization).
    
    Returns:
        AppConfig instance
    """
    global _config
    
    if _config is None:
        # Try to load from YAML first
        config_path = os.environ.get(
            "AEGISSCAN_CONFIG",
            "aegisscan.yaml"
        )
        
        if Path(config_path).exists():
            _config = AppConfig.from_yaml(config_path)
        else:
            # Load from environment or use defaults
            _config = AppConfig.from_env()
    
    return _config


def set_config(config: AppConfig) -> None:
    """
    Set global configuration instance.
    
    Args:
        config: AppConfig instance to use globally
    """
    global _config
    _config = config
