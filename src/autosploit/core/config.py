from pathlib import Path
from typing import Optional, List, Literal
from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
import tomli
import tomli_w
import os


class LoggingConfig(BaseModel):
    """Logging system configuration."""

    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO",
        description="Global log level for the application"
    )
    file_path: str = Field(
        default="~/.autosploit/logs/autosploit.log",
        description="Path to log file (supports ~ expansion)"
    )
    max_bytes: int = Field(
        default=10_485_760,  # 10MB
        ge=1_000_000,
        le=100_000_000,
        description="Maximum size of log file before rotation"
    )
    backup_count: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Number of rotated log files to keep"
    )
    console_output: bool = Field(
        default=True,
        description="Enable/disable console logging"
    )
    json_format: bool = Field(
        default=False,
        description="Use JSON format for file logs"
    )
    include_timestamp: bool = Field(
        default=True,
        description="Include timestamps in log entries"
    )
    log_can_traffic: bool = Field(
        default=False,
        description="Log all CAN bus traffic (generates large logs)"
    )

    @field_validator("file_path")
    @classmethod
    def expand_path(cls, v: str) -> str:
        if not v or not v.strip():
            return ""
        return str(Path(v).expanduser().resolve())

    model_config = {
        "validate_assignment": True,
        "extra": "forbid"
    }


class HardwareConfig(BaseModel):
    """Hardware interface configuration."""

    default_interface: Literal["socketcan", "slcan", "virtual", "pcan", "kvaser"] = Field(
        default="socketcan",
        description="Default CAN interface type"
    )
    default_channel: str = Field(
        default="vcan0",
        description="Default CAN channel/device name"
    )
    default_bitrate: int = Field(
        default=500_000,
        ge=10_000,
        le=1_000_000,
        description="Default CAN bus bitrate in bits/second"
    )
    recv_timeout: float = Field(
        default=1.0,
        ge=0.1,
        le=30.0,
        description="Receive timeout in seconds"
    )
    reconnect_attempts: int = Field(
        default=3,
        ge=0,
        le=10,
        description="Number of automatic reconnection attempts"
    )
    auto_reconnect: bool = Field(
        default=True,
        description="Automatically attempt to reconnect on connection loss"
    )

    @field_validator("default_channel")
    @classmethod
    def validate_channel_name(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Channel name cannot be empty")
        if not all(c.isalnum() or c == '_' for c in v):
            raise ValueError("Channel name must be alphanumeric with underscores")
        return v.strip()

    model_config = {"validate_assignment": True, "extra": "forbid"}


class SafetyConfig(BaseModel):
    """Safety system configuration."""

    require_confirmation: bool = Field(
        default=True,
        description="Require user confirmation for dangerous operations"
    )
    dangerous_ids: List[int] = Field(
        default_factory=lambda: [0x7E0, 0x7E1, 0x7E8, 0x7DF],  # Real automotive ECU IDs
        description="CAN IDs that require extra confirmation (critical ECUs)"
    )
    max_messages_per_second: int = Field(
        default=100,
        ge=1,
        le=1000,
        description="Maximum CAN messages per second to prevent bus flooding"
    )
    enable_bus_monitoring: bool = Field(
        default=True,
        description="Monitor bus health and detect anomalies"
    )
    emergency_stop_enabled: bool = Field(
        default=True,
        description="Enable emergency stop on Ctrl+C"
    )
    auto_backup_before_write: bool = Field(
        default=True,
        description="Automatically backup current state before write operations"
    )

    @field_validator("dangerous_ids")
    @classmethod
    def validate_can_ids(cls, v: List[int]) -> List[int]:
        for can_id in v:
            if not (0x000 <= can_id <= 0x7FF or 0x00000000 <= can_id <= 0x1FFFFFFF):
                raise ValueError(
                    f"CAN ID {hex(can_id)} out of valid range. "
                    f"Standard: 0x000-0x7FF, Extended: 0x00000000-0x1FFFFFFF"
                )
        return v

    model_config = {"validate_assignment": True, "extra": "forbid"}


class UIConfig(BaseModel):
    """User interface configuration."""

    prompt_style: Literal["standard", "minimal", "detailed"] = Field(
        default="standard",
        description="Style of command prompt"
    )
    show_timestamps: bool = Field(
        default=False,
        description="Show timestamps in console output"
    )
    table_style: Literal["simple", "rounded", "heavy", "double", "minimal"] = Field(
        default="rounded",
        description="Rich table border style"
    )
    color_scheme: Literal["default", "dark", "light", "monochrome"] = Field(
        default="default",
        description="Color scheme for terminal output"
    )
    show_banner: bool = Field(
        default=True,
        description="Display ASCII banner on startup"
    )
    page_results: bool = Field(
        default=True,
        description="Page long output instead of scrolling"
    )
    max_table_rows: int = Field(
        default=50,
        ge=10,
        le=500,
        description="Maximum rows to display in tables before pagination"
    )

    model_config = {"validate_assignment": True, "extra": "forbid"}


class WorkspaceConfig(BaseModel):
    """Workspace configuration."""

    default_path: str = Field(
        default="~/.autosploit/workspace",
        description="Default workspace directory path"
    )
    auto_save_sessions: bool = Field(
        default=True,
        description="Automatically save session state"
    )
    save_interval_seconds: int = Field(
        default=300,  # 5 minutes
        ge=60,
        le=3600,
        description="Auto-save interval in seconds"
    )
    create_session_logs: bool = Field(
        default=True,
        description="Create separate log file for each session"
    )
    max_workspace_size_mb: int = Field(
        default=1000,  # 1GB
        ge=100,
        le=10000,
        description="Maximum total workspace size in megabytes"
    )

    @field_validator("default_path")
    @classmethod
    def expand_and_create_path(cls, v: str) -> str:
        expanded = Path(v).expanduser().resolve()
        return str(expanded)

    model_config = {"validate_assignment": True, "extra": "forbid"}


class AutoSploitConfig(BaseSettings):
    """Main Autosploit configuration."""

    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    hardware: HardwareConfig = Field(default_factory=HardwareConfig)
    safety: SafetyConfig = Field(default_factory=SafetyConfig)
    ui: UIConfig = Field(default_factory=UIConfig)
    workspace: WorkspaceConfig = Field(default_factory=WorkspaceConfig)

    config_version: str = Field(
        default="1.0.0",
        description="Configuration schema version"
    )

    model_config = SettingsConfigDict(
        env_prefix="AUTOSPLOIT_",
        env_nested_delimiter="__",
        case_sensitive=False,
        toml_file=None,
        validate_assignment=True,
        extra="forbid",
        frozen=False,
    )

    @model_validator(mode="after")
    def validate_config_consistency(self) -> "AutoSploitConfig":
        # Ensure JSON logging has a file path
        if self.logging.json_format and not self.logging.file_path:
            raise ValueError("JSON logging requires a file path to be set")

        # Ensure workspace and log directories are different
        workspace_path = Path(self.workspace.default_path)
        log_path = Path(self.logging.file_path).parent
        if workspace_path == log_path:
            raise ValueError("Workspace and log directories cannot be the same")

        return self


class ConfigManager:
    """Manages configuration loading, merging, and saving."""

    DEFAULT_CONFIG_LOCATIONS = [
        Path(__file__).parent.parent / "data" / "configs" / "default_config.toml",
        Path.home() / ".autosploit" / "config.toml",
        Path.cwd() / "workspace" / "config.toml",
    ]

    def __init__(self):
        self._config: Optional[AutoSploitConfig] = None
        self._config_sources: List[Path] = []

    def load_config(
        self,
        config_paths: Optional[List[Path]] = None,
        env_override: bool = True,
        cli_overrides: Optional[dict] = None
    ) -> AutoSploitConfig:
        """Load and merge configuration from multiple sources."""
        merged_config = {}

        paths_to_load = config_paths if config_paths else self.DEFAULT_CONFIG_LOCATIONS

        # Load each config file in order
        for path in paths_to_load:
            if path.exists():
                try:
                    loaded = self._load_toml_file(path)
                    merged_config = self._deep_merge(merged_config, loaded)
                    self._config_sources.append(path)
                except Exception as e:
                    raise ValueError(f"Failed to load config from {path}: {e}")

        # Apply environment variable overrides
        if env_override:
            env_overrides = self._extract_env_overrides()
            merged_config = self._deep_merge(merged_config, env_overrides)

        # Apply CLI overrides (highest priority)
        if cli_overrides:
            merged_config = self._deep_merge(merged_config, cli_overrides)

        # Create and validate final config
        try:
            self._config = AutoSploitConfig(**merged_config)
        except Exception as e:
            raise ValueError(f"Configuration validation failed: {e}")

        return self._config

    @staticmethod
    def _load_toml_file(path: Path) -> dict:
        """Load TOML file and return as dictionary."""
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")

        try:
            with open(path, "rb") as f:
                return tomli.load(f)
        except tomli.TOMLDecodeError as e:
            raise ValueError(f"Invalid TOML in {path}: {e}")

    @staticmethod
    def _deep_merge(base: dict, override: dict) -> dict:
        """Recursively merge two dictionaries."""
        result = base.copy()

        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = ConfigManager._deep_merge(result[key], value)
            else:
                result[key] = value

        return result

    @staticmethod
    def _extract_env_overrides() -> dict:
        """Extract Autosploit config from environment variables."""
        overrides = {}
        prefix = "AUTOSPLOIT_"

        for key, value in os.environ.items():
            if not key.startswith(prefix):
                continue

            clean_key = key[len(prefix):]
            parts = clean_key.lower().split("__")

            # Build nested dict
            current = overrides
            for part in parts[:-1]:
                if part not in current:
                    current[part] = {}
                current = current[part]

            current[parts[-1]] = value

        return overrides

    def save_config(self, path: Path, config: Optional[AutoSploitConfig] = None) -> None:
        """Save configuration to TOML file."""
        if config is None:
            if self._config is None:
                raise ValueError("No configuration loaded to save")
            config = self._config

        path.parent.mkdir(parents=True, exist_ok=True)

        config_dict = config.model_dump(mode="python", exclude_none=True)

        try:
            with open(path, "wb") as f:
                tomli_w.dump(config_dict, f)
        except Exception as e:
            raise PermissionError(f"Failed to write config to {path}: {e}")

    def get(self, key: str, default=None):
        """Get configuration value using dot notation."""
        if self._config is None:
            raise ValueError("No configuration loaded")

        parts = key.split(".")
        current = self._config
        for part in parts:
            if not hasattr(current, part):
                return default
            current = getattr(current, part)

        return current

    def set(self, key: str, value) -> None:
        """Set configuration value using dot notation."""
        if self._config is None:
            raise ValueError("No configuration loaded")

        parts = key.split(".")
        current = self._config
        for part in parts[:-1]:
            if not hasattr(current, part):
                raise ValueError(f"Invalid config path: {key}")
            current = getattr(current, part)

        final_key = parts[-1]
        if not hasattr(current, final_key):
            raise ValueError(f"Invalid config key: {key}")

        setattr(current, final_key, value)

    def validate(self) -> tuple[bool, List[str]]:
        """Validate current configuration."""
        if self._config is None:
            return False, ["No configuration loaded"]

        errors = []

        # Validate file paths exist or can be created
        try:
            log_path = Path(self._config.logging.file_path)
            log_path.parent.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            errors.append(f"Invalid log path: {e}")

        try:
            workspace_path = Path(self._config.workspace.default_path)
            workspace_path.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            errors.append(f"Invalid workspace path: {e}")

        # Validate CAN IDs
        for can_id in self._config.safety.dangerous_ids:
            if not (0x000 <= can_id <= 0x7FF or 0x00000000 <= can_id <= 0x1FFFFFFF):
                errors.append(f"Invalid CAN ID in safety blacklist: {hex(can_id)}")

        # Check for risky settings
        if self._config.safety.max_messages_per_second > 1000:
            errors.append("Warning: Very high rate limit may cause bus issues")

        return len(errors) == 0, errors


def create_default_config() -> AutoSploitConfig:
    """Create configuration with all default values."""
    return AutoSploitConfig()


def load_config_from_file(path: Path) -> AutoSploitConfig:
    """Load configuration from a single file."""
    manager = ConfigManager()
    return manager.load_config(config_paths=[path])


def get_config_manager() -> ConfigManager:
    """Get singleton configuration manager instance."""
    global _config_manager_instance
    if '_config_manager_instance' not in globals():
        _config_manager_instance = ConfigManager()
    return _config_manager_instance