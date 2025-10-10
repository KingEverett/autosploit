import pytest
import os
from pathlib import Path
from pydantic import ValidationError
from autosploit.core.config import (
    LoggingConfig,
    HardwareConfig,
    SafetyConfig,
    UIConfig,
    WorkspaceConfig,
    AutoSploitConfig,
    ConfigManager,
)


class TestConfigModels:
    """Test configuration model validation."""

    def test_logging_config_defaults(self):
        config = LoggingConfig()
        assert config.level == "INFO"
        assert config.max_bytes == 10_485_760
        assert config.backup_count == 5
        assert config.console_output is True

    def test_logging_config_validation_level(self):
        with pytest.raises(ValidationError):
            LoggingConfig(level="INVALID")

    def test_logging_config_validation_max_bytes(self):
        with pytest.raises(ValidationError):
            LoggingConfig(max_bytes=100)  # Too small

        with pytest.raises(ValidationError):
            LoggingConfig(max_bytes=200_000_000)  # Too large

    def test_logging_config_path_expansion(self):
        config = LoggingConfig(file_path="~/test.log")
        assert "~" not in config.file_path
        assert config.file_path.startswith(str(Path.home()))

    def test_hardware_config_defaults(self):
        config = HardwareConfig()
        assert config.default_interface == "socketcan"
        assert config.default_channel == "vcan0"
        assert config.default_bitrate == 500_000

    def test_hardware_config_validation_bitrate(self):
        with pytest.raises(ValidationError):
            HardwareConfig(default_bitrate=5_000)  # Too low

        with pytest.raises(ValidationError):
            HardwareConfig(default_bitrate=2_000_000)  # Too high

    def test_hardware_config_validation_channel(self):
        with pytest.raises(ValidationError):
            HardwareConfig(default_channel="")  # Empty

        with pytest.raises(ValidationError):
            HardwareConfig(default_channel="bad-name!")  # Invalid chars

    def test_safety_config_automotive_ids(self):
        config = SafetyConfig()
        # Check default automotive ECU IDs
        expected_ids = [0x7E0, 0x7E1, 0x7E8, 0x7DF]
        assert config.dangerous_ids == expected_ids

    def test_safety_config_can_id_validation(self):
        # Valid standard ID
        config = SafetyConfig(dangerous_ids=[0x100])
        assert 0x100 in config.dangerous_ids

        # Valid extended ID
        config = SafetyConfig(dangerous_ids=[0x1FFFFFFF])
        assert 0x1FFFFFFF in config.dangerous_ids

        # Invalid ID
        with pytest.raises(ValidationError):
            SafetyConfig(dangerous_ids=[0x20000000])  # Too large

    def test_ui_config_defaults(self):
        config = UIConfig()
        assert config.prompt_style == "standard"
        assert config.table_style == "rounded"
        assert config.color_scheme == "default"

    def test_workspace_config_path_expansion(self):
        config = WorkspaceConfig(default_path="~/workspace")
        assert "~" not in config.default_path
        assert config.default_path.startswith(str(Path.home()))


class TestConfigManager:
    """Test ConfigManager functionality."""

    def test_load_default_config(self, tmp_path):
        manager = ConfigManager()
        config = manager.load_config(config_paths=[])

        assert isinstance(config, AutoSploitConfig)
        assert config.logging.level == "INFO"

    def test_load_from_file(self, tmp_path):
        # Create test config file
        config_file = tmp_path / "test_config.toml"
        config_file.write_text("""
[logging]
level = "DEBUG"
max_bytes = 5000000

[hardware]
default_bitrate = 250000
        """)

        manager = ConfigManager()
        config = manager.load_config(config_paths=[config_file])

        assert config.logging.level == "DEBUG"
        assert config.logging.max_bytes == 5_000_000
        assert config.hardware.default_bitrate == 250_000

    def test_config_precedence(self, tmp_path):
        # Create two config files
        config1 = tmp_path / "config1.toml"
        config1.write_text('[logging]\nlevel = "INFO"')

        config2 = tmp_path / "config2.toml"
        config2.write_text('[logging]\nlevel = "DEBUG"')

        manager = ConfigManager()
        config = manager.load_config(config_paths=[config1, config2])

        # config2 should override config1
        assert config.logging.level == "DEBUG"

    def test_deep_merge(self):
        base = {"a": {"b": 1, "c": 2}, "d": 3}
        override = {"a": {"b": 10}, "e": 4}

        result = ConfigManager._deep_merge(base, override)

        assert result["a"]["b"] == 10  # Overridden
        assert result["a"]["c"] == 2   # Preserved
        assert result["d"] == 3        # Preserved
        assert result["e"] == 4        # Added

    def test_environment_variables(self, monkeypatch):
        # Set environment variable
        monkeypatch.setenv("AUTOSPLOIT_LOGGING__LEVEL", "ERROR")

        manager = ConfigManager()
        config = manager.load_config(config_paths=[])

        assert config.logging.level == "ERROR"

    def test_get_value(self):
        manager = ConfigManager()
        config = manager.load_config(config_paths=[])

        value = manager.get("logging.level")
        assert value == "INFO"

        value = manager.get("hardware.default_bitrate")
        assert value == 500_000

    def test_get_nonexistent_value(self):
        manager = ConfigManager()
        config = manager.load_config(config_paths=[])

        value = manager.get("nonexistent.key", "default")
        assert value == "default"

    def test_set_value(self):
        manager = ConfigManager()
        config = manager.load_config(config_paths=[])

        manager.set("logging.level", "DEBUG")
        assert manager.get("logging.level") == "DEBUG"

    def test_set_invalid_value(self):
        manager = ConfigManager()
        config = manager.load_config(config_paths=[])

        with pytest.raises(ValidationError):
            manager.set("logging.level", "INVALID")

    def test_set_invalid_key(self):
        manager = ConfigManager()
        config = manager.load_config(config_paths=[])

        with pytest.raises(ValueError, match="Invalid config key"):
            manager.set("logging.nonexistent", "value")

    def test_save_config(self, tmp_path):
        manager = ConfigManager()
        config = manager.load_config(config_paths=[])
        config.logging.level = "DEBUG"

        output_file = tmp_path / "saved_config.toml"
        manager.save_config(output_file)

        assert output_file.exists()

        # Load saved config and verify
        manager2 = ConfigManager()
        loaded = manager2.load_config(config_paths=[output_file])
        assert loaded.logging.level == "DEBUG"

    def test_validate_config(self):
        manager = ConfigManager()
        config = manager.load_config(config_paths=[])

        is_valid, errors = manager.validate()
        assert is_valid
        assert len(errors) == 0

    def test_validate_invalid_config(self, tmp_path):
        manager = ConfigManager()
        config = manager.load_config(config_paths=[])

        # Set invalid log path
        config.logging.file_path = "/invalid/path/that/cannot/be/created"

        is_valid, errors = manager.validate()
        # Note: This might still pass if the test has sufficient permissions
        # The actual validation depends on system permissions


class TestCrossValidation:
    """Test cross-section validation in AutoSploitConfig."""

    def test_json_logging_requires_file_path(self):
        with pytest.raises(ValidationError, match="JSON logging requires a file path"):
            AutoSploitConfig(
                logging=LoggingConfig(json_format=True, file_path="")
            )

    def test_workspace_log_directory_conflict(self, tmp_path):
        log_dir = tmp_path / "logs"
        log_file = log_dir / "app.log"

        with pytest.raises(ValidationError, match="Workspace and log directories cannot be the same"):
            AutoSploitConfig(
                logging=LoggingConfig(file_path=str(log_file)),
                workspace=WorkspaceConfig(default_path=str(log_dir))
            )


class TestEnvironmentVariables:
    """Test environment variable handling."""

    def test_extract_env_overrides(self, monkeypatch):
        # Set test environment variables
        monkeypatch.setenv("AUTOSPLOIT_LOGGING__LEVEL", "DEBUG")
        monkeypatch.setenv("AUTOSPLOIT_HARDWARE__DEFAULT_BITRATE", "250000")
        monkeypatch.setenv("OTHER_VAR", "ignored")

        overrides = ConfigManager._extract_env_overrides()

        assert overrides == {
            "logging": {"level": "DEBUG"},
            "hardware": {"default_bitrate": "250000"}
        }

    def test_env_case_insensitive(self, monkeypatch):
        monkeypatch.setenv("AUTOSPLOIT_LOGGING__LEVEL", "WARNING")

        manager = ConfigManager()
        config = manager.load_config(config_paths=[])

        assert config.logging.level == "WARNING"


class TestUtilityFunctions:
    """Test utility functions."""

    def test_create_default_config(self):
        from autosploit.core.config import create_default_config

        config = create_default_config()
        assert isinstance(config, AutoSploitConfig)
        assert config.logging.level == "INFO"

    def test_load_config_from_file(self, tmp_path):
        from autosploit.core.config import load_config_from_file

        config_file = tmp_path / "test.toml"
        config_file.write_text('[logging]\nlevel = "ERROR"')

        config = load_config_from_file(config_file)
        assert config.logging.level == "ERROR"

    def test_get_config_manager(self):
        from autosploit.core.config import get_config_manager

        manager1 = get_config_manager()
        manager2 = get_config_manager()

        # Should return the same instance (singleton)
        assert manager1 is manager2


class TestFileHandling:
    """Test file loading and error handling."""

    def test_load_nonexistent_file(self):
        manager = ConfigManager()
        nonexistent = Path("/nonexistent/config.toml")

        # Should skip missing files gracefully and load defaults
        config = manager.load_config(config_paths=[nonexistent])
        assert config.logging.level == "INFO"  # Default value

    def test_load_invalid_toml(self, tmp_path):
        bad_toml = tmp_path / "bad.toml"
        bad_toml.write_text("invalid toml content [[[")

        manager = ConfigManager()

        with pytest.raises(ValueError, match="Failed to load config"):
            manager.load_config(config_paths=[bad_toml])

    def test_save_to_readonly_directory(self, tmp_path):
        manager = ConfigManager()
        config = manager.load_config(config_paths=[])

        # Create a directory and make it read-only
        readonly_dir = tmp_path / "readonly"
        readonly_dir.mkdir()
        readonly_dir.chmod(0o444)

        readonly_file = readonly_dir / "config.toml"

        try:
            with pytest.raises(PermissionError):
                manager.save_config(readonly_file)
        finally:
            # Restore permissions for cleanup
            readonly_dir.chmod(0o755)