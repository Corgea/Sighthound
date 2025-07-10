# Test 4.1: Configuration Patterns (Safe) - CONFIG MANAGER
# Expected: These patterns should NOT be flagged as taint sources

import os


def setup_environment():
    """
    CONFIGURATION: These should NOT be flagged as sources
    Tests the configuration pattern classification fix
    """
    # These are configuration operations, not user input
    os.environ.setdefault("DEBUG", "False")
    os.environ.setdefault("LOG_LEVEL", "INFO")
    os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
    os.environ.setdefault("SECRET_KEY", "dev-key-not-for-production")

    return "Configuration complete"


def configure_logging():
    """
    Another configuration function
    """
    log_level = os.environ.setdefault("LOG_LEVEL", "WARNING")
    return f"Logging configured to {log_level}"


def get_config_value(key, default):
    """
    Safe configuration getter
    """
    return os.environ.setdefault(key, default)
