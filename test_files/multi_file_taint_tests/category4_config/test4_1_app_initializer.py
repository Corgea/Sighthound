# Test 4.1: Configuration Patterns (Safe) - APP INITIALIZER
# Expected: Should NOT detect any vulnerabilities (configuration, not user input)

from test4_1_config_manager import setup_environment, configure_logging
import subprocess


def initialize():
    """
    SAFE: Using configuration functions should not create taint flows
    """
    result = setup_environment()  # Configuration function call
    subprocess.run(["echo", result])  # Safe command with config result

    log_config = configure_logging()
    subprocess.run(["echo", log_config])  # Another safe command


def start_application():
    """
    Application startup with configuration
    """
    initialize()

    # Safe system commands for application startup
    subprocess.run(["echo", "Application starting..."])
    subprocess.run(["mkdir", "-p", "/tmp/app_logs"])  # Safe file operations
