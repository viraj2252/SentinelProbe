"""Tests for the logging module."""

from unittest.mock import MagicMock, patch

import pytest
from loguru import logger

from sentinelprobe.core.logging import configure_logging, get_logger


def test_get_logger() -> None:
    """Test get_logger function."""
    log = get_logger()
    assert log is logger


@patch("sentinelprobe.core.logging.logger")
@patch("sentinelprobe.core.logging.get_settings")
def test_configure_logging_debug(
    mock_get_settings: MagicMock, mock_logger: MagicMock
) -> None:
    """Test logging configuration in debug mode.

    Args:
        mock_get_settings: Mock for get_settings function.
        mock_logger: Mock for logger.
    """
    # Configure mock settings
    mock_settings = MagicMock()
    mock_settings.LOG_LEVEL = "DEBUG"
    mock_get_settings.return_value = mock_settings

    # Call the function
    configure_logging()

    # Verify logger configuration
    mock_logger.remove.assert_called_once()
    mock_logger.add.assert_called_once()
    mock_logger.info.assert_called_once()


@patch("sentinelprobe.core.logging.logger")
@patch("sentinelprobe.core.logging.get_settings")
def test_configure_logging_non_debug(
    mock_get_settings: MagicMock, mock_logger: MagicMock
) -> None:
    """Test logging configuration in non-debug mode.

    Args:
        mock_get_settings: Mock for get_settings function.
        mock_logger: Mock for logger.
    """
    # Configure mock settings
    mock_settings = MagicMock()
    mock_settings.LOG_LEVEL = "INFO"
    mock_get_settings.return_value = mock_settings

    # Call the function
    configure_logging()

    # Verify logger configuration
    mock_logger.remove.assert_called_once()
    assert mock_logger.add.call_count == 2  # Console and file handlers
    mock_logger.info.assert_called_once()


class MockSettings:
    """Mock settings for testing."""

    def __init__(self, log_level="INFO", log_file=None):
        """Initialize with custom settings."""
        self.LOG_LEVEL = log_level
        self.log_file = log_file


@patch("sentinelprobe.core.logging.logger")
@patch("sentinelprobe.core.logging.get_settings")
def test_configure_logging_with_custom_level(mock_get_settings, mock_logger):
    """Test configure_logging with custom level."""
    # Configure mock settings
    mock_settings = MockSettings(log_level="DEBUG")
    mock_get_settings.return_value = mock_settings

    # Call function
    configure_logging()

    # Check if logger was configured correctly
    mock_logger.remove.assert_called_once()
    mock_logger.add.assert_called()

    # Verify the log level was used
    for call in mock_logger.add.call_args_list:
        args, kwargs = call
        assert "level" in kwargs
        # The level should match our mock settings
        assert kwargs["level"] == mock_settings.LOG_LEVEL
