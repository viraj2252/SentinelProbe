"""Tests for the logging module."""

import sys
from unittest.mock import MagicMock, patch

from loguru import logger

from sentinelprobe.core.logging import configure_logging, get_logger


def test_get_logger() -> None:
    """Test get_logger function."""
    log = get_logger()
    assert log is logger


@patch("sentinelprobe.core.logging.logger")
@patch("sentinelprobe.core.logging.get_settings")
def test_configure_logging_debug(mock_get_settings: MagicMock, mock_logger: MagicMock) -> None:
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
def test_configure_logging_non_debug(mock_get_settings: MagicMock, mock_logger: MagicMock) -> None:
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