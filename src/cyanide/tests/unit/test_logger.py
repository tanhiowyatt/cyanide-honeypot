import logging
import logging.handlers

import pytest

from cyanide.logger import CyanideLogger


@pytest.fixture
def temp_log_dir(tmp_path):
    d = tmp_path / "logs"
    d.mkdir()
    return str(d)


def test_logger_plain_handlers(temp_log_dir):
    """Test standard plain logging instantiation yields basic FileHandlers."""
    config = {"logtype": "plain"}

    CyanideLogger(temp_log_dir, logging_config=config)

    server_logger = logging.getLogger("cyanide_server")
    assert len(server_logger.handlers) == 1
    assert isinstance(server_logger.handlers[0], logging.FileHandler)
    assert not isinstance(server_logger.handlers[0], logging.handlers.RotatingFileHandler)
    assert not isinstance(server_logger.handlers[0], logging.handlers.TimedRotatingFileHandler)


def test_logger_time_rotating_handlers(temp_log_dir):
    """Test TimedRotatingFileHandler instantiation."""
    config = {
        "logtype": "rotating",
        "rotation": {"strategy": "time", "when": "midnight", "interval": 1, "backup_count": 7},
    }

    CyanideLogger(temp_log_dir, logging_config=config)

    server_logger = logging.getLogger("cyanide_server")
    assert len(server_logger.handlers) == 1
    handler = server_logger.handlers[0]
    assert isinstance(handler, logging.handlers.TimedRotatingFileHandler)
    assert handler.when == "MIDNIGHT"  # timedrotatingfilehandler converts it to upper
    assert handler.interval == 86400  # TimedRotatingFileHandler works natively in seconds
    assert handler.backupCount == 7


def test_logger_size_rotating_handlers(temp_log_dir):
    """Test RotatingFileHandler instantiation."""
    config = {
        "logtype": "rotating",
        "rotation": {"strategy": "size", "max_bytes": 1024, "backup_count": 3},
    }

    CyanideLogger(temp_log_dir, logging_config=config)

    server_logger = logging.getLogger("cyanide_server")
    assert len(server_logger.handlers) == 1
    handler = server_logger.handlers[0]
    assert isinstance(handler, logging.handlers.RotatingFileHandler)
    # TimedRotating subclassess Rotating so must check specific types accurately
    assert handler.maxBytes == 1024
    assert handler.backupCount == 3


def test_logger_handler_deduplication(temp_log_dir):
    """Test that multiple instantiations do not duplicate handlers on the underlying root loggers."""
    config = {"logtype": "plain"}

    # Init 1
    CyanideLogger(temp_log_dir, logging_config=config)
    server_logger = logging.getLogger("cyanide_server")
    assert len(server_logger.handlers) == 1

    # Init 2
    CyanideLogger(temp_log_dir, logging_config=config)
    # The logger logic should remove the previous handler and add the new one
    assert len(server_logger.handlers) == 1


def test_get_target_logger(temp_log_dir):
    """Test routing of event types to proper loggers."""
    config = {"logtype": "plain"}
    logger = CyanideLogger(temp_log_dir, logging_config=config)

    # FS log events
    assert logger._get_target_logger_info("command.input")[0] == logger.fs_log
    assert logger._get_target_logger_info("sftp_op")[0] == logger.fs_log
    assert logger._get_target_logger_info("rsync_filelist")[0] == logger.fs_log

    # ML events
    assert logger._get_target_logger_info("ml_classification")[0] == logger.ml_log
    assert logger._get_target_logger_info("ml_thought")[0] == logger.ml_log

    # Stats
    assert logger._get_target_logger_info("stats")[0] == logger.stats_log

    # Default
    assert logger._get_target_logger_info("system_init")[0] == logger.server_log
