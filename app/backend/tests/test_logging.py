import logging
import json
from app.core.logging import JsonFormatter, configure_logging, get_logger


def test_json_formatter():
    formatter = JsonFormatter()
    
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg="test message",
        args=(),
        exc_info=None
    )
    
    result = formatter.format(record)
    assert result is not None
    data = json.loads(result)
    assert data["message"] == "test message"
    assert data["level"] == "INFO"


def test_json_formatter_with_extra():
    formatter = JsonFormatter()
    
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg="test message",
        args=(),
        exc_info=None
    )
    record.extra = {"custom": "value"}
    
    result = formatter.format(record)
    assert result is not None
    data = json.loads(result)
    assert data["extra"]["custom"] == "value"


def test_configure_logging():
    import logging
    root = logging.getLogger()
    initial_handlers = len(root.handlers)
    
    configure_logging()
    
    assert len(root.handlers) >= initial_handlers


def test_get_logger():
    logger = get_logger("test")
    assert logger is not None
    assert logger.name == "test"


def test_get_logger_with_level():
    logger = get_logger("test")
    logger.setLevel(logging.INFO)
    assert logger.level == logging.INFO