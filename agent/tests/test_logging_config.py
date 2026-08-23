import json
import logging

from sentinelguard_agent.logging_config import configure_logging


def test_configure_logging_emits_valid_json(capsys):
    configure_logging("INFO")
    logger = logging.getLogger("test.logger")
    logger.info("hello world")

    captured = capsys.readouterr()
    line = captured.err.strip().splitlines()[-1]
    payload = json.loads(line)

    assert payload["message"] == "hello world"
    assert payload["level"] == "INFO"
    assert payload["logger"] == "test.logger"
    assert "timestamp" in payload


def test_configure_logging_is_idempotent(capsys):
    configure_logging("INFO")
    configure_logging("INFO")
    logger = logging.getLogger("test.idempotent")
    logger.info("only once")

    captured = capsys.readouterr()
    lines = [line for line in captured.err.strip().splitlines() if "only once" in line]
    assert len(lines) == 1  # not duplicated across handlers


def test_configure_logging_respects_level(capsys):
    configure_logging("WARNING")
    logger = logging.getLogger("test.level")
    logger.info("should not appear")
    logger.warning("should appear")

    captured = capsys.readouterr()
    assert "should not appear" not in captured.err
    assert "should appear" in captured.err


def test_exception_info_included(capsys):
    configure_logging("INFO")
    logger = logging.getLogger("test.exc")
    try:
        raise ValueError("boom")
    except ValueError:
        logger.exception("failed")

    captured = capsys.readouterr()
    line = captured.err.strip().splitlines()[-1]
    payload = json.loads(line)
    assert "exception" in payload
    assert "ValueError: boom" in payload["exception"]
