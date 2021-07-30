import logging
import colorlog

logging.getLogger(__name__).addHandler(logging.NullHandler())

LOGGER_FORMAT = "[{asctime} {log_color}{levelname:<7}{reset}] {message}"

def start_logging(level=logging.DEBUG, fmt=LOGGER_FORMAT):
    """Start logging activity.

    Adapted from urllib3/__init__.py
    """
    logger = logging.getLogger(__name__)
    handler = logging.StreamHandler()
    handler.setFormatter(
        colorlog.ColoredFormatter(
            fmt=fmt,
            style="{",
        ),
    )
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.debug(f"Logging enabled for {__name__}")

    return handler
