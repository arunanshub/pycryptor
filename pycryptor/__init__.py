import logging

logging.getLogger(__name__).addHandler(logging.NullHandler())

LOGGER_FORMAT = "[{asctime}] - {levelname:<8} - {threadName:<15} - {name}({lineno:>3}): {message}"


def start_logging(level=logging.DEBUG, fmt=LOGGER_FORMAT):
    """Start logging activity.

    Adapted from urllib3/__init__.py
    """
    logger = logging.getLogger(__name__)
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter(
            fmt=fmt,
            style="{",
        ),
    )
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.debug(f"Logging enabled for {__name__}")

    return handler
