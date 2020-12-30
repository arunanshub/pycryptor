import logging

logging.getLogger(__name__).addHandler(logging.NullHandler())


def start_logging(level=logging.DEBUG):
    """Start logging activity.

    Adapted from urllib3/__init__.py
    """
    logger = logging.getLogger(__name__)
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter(
            fmt="[{asctime}] - {levelname:<8} - {name}({lineno}): {message}",
            style="{",
        ),
    )
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.debug(f"Logging enabled for {__name__}")

    return handler
