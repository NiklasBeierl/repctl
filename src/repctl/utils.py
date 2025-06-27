import logging
import sys


def setup_logging():
    repctl_logger = logging.getLogger("repctl")
    repctl_logger.propagate = False
    repctl_logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(stream=sys.stdout)
    formatter = logging.Formatter("%(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    repctl_logger.addHandler(handler)
