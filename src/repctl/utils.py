import logging
import os
import sys
from argparse import Namespace

LOGGER = logging.getLogger(__name__)


def setup_logging():
    repctl_logger = logging.getLogger("repctl")
    repctl_logger.propagate = False
    repctl_logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(stream=sys.stdout)
    formatter = logging.Formatter("%(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    repctl_logger.addHandler(handler)


def get_api_key(args: Namespace) -> str | None:
    if not (api_key := args.api_key or os.getenv("REPTOR_KEY")):
        LOGGER.error("No Reptor API key provided, pass --api-key or set REPTOR_KEY")
    return api_key
