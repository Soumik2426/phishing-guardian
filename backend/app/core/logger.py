import logging
import sys

from app.core.config import settings

# Create logger
logger = logging.getLogger(settings.APP_NAME)

# Prevent duplicate logs
logger.propagate = False

# Set log level
if settings.DEBUG:
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)

# Create console handler
console_handler = logging.StreamHandler(sys.stdout)

# Handler log level
console_handler.setLevel(logger.level)

# Log format
formatter = logging.Formatter(
    fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

console_handler.setFormatter(formatter)

# Avoid duplicate handlers when using --reload
if not logger.handlers:
    logger.addHandler(console_handler)