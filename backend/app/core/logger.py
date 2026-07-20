import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from app.core.config import settings

# ==========================================================
# Logger
# ==========================================================

logger = logging.getLogger(settings.APP_NAME)
logger.propagate = False

if settings.DEBUG:
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)

# ==========================================================
# Formatter
# ==========================================================

formatter = logging.Formatter(
    fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# ==========================================================
# Console Handler
# ==========================================================

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logger.level)
console_handler.setFormatter(formatter)

# ==========================================================
# Logs Directory
# ==========================================================

BASE_DIR = Path(__file__).resolve().parent.parent.parent

LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

LOG_FILE = LOG_DIR / "app.log"

# ==========================================================
# File Handler
# ==========================================================

file_handler = RotatingFileHandler(
    LOG_FILE,
    maxBytes=10 * 1024 * 1024,   # 10 MB
    backupCount=5,
    encoding="utf-8"
)

file_handler.setLevel(logger.level)
file_handler.setFormatter(formatter)

# ==========================================================
# Register Handlers
# ==========================================================

if not logger.handlers:
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)