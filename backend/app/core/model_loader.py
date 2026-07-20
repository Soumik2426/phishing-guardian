from pathlib import Path

import boto3
import joblib
from botocore.exceptions import ClientError, NoCredentialsError

from app.core.config import settings
from app.core.logger import logger

# Cache loaded model
_model = None

# backend/
BASE_DIR = Path(__file__).resolve().parent.parent.parent

MODEL_PATH = BASE_DIR / settings.LOCAL_MODEL_PATH


def download_model_from_s3():
    """
    Downloads the model from S3 if it is not available locally.
    """

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)

    logger.info("Local model not found.")
    logger.info("Downloading model from S3...")

    s3 = boto3.client(
        "s3",
        region_name=settings.AWS_REGION
    )

    s3.download_file(
        settings.S3_BUCKET,
        settings.S3_MODEL_KEY,
        str(MODEL_PATH)
    )

    logger.info("Model downloaded successfully.")


def load_model():
    """
    Loads the phishing detection model.

    Priority:
    1. Local model
    2. S3 download
    """

    global _model

    if _model is not None:
        return _model

    if MODEL_PATH.exists():
        logger.info(f"Using local model: {MODEL_PATH}")

    else:
        try:
            download_model_from_s3()

        except NoCredentialsError:
            logger.error("AWS credentials not found.")
            raise RuntimeError(
                "Model not found locally and AWS credentials are unavailable."
            )

        except ClientError as e:
            logger.error(f"Failed to download model from S3: {e}")
            raise RuntimeError(
                f"Failed to download model from S3: {e}"
            )

    logger.info("Loading ML model...")

    _model = joblib.load(MODEL_PATH)

    logger.info("Model loaded successfully.")

    return _model


def get_model():
    """
    Returns the loaded ML model.
    """

    if _model is None:
        logger.error("Model has not been loaded.")
        raise RuntimeError(
            "Model has not been loaded."
        )

    return _model