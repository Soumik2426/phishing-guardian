from pathlib import Path

import boto3
import joblib
from botocore.exceptions import ClientError, NoCredentialsError

from app.core.config import settings

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

    print("[INFO] Local model not found.")
    print("[INFO] Downloading model from S3...")

    s3 = boto3.client(
        "s3",
        region_name=settings.AWS_REGION
    )

    s3.download_file(
        settings.S3_BUCKET,
        settings.S3_MODEL_KEY,
        str(MODEL_PATH)
    )

    print("[INFO] Model downloaded successfully.")


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
        print(f"[INFO] Using local model: {MODEL_PATH}")

    else:

        try:
            download_model_from_s3()

        except NoCredentialsError:
            raise RuntimeError(
                "Model not found locally and AWS credentials are unavailable."
            )

        except ClientError as e:
            raise RuntimeError(
                f"Failed to download model from S3: {e}"
            )

    print("[INFO] Loading ML model...")
    _model = joblib.load(MODEL_PATH)

    print("[INFO] Model loaded successfully.")
    return _model


def get_model():
    if _model is None:
        raise RuntimeError(
            "Model has not been loaded."
        )

    return _model