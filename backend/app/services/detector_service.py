from app.ml_engine.detector import predict_url


def analyze_url(url: str):
    """
    Service layer responsible for URL analysis.
    Future responsibilities:
    - Save scan history
    - Logging
    - Caching
    - Rate limiting
    """
    return predict_url(url)