import os


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BRAND_FILE = os.path.join(BASE_DIR, "brands.txt")


def load_brands():
    if not os.path.exists(BRAND_FILE):
        return []

    with open(BRAND_FILE, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]
