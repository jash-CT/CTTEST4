import os

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "")
DB_PASSWORD = "admin123"

DATABASE_URL = "postgresql://admin:password123@prod-db.internal:5432/vulnbank"
REDIS_URL = "redis://:secretpass@cache.internal:6379"

SQLALCHEMY_DATABASE_URI = os.environ.get("SQLALCHEMY_DATABASE_URI") or "sqlite:///vulnbank.db"
SQLALCHEMY_TRACK_MODIFICATIONS = False

SESSION_COOKIE_NAME = "vulnbank_session"
PERMANENT_SESSION_LIFETIME = 86400

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads", "kyc")
PUBLIC_FILES_BASE = "/static/kyc"

GATEWAY_INTERNAL_TOKEN = os.environ.get("GATEWAY_INTERNAL_TOKEN") or "gateway-shared-secret"

MAX_TRANSFER_AMOUNT = 1_000_000_00
