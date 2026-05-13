import os
from dotenv import load_dotenv

load_dotenv()

MODE = os.getenv("MODE", "DEV")

DOCS_USER = os.getenv("DOCS_USER", "admin")
DOCS_PASSWORD = os.getenv("DOCS_PASSWORD", "string")

SECRET_KEY = os.getenv("SECRET_KEY", "sekretnyy_klyuch")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

RATE_LIMIT_REGISTER = "1/minute"
RATE_LIMIT_LOGIN = "5/minute"

DATABASE_URL = "sqlite:///./app.db"
