"""
SecureVault — Django Settings
Classification: Internal / Confidential

All sensitive values are loaded from environment variables.
Never hardcode secrets in this file.
"""

import os
from pathlib import Path
from datetime import timedelta

BASE_DIR = Path(__file__).resolve().parent.parent

# ─────────────────────────────────────────────
# CORE
# ─────────────────────────────────────────────
SECRET_KEY = os.environ["SECRET_KEY"]  # Never fallback; fail if missing
DEBUG = os.environ.get("DEBUG", "False").lower() == "true"
ALLOWED_HOSTS = os.environ.get("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")
APP_VERSION = os.environ.get("APP_VERSION", "5.0.0")

# ─────────────────────────────────────────────
# APPLICATIONS
# ─────────────────────────────────────────────
DJANGO_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
]

THIRD_PARTY_APPS = [
    "rest_framework",
    "rest_framework_simplejwt",
    "rest_framework_simplejwt.token_blacklist",
    "corsheaders",
    "django_ratelimit",
    "axes",
    "storages",
]

LOCAL_APPS = [
    "src.backend.auth",
    "src.backend.api",
    "src.backend.files",
    "src.backend.core",
]

INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

# ─────────────────────────────────────────────
# MIDDLEWARE (ORDER IS CRITICAL)
# ─────────────────────────────────────────────
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",         # must be first
    "corsheaders.middleware.CorsMiddleware",                 # before CommonMiddleware
    "src.backend.middleware.security_headers.SecurityHeadersMiddleware",
    "src.backend.middleware.audit_logger.AuditLogMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "axes.middleware.AxesMiddleware",                        # brute force protection
    "src.backend.middleware.rate_limiter.RateLimitMiddleware",
]

ROOT_URLCONF = "src.backend.core.urls"
WSGI_APPLICATION = "src.backend.core.wsgi.application"

# ─────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ["DB_NAME"],
        "USER": os.environ["DB_USER"],
        "PASSWORD": os.environ["DB_PASSWORD"],
        "HOST": os.environ.get("DB_HOST", "postgres"),
        "PORT": os.environ.get("DB_PORT", "5432"),
        "OPTIONS": {
            "sslmode": os.environ.get("DB_SSL_MODE", "require"),
            "connect_timeout": 10,
        },
        "CONN_MAX_AGE": 60,
        "TEST": {
            "NAME": "test_securevault_db",
        },
    }
}

# ─────────────────────────────────────────────
# CACHE (REDIS)
# ─────────────────────────────────────────────
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": os.environ["REDIS_URL"],
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
            "SOCKET_CONNECT_TIMEOUT": 5,
            "SOCKET_TIMEOUT": 5,
        },
        "KEY_PREFIX": "securevault",
        "TIMEOUT": int(os.environ.get("CACHE_TTL", "300")),
    }
}

SESSION_ENGINE = "django.contrib.sessions.backends.cache"
SESSION_CACHE_ALIAS = "default"

# ─────────────────────────────────────────────
# AUTHENTICATION
# ─────────────────────────────────────────────
AUTH_USER_MODEL = "auth.User"

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
     "OPTIONS": {"min_length": 14}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# Argon2id password hasher (highest priority)
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",  # fallback for migration
]

# ─────────────────────────────────────────────
# JWT CONFIGURATION
# ─────────────────────────────────────────────
def _load_key(path_env: str) -> str:
    """Load RSA key from file path specified in ENV."""
    key_path = os.environ.get(path_env)
    if not key_path:
        raise ValueError(f"Missing required ENV: {path_env}")
    with open(key_path, "r") as f:
        return f.read()


SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(
        minutes=int(os.environ.get("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
    ),
    "REFRESH_TOKEN_LIFETIME": timedelta(
        days=int(os.environ.get("JWT_REFRESH_TOKEN_EXPIRE_DAYS", "7"))
    ),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
    "UPDATE_LAST_LOGIN": True,
    "ALGORITHM": "RS256",
    "SIGNING_KEY": _load_key("JWT_PRIVATE_KEY_PATH") if not DEBUG else "dev-only-key",
    "VERIFYING_KEY": _load_key("JWT_PUBLIC_KEY_PATH") if not DEBUG else "dev-only-key",
    "AUTH_HEADER_TYPES": ("Bearer",),
    "USER_ID_FIELD": "id",
    "USER_ID_CLAIM": "user_id",
    "AUTH_TOKEN_CLASSES": ("rest_framework_simplejwt.tokens.AccessToken",),
    "TOKEN_TYPE_CLAIM": "token_type",
    "JTI_CLAIM": "jti",
}

# ─────────────────────────────────────────────
# REST FRAMEWORK
# ─────────────────────────────────────────────
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",  # Deny by default
    ],
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": "20/minute",
        "user": os.environ.get("RATE_LIMIT_API", "100/minute"),
        "login": os.environ.get("RATE_LIMIT_LOGIN", "5/minute"),
        "upload": os.environ.get("RATE_LIMIT_UPLOAD", "10/minute"),
    },
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
    "DEFAULT_PARSER_CLASSES": [
        "rest_framework.parsers.JSONParser",
        "rest_framework.parsers.MultiPartParser",  # for file upload
    ],
    "EXCEPTION_HANDLER": "src.backend.core.exceptions.custom_exception_handler",
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.LimitOffsetPagination",
    "PAGE_SIZE": 20,
    "MAX_PAGE_SIZE": 100,
}

# ─────────────────────────────────────────────
# CORS CONFIGURATION
# ─────────────────────────────────────────────
CORS_ALLOWED_ORIGINS = os.environ.get(
    "CORS_ALLOWED_ORIGINS", "https://localhost:3000"
).split(",")
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_ALL_ORIGINS = False  # NEVER enable in production
CORS_ALLOWED_HEADERS = [
    "accept", "authorization", "content-type",
    "x-csrf-token", "x-request-id",
]

# ─────────────────────────────────────────────
# CSRF
# ─────────────────────────────────────────────
CSRF_TRUSTED_ORIGINS = os.environ.get(
    "CSRF_TRUSTED_ORIGINS", "https://localhost:3000"
).split(",")
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = False   # Must be readable by JS to attach to requests
CSRF_COOKIE_SAMESITE = "Strict"
CSRF_USE_SESSIONS = False      # Cookie-based double-submit pattern

# ─────────────────────────────────────────────
# SESSION SECURITY
# ─────────────────────────────────────────────
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Strict"
SESSION_COOKIE_AGE = 7 * 24 * 60 * 60  # 7 days
SESSION_SAVE_EVERY_REQUEST = False

# ─────────────────────────────────────────────
# SECURITY SETTINGS
# ─────────────────────────────────────────────
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_SSL_REDIRECT = not DEBUG  # Redirect HTTP to HTTPS in production
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
X_FRAME_OPTIONS = "DENY"

# ─────────────────────────────────────────────
# BRUTE FORCE PROTECTION (django-axes)
# ─────────────────────────────────────────────
AXES_FAILURE_LIMIT = int(os.environ.get("ACCOUNT_LOCKOUT_ATTEMPTS", "5"))
AXES_COOLOFF_TIME = timedelta(
    seconds=int(os.environ.get("ACCOUNT_LOCKOUT_DURATION", "900"))
)
AXES_LOCK_OUT_AT_FAILURE = True
AXES_USE_USER_AGENT = True
AXES_LOCKOUT_URL = "/api/v1/auth/locked/"
AXES_RESET_ON_SUCCESS = True
AXES_HANDLER = "src.backend.auth.lockout.CustomAxesHandler"

# ─────────────────────────────────────────────
# OBJECT STORAGE
# ─────────────────────────────────────────────
STORAGE_BACKEND = os.environ.get("STORAGE_BACKEND", "minio")
MAX_FILE_SIZE_BYTES = int(os.environ.get("MAX_FILE_SIZE_MB", "50")) * 1024 * 1024
PRESIGNED_URL_EXPIRY = int(os.environ.get("PRESIGNED_URL_EXPIRY", "300"))

ALLOWED_FILE_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".txt", ".csv", ".json", ".xml",
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg",
    ".zip", ".tar", ".gz",
    ".mp4", ".mp3",
}

BLOCKED_MIME_TYPES = {
    "application/x-executable",
    "application/x-sharedlib",
    "application/x-dosexec",
    "application/java-archive",
    "text/x-php",
    "application/x-httpd-php",
}

if STORAGE_BACKEND == "minio":
    MINIO_ENDPOINT = os.environ.get("MINIO_ENDPOINT", "minio:9000")
    MINIO_ACCESS_KEY = os.environ["MINIO_ACCESS_KEY"]
    MINIO_SECRET_KEY = os.environ["MINIO_SECRET_KEY"]
    MINIO_BUCKET = os.environ.get("MINIO_BUCKET", "securevault-files")
    MINIO_SECURE = os.environ.get("MINIO_SECURE", "True").lower() == "true"
else:
    AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
    AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
    AWS_STORAGE_BUCKET_NAME = os.environ.get("AWS_STORAGE_BUCKET_NAME")
    AWS_S3_REGION_NAME = os.environ.get("AWS_S3_REGION_NAME", "us-east-1")
    AWS_DEFAULT_ACL = "private"
    AWS_S3_FILE_OVERWRITE = False

# ─────────────────────────────────────────────
# CLAMAV
# ─────────────────────────────────────────────
CLAMAV_HOST = os.environ.get("CLAMAV_HOST", "clamav")
CLAMAV_PORT = int(os.environ.get("CLAMAV_PORT", "3310"))
CLAMAV_TIMEOUT = int(os.environ.get("CLAMAV_TIMEOUT", "30"))

# ─────────────────────────────────────────────
# CELERY
# ─────────────────────────────────────────────
CELERY_BROKER_URL = os.environ["CELERY_BROKER_URL"]
CELERY_RESULT_BACKEND = os.environ["CELERY_RESULT_BACKEND"]
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_TIMEZONE = "UTC"
CELERY_TASK_TRACK_STARTED = True
CELERY_TASK_TIME_LIMIT = 300  # 5 minutes max per task
CELERY_WORKER_MAX_TASKS_PER_CHILD = 100  # Prevent memory leaks

# ─────────────────────────────────────────────
# LOGGING & AUDIT
# ─────────────────────────────────────────────
ELASTICSEARCH_HOST = os.environ.get("ELASTICSEARCH_HOST", "elasticsearch:9200")
ELASTICSEARCH_INDEX_PREFIX = os.environ.get("ELASTICSEARCH_INDEX_PREFIX", "securevault")

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "()": "pythonjsonlogger.jsonlogger.JsonFormatter",
            "format": "%(asctime)s %(name)s %(levelname)s %(message)s",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "json",
        },
        "elasticsearch": {
            "class": "src.backend.middleware.audit_logger.ElasticsearchHandler",
            "level": "INFO",
        },
    },
    "loggers": {
        "securevault.audit": {
            "handlers": ["elasticsearch", "console"],
            "level": "INFO",
            "propagate": False,
        },
        "securevault.security": {
            "handlers": ["elasticsearch", "console"],
            "level": "WARNING",
            "propagate": False,
        },
        "django": {
            "handlers": ["console"],
            "level": "WARNING",
            "propagate": False,
        },
    },
}

# ─────────────────────────────────────────────
# EMAIL
# ─────────────────────────────────────────────
EMAIL_BACKEND = os.environ.get(
    "EMAIL_BACKEND", "django.core.mail.backends.console.EmailBackend"
)
EMAIL_HOST = os.environ.get("EMAIL_HOST", "localhost")
EMAIL_PORT = int(os.environ.get("EMAIL_PORT", "587"))
EMAIL_USE_TLS = os.environ.get("EMAIL_USE_TLS", "True").lower() == "true"
EMAIL_HOST_USER = os.environ.get("EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = os.environ.get("EMAIL_HOST_PASSWORD", "")
DEFAULT_FROM_EMAIL = os.environ.get("DEFAULT_FROM_EMAIL", "SecureVault <noreply@securevault.io>")

# ─────────────────────────────────────────────
# INTERNATIONALIZATION
# ─────────────────────────────────────────────
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

# ─────────────────────────────────────────────
# STATIC / MEDIA
# ─────────────────────────────────────────────
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
MEDIA_URL = ""   # Files served via pre-signed URLs, never via Django media
MEDIA_ROOT = ""  # Not used; files go to MinIO/S3

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
