"""
Django settings for the Meshview 3D project.

Phase 1 scope: project wiring, models, PCAP parsing, dissectors.
Live capture, the DRF API surface, and the Three.js frontend are added
in later phases (see README.md).
"""

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# --- Security -----------------------------------------------------------
# Replace this before any real deployment. Fine for local dev only.
SECRET_KEY = "dev-only-secret-key-change-me"

DEBUG = True

ALLOWED_HOSTS: list[str] = ["127.0.0.1", "localhost"]

# --- Apps -----------------------------------------------------------------
INSTALLED_APPS = [
    # Must come first: it makes `runserver` an ASGI server, which is what
    # lets the /ws/scene/ WebSocket route work under plain
    # `python manage.py runserver` (otherwise it's WSGI-only -> HTTP 404).
    "daphne",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "channels",
    "netcap",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "meshview.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "meshview.wsgi.application"
ASGI_APPLICATION = "meshview.asgi.application"

# --- Database ---------------------------------------------------------
# SQLite in WAL mode per the architecture doc: capture writes batches of
# packets while the web process reads concurrently, and WAL lets readers
# and a single writer coexist without locking each other out.
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
        "OPTIONS": {
            "init_command": (
                "PRAGMA journal_mode=WAL; "
                "PRAGMA synchronous=NORMAL; "
                "PRAGMA foreign_keys=ON;"
            ),
        },
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# --- Meshview-specific settings --------------------------------------
# How many decoded packets to buffer before a bulk_create to the DB.
# The architecture doc calls for "roughly every half second"; batch size
# is the other half of that knob (whichever limit is hit first should
# flush, once the live-capture command in Phase 4 adds a timer).
MESHVIEW_BATCH_SIZE = 500

# How many bytes of payload to store per packet, per the ethics/safety
# section: headers + a short preview, not full payloads.
MESHVIEW_PAYLOAD_PREVIEW_BYTES = 64

REST_FRAMEWORK = {
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 200,
}

# --- Phase 4: live capture ----------------------------------------------
# No CHANNEL_LAYERS on purpose. capture_live and the web server are two
# separate processes and Channels' in-memory layer can't span processes;
# SceneConsumer reads the shared SQLite DB instead (see netcap/consumers.py).

# How many seconds of packets a live session keeps in the DB / feeds
# into the scene before they're pruned. See netcap/capture/engine.py.
MESHVIEW_LIVE_WINDOW_SECONDS = 60
