import os
from pathlib import Path
from decouple import config
from dotenv import load_dotenv
load_dotenv()

from environ import Env
env = Env()
env.read_env()

ENVIRONMENT = env('ENVIRONMENT', default="production")
print(f"ENVIRONMENT: {ENVIRONMENT}")


PAYMENT_BASE_URL_LINK = "https://sandbox.zarinpal.com/pg/StartPay"
COUNTRY = "United States"

HOST = "http://127.0.0.1:8000"
BASE_API_URL = f"{HOST}/api/v1"


# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get("SECRET_KEY")

# SECURITY WARNING: don't run with debug turned on in production!
# Set to True for connecting to remote database from local environment
POSTGRES_LOCALLY = False

if ENVIRONMENT == 'development':
    DEBUG = True
else:
    DEBUG = False

ALLOWED_HOSTS = ['web-b7uo9461trki.up-de-fra1-k8s-1.apps.run-on-seenode.com']
CSRF_TRUSTED_ORIGINS = ['https://web-b7uo9461trki.up-de-fra1-k8s-1.apps.run-on-seenode.com']

SITE_PUBLISHED = True
DJANGO_ALLOW_ASYNC_UNSAFE = True
CORS_ALLOW_ALL_ORIGINS = True

COUNTRIES_CHOICE = [
    ("US", "United States"),
    ("UK", "United Kingdom"),
    ("CA", "Canada"),
    ("AU", "Australia"),
    ("IN", "India"),
    ("FR", "France"),
    ("DE", "Germany"),
    ("ES", "Spain"),
    ("CH", "Switzerland"),
    ("IT", "Italy"),
    ("NL", "Netherlands"),
]

CURRENT_COUNTRY = "US"

ROLES_CHOICE = [
    (
        "admin",
        "Administrator role: Has full access to all system features and settings.",
    ),
    ("user", "User role: Regular user with basic access to the application."),
    ("user_manager", "User Manager role: Can manage users and their permissions."),
    (
        "super_admin",
        "Super Admin role: Has the highest level of access and control over the application.",
    ),
]

CURRENT_ROLE = "user"

# add the CSRF_TRUSTED_ORIGINS=['']
CSRF_TRUSTED_ORIGINS = [os.environ.get("CSRF_TRUSTED_ORIGINS")]

SECURE_REFERRER_POLICY = os.environ.get("SECURE_REFERRER_POLICY")

# Application definition
INSTALLED_APPS = [
    "unfold",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "maintenance_mode",
    "rest_framework",
    "rest_framework.authtoken",
    "ApiPlatform",
    "adrf",
    "django_user_agents",
    "channels",
]

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "127.0.0.1:8000",
        "TIMEOUT": 300,
    }
}

USER_AGENTS_CACHE = "default"

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework.authentication.TokenAuthentication",
    ),
}

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "ApiPlatform.middlewares.SitePublishedMiddleware",
    "ApiPlatform.middlewares.TimezoneMiddleware",
    "maintenance_mode.middleware.MaintenanceModeMiddleware",
]

MIDDLEWARE += ["ApiPlatform.login_attempt_middleware.LoginAttemptMiddleware"]
MIDDLEWARE += ["ApiPlatform.ip_ban_middleware.BanIPMiddleware"]
MIDDLEWARE += ["django_user_agents.middleware.UserAgentMiddleware"]

ROOT_URLCONF = "CoinsSellingPlatformProject.urls"

templates = BASE_DIR / "templates"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [templates],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "ApiPlatform.context_processors.user_profile_context",
                "ApiPlatform.context_processors.player_creation_notifications_context",
                "ApiPlatform.context_processors.game_creation_notifications_context",
            ],
        },
    },
]

WSGI_APPLICATION = "CoinsSellingPlatformProject.wsgi.application"
# gunicorn CoinsSellingPlatformProject.wsgi --bind 0.0.0.0:80


DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': env('DB_NAME'),
        'USER': env('USER'),
        'PASSWORD': env('PASSWORD'),
        'HOST': env('HOST'),
        'PORT': env('PORT'),
    }
}


AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


LANGUAGE_CODE = "en-us"
TIME_ZONE = "Asia/Karachi"
TIME_INPUT_FORMATS = ("%I:%M %p",)
USE_I18N = True
USE_TZ = True


# static files' settings
STATIC_URL = config("STATIC_URL", default="/static/")
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = BASE_DIR / "staticfiles"

MEDIA_URL = "/media/"  # The URL to access media files
MEDIA_ROOT = os.path.join(
    BASE_DIR, "media"
)  # The absolute path where media files are stored


# Email settings - CREDENTIALS
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = "smtp.office365.com"
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = "TariqMehmood@thedarkbytes.com"  # Your Outlook email
EMAIL_HOST_PASSWORD = "Y@611026051774uq"  # Your Outlook email password or app password
DEFAULT_FROM_EMAIL = "TariqMehmood@thedarkbytes.com"  # Default sender email
ADMIN_DEFAULT_FROM_EMAIL = "info@thedarkbytes.com"


DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


## MAINTENANCE MODE

# if True the maintenance-mode will be activated
MAINTENANCE_MODE = False  # True/False/None

# if True admin site will not be affected by the maintenance-mode page
MAINTENANCE_MODE_IGNORE_ADMIN_SITE = True  # True/False/None

# if True anonymous users will not see the maintenance-mode page
MAINTENANCE_MODE_IGNORE_ANONYMOUS_USER = True  # True/False/None

MAINTENANCE_MODE_TEMPLATE = "503.html"

MAINTENANCE_MODE_STATUS_CODE = 503

# the value in seconds of the Retry-After header during maintenance-mode
MAINTENANCE_MODE_RETRY_AFTER = 3600  # 1 hour

## MAINTENANCE MODE


###################################################################################


## DJANGO-UNFOLD SETTINGS
from django.templatetags.static import static
from django.urls import reverse_lazy
from django.utils.translation import gettext_lazy as _

UNFOLD = {
    "SITE_TITLE": "Admin Panel - Casinoze",
    "SITE_HEADER": "Admin Panel - Casinoze",
    "SITE_SUBHEAD": "Admin Panel - Casinoze",
    "SITE_DROPDOWN": [
        {
            "icon": "diamond",
            "title": _("Casinoze"),
            "link": "",
        },
    ],
    "SITE_URL": "/",
    "SITE_ICON": {
        "light": lambda request: static("images/logo.png"),  # light mode
        "dark": lambda request: static("images/logo.png"),  # dark mode
    },
    "SITE_LOGO": {
        "light": lambda request: static("images/logo.png"),  # light mode
        "dark": lambda request: static("images/logo.png"),  # dark mode
    },
    "SITE_SYMBOL": "speed",  # symbol from icon set
    "SITE_FAVICONS": [
        {
            "rel": "icon",
            "sizes": "32x32",
            "type": "image/png",
            "href": lambda request: static("images/logo.png"),
        },
    ],
    "SHOW_HISTORY": True,
    "SHOW_VIEW_ON_SITE": True,
    "SHOW_BACK_BUTTON": True,
    "THEME": "light",
    "BORDER_RADIUS": "6px",
    "COLORS": {
        "base": {
            "50": "249 250 251",
            "100": "243 244 246",
            "200": "229 231 235",
            "300": "209 213 219",
            "400": "156 163 175",
            "500": "107 114 128",
            "600": "75 85 99",
            "700": "55 65 81",
            "800": "31 41 55",
            "900": "17 24 39",
            "950": "3 7 18",
        },
        "primary": {
            "50": "250 245 255",
            "100": "243 232 255",
            "200": "233 213 255",
            "300": "216 180 254",
            "400": "192 132 252",
            "500": "168 85 247",
            "600": "147 51 234",
            "700": "126 34 206",
            "800": "107 33 168",
            "900": "88 28 135",
            "950": "59 7 100",
        },
        "font": {
            "subtle-light": "var(--color-base-500)",  # text-base-500
            "subtle-dark": "var(--color-base-400)",  # text-base-400
            "default-light": "var(--color-base-600)",  # text-base-600
            "default-dark": "var(--color-base-300)",  # text-base-300
            "important-light": "var(--color-base-900)",  # text-base-900
            "important-dark": "var(--color-base-100)",  # text-base-100
        },
    },
    "SIDEBAR": {
        "show_search": True,  # Search in applications and models names
        "show_all_applications": True,  # Dropdown with all applications and models
        "navigation": [
            {
                "title": _("Navigation"),
                "separator": True,  # Top border
                "collapsible": False,  # Collapsible group of links
                "items": [
                    {
                        "title": _("Dashboard"),
                        "icon": "dashboard",  # Supported icon set: https://fonts.google.com/icons
                        "link": reverse_lazy("admin:index"),
                        "badge": "Main Admin",
                        "permission": lambda request: request.user.is_superuser,
                    },
                ],
            },
            {
                "title": _("Settings"),
                "separator": True,  # Top border
                "collapsible": False,  # Collapsible group of links
                "items": [
                    {
                        "title": _("Users"),
                        "icon": "group",
                        "link": reverse_lazy("admin:auth_user_changelist"),
                    },
                ],
            },
        ],
    },
}

## DJANGO-UNFOLD SETTINGS


###################################################################################
