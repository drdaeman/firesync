"""
Django settings for firesync project.

For more information on this file, see
https://docs.djangoproject.com/en/1.6/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/1.6/ref/settings/
"""

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
import os
from django.conf import global_settings
import email.utils


# Lock down insecure pure-Python fallback RSA implementation in PyBrowserID
def _lock_down_insecure_crypto():
    from browserid.crypto import fallback

    class DisabledInsecureImplementation(object):
        @classmethod
        def _fail(self):
            # Pure-Python fallback RSA-OAEP implementation is broken in all senses.
            # First of all, it doesn't work - it can't even validate a signature.
            # But even if it would, it's implemented in an awfully naive way,
            # that's at the very least is prone to timing attacks, if not worse.
            # I'm not a cryptographer, but the code I saw just cried of that.
            #
            # So, let's avoid it.
            #
            # HINT: If M2Crypto fails for you, try a specific version.
            # Say, 0.22.3 from PyPI does the trick for me, while 0.22.5 fails complaining
            # that my OpenSSL doesn't export SSLv2_method symbol.
            raise RuntimeError("You MUST install M2Crypto for PyBrowserID.")

        def __init__(self):
            self._fail()

        @classmethod
        def sign(cls, data):
            cls._fail()

        @classmethod
        def verify(cls, data, signature):
            cls._fail()

    for class_name in ["Key", "RSKey", "DSKey"]:
        setattr(getattr(fallback, class_name), "sign", DisabledInsecureImplementation.sign)
        setattr(getattr(fallback, class_name), "verify", DisabledInsecureImplementation.verify)
        setattr(fallback, class_name, DisabledInsecureImplementation)
_lock_down_insecure_crypto()


BASE_DIR = os.path.dirname(os.path.dirname(__file__))   # Project's base directory
DATA_DIR = os.environ.get("DATA_DIR", BASE_DIR)         # Storage directory


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/1.6/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY_FILE = os.path.join(DATA_DIR, "secret-key.dat")
try:
    fh = os.open(SECRET_KEY_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 384)  # 384 = 0o600
except OSError as e:
    import errno
    if e.errno == errno.EEXIST:
        with open(SECRET_KEY_FILE, "r") as f:
            SECRET_KEY = f.read()
    else:
        raise
else:
    import random, string
    SECRET_KEY = "".join([
        random.SystemRandom().choice(
            string.ascii_letters + string.digits + string.punctuation
        ) for i in range(48)
    ])
    with os.fdopen(fh, "w") as f:
        f.write(SECRET_KEY)

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.environ.get("DEBUG", "").lower() in ("1", "y", "yes", "true", "t", "on")

# Main hostname. Used as default value for BROWSERID_ISSUER and ALLOWED_HOSTS.
FIRESYNC_HOSTNAME = os.environ.get("FIRESYNC_HOSTNAME", "localhost:8000")

# SECURITY WARNING: keep this file private and unreadable to others
BROWSERID_KEY_FILE = os.path.join(DATA_DIR, "browserid.pem")
BROWSERID_ISSUER = os.environ.get("BROWSERID_ISSUER", FIRESYNC_HOSTNAME)

# A list of strings representing the host/domain names that this Django site can serve.
# Usually you don't need to provide one, but specify FIRESYNC_HOSTNAME instead.
ALLOWED_HOSTS = list(filter(None, os.environ.get("ALLOWED_HOSTS", FIRESYNC_HOSTNAME).split()))

# A list of all the people who get code error notifications.
# Specified as "User Name <someone@example.org>, Another Name <someone-else@example.net>".
ADMINS = list(map(email.utils.parseaddr, filter(None, os.environ.get("ADMINS", "").split(","))))


# Application definition

INSTALLED_APPS = (
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'sslserver',
    'corsheaders',
    'janus',
    'mnemosyne',
)

MIDDLEWARE_CLASSES = (
    'corsheaders.middleware.CorsMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'janus.auth.HawkAuthenticationMiddleware',
    'janus.auth.BrowserIDAuthenticationMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
)

CORS_ORIGIN_ALLOW_ALL = True

AUTH_USER_MODEL = 'janus.User'
PASSWORD_HASHERS = ['janus.auth.MozillaOnePWHasher'] + list(global_settings.PASSWORD_HASHERS)

ROOT_URLCONF = 'firesync.urls'

WSGI_APPLICATION = 'firesync.wsgi.application'


# Database
# https://docs.djangoproject.com/en/1.6/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(DATA_DIR, 'db.sqlite3'),
    }
}

# Internationalization
# https://docs.djangoproject.com/en/1.6/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.6/howto/static-files/

STATIC_ROOT = os.path.join(BASE_DIR, 'static')
STATIC_URL = '/static/'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            os.path.join(BASE_DIR,  'templates'),
        ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.contrib.auth.context_processors.auth',
                'django.template.context_processors.debug',
                'django.template.context_processors.i18n',
                'django.template.context_processors.media',
                'django.template.context_processors.static',
                'django.template.context_processors.tz',
                'django.contrib.messages.context_processors.messages',
            ],
            'debug': DEBUG,
        },
    }
]

# Logging

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '%(levelname)s %(asctime)s %(module)s %(process)d %(thread)d %(message)s'
        },
        'simple': {
            'format': '%(levelname)s %(message)s'
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose'
        },
    },
    'loggers': {
        'janus': {
            'handlers': ['console'],
            'level': 'DEBUG' if DEBUG else 'INFO',
            'propagate': True,
        },
        'mnemosyne': {
            'handlers': ['console'],
            'level': 'DEBUG' if DEBUG else 'INFO',
            'propagate': True,
        },
    },
}
