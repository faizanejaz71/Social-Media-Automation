"""
Django settings for SocialManager project.

Generated by 'django-admin startproject' using Django 5.1.5.

For more information on this file, see
https://docs.djangoproject.com/en/5.1/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/5.1/ref/settings/
"""

from pathlib import Path
import os

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-2x_m7rl5&wan2@z-*-ut%rmnbyi*443(5=*vr7jfut5l0tbm3&'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['socialmanager.pythonanywhere.com']


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'accountManager',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'SocialManager.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'SocialManager.wsgi.application'


# Database
# https://docs.djangoproject.com/en/5.1/ref/settings/#databases

# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.postgresql',
#         'NAME': 'socialdb',  # Apna PostgreSQL database ka naam yahan likho
#       "USER": "postgres",
#         "PASSWORD": "Faizan71#",
#         'HOST': '127.0.0.1',           # Localhost
#         'PORT': '5432',                # PostgreSQL ka default port

#     }
# }

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}


# Password validation
# https://docs.djangoproject.com/en/5.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.1/howto/static-files/

# STATIC_URL = 'static/'
# STATICFILES_DIRS = [
#     os.path.join(BASE_DIR, 'App', 'static'),
#     os.path.join(BASE_DIR, 'Dashboard', 'static'),
# ]

STATIC_URL = '/static/'  # URL to access static files
STATICFILES_DIRS = [os.path.join(BASE_DIR, "static")]  # Optional: For additional static files

# For production, collect all static files into this directory
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
# Default primary key field type
# https://docs.djangoproject.com/en/5.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'



#Twitter API
TWITTER_CLIENT_ID = 'SU9pdTYxT1FfNXZ3OThkVWhVWGg6MTpjaQ'
TWITTER_API_SECRET_KEY = 'qcl95Xga7QfN4n7sJnpPeXA60GJw1girS8Ya0SGQ_bbNrcXG'
TWITTER_REDIRECT_URI = "https://socialmanager.pythonanywhere.com/twitter/callback/"
TWITTER_SCOPES = ["tweet.read", "tweet.write", "users.read", "offline.access"]
TWITTER_TOKEN_URL = "https://api.twitter.com/2/oauth2/token"
TWITTER_BEARER_TOKEN = "AAAAAAAAAAAAAAAAAAAAAC6WzAEAAAAAqM8UqsaWNo2eATd5EHE6keDPzaw%3DO4vDng7EfSSNoO61tul28ESWpgfwTM96HzAdjeb09P64sxT7fF"