# Superset Native Azure AD SSO Configuration
# This uses Superset's built-in Flask-AppBuilder OAuth support
import os
from flask_appbuilder.security.manager import AUTH_OAUTH
from celery.schedules import crontab

# Flask App Builder configuration
WTF_CSRF_ENABLED = True
WTF_CSRF_EXEMPT_LIST = []
WTF_CSRF_TIME_LIMIT = None

# Mapbox API key for map visualizations
MAPBOX_API_KEY = os.getenv('MAPBOX_API_KEY', '')

# ---------------------------------------------------
# Babel config for translations
# ---------------------------------------------------
BABEL_DEFAULT_LOCALE = 'en'
BABEL_DEFAULT_TIMEZONE = 'UTC'

# ---------------------------------------------------
# Feature flags
# ---------------------------------------------------
FEATURE_FLAGS = {
    "ENABLE_TEMPLATE_PROCESSING": True,
    "DASHBOARD_NATIVE_FILTERS": True,
    "DASHBOARD_CROSS_FILTERS": True,
    "DASHBOARD_RBAC": True,
    "EMBEDDABLE_CHARTS": True,
    "SCHEDULED_QUERIES": True,
    "ESTIMATE_QUERY_COST": False,
    "ENABLE_TEMPLATE_REMOVE_FILTERS": True,
    "ALLOW_FULL_CSV_EXPORT": True,
    "ALERTS_ATTACH_REPORTS": True,
}

# ---------------------------------------------------
# Native Azure AD OAuth Authentication
# ---------------------------------------------------
AUTH_TYPE = AUTH_OAUTH

# Enable user self-registration
AUTH_USER_REGISTRATION = True

# Default role for new users
AUTH_USER_REGISTRATION_ROLE = "Admin"  # Options: Admin, Alpha, Gamma, Public

# Map Azure AD groups/roles to Superset roles
# This requires Azure AD to send group information in the token
# To enable: Set "groupMembershipClaims": "SecurityGroup" in Azure AD app manifest
# Add MS Graph API permission: GroupMember.Read.All
AUTH_ROLES_MAPPING = {
    # Langfuse Admins → Superset Admin (full access)
    os.getenv('AZURE_AD_LANGFUSE_ADMINS_GROUP_ID', ''): ["Admin"],
    
    # Langfuse Viewers → Superset Gamma (view-only access)
    os.getenv('AZURE_AD_LANGFUSE_VIEWERS_GROUP_ID', ''): ["Gamma"],
}

# Sync roles at login - updates user roles based on Azure AD token
AUTH_ROLES_SYNC_AT_LOGIN = True

# Allow users to update their profile
AUTH_USER_REGISTRATION = True

# OAuth Providers Configuration
OAUTH_PROVIDERS = [
    {
        'name': 'azure',
        'icon': 'fa-microsoft',
        'token_key': 'access_token',
        'remote_app': {
            'client_id': os.getenv('AZURE_CLIENT_ID', 'YOUR_AZURE_AD_CLIENT_ID'),
            'client_secret': os.getenv('AZURE_CLIENT_SECRET', 'YOUR_AZURE_AD_CLIENT_SECRET'),
            'server_metadata_url': f'https://login.microsoftonline.com/{os.getenv("AZURE_TENANT_ID", "YOUR_TENANT_ID")}/v2.0/.well-known/openid-configuration',
            'client_kwargs': {
                'scope': 'openid profile email',  # Groups are included in ID token when configured in Azure AD
            },
        }
    }
]

# Custom OAuth user info parsing
# Azure AD returns user info in a specific format - this extracts it properly
def AUTH_USER_REMOTE_USER_INFO(provider, resp):
    """
    Extract user information from Azure AD OAuth response
    """
    if provider == 'azure':
        # Azure AD returns user info in the ID token or via MS Graph
        me = resp.get('userinfo', {})
        
        return {
            'username': me.get('preferred_username', me.get('email', '')).split('@')[0],
            'email': me.get('preferred_username', me.get('email', '')),
            'first_name': me.get('given_name', me.get('name', '').split(' ')[0]),
            'last_name': me.get('family_name', me.get('name', '').split(' ')[-1] if ' ' in me.get('name', '') else ''),
        }
    
    return {}

# ---------------------------------------------------
# Image and file upload configuration
# ---------------------------------------------------
UPLOAD_FOLDER = '/app/superset_home/app_data/'
IMG_UPLOAD_FOLDER = '/app/superset_home/app_data/'
IMG_UPLOAD_URL = '/static/uploads/'

# ---------------------------------------------------
# Cache configuration with Redis
# ---------------------------------------------------
CACHE_CONFIG = {
    'CACHE_TYPE': 'RedisCache',
    'CACHE_DEFAULT_TIMEOUT': 300,
    'CACHE_KEY_PREFIX': 'superset_',
    'CACHE_REDIS_HOST': os.getenv('REDIS_HOST', 'redis'),
    'CACHE_REDIS_PORT': os.getenv('REDIS_PORT', 6379),
    'CACHE_REDIS_DB': 1,
}

DATA_CACHE_CONFIG = {
    'CACHE_TYPE': 'RedisCache',
    'CACHE_DEFAULT_TIMEOUT': 86400,  # 1 day
    'CACHE_KEY_PREFIX': 'superset_data_',
    'CACHE_REDIS_HOST': os.getenv('REDIS_HOST', 'redis'),
    'CACHE_REDIS_PORT': os.getenv('REDIS_PORT', 6379),
    'CACHE_REDIS_DB': 2,
}

# ---------------------------------------------------
# Celery configuration for async queries
# ---------------------------------------------------
class CeleryConfig:
    broker_url = f'redis://{os.getenv("REDIS_HOST", "redis")}:{os.getenv("REDIS_PORT", 6379)}/0'
    result_backend = f'redis://{os.getenv("REDIS_HOST", "redis")}:{os.getenv("REDIS_PORT", 6379)}/0'
    
    imports = ('superset.sql_lab', 'superset.tasks', 'superset.tasks.thumbnails')
    
    task_annotations = {
        'sql_lab.get_sql_results': {
            'rate_limit': '100/s',
        },
    }
    
    beat_schedule = {
        'reports.scheduler': {
            'task': 'reports.scheduler',
            'schedule': crontab(minute='*', hour='*'),
        },
        'reports.prune_log': {
            'task': 'reports.prune_log',
            'schedule': crontab(minute=0, hour=0),
        },
    }

CELERY_CONFIG = CeleryConfig

# ---------------------------------------------------
# Async query configuration
# ---------------------------------------------------
RESULTS_BACKEND = {
    'SQLALCHEMY_DATABASE_URI': f'postgresql://{os.getenv("DATABASE_USER", "superset")}:{os.getenv("DATABASE_PASSWORD", "")}@{os.getenv("DATABASE_HOST", "postgres")}:{os.getenv("DATABASE_PORT", "5432")}/{os.getenv("DATABASE_DB", "superset")}'
}

# ---------------------------------------------------
# SQL Lab configuration
# ---------------------------------------------------
SQLLAB_ASYNC_TIME_LIMIT_SEC = 60 * 60 * 6  # 6 hours
SQLLAB_TIMEOUT = 300
SQLALCHEMY_POOL_SIZE = 5
SQLALCHEMY_MAX_OVERFLOW = 10

# ---------------------------------------------------
# Row limit for SQL queries
# ---------------------------------------------------
ROW_LIMIT = 50000
SQL_MAX_ROW = 100000

# ---------------------------------------------------
# Security
# ---------------------------------------------------
# CORS Options
ENABLE_CORS = True
CORS_OPTIONS = {
    'supports_credentials': True,
    'allow_headers': ['*'],
    'resources': ['*'],
    'origins': ['*']
}

# Content Security Policy
TALISMAN_ENABLED = False

# Session configuration
PERMANENT_SESSION_LIFETIME = 86400  # 24 hours

# Public role - what unauthenticated users can access
# Set to None to require authentication
PUBLIC_ROLE_LIKE: None

# ---------------------------------------------------
# Optional: Azure AD Group-based Role Mapping
# ---------------------------------------------------
# To enable group-based role mapping:
# 1. In Azure AD app, add "groupMembershipClaims": "SecurityGroup" to manifest
# 2. Add MS Graph API permission: GroupMember.Read.All
# 3. Configure mapping below:

# AUTH_ROLES_MAPPING = {
#     "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx": ["Admin"],   # Azure AD Admin Group ID
#     "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy": ["Alpha"],   # Azure AD Analyst Group ID
#     "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz": ["Gamma"],   # Azure AD Viewer Group ID
# }

# Custom security manager for Azure AD group handling
# This extracts group information from Azure AD tokens
from superset.security import SupersetSecurityManager

class CustomSecurityManager(SupersetSecurityManager):
    def oauth_user_info(self, provider, response=None):
        if provider == 'azure':
            # Get user info from Azure AD
            me = response
            
            # Extract groups if available (requires Azure AD configuration)
            groups = me.get('groups', [])
            
            # Log for debugging
            import logging
            logging.info(f"Azure AD Login - User: {me.get('preferred_username')}, Groups: {groups}")
            
            return {
                'username': me.get('preferred_username', me.get('email', '')).split('@')[0],
                'email': me.get('preferred_username', me.get('email', '')),
                'first_name': me.get('given_name', ''),
                'last_name': me.get('family_name', ''),
                'role_keys': groups,  # Pass groups for AUTH_ROLES_MAPPING
            }
        return {}

CUSTOM_SECURITY_MANAGER = CustomSecurityManager

# ---------------------------------------------------
# Email configuration (for alerts/reports)
# ---------------------------------------------------
SMTP_HOST = os.getenv('SMTP_HOST', 'email-smtp.ca-central-1.amazonaws.com')
SMTP_STARTTLS = True
SMTP_SSL = False
SMTP_USER = os.getenv('SMTP_USER', 'AKIA3TBONZGSPFBABQXQ')
SMTP_PORT = os.getenv('SMTP_PORT', 587)
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', 'BDa5otcImhwwsanVfOevw5GXnIu4+dzXm7vLUiM9xA7E')
SMTP_MAIL_FROM = os.getenv('SMTP_MAIL_FROM', 'noreply@orthoplex.ca')

EMAIL_NOTIFICATIONS = True
EMAIL_HEADER_MUTATOR = lambda msg, **kwargs: None

# Optional: Set display name
EMAIL_HEADER_MUTATOR = lambda msg, **kwargs: msg
