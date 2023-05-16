1 # No special middleware needed, just use the normal Django auth middleware
MIDDLEWARE = [
  "django.middleware.csrf.CsrfViewMiddleware",
  "django.contrib.auth.middleware.AuthenticationMiddleware",
  ...
]

LOGIN_URL = "/login/"

# SSO
SSO_API_KEY = env("SSO_API_KEY", default="")
SSO_CLIENT_ID = env("SSO_CLIENT_ID", default="")
SSO_URL = env("SSO_URL", default="")

if SSO_API_KEY and SSO_CLIENT_ID and SSO_URL:
    SSO_AVAILABLE = True
else:
    SSO_AVAILABLE = False
