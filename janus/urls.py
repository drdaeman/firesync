from django.conf.urls import patterns, include, url

urlpatterns = patterns("janus.views",
    url(r"^signup$", "page_signup"),
    url(r"^signin$", "page_signin"),
    url(r"^force_auth", "page_signin"),

    url(r"^v1/account/create$", "account_create"),
    url(r"^v1/account/status$", "account_status"),
    url(r"^v1/account/login$", "account_login"),
    url(r"^v1/account/devices$", "account_devices"),
    url(r"^v1/account/keys", "account_keys"),

    url(r"^v1/session/destroy", "session_destroy"),
)
