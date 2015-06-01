from django.conf.urls import patterns, include, url

urlpatterns = patterns("",
    url(r"^signup$", "janus.views.page_signup"),
    url(r"^signin$", "janus.views.page_signin"),
    url(r"^force_auth", "janus.views.page_signin"),

    url(r"^v1/account/create$", "janus.views.account_create"),
    url(r"^v1/account/status$", "janus.views.account_status"),
    url(r"^v1/account/login$", "janus.views.account_login"),
    url(r"^v1/account/devices$", "janus.views.account_devices"),
    url(r"^v1/account/keys", "janus.views.account_keys"),
)
