from django.conf.urls import url
from . import views

urlpatterns = [
    url(r"^signup$", views.page_signup),
    url(r"^signin$", views.page_signin),
    url(r"^force_auth", views.page_signin),

    url(r"^v1/account/create$", views.account_create),
    url(r"^v1/account/status$", views.account_status),
    url(r"^v1/account/login$", views.account_login),
    url(r"^v1/account/devices$", views.account_devices),
    url(r"^v1/account/keys", views.account_keys),
    url(r"^v1/certificate/sign", views.certificate_sign),
    url(r"^v1/session/destroy", views.session_destroy),

    url(r"^1\.0/sync/1\.5$", views.token_sync),

    url(r"^oauth/v1/authorization$", views.oauth_authorization),
    url(r"^profile/v1/profile$", views.profile_profile),
]
