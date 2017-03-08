from django.conf.urls import url
from . import views

urlpatterns = [
    url(r"^info/collections$", views.info_collections),
    url(r"^info/quota$", views.info_quota),
    url(r"^info/collection_usage", views.info_collection_usage),

    url(r"^storage/(?P<collection_name>[^/]+)/?$", views.storage_collection),
    url(r"^storage/(?P<collection_name>[^/]+)/(?P<bsoid>[^/]+)$", views.storage_object),
]
