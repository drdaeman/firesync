from django.conf.urls import patterns, include, url

urlpatterns = patterns("mnemosyne.views",
    url(r"^info/collections$", "info_collections"),
    url(r"^info/quota$", "info_quota"),
    url(r"^info/collection_usage", "info_collection_usage"),

    url(r"^storage/(?P<collection_name>[^/]+)/?$", "storage_collection"),
    url(r"^storage/(?P<collection_name>[^/]+)/(?P<bsoid>[^/]+)$", "storage_object"),
)
