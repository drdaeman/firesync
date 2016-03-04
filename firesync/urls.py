from django.conf.urls import include, url

from django.contrib import admin
admin.autodiscover()

urlpatterns = [
    url(r'^sync/1\.5/', include("mnemosyne.urls")),
    url(r'^', include("janus.urls")),

    url(r'^admin/', include(admin.site.urls)),
]
