from django.conf.urls import patterns, include, url

from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
    url(r'^sync/1\.5/', include("mnemosyne.urls")),
    url(r'^', include("janus.urls")),

    url(r'^admin/', include(admin.site.urls)),
)
