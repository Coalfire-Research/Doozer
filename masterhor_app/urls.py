from django.conf.urls import patterns, include, url
from django.contrib import admin
admin.autodiscover()


urlpatterns = patterns('',
    url(r'^$', 'masterhor_app.views.home', name='home'),
    url(r'^submit/', 'masterhor_app.views.submit'),
    url(r'^check/', 'masterhor_app.views.check'),
    url(r'^fetch/', 'masterhor_app.views.fetch'),
    url(r'^pwlist/', 'masterhor_app.views.master_password_list'),
    url(r'^hashlist/', 'masterhor_app.views.master_hash_list'),
    url(r'^sessions/', 'masterhor_app.views.sessions'),
    url(r'^session/(.*?)/$', 'masterhor_app.views.session_fetch'),
    url(r'^admin/', include(admin.site.urls)),
)
