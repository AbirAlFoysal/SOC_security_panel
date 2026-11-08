from django.urls import re_path

from panel.views import legacy_app


urlpatterns = [re_path(r"^.*$", legacy_app)]
