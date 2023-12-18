from django.urls import re_path
from django.urls import path, include
# from . import views
from .views import handle_404

handler404 = handle_404
from django.views.defaults import page_not_found

urlpatterns = [
    # re_path('signup', views.signup),
    # re_path('login', views.login),
    # re_path('test_token', views.test_token),
    path('auth/', include('user_auth.urls')),  # Include the app's URLs

]
urlpatterns += [
    path('404/', handle_404, name='404'),
]