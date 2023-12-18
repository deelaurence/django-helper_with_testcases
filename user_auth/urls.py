# re_path('signup', views.signup),
#     re_path('login', views.login),
#     re_path('test_token', views.test_token),


from django.urls import path
from . import views
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenVerifyView
# from  user_auth import views
from .views import google_auth_initiate, google_auth_callback
urlpatterns = [
    path('signup/', views.signup, name='signup'),
    path('tokenize/', views.test_token, name='tokenize'),
    path('google/initiate/', google_auth_initiate, name='google_auth_initiate'),
    path('google/redirected/', google_auth_callback, name='google_auth_callback'),
    #A CUSTOM MIDDLEWARE CONDITION DEPENDS ON THIS PATH {api/token}
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('verify-email/<uuid:token>/', views.verify_email, name='verify-email'),
    path('protected/', views.test_token, name='protected_view'),
    path('reset-password/', views.reset_password, name='reset_password'),
    path('update-password/', views.update_password, name='update_password'),
    path('reset-password-confirm/', views.reset_password_confirm, name='reset_password_confirm'),

    # Add more app-specific URLs as needed
]