from django.urls import path, include
from account.views import UserRegisterView, UserLoginView, UserProfileView, VerifyOTPView,\
      UserChangePasswordView, SendPasswordResetEmailView, UserPasswordResetView
 
urlpatterns = [
    path('register/', UserRegisterView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('profile/',UserProfileView.as_view(), name='profile'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),
    path('change-password/', UserChangePasswordView.as_view(), name='change-password'),
    path('reset-password-request/',SendPasswordResetEmailView.as_view(), name='reset-password-request'),
    path('reset-password/<uid>/<token>/',UserPasswordResetView.as_view(), name='reset-password-request')
]
