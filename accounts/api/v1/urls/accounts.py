from django.urls import path
from ..views import (
    CheckRegistrationView, 
    VerifyPhoneOTPView,  
    SetPasswordView, 
    LoginWithPasswordView
)

urlpatterns = [
    path('check-registration/', CheckRegistrationView.as_view(), name='check-registration'),
    path('verify-otp/', VerifyPhoneOTPView.as_view(), name='verify-otp'),
    path('set-password/', SetPasswordView.as_view(), name='set-password'),
    path('login/', LoginWithPasswordView.as_view(), name='login'),
]
