from django.urls import path

from .views import (
    TOTPActivateView,
    TOTPDisableView,
    TOTPSetupView,
    TOTPVerifyView,
)

urlpatterns = [
    path("mfa/setup/", TOTPSetupView.as_view(), name="totp-setup"),
    path("mfa/activate/", TOTPActivateView.as_view(), name="totp-activate"),
    path("mfa/verify/", TOTPVerifyView.as_view(), name="totp-verify"),
    path("mfa/disable/", TOTPDisableView.as_view(), name="totp-disable"),
]
