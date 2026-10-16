from django.urls import path

from .views import (
    TOTPActivateView,
    TOTPDisableView,
    TOTPSetupView,
    TOTPVerifyView,
)

from .mfa_views import MFAVerifyView


urlpatterns = [
    path("mfa/setup/", TOTPSetupView.as_view(), name="totp-setup"),
    path("mfa/activate/", TOTPActivateView.as_view(), name="totp-activate"),
    path("mfa/verify/", TOTPVerifyView.as_view(), name="totp-verify"),
    path("mfa/disable/", TOTPDisableView.as_view(), name="totp-disable"),
    path("mfa/verify-login/", MFAVerifyView.as_view(),name="mfa-verify-login",),
]
