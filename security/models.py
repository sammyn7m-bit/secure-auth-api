from django.conf import settings
from django.db import models
from django_otp.plugins.otp_totp.models import TOTPDevice


class TOTPProfile(models.Model):

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="totp_profile",
    )

    enabled = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"TOTP profile - {self.user}"
