from django.contrib.auth import get_user_model
from django.contrib.auth.signals import (
    user_logged_in,
    user_login_failed,
)
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.serializers import (
    TokenObtainPairSerializer,
)

from security.mfa_challenges import create_mfa_challenge
from security.services import is_totp_enabled


User = get_user_model()


class ProtectedTokenObtainPairSerializer(
    TokenObtainPairSerializer
):
    def validate(self, attrs):
        request = self.context.get("request")

        username = str(
            attrs.get(self.username_field, "")
        ).strip().casefold()

        try:
            data = super().validate(attrs)

        except AuthenticationFailed:
            user_login_failed.send(
                sender=User,
                request=getattr(
                    request,
                    "_request",
                    request,
                ),
                credentials={
                    "username": username,
                },
            )
            raise

        # Password is correct, but don't return JWTs yet
        # when this user has MFA enabled.
        if is_totp_enabled(self.user):
            challenge = create_mfa_challenge(
                self.user
            )

            return {
                "mfa_required": True,
                "challenge": challenge,
                "expires_in": 300,
            }

        # No MFA: normal successful login.
        user_logged_in.send(
            sender=User,
            request=getattr(
                request,
                "_request",
                request,
            ),
            user=self.user,
        )

        return data
