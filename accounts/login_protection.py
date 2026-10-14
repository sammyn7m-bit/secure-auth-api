from django.contrib.auth import get_user_model
from django.contrib.auth.signals import (
    user_logged_in,
    user_login_failed,
)
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.serializers import (
    TokenObtainPairSerializer,
)

from security.services import (
    is_totp_enabled,
    verify_totp,
)


User = get_user_model()


class ProtectedTokenObtainPairSerializer(
    TokenObtainPairSerializer
):
    totp_code = serializers.CharField(
        required=False,
        write_only=True,
        min_length=6,
        max_length=6,
    )

    def validate(self, attrs):
        request = self.context.get("request")

        username = str(
            attrs.get(self.username_field, "")
        ).strip().casefold()

        totp_code = attrs.pop("totp_code", None)

        try:
            # This validates username/password and initially
            # generates the JWT pair.
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

        if is_totp_enabled(self.user):
            if not totp_code:
                raise serializers.ValidationError(
                    {
                        "mfa_required": True,
                        "detail": (
                            "TOTP code is required."
                        ),
                    }
                )

            if not totp_code.isdigit():
                raise serializers.ValidationError(
                    {
                        "totp_code": (
                            "TOTP code must contain "
                            "only digits."
                        )
                    }
                )

            if not verify_totp(
                self.user,
                totp_code,
            ):
                raise AuthenticationFailed(
                    "Invalid TOTP code."
                )

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
