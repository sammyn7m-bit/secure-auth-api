from django.contrib.auth import get_user_model
from django.contrib.auth.signals import user_login_failed, user_logged_in
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer


User = get_user_model()


class ProtectedTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        request = self.context.get("request")
        email = str(attrs.get(self.username_field, "")).strip().casefold()

        try:
            data = super().validate(attrs)
        except Exception as exc:
            # Only report authentication failures to Axes. Other errors
            # should not count as incorrect password attempts.
            from rest_framework.exceptions import AuthenticationFailed

            if isinstance(exc, AuthenticationFailed):
                user_login_failed.send(
                    sender=User,
                    request=getattr(request, "_request", request),
                    credentials={"username": email},
                )
            raise

        user_logged_in.send(
            sender=User,
            request=getattr(request, "_request", request),
            user=self.user,
        )

        return data
