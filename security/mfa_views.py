from django.contrib.auth import get_user_model
from django.contrib.auth.signals import user_logged_in

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from rest_framework_simplejwt.tokens import RefreshToken

from .mfa_serializers import MFAVerifySerializer
from .mfa_challenges import (
    get_mfa_challenge,
    consume_mfa_challenge,
)
from .services import verify_totp


User = get_user_model()


class MFAVerifyView(APIView):

    def post(self, request):
        serializer = MFAVerifySerializer(
            data=request.data
        )
        serializer.is_valid(raise_exception=True)

        challenge_id = serializer.validated_data[
            "challenge"
        ]

        code = serializer.validated_data["code"]

        challenge = get_mfa_challenge(
            challenge_id
        )

        if not challenge:
            return Response(
                {
                    "detail": (
                        "MFA challenge is invalid "
                        "or has expired."
                    )
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )

        try:
            user = User.objects.get(
                pk=challenge["user_id"]
            )
        except User.DoesNotExist:
            consume_mfa_challenge(challenge_id)

            return Response(
                {"detail": "Invalid MFA challenge."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        if not verify_totp(user, code):
            return Response(
                {"detail": "Invalid TOTP code."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # Successful MFA: consume the challenge.
        consume_mfa_challenge(challenge_id)

        refresh = RefreshToken.for_user(user)

        user_logged_in.send(
            sender=User,
            request=request,
            user=user,
        )

        return Response(
            {
                "refresh": str(refresh),
                "access": str(refresh.access_token),
            },
            status=status.HTTP_200_OK,
        )
