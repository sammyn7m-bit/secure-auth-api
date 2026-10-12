import base64
import binascii

from django_otp.plugins.otp_totp.models import TOTPDevice
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import TOTPProfile
from .serializers import TOTPCodeSerializer


class TOTPSetupView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        profile, _ = TOTPProfile.objects.get_or_create(
            user=request.user
        )

        if profile.enabled:
            return Response(
                {"detail": "TOTP is already enabled."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Remove any previous unfinished setup.
        TOTPDevice.objects.filter(
            user=request.user,
            confirmed=False,
        ).delete()

        # Create a new TOTP device.
        device = TOTPDevice.objects.create(
            user=request.user,
            name="default",
            confirmed=False,
            digits=6,
            tolerance=1,
            step=30,
        )

        # django-otp stores the key in hexadecimal.
        # Convert it to Base32 for authenticator apps.
        try:
            secret_bytes = binascii.unhexlify(device.key)
            secret = (
                base64.b32encode(secret_bytes)
                .decode("utf-8")
                .rstrip("=")
            )
        except (binascii.Error, ValueError):
            device.delete()

            return Response(
                {"detail": "Unable to generate TOTP secret."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return Response(
            {
                "message": "TOTP setup initiated.",
                "secret": secret,
                "issuer": "Secure Auth API",
                "account": request.user.get_username(),
                "digits": 6,
                "period": 30,
            },
            status=status.HTTP_201_CREATED,
        )


class TOTPActivateView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = TOTPCodeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        code = serializer.validated_data["code"]

        try:
            device = TOTPDevice.objects.get(
                user=request.user,
                name="default",
                confirmed=False,
            )
        except TOTPDevice.DoesNotExist:
            return Response(
                {
                    "detail": (
                        "TOTP setup has not been initiated."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Verify the first authenticator code.
        if not device.verify_token(code):
            return Response(
                {"detail": "Invalid TOTP code."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Mark the TOTP device as confirmed.
        device.confirmed = True
        device.save(update_fields=["confirmed"])

        # Enable TOTP for the user.
        profile, _ = TOTPProfile.objects.get_or_create(
            user=request.user
        )

        profile.enabled = True
        profile.save(
            update_fields=[
                "enabled",
                "updated_at",
            ]
        )

        return Response(
            {"message": "TOTP enabled successfully."},
            status=status.HTTP_200_OK,
        )


class TOTPVerifyView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = TOTPCodeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        code = serializer.validated_data["code"]

        try:
            device = TOTPDevice.objects.get(
                user=request.user,
                name="default",
                confirmed=True,
            )
        except TOTPDevice.DoesNotExist:
            return Response(
                {"detail": "TOTP is not enabled."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not device.verify_token(code):
            return Response(
                {"detail": "Invalid TOTP code."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        return Response(
            {
                "message": (
                    "TOTP code verified successfully."
                )
            },
            status=status.HTTP_200_OK,
        )


class TOTPDisableView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = TOTPCodeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        code = serializer.validated_data["code"]

        try:
            device = TOTPDevice.objects.get(
                user=request.user,
                name="default",
                confirmed=True,
            )
        except TOTPDevice.DoesNotExist:
            return Response(
                {"detail": "TOTP is not enabled."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Require a valid TOTP code before disabling MFA.
        if not device.verify_token(code):
            return Response(
                {"detail": "Invalid TOTP code."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Remove the TOTP device.
        device.delete()

        # Disable TOTP on the user's profile.
        profile, _ = TOTPProfile.objects.get_or_create(
            user=request.user
        )

        profile.enabled = False
        profile.save(
            update_fields=[
                "enabled",
                "updated_at",
            ]
        )

        return Response(
            {"message": "TOTP disabled successfully."},
            status=status.HTTP_200_OK,
        )
