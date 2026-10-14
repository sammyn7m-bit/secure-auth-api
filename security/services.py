from django_otp.plugins.otp_totp.models import TOTPDevice

from .models import TOTPProfile


def is_totp_enabled(user):
    return TOTPProfile.objects.filter(
        user=user,
        enabled=True,
    ).exists()


def verify_totp(user, code):
    try:
        device = TOTPDevice.objects.get(
            user=user,
            name="default",
            confirmed=True,
        )
    except TOTPDevice.DoesNotExist:
        return False

    return device.verify_token(code)
