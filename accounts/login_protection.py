import hashlib

from django.core.cache import cache
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer


FAILURE_LIMIT = 5
FAILURE_WINDOW_SECONDS = 15 * 60
COOLDOWN_SECONDS = 5 * 60


def _account_key(prefix, email):
    normalized_email = email.strip().casefold()
    digest = hashlib.sha256(normalized_email.encode()).hexdigest()
    return f"login_protection:{prefix}:{digest}"


def _record_failure(key):
    if cache.add(key, 1, timeout=FAILURE_WINDOW_SECONDS):
        return 1

    try:
        return cache.incr(key)
    except ValueError:
        # The key may have expired between the add and increment.
        cache.add(key, 1, timeout=FAILURE_WINDOW_SECONDS)
        return cache.get(key, 1)


class ProtectedTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        email = str(attrs.get(self.username_field, ""))
        account_key = _account_key("failures", email)
        blocked_key = _account_key("blocked", email)

        # Use the same generic authentication message to avoid revealing
        # whether an email address belongs to a registered account.
        if cache.get(blocked_key):
            raise AuthenticationFailed("Invalid email or password.")

        try:
            data = super().validate(attrs)
        except AuthenticationFailed:
            failures = _record_failure(account_key)

            if failures >= FAILURE_LIMIT:
                cache.set(
                    blocked_key,
                    True,
                    timeout=COOLDOWN_SECONDS,
                )

            raise

        # A successful login clears the account's failure counter.
        cache.delete(account_key)
        cache.delete(blocked_key)

        return data
