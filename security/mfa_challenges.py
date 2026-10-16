import secrets

from django.core.cache import cache


MFA_CHALLENGE_TTL = 300  # 5 minutes
MFA_CHALLENGE_PREFIX = "mfa_challenge"


def _challenge_key(challenge_id):
    return f"{MFA_CHALLENGE_PREFIX}:{challenge_id}"


# create short kived mfa challenge
def create_mfa_challenge(user):

    challenge_id = secrets.token_urlsafe(32)

    cache.set(
        _challenge_key(challenge_id),
        {
            "user_id": user.pk,
        },
        timeout=MFA_CHALLENGE_TTL,
    )

    return challenge_id


def get_mfa_challenge(challenge_id):

    return cache.get(
        _challenge_key(challenge_id)
    )


# delete a challange
def consume_mfa_challenge(challenge_id):

    cache.delete(
        _challenge_key(challenge_id)
    )
