from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import identify_hasher
from django.core.cache import cache
from rest_framework import status
from rest_framework.test import APITestCase, APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from accounts.login_protection import _account_key
from accounts.views import RateLimitedLoginView

User = get_user_model()


class RegistrationTests(APITestCase):
    def setUp(self):
        self.url = "/api/auth/register/"
        self.payload = {
            "username": "testuser",
            "email": "testuser@example.com",
            "password": "Strong-Test-Password-923!",
        }

    def test_registration_creates_user(self):
        response = self.client.post(
            self.url, self.payload, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(
            User.objects.filter(email=self.payload["email"]).exists()
        )

    def test_password_is_hashed_with_argon2(self):
        self.client.post(self.url, self.payload, format="json")
        user = User.objects.get(email=self.payload["email"])

        self.assertNotEqual(user.password, self.payload["password"])
        self.assertEqual(
            identify_hasher(user.password).algorithm, "argon2"
        )
        self.assertTrue(user.check_password(self.payload["password"]))

    def test_duplicate_email_is_rejected(self):
        self.client.post(self.url, self.payload, format="json")
        duplicate_payload = {
            **self.payload,
            "username": "anotheruser",
        }

        response = self.client.post(
            self.url, duplicate_payload, format="json"
        )
        self.assertEqual(
            response.status_code, status.HTTP_400_BAD_REQUEST
        )
        self.assertEqual(
            User.objects.filter(email=self.payload["email"]).count(), 1
        )


class AuthenticationTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="authuser",
            email="authuser@example.com",
            password="Strong-Auth-Password-923!",
        )
        self.login_url = "/api/auth/login/"
        self.refresh_url = "/api/auth/refresh/"
        self.logout_url = "/api/auth/logout/"

    def test_login_returns_tokens(self):
        response = self.client.post(
            self.login_url,
            {
                "email": "authuser@example.com",
                "password": "Strong-Auth-Password-923!",
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)

    def test_login_rejects_wrong_password(self):
        response = self.client.post(
            self.login_url,
            {
                "email": "authuser@example.com",
                "password": "Wrong-Password-123!",
            },
            format="json",
        )
        self.assertEqual(
            response.status_code, status.HTTP_401_UNAUTHORIZED
        )

    def test_refresh_rotates_refresh_token(self):
        refresh = RefreshToken.for_user(self.user)
        response = self.client.post(
            self.refresh_url, {"refresh": str(refresh)}, format="json"
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)
        self.assertNotEqual(response.data["refresh"], str(refresh))

    def test_logout_blacklists_refresh_token(self):
        refresh_token = str(RefreshToken.for_user(self.user))
        response = self.client.post(
            self.logout_url,
            {"refresh": refresh_token},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        refresh_response = self.client.post(
            self.refresh_url,
            {"refresh": refresh_token},
            format="json",
        )
        self.assertEqual(
            refresh_response.status_code,
            status.HTTP_401_UNAUTHORIZED,
        )


class FailedLoginProtectionTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user(
            username="protecteduser",
            email="protecteduser@example.com",
            password="Strong-Protected-Password-923!",
        )
        self.url = "/api/auth/login/"
        self.credentials = {
            "email": "protecteduser@example.com",
            "password": "Strong-Protected-Password-923!",
        }

    def test_repeated_failures_temporarily_block_login(self):
        cache.clear()
        client = APIClient()

        # Temporarily disable the IP throttle to test account protection
        # independently. Restore it even if an assertion fails.
        original_throttles = RateLimitedLoginView.throttle_classes
        RateLimitedLoginView.throttle_classes = []

        try:
            for _ in range(5):
                response = client.post(
                    self.url,
                    {
                        "email": self.credentials["email"],
                        "password": "Wrong-Password-123!",
                    },
                    format="json",
                )
                self.assertEqual(
                    response.status_code,
                    status.HTTP_401_UNAUTHORIZED,
                )

            blocked_key = _account_key(
                "blocked", self.credentials["email"]
            )
            self.assertTrue(cache.get(blocked_key))

            response = client.post(
                self.url, self.credentials, format="json"
            )
            self.assertEqual(
                response.status_code,
                status.HTTP_401_UNAUTHORIZED,
            )
        finally:
            RateLimitedLoginView.throttle_classes = original_throttles

    def test_successful_login_clears_failure_counter(self):
        failure_key = _account_key(
            "failures", self.credentials["email"]
        )
        cache.set(failure_key, 2, timeout=900)

        response = self.client.post(
            self.url, self.credentials, format="json"
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsNone(cache.get(failure_key))
