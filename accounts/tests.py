from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import identify_hasher
from django.test import TestCase, override_settings
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import RefreshToken
from axes.models import AccessAttempt

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


@override_settings(
    AXES_FAILURE_LIMIT=5,
    AXES_COOLOFF_TIME=1 / 12,
    AXES_LOCKOUT_PARAMETERS=["ip_address", "username"],
)
class AxesLoginProtectionTests(APITestCase):
    def setUp(self):
        AccessAttempt.objects.all().delete()
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

    def test_failed_login_attempts_are_recorded(self):
        response = self.client.post(
            self.url,
            {
                "email": self.credentials["email"],
                "password": "Wrong-Password-123!",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code, status.HTTP_401_UNAUTHORIZED
        )
        self.assertTrue(AccessAttempt.objects.exists())

    def test_repeated_failures_trigger_axes_lockout(self):
        # Use a fresh client for predictable request throttling.
        from rest_framework.test import APIClient

        client = APIClient()

        for _ in range(5):
            client.post(
                self.url,
                {
                    "email": self.credentials["email"],
                    "password": "Wrong-Password-123!",
                },
                format="json",
            )

        response = client.post(self.url, self.credentials, format="json")

        self.assertIn(
            response.status_code,
            [
                status.HTTP_401_UNAUTHORIZED,
                status.HTTP_403_FORBIDDEN,
                status.HTTP_429_TOO_MANY_REQUESTS,
            ],
        )
        self.assertTrue(AccessAttempt.objects.exists())
