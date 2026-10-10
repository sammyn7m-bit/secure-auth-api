from django.contrib.auth import get_user_model
from rest_framework.generics import CreateAPIView
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.views import TokenObtainPairView

from .serializers import RegisterSerializer
from .throttles import LoginRateThrottle
from .login_protection import ProtectedTokenObtainPairSerializer


User = get_user_model()


class RegisterView(CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]
    authentication_classes = []


class RateLimitedLoginView(TokenObtainPairView):
    serializer_class = ProtectedTokenObtainPairSerializer
    throttle_classes = [LoginRateThrottle]
