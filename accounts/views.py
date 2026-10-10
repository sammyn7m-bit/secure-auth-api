from django.contrib.auth import get_user_model
from django.utils.decorators import method_decorator
from rest_framework.generics import CreateAPIView
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.views import TokenObtainPairView

from axes.decorators import axes_dispatch

from .serializers import RegisterSerializer
from .throttles import LoginRateThrottle
from .login_protection import ProtectedTokenObtainPairSerializer


User = get_user_model()


class RegisterView(CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]
    authentication_classes = []


@method_decorator(axes_dispatch, name="dispatch")
class RateLimitedLoginView(TokenObtainPairView):
    serializer_class = ProtectedTokenObtainPairSerializer
    throttle_classes = [LoginRateThrottle]
