from .models import User
from .serializers import RegisterSerializer
from rest_framework.generics import CreateAPIView
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.views import TokenObtainPairView
from .throttles import LoginRateThrottle


# user registering
class RegisterView(CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]
    authentication_classes = []

#rate limit login requests
class RateLimitedLoginView(TokenObtainPairView):
    throttle_classes = [LoginRateThrottle]

