from .models import User
from .serializers import RegisterSerializer
from rest_framework.generics import CreateAPIView
from rest_framework.permissions import AllowAny



class RegisterView(CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]
    authentication_classes = []

