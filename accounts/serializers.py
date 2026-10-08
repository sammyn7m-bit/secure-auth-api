from rest_framework import serializers
from .models import User
from django.contrib.auth.password_validation import validate_password


# create user registering serializer
class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only = True, required = True)

    class Meta:
        model = User
        fields = [ 'username', 'email', 'password']


# validate password
    def validate_password(self, value):
        validate_password(value)
        return value


# hash password
    def create(self,validated_data):
        password = validated_data.pop("password")
        user = User.objects.create_user(
          password = password, **validated_data)

        return user
