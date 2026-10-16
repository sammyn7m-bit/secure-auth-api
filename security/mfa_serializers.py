from rest_framework import serializers


class MFAVerifySerializer(serializers.Serializer):
    challenge = serializers.CharField(
        required=True,
        write_only=True,
    )

    code = serializers.CharField(
        required=True,
        min_length=6,
        max_length=6,
        write_only=True,
    )

    def validate_code(self, value):
        if not value.isdigit():
            raise serializers.ValidationError(
                "TOTP code must contain only digits."
            )

        return value
