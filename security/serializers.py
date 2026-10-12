from rest_framework import serializers

"""using one serializer since all (acrivate, verify and deactivate serializers are the same) """

class TOTPCodeSerializer(serializers.Serializer):
    code = serializers.CharField(
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
