from django.contrib import admin

from .models import TOTPProfile


@admin.register(TOTPProfile)
class TOTPProfileAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "enabled",
        "created_at",
        "updated_at",
    )
    list_filter = ("enabled",)
    search_fields = ("user__username", "user__email")
    readonly_fields = ("created_at", "updated_at")


from django_otp.plugins.otp_totp.models import TOTPDevice


@admin.register(TOTPDevice)
class TOTPDeviceAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "name",
        "confirmed",
        "last_t",
    )
    list_filter = ("confirmed",)
    search_fields = ("user__username", "user__email")
