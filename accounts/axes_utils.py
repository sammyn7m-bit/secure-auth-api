import json


def get_axes_username(request, credentials=None):
    credentials = credentials or {}

    email = credentials.get("email") or credentials.get("username")

    if not email and request is not None:
        # Django Axes checks requests before DRF parses JSON credentials.
        email = request.POST.get("email") or request.POST.get("username")

        if not email:
            try:
                payload = json.loads(request.body or b"{}")
                email = payload.get("email") or payload.get("username")
            except (ValueError, AttributeError, TypeError):
                email = None

    if email is None:
        return None

    return str(email).strip().casefold() or None
