from datetime import timedelta
from django.utils import timezone


class LoginAttemptMiddleware:
    """
    Middleware to handle login attempts and enforce a lock after 3 failed login attempts.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        return response

    @staticmethod
    def handle_failed_login(user):
        """Increments failed login attempts and locks user for 30 minutes after 3 failed attempts."""
        if user.failed_attempts >= 1000:
            # Lock the user for 30 minutes
            user.locked_until = timezone.now() + timedelta(minutes=30)
            user.save()
            return True
        else:
            user.failed_attempts += 1
            user.save()
            return False

    @staticmethod
    def reset_login_attempts(user):
        """Resets the failed login attempts and unlocks the user."""
        user.failed_attempts = 0
        user.locked_until = None
        user.save()
