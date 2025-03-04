from django.http import JsonResponse
from rest_framework.authentication import get_authorization_header
from rest_framework.authtoken.models import Token
from django.utils.deprecation import MiddlewareMixin


class APIAuthMiddleware(MiddlewareMixin):
    @staticmethod
    def process_request(request):
        # Skip non-API URLs
        if not request.path.startswith('/api/'):
            return None

        # Check the Authorization header for the token
        auth_header = get_authorization_header(request).split()
        token_key = None

        if len(auth_header) == 2 and auth_header[0].lower() == b'bearer':
            token_key = auth_header[1].decode('utf-8')
        elif 'auth_token' in request.COOKIES:  # Fallback to token in cookies
            token_key = request.COOKIES.get('auth_token')

        if token_key:
            try:
                token = Token.objects.get(key=token_key)
                request.user = token.user  # Attach the authenticated user to the request
                return None
            except Token.DoesNotExist:
                return JsonResponse({"detail": "Invalid token."}, status=401)

        # Handle unauthenticated requests
        return JsonResponse({"detail": "Authentication credentials were not provided."}, status=401)
