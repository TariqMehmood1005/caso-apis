from datetime import datetime, timedelta
from rest_framework.authtoken.models import Token


class TokenService:
    @staticmethod
    def generate_token(user, expiration_days=1):
        """
        Generate a token for the given user with a specified expiration time.

        Args:
            user (User): The user for whom the token is being generated.
            expiration_days (int): The number of days the token is valid.

        Returns:
            dict: Contains the token and its expiration date.
        """
        # Set the expiration date
        expiration_date = datetime.now() + timedelta(days=expiration_days)

        # Create or get a token
        token, created = Token.objects.get_or_create(user=user)

        # Update the created time to enforce a new expiration for existing tokens
        token.created = datetime.now()
        token.save()

        return {
            "token": token.key,
            "expires_at": expiration_date
        }

    @staticmethod
    def validate_token(token_key):
        """
        Validate the token and check its expiration.

        Args:
            token_key (str): The token key to validate.

        Returns:
            bool: True if valid, False otherwise.
        """
        try:
            token = Token.objects.get(key=token_key)
            expiration_days = 15 if token.created + timedelta(days=15) > datetime.now() else 1
            expiration_date = token.created + timedelta(days=expiration_days)
            return datetime.now() < expiration_date
        except Token.DoesNotExist:
            return False
