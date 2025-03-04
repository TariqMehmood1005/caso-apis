from rest_framework.exceptions import AuthenticationFailed, NotFound, PermissionDenied
from rest_framework.authtoken.models import Token
from ApiPlatform.models import User, Role


class AuthService:
    """
    Utility class to handle authentication and role-based validation.
    """

    @staticmethod
    def get_user_from_token(request):
        """
        Retrieve and validate the user based on the token.
        :param request: HTTP request object
        :return: User instance
        :raises: AuthenticationFailed, NotFound
        """
        # Retrieve token from cookies or headers
        token = request.headers.get('Authorization', '').split(' ')[-1]
        if not token:
            raise AuthenticationFailed("Authentication token is missing.")

        try:
            token_instance = Token.objects.get(key=token)
            return token_instance.user  # Authenticated user instance
        except Token.DoesNotExist:
            raise AuthenticationFailed("Invalid or expired token.")

    @staticmethod
    def validate_user_role(user, role_name):
        """
        Validate that the user has the specified role.
        :param user: User instance
        :param role_name: Role name to validate
        :return: User instance if valid
        :raises: PermissionDenied, NotFound
        """
        # Fetch role by name
        role = Role.objects.filter(roles=role_name).first()
        if not role:
            raise PermissionDenied("Role is not properly configured.")

        # Ensure user has the required role
        user_with_role = User.objects.filter(user_id=user, role_id=role).first()
        if not user_with_role:
            raise NotFound(f"User not found or does not have the '{role_name}' role.")

        return user_with_role

    @staticmethod
    def validate_user_uuid_role(user_uuid, role_name):
        """
        Validate that the user has the specified role.
        :param user_uuid: User instance
        :param role_name: Role name to validate
        :return: User instance if valid
        :raises: PermissionDenied, NotFound
        """
        # Fetch role by name
        role = Role.objects.filter(roles=role_name).first()
        if not role:
            raise PermissionDenied("Role is not properly configured.")

        # Ensure user has the required role
        user_with_role = User.objects.filter(id=user_uuid, role_id=role).first()
        if not user_with_role:
            raise NotFound(f"User not found or does not have the '{role_name}' role.")

        return user_with_role
