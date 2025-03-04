import random
import string
import os
import uuid
import jwt
import time
from functools import wraps
from datetime import datetime
from httpcore import Response
from datetime import timedelta
from django.core.cache import cache
from django.utils.timezone import now
from asgiref.sync import sync_to_async
from CoinsSellingPlatformProject import settings
from .api_handler import APIResponse
from .auth_service import AuthService
from .models import User, AgentChat, Referral
from rest_framework.pagination import PageNumberPagination


@sync_to_async
def get_user_by_username(username):
    from ApiPlatform.models import User  # Import inside function
    return User.objects.filter(username=username).first()


@sync_to_async
def get_game_by_game_id(game_id):
    from ApiPlatform.models import Game  # Import inside function
    return Game.objects.filter(game_id=game_id).first()


@sync_to_async
def get_wallet_for_user(user):
    from ApiPlatform.models import Wallet  # Import inside function
    return Wallet.objects.filter(user=user).first()


@sync_to_async
def save_admin_score(admin_score_model):
    admin_score_model.save()


def generate_otp(minutes: int = 5):
    otp = ''.join(random.choices(string.digits, k=6))

    # Calculate expiration time with respect to the current timezone
    expiration_time = now() + timedelta(minutes=minutes)

    return otp, expiration_time


def is_admin(role_instance):
    return role_instance.roles == 'Admin'


def generate_and_store_otp(email):
    otp = generate_otp()
    cache.set(f"otp_{email}", otp, timeout=300)  # Store OTP with a 5-minute expiration
    return otp


def retrieve_otp_for_email(email):
    from ApiPlatform.models import OTPVerification  # Import inside function
    try:
        otp_record = OTPVerification.objects.get(user__email=email)
        return otp_record.otp
    except OTPVerification.DoesNotExist:
        return None


def file_upload_to(filename, identifier, path_to_upload):
    """
    Generate a dynamic file path with a filename based on the provided identifier.
    The filename format will be "<identifier>_<random_string>.<extension>".

    Arguments:
    - filename: The original filename of the uploaded file.
    - identifier: A string identifier like user_name or game_name.
    - path_to_upload: The base directory path for upload (e.g., 'user_profiles' or 'games').

    Returns:
    - A dynamic file path string with a unique filename.
    """
    # Extract the file extension
    ext = os.path.splitext(filename)[1]  # e.g., '.jpg', '.png'

    # Generate a random string
    random_string = uuid.uuid4().hex[:8]

    # Sanitize identifier (replace spaces with underscores, and lowercase the string)
    identifier = identifier.replace(" ", "_").lower()

    # Construct the new filename
    new_filename = f"{identifier}_{random_string}{ext}"

    # Return the full upload path
    return os.path.join(path_to_upload, new_filename)  # Combine the base path with the filename


def user_profile_upload_to(instance, filename):
    random_string = uuid.uuid4().hex  # Generate a random string
    return f"user_profiles/{instance.user.username}_{random_string}_{filename}"


def banner_upload_to(instance, filename):
    random_string = uuid.uuid4().hex  # Generate a random string
    return f"user_profiles/banners/{instance.user.username}_{random_string}_{filename}"


@sync_to_async
def get_user_by_username(username: str):
    from ApiPlatform.models import User
    return User.objects.select_related('user').get(user__username=username)


@sync_to_async
def get_wallet_by_user(user_model_instance):
    from ApiPlatform.models import Wallet
    return Wallet.objects.get(user=user_model_instance)


def delete_inactive_user_messages(timedelta_time: float = 86400):
    """
    Periodically delete all messages of users who have been inactive for more than 15 minutes
    and have at least one chat.
    """
    while True:
        try:
            inactivity_limit = now() - timedelta(seconds=timedelta_time)

            # Find users who are inactive and have at least one chat
            inactive_users_with_chats = User.objects.filter(
                last_active__lt=inactivity_limit
            ).distinct()

            for user in inactive_users_with_chats:
                # Delete all messages of the inactive user
                AgentChat.objects.filter(user_id=user.id).delete()

                """
                 update user's is_last_active = false
                """
                User.objects.filter(id=user.id).update(is_last_active=False)

                # Optional: Log deletion or notify the user
        except Exception as e:
            print(f"Error occurred while deleting inactive user messages: {str(e)}")

        # Sleep for a specific interval (e.g., 15 minutes) before re-running the function
        time.sleep(timedelta_time)


def upload_to_agent_user_chats(instance, filename):
    """
    Custom upload path and filename for attachment images.
    Saves files as agent-user-chats/<sender_username>_<random_string>.<extension>.
    """
    # Extract the file extension
    file_extension = os.path.splitext(filename)[-1].lower()

    # Generate a new filename
    random_string = uuid.uuid4().hex[:8]  # Short random string
    new_filename = f"{instance.user_id.user_id.username}_{random_string}{file_extension}"

    # Return the full upload path
    return os.path.join("agent-user-chats/", new_filename)


def process_referral(instance):
    # Assuming the referral key is present and there's a `referral_code` field in the user instance
    if instance.referral_code:
        # Find the referral entry using the referral_key
        referral = Referral.objects.filter(referral_key=instance.referral_code).first()

        if referral:
            # Retrieve the referred user (receiver of the referral)
            referred_user = referral.receiver_user_id

            if referred_user:
                # Assuming quantity field in Referral model represents the requested reward amount
                requested_amount = referral.quantity  # Get the requested amount dynamically

                if requested_amount:
                    # Start a transaction to ensure atomicity in case of errors
                    from django.db import transaction
                    with transaction.atomic():
                        # Add the requested amount to the referred user's wallet (assuming it's in their `wallet` model)
                        referred_user.wallet_id.current_balance += requested_amount
                        referred_user.wallet_id.save()

                        # Calculate 20% of the requested amount for the referrer reward
                        referrer_reward = requested_amount * 0.20
                        referral.user_id.wallet_id.current_balance += referrer_reward
                        referral.user_id.wallet_id.save()

                        # Optionally, you can add logging or notifications to inform users of successful referral
                        # Example: send notification to users or log it in the database

                else:
                    # Handle case where requested amount is not found (can log or notify)
                    print("Requested amount is not defined in the referral model")
            else:
                print("Referred user not found with the given referral key")
        else:
            print("Referral key is invalid or not found")


def delete_all_referrals_after_given_time(delta_time: any = 60):
    from ApiPlatform.models import Referral
    timedelta_data = now() - timedelta(days=delta_time)
    Referral.objects.filter(referral_created_at__lt=timedelta_data).delete()


def decode_token(token: str) -> dict:
    """
    Decode and validate the JWT token.

    Args:
        token (str): The JWT token to decode.

    Returns:
        dict: The decoded token payload if valid.

    Raises:
        jwt.ExpiredSignatureError: If the token is expired.
        jwt.InvalidTokenError: If the token is invalid.
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])

        return payload
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired.")
    except jwt.InvalidTokenError:
        raise ValueError("Invalid token.")


def time_ago(created_at):
    created_time = datetime.strptime(created_at, "%Y-%m-%d %H:%M:%S")
    now_time = datetime.now()
    diff = now_time - created_time

    days = diff.days
    seconds = diff.seconds
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    seconds %= 60

    if days > 0:
        return f"{days} day{'s' if days > 1 else ''} ago"
    elif hours > 0:
        return f"{hours} hour{'s' if hours > 1 else ''} ago"
    elif minutes > 0:
        return f"{minutes} minute{'s' if minutes > 1 else ''} ago"
    else:
        return f"{seconds} second{'s' if seconds > 1 else ''} ago"


class CustomPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'limit'
    max_page_size = 100

    def get_paginated_response(self, data):
        return Response({
            'links': {
                'next': self.get_next_link(),
                'previous': self.get_previous_link()
            },
            'count': self.page.paginator.count,
            'results': data
        })

    def paginate_queryset(self, queryset, request, view=None):
        """
        This method returns a page of results based on the 'page' and 'limit' query params.
        If no limit is specified, it will use the default 'page_size' set in this class.
        """
        limit = request.query_params.get(self.page_size_query_param, self.page_size)
        try:
            limit = int(limit)
        except ValueError:
            limit = self.page_size  # Fallback to default page_size if limit is not an integer

        self.page_size = limit  # Update page_size dynamically
        return super().paginate_queryset(queryset, request, view=view)


def authenticate_and_authorize(allowed_roles=None):
    if allowed_roles is None:
        allowed_roles = ["Admin"]

    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            # Authenticate and fetch the user
            user_instance = AuthService.get_user_from_token(request)
            if not user_instance:
                return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

            # Fetch the user from DB
            try:
                current_user = User.objects.get(user_id=user_instance.id)
            except User.DoesNotExist:
                return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")

            # Validate the user's role
            role = getattr(current_user.role_id, "roles", None)
            if role not in allowed_roles:
                return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")

            # Attach user and role to request object
            request.user_instance = current_user
            request.user_role = role

            return view_func(request, *args, **kwargs)

        return _wrapped_view

    return decorator
