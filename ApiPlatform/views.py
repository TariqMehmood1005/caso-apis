import math
import random
import uuid
from collections import defaultdict
from datetime import datetime
from datetime import timedelta
from decimal import Decimal

import qrcode
import requests
from amqp import InvalidPath
from asgiref.sync import async_to_sync
from celery.utils.time import timezone
from dateutil.tz import UTC
from django.contrib.auth import authenticate, login
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import User as DjangoUser
from django.core.cache import cache
from django.core.mail import send_mail
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger, InvalidPage
from django.db import transaction, IntegrityError
from django.db.models import Avg, Sum
from django.db.models import Q
from django.forms import ValidationError, model_to_dict
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view
from rest_framework.decorators import permission_classes
from rest_framework.generics import get_object_or_404
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from CoinsSellingPlatformProject import settings
from . import serializers
from .api_handler import APIResponse
from .app_views.admin_game_panel import AdminGamePanel
from .app_views.agent_game_panel import AgentGamePanel
from .app_views.user_game_panel import UserGamePanel
from .auth_service import AuthService
from .forms import (GameRatingForm, MessageForm, UserForm, AgentChatForm, GlobalChatForm, GameReviewForm,
                    AdminReplyForm, GameForm, UpdatePrizeForm, CreatePrizeForm, PromoCodeForm, LevelForm,
                    FreePlayForm, WalletTransactionHistoryFormUpdated, WalletTransactionHistoryForm,
                    UpdateUserLicenseForm, UpdateUserDocumentForm, UpdateUserPhoneAndGetFreeXPForm, AddBonusForm)
from .login_attempt_middleware import LoginAttemptMiddleware
from .models import (GameRating, MessageConversation, OTPVerification, ReplyHelpFull, ReplyNotHelpFull, ReviewHelpFull,
                     ReviewNotHelpFull, Role, GlobalChat, GameReview, AdminReply, Game, GameTransactionHistory, Player,
                     Referral, Spin, SpinHistory, Prize, PromoCode, Level, Country, Wallet, WalletTransactionHistory,
                     FreePlay, SubscriptionPlan, BannedIP, Message, Bonus, Notification)
from .models import User, AgentChat
from .signals import player_created_signal, payment_signal
from .utils import generate_otp, time_ago


# Start the thread when the application runs
# thread = threading.Thread(target=delete_inactive_user_messages, daemon=True)
# thread.start()

def ban_ip(ip, reason="Exceeded request limit"):
    # Ban IP for 1 hour
    ban_expiry = timezone.now() + timedelta(hours=1)
    BannedIP.objects.create(ip_address=ip, reason=reason, ban_expiry=ban_expiry)
    return APIResponse.HTTP_429_TOO_MANY_REQUESTS(message="Too many requests. Please try again later.")


def return_level_scores():
    l_0 = get_object_or_404(Level, level_code='L0')
    l_1 = get_object_or_404(Level, level_code='L1')
    l_2 = get_object_or_404(Level, level_code='L2')
    l_3 = get_object_or_404(Level, level_code='L3')
    l_4 = get_object_or_404(Level, level_code='L4')

    return l_0, l_1, l_2, l_3, l_4


def return_subscriptions():
    free = get_object_or_404(SubscriptionPlan, pro_status='Free')
    premium = get_object_or_404(SubscriptionPlan, pro_status='Premium')
    elite = get_object_or_404(SubscriptionPlan, pro_status='Elite')

    return free, premium, elite


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_all_agents(request):
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin", "Agent"]

    try:
        # Retrieve the user
        user = User.objects.get(user_id=user_instance.id)
    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")

    # Validate the user's role
    get_user_role = getattr(user.role_id, "roles", None)
    if get_user_role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{get_user_role}' is not authorized.")

    try:
        # Fetch query parameters
        search_query = request.GET.get('search', None)
        page = request.GET.get('page', 1)
        per_page = request.GET.get('per_page', 10)

        # Base query
        users_query = User.objects.filter(role_id=Role.objects.get(roles="Agent")).all()

        if search_query:
            users_query = users_query.filter(
                Q(user_id__username__icontains=search_query) | Q(user_id__email__icontains=search_query)
            )

        # Paginate the results
        paginator = Paginator(users_query, per_page)
        try:
            users_page = paginator.page(page)
        except PageNotAnInteger:
            return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid page number.")
        except EmptyPage:
            return APIResponse.HTTP_404_NOT_FOUND(message="No more pages available.")

        # Serialize users
        users_data = [user.to_dict() for user in users_page]

        # Response with pagination metadata
        response_data = {
            "users": users_data,
            "total_users": paginator.count,
            "total_pages": paginator.num_pages,
            "current_page": users_page.number,
            "per_page": per_page,
        }

        return APIResponse.HTTP_200_OK(data=response_data, message="Agents fetched successfully.")

    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"Error fetching agents: {str(e)}")


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def helpful_review(request):
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin", "Agent"]

    try:
        # Retrieve the user
        user = get_object_or_404(User, user_id=user_instance.id)
    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")

    # Validate the user's role
    get_user_role = getattr(user.role_id, "roles", None)  # Adjust field name accordingly
    if get_user_role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{get_user_role}' is not authorized.")

    try:
        # Parse pagination parameters
        try:
            review_id = request.query_params.get('review_id', None)
            page = int(request.GET.get('page', 1))
            per_page = int(request.GET.get('per_page', 10))
        except ValueError:
            return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid pagination parameters.")

        # Query helpful reviews
        if review_id:
            helpful_reviews_query = ReviewHelpFull.objects.select_related('review_id').filter(review_id=review_id)
        else:
            helpful_reviews_query = ReviewHelpFull.objects.select_related('review_id').all()

        # Paginate the results
        paginator = Paginator(helpful_reviews_query, per_page)
        try:
            helpful_reviews_page = paginator.page(page)
        except PageNotAnInteger:
            return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid page number.")
        except EmptyPage:
            return APIResponse.HTTP_404_NOT_FOUND(message="No more pages available.")

        # Serialize helpful reviews
        helpful_reviews_data = [
            {
                'id': str(review.id),
                'helpful_review_sender': review.user_id.to_dict() if review.user_id else None,
                'helpful_review_receiver': review.review_id.to_dict() if review.review_id else None,
                'is_liked': review.is_liked,
            }
            for review in helpful_reviews_page
        ]

        # Response with pagination metadata
        response_data = {
            "helpful_reviews": helpful_reviews_data,
            "total_helpful_reviews": paginator.count,
            "total_pages": paginator.num_pages,
            "current_page": helpful_reviews_page.number,
            "per_page": per_page,
        }

        return APIResponse.HTTP_200_OK(data=response_data, message="Helpful Reviews fetched successfully.")

    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"Error fetching helpful reviews: {str(e)}")


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def not_helpful_review(request):
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin", "Agent"]

    try:
        # Retrieve the user
        user = get_object_or_404(User, user_id=user_instance.id)
    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")

    # Validate the user's role
    get_user_role = getattr(user.role_id, "roles", None)  # Adjust field name accordingly
    if get_user_role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{get_user_role}' is not authorized.")

    try:
        # Parse pagination parameters
        try:
            page = int(request.GET.get('page', 1))
            per_page = int(request.GET.get('per_page', 10))
        except ValueError:
            return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid pagination parameters.")

        # Query helpful reviews
        not_helpful_reviews_query = ReviewNotHelpFull.objects.select_related('review_id').all()

        # Paginate the results
        paginator = Paginator(not_helpful_reviews_query, per_page)
        try:
            not_helpful_reviews_page = paginator.page(page)
        except PageNotAnInteger:
            return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid page number.")
        except EmptyPage:
            return APIResponse.HTTP_404_NOT_FOUND(message="No more pages available.")

        # Serialize helpful reviews
        not_helpful_reviews_data = [
            {
                'id': str(review.id),
                'user_id': review.user_id.to_dict() if review.user_id else None,
                'review_id': review.review_id.to_dict() if review.review_id else None,
                'is_liked': review.is_liked,
            }
            for review in not_helpful_reviews_page
        ]

        # Response with pagination metadata
        response_data = {
            "not_helpful_reviews": not_helpful_reviews_data,
            "total_not_helpful_reviews": paginator.count,
            "total_pages": paginator.num_pages,
            "current_page": not_helpful_reviews_page.number,
            "per_page": per_page,
        }

        return APIResponse.HTTP_200_OK(data=response_data, message="Not Helpful Reviews fetched successfully.")

    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"Error fetching not helpful reviews: {str(e)}")


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_all_users(request):
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin", "Agent"]

    try:
        # Retrieve the user
        user = User.objects.get(user_id=user_instance.id)
    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")

    # Validate the user's role
    get_user_role = getattr(user.role_id, "roles", None)
    if get_user_role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{get_user_role}' is not authorized.")

    try:
        # Fetch query parameters
        search_query = request.GET.get('search', None)
        page = request.GET.get('page', 1)
        per_page = request.GET.get('per_page', 10)

        # Base query
        users_query = User.objects.filter(role_id=Role.objects.get(roles="User")).all()

        if search_query:
            users_query = users_query.filter(
                Q(user_id__username__icontains=search_query) | Q(user_id__email__icontains=search_query)
            )

        # Paginate the results
        paginator = Paginator(users_query, per_page)
        try:
            users_page = paginator.page(page)
        except PageNotAnInteger:
            return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid page number.")
        except EmptyPage:
            return APIResponse.HTTP_404_NOT_FOUND(message="No more pages available.")

        # Serialize users
        users_data = [user.to_dict() for user in users_page]

        # Response with pagination metadata
        response_data = {
            "users": users_data,
            "total_users": paginator.count,
            "total_pages": paginator.num_pages,
            "current_page": users_page.number,
            "per_page": per_page,
        }

        return APIResponse.HTTP_200_OK(data=response_data, message="Users fetched successfully.")

    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"Error fetching agents: {str(e)}")


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_all_unblocked_users(request):
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin", "Agent"]

    try:
        # Retrieve the user
        user = User.objects.get(user_id=user_instance.id)
    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")

    # Validate the user's role
    get_user_role = getattr(user.role_id, "roles", None)
    if get_user_role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{get_user_role}' is not authorized.")

    try:
        # Fetch query parameters
        search_query = request.GET.get('search', None)
        page = request.GET.get('page', 1)
        per_page = request.GET.get('per_page', 10)

        # Base query
        users_query = User.objects.filter(
            role_id=Role.objects.get(roles="User")).all().exclude(user_id__is_active=False)

        if search_query:
            users_query = users_query.filter(
                Q(user_id__username__icontains=search_query) | Q(user_id__email__icontains=search_query)
            )

        # Paginate the results
        paginator = Paginator(users_query, per_page)
        try:
            users_page = paginator.page(page)
        except PageNotAnInteger:
            return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid page number.")
        except EmptyPage:
            return APIResponse.HTTP_404_NOT_FOUND(message="No more pages available.")

        # Serialize users
        users_data = [user.to_dict() for user in users_page]

        # Response with pagination metadata
        response_data = {
            "users": users_data,
            "total_users": paginator.count,
            "total_pages": paginator.num_pages,
            "current_page": users_page.number,
            "per_page": per_page,
        }

        return APIResponse.HTTP_200_OK(data=response_data, message="Users fetched successfully.")

    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"Error fetching agents: {str(e)}")


@api_view(['POST'])
def sign_up_api_view(request):
    otp, expiration_time = generate_otp()
    data = request.data

    if not data:
        return APIResponse.HTTP_400_BAD_REQUEST(message="No data provided.")

    expiration = expiration_time.strftime('%Y-%m-%d %H:%M:%S %Z')

    # Extract Django User data
    django_user_data = {
        'username': data.get('user', {}).get('username'),
        'password': make_password(data.get('user', {}).get('password')),
        'email': data.get('user', {}).get('email'),
        'first_name': data.get('first_name'),
        'last_name': data.get('last_name'),
    }

    if (not django_user_data['username'] or not django_user_data['password'] or not django_user_data['email']
            or not django_user_data['first_name'] or not django_user_data['last_name']):
        return APIResponse.HTTP_400_BAD_REQUEST(
            message="Username, Password, Email, First Name, and Last Name are required.")

    try:
        # Extract Custom User data
        user_form_data = {
            key: value
            for key, value in data.items()
            if key in UserForm.Meta.fields and key not in ['user_id', 'user_level', 'role', 'country']
        }

        # Validate Django User data
        if DjangoUser.objects.filter(email=django_user_data['email']).exists():
            return APIResponse.HTTP_400_BAD_REQUEST(message="Email already exists.")

        if DjangoUser.objects.filter(username=django_user_data['username']).exists():
            return APIResponse.HTTP_400_BAD_REQUEST(message="Username already exists.")

        # Fetch role, country, and level from the database using text fields
        role_text = data.get('role', 'User')  # Default to 'User' if not provided
        country_text = data.get('country', 'United States')  # Default to 'United States' if not provided
        level_text = data.get('level', 'Level 0')  # Default to 'Level 0' if not provided

        role_obj = Role.objects.filter(roles=role_text).first()
        if not role_obj:
            return APIResponse.HTTP_400_BAD_REQUEST(message=f"Role '{role_text}' does not exist.")

        country_obj = Country.objects.filter(country=country_text).first()
        if not country_obj:
            return APIResponse.HTTP_400_BAD_REQUEST(message=f"Country '{country_text}' does not exist.")

        level_obj = Level.objects.filter(level=level_text).first()
        if not level_obj:
            return APIResponse.HTTP_400_BAD_REQUEST(message=f"Level '{level_text}' does not exist.")

        # Track signup data
        signup_data = {
            'django_user_data': django_user_data,
            'user_form_data': user_form_data,
            'role_obj': role_obj,
            'country_obj': country_obj,
            'level_obj': level_obj,
        }

        cache_key = f"signup_data_{django_user_data['email']}"
        cache.set(cache_key, signup_data, timeout=900)  # Cache for 15 minutes

        # Create OTP verification record
        otp_verification = OTPVerification.objects.create(
            otp=otp,
            otp_created_at=datetime.now(),
            expire_at=str(expiration_time),
            verification_type="OTP"
        )

        # Cache OTP
        cache.set(f"otp_{django_user_data['email']}", otp, timeout=15000)  # 5 minutes timeout

        # Send OTP email
        send_mail(
            'OTP Verification',
            f'Your OTP is: {otp}, and it expires in {expiration}.',
            settings.EMAIL_HOST_USER,
            [django_user_data['email']],
        )

        response_data = {
            'otp_id': otp_verification.id,
            'otp': otp_verification.otp,
            'expire_at': expiration,
            'email': django_user_data['email'],
            'username': django_user_data['username'],
            'first_name': django_user_data['first_name'],
            'last_name': django_user_data['last_name'],
        }

        return APIResponse.HTTP_201_CREATED(message="OTP sent successfully.", data=response_data)

    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


def create_game_user_in_background(
        username="", password="", nickname="", temp_record_id="", logged_in_user_id="",
        game_id="",  # on which function will perform
        method="reset_player", score=2,
):
    try:
        if method == "player":
            # API call of create player
            ...
        status = {
            "status": 200,
            "message": "",
            "data": {
                "username": 'ak12',
                'datetime': 'UTC',
                'nickname': 'ak12',
                'score': 0
            }
        }
        if status['status'] == 200:
            # entry in db (Approved)
            ...
        else:
            # entry in db (Failed)
            ...
    except Exception:
        # entry in db (Failed)
        ...

def check_status():
    ...

@permission_classes([IsAuthenticated])
class CreateAgentAPIView(APIView):
    @staticmethod
    def post(request):

        # Authenticate and fetch the user
        user_instance = AuthService.get_user_from_token(request)
        if not user_instance:
            return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

        # Allowed roles
        allowed_roles = ["Admin", "Agent"]

        try:
            # Retrieve the user
            user = User.objects.get(user_id=user_instance.id)
        except User.DoesNotExist:
            return APIResponse.HTTP_404_NOT_FOUND(message="Admin not found.")

        # Validate the user's role
        get_user_role = getattr(user.role_id, "roles", None)
        if get_user_role not in allowed_roles:
            return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{get_user_role}' is not authorized.")

        data = request.data
        user_data = data.get("user", {})

        ...

        # Validate required fields
        if not data:
            return APIResponse.HTTP_400_BAD_REQUEST(message="All fields are required.")
        try:
            with transaction.atomic():
                # Create Django user
                django_user = DjangoUser.objects.create_user(
                    first_name=user_data["first_name"],
                    last_name=user_data["last_name"],
                    username=user_data["username"],
                    email=user_data["email"],
                    password=user_data["password"]
                )

                # Fetch or create role, level, subscription plan
                agent_role = get_object_or_404(Role, roles=data.get("role_name", "Agent"))
                user_level = get_object_or_404(Level, level=data.get("user_level", "Level 0"))
                subscription_plan = get_object_or_404(SubscriptionPlan, pro_status=data.get("pro_status", "Free"))

                # Create Wallet
                wallet = Wallet.objects.create(
                    current_balance=0,
                    total_amount=0,
                    withdrawal_percentage_tax=0,
                    last_transaction_date=datetime.now(),
                )

                # Fetch country
                country = get_object_or_404(Country, country=data.get("country_name"))

                # Create Custom User Profile
                agent = User.objects.create(
                    user_id=django_user,
                    first_name=data.get("first_name", ""),
                    last_name=data.get("last_name", ""),
                    email=data.get("email"),
                    is_verified_license=data.get("is_verified_license", False),
                    gender=data.get("gender", "M"),
                    date_of_birth=data.get("date_of_birth"),
                    waiting_list=data.get("waiting_list", False),
                    experience_points=data.get("experience_points", 0),
                    user_level=user_level,
                    referral=data.get("referral", False),
                    referral_key=data.get("referral_key", ""),
                    country_id=country,
                    wallet_id=wallet,
                    role_id=agent_role,
                    created_by=user,
                    subscription_plan=subscription_plan,
                )

                print(f"Agent created successfully: {agent}")

                # Prepare Response Data
                response_data = {
                    "agent_id": str(agent.id),
                    "username": django_user.username,
                    "email": django_user.email,
                    "first_name": agent.first_name,
                    "last_name": agent.last_name,
                    "is_verified_license": agent.is_verified_license,
                    "gender": agent.gender,
                    "date_of_birth": str(agent.date_of_birth),
                    "waiting_list": agent.waiting_list,
                    "experience_points": agent.experience_points,
                    "user_level": user_level.level,
                    "referral": agent.referral,
                    "referral_key": agent.referral_key,
                    "country": country.country,
                    "wallet": {
                        "wallet_id": wallet.id,
                        "current_balance": wallet.current_balance,
                        "total_amount": wallet.total_amount,
                        "withdrawal_percentage_tax": wallet.withdrawal_percentage_tax,
                        "last_transaction_date": str(wallet.last_transaction_date),
                    },
                    "role": agent_role.roles,
                    "created_by": str(agent.created_by.id),
                    "subscription_plan": subscription_plan.pro_status,
                }

                return APIResponse.HTTP_201_CREATED(message="Agent created successfully", data=response_data)

        except Exception as e:
            return APIResponse.HTTP_400_BAD_REQUEST(message=f"Error: {str(e)}")


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_role(request):
    """
    Endpoint to upload user profile and banner images with random filenames.
    """

    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin", "User", "Agent"]

    user_instance = get_object_or_404(User, user_id=user_instance.id)

    # Validate the user's role
    get_user_role = getattr(user_instance.role_id, "roles", None)
    if get_user_role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{get_user_role}' is not authorized.")

    try:

        data = {
            "role": user_instance.role_id.to_dict(),
            **user_instance.to_dict()
        }

        # Return a success response
        return APIResponse.HTTP_200_OK(
            message='User role fetched successfully',
            data=data
        )

    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f'Error: {e}')


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def upload_profiles_and_banners(request):
    """
    Endpoint to upload user profile and banner images with random filenames.
    """

    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin", "User", "Agent"]

    user_instance = get_object_or_404(User, user_id=user_instance.id)

    # Validate the user's role
    get_user_role = getattr(user_instance.role_id, "roles", None)
    if get_user_role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{get_user_role}' is not authorized.")

    # Get files from the request
    profile_image = request.FILES.get('user_profile')
    banner_image = request.FILES.get('banner')

    # Ensure at least one file is provided
    if not profile_image and not banner_image:
        return APIResponse.HTTP_400_BAD_REQUEST(message='At least one of Profile or Banner image is required.')

    try:
        updated_data = {}

        # Handle profile image upload if provided
        if profile_image:
            profile_file_name = f'{user_instance.user_id.username}__{uuid.uuid4().hex}.jpg'
            profile_file_path = f'user_profiles/{profile_file_name}'
            file_path = default_storage.save(profile_file_path, profile_image)
            user_instance.profile_image = file_path
            updated_data['profile_image_url'] = f'{settings.HOST}/media/{file_path}'

        # Handle banner image upload if provided
        if banner_image:
            banner_file_name = f'{user_instance.user_id.username}__{uuid.uuid4().hex}.jpg'
            banner_file_path = f'user_profiles/banners/{banner_file_name}'
            file_path = default_storage.save(banner_file_path, banner_image)
            user_instance.banner_image = file_path
            updated_data['banner_image_url'] = f'{settings.HOST}/media/{file_path}'

        # Save the updated user instance only if changes were made
        user_instance.save()

        # Return a success response
        return APIResponse.HTTP_200_OK(
            message='Profile and/or banner images updated successfully',
            data=updated_data
        )

    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f'Error: {e}')


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def upload_profile_photo(request):
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin", "User", "Agent"]

    current_user = User.objects.get(user_id=user_instance.id)

    # Validate the user's role
    get_user_role = getattr(current_user.role_id, "roles", None)
    if get_user_role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{get_user_role}' is not authorized.")

    # Initialize the files from the request
    profile_image = request.FILES.get('user_profile')

    if not profile_image:
        return APIResponse.HTTP_400_BAD_REQUEST(message='Profile image are required')

    try:
        profile_file_name = f'{current_user.user_id.username}__{uuid.uuid4().hex}.png'
        profile_file_path = f'user_profiles/{profile_file_name}'

        # Save the image file
        file_path = default_storage.save(profile_file_path, profile_image)
        current_user.profile_image = file_path

        # Save the updated user instance
        current_user.save()

        # Return a success response
        return APIResponse.HTTP_200_OK(message='Your profile has been updated!', data=current_user.to_dict())
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f'Error: {e}')


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def profile(request):
    """
    API endpoint to retrieve the user profile using the provided token in the Authorization header or cookies.
    """

    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")
    # print(f"user_instance: {user_instance}")

    # Allowed roles
    allowed_roles = ["Admin", "Agent", "User"]

    try:
        # Retrieve the user
        user = User.objects.get(user_id=user_instance.id)
    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")

    # Validate the user's role
    get_user_role = getattr(user.role_id, "roles", None)
    if get_user_role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{get_user_role}' is not authorized.")

    try:

        # Assuming wallet transaction history is available
        if user.wallet_id and user.wallet_id.wallet_transaction_history_id.exists():
            last_transaction = user.wallet_id.wallet_transaction_history_id.last()  # Get the last transaction
            last_payment_method = last_transaction.payment_method if last_transaction else None
        else:
            last_payment_method = None

        # Prepare the profile data
        profile_data = {
            "id": user.id,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "username": user.user_id.username,
            "email": user.email,
            "profile": f'{settings.HOST}{user.profile_image.url}' if user.profile_image else None,
            "banner": f'{settings.HOST}{user.banner_image.url}' if user.banner_image else None,
            "front_images": f'{settings.HOST}{user.front_images.url}' if user.front_images else None,
            "back_images": f'{settings.HOST}{user.back_images.url}' if user.back_images else None,
            "selected_documents": user.selected_documents,
            "role": user.role_id.roles,
            "dob": user.date_of_birth,
            "gender": user.gender,
            "subscription_plan": {
                "name": user.subscription_plan.pro_status if user.subscription_plan else None,
                "price": user.subscription_plan.redemption_on_free_subscription if user.subscription_plan else None,
                "duration": user.subscription_plan.subscription_plan_amount if user.subscription_plan else None,
            } if user.subscription_plan else None,
            "country": {
                "country": user.country_id.country if user.country_id else None,
            } if user.country_id else None,
            "phone": user.phone,
            "wallet": {
                "id": user.wallet_id.id if user.wallet_id else None,
                "current_balance": user.wallet_id.current_balance if user.wallet_id else None,
                "total_amount": user.wallet_id.total_amount if user.wallet_id else None,
                "payment_method": last_payment_method,
            } if user.wallet_id else None,
        }

        # Return the profile data in the response
        return APIResponse.HTTP_200_OK(message="User profile retrieved successfully.", data=profile_data)

    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message="An unexpected error occurred.")


@api_view(['POST'])
def login_api_view(request):
    """
    Login API view to check user credentials, handle failed attempts, and lockout after 3 attempts.
    """
    identifier = request.data.get('username_or_email')  # Accepts either username or email
    password = request.data.get('password')
    remember_me = request.data.get('remember_me')

    if not identifier or not password:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Username or email and password are required.")

    try:
        # Retrieve the `DjangoUser` object based on the identifier
        if '@' in identifier:
            django_user = DjangoUser.objects.get(email=identifier)
        else:
            django_user = DjangoUser.objects.get(username=identifier)

    except DjangoUser.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message=f"User with email or username {identifier} not found.")

    try:
        # Retrieve the `User` object linked to the `DjangoUser`
        user = User.objects.get(user_id=django_user.id)
    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message=f"User with email or username {identifier} not found.")

    # Check if user is locked due to failed attempts
    if user.is_locked():
        return APIResponse.HTTP_403_FORBIDDEN(
            message="Reset password or wait for 30 minutes to login again."
        )

    # Check if user is frozen
    if getattr(user, 'is_frozen', False):
        return APIResponse.HTTP_403_FORBIDDEN(message="Your account is frozen. Please contact support.")

    try:
        # Authenticate user with the provided password
        if django_user.check_password(password):
            # Reset failed attempts and unlock the user
            user.reset_failed_attempts()
            user.last_active = timezone.now()
            user.is_last_active = True
            user.save()

            # Generate or retrieve the token for the user
            token, created = Token.objects.get_or_create(user=django_user)

            # Create the response data
            response_data = {
                "user_id": user.id,
                "username": django_user.username,
                "email": django_user.email,
                "is_superuser": django_user.is_superuser,
                "is_staff": django_user.is_staff,
                "role": user.role_id.roles,
                "token": token.key,
            }

            # Set cookie with token
            if remember_me:
                expires = timezone.now() + timedelta(days=15)
            else:
                expires = timezone.now() + timedelta(days=1)

            # Create the response
            response = Response({
                "message": "Login successful.",
                "data": response_data,
                "last_login": user.last_login,
                "cookie_expire_in": expires,
                "remember_me": remember_me,
            })

            response.set_cookie(
                'token',
                token.key,
                expires=expires,
                httponly=True,
                secure=True,
                samesite='Lax'
            )

            authenticated = authenticate(request, username=identifier, password=password)

            if authenticated is not None:
                login(request, authenticated)
            else:
                print("Failed to login..")

            return response

        # Handle incorrect password
        if LoginAttemptMiddleware.handle_failed_login(user):
            return APIResponse.HTTP_403_FORBIDDEN(
                message="Too many failed attempts. Your account is locked for 30 minutes."
            )
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid credentials.")
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"Internal Server Error: {e}")


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_api_view(request):
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin", "Agent", "User"]

    try:
        # Retrieve the user
        user = User.objects.get(user_id=user_instance.id)
    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")

    # Validate the user's role
    get_user_role = getattr(user.role_id, "roles", None)
    if get_user_role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{get_user_role}' is not authorized.")

    try:
        user.last_active = timezone.now()
        user.last_login = timezone.now()
        user.is_last_active = False
        user.save()

        return APIResponse.HTTP_200_OK(message="Logout successful.", data={
            **user.to_dict()
        })
    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message=f"User not found.")
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"Internal Server Error: {e}")


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def de_activate_user(request):
    """
        Freeze the user's account with username.
        means user.is_active = False
    """
    # First, check if the user is authenticated via token
    token = request.COOKIES.get('token')  # Retrieve the token from cookies
    if not token:
        token = request.headers.get('Authorization')  # Retrieve from Authorization header if not in cookies
        if token:
            token = token.split(' ')[1]  # Extract the token from 'Bearer <token>'

    if not token:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Authentication token is missing.")

    # print(f"token 2: {token}")
    try:
        # Check if token is valid
        token_instance = Token.objects.get(key=token)
        user_instance = token_instance.user
        userid = user_instance.id

    except Token.DoesNotExist:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or expired token.")

    admin = User.objects.get(user_id=userid)

    if admin.role_id.roles != 'Admin':
        return APIResponse.HTTP_401_UNAUTHORIZED(message="You are not authorized to perform this action.")

    username_or_email = request.data.get('username') or request.data.get('email')

    if '@' in username_or_email:
        username = username_or_email
    else:
        username = username_or_email

    try:

        user = DjangoUser.objects.get(username=username)
        user.is_active = False
        user.save()

        # Send email to user
        send_mail(
            'Account Blocked',
            f'Your account has been blocked. Please contact support for further assistance.',
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
        )

        data = {
            "user_id": user.id,
            "username": user.username,
            "email": user.email,
            "is_superuser": user.is_superuser,
            "is_staff": user.is_staff,
        }

        return APIResponse.HTTP_200_OK(message="Account blocked successfully.", data=data)
    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def block_unblock_user(request):
    """
        block and unblock the user's account with username.
        means user.is_active = False
    """

    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin", "Agent", "User"]

    try:
        # Retrieve the user
        user = User.objects.get(user_id=user_instance.id)
    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")

    # Validate the user's role
    get_user_role = getattr(user.role_id, "roles", None)
    if get_user_role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{get_user_role}' is not authorized.")

    username_or_email = request.data.get('username') or request.data.get('email')

    if '@' in username_or_email:
        username = username_or_email
    else:
        username = username_or_email

    print(f"PUT: {username_or_email}")

    try:

        user = DjangoUser.objects.get(username=username)

        if user.is_active:
            user.is_active = False
        else:
            user.is_active = True

        user.save()

        is_blocked = 'Activated' if user.is_active else 'De-activated'

        print(f"is_blocked: {is_blocked}")

        # Send email to user
        send_mail(
            f'Account {is_blocked}',
            f'Your account has been {is_blocked}. Please contact support for further assistance.',
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
        )

        data = {
            "user_id": user.id,
            "username": user.username,
            "email": user.email,
            "is_superuser": user.is_superuser,
            "is_staff": user.is_staff,
            "is_active": user.is_active,
            'code': is_blocked
        }

        return APIResponse.HTTP_200_OK(message=f"Account {is_blocked} successfully.", data=data)
    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def admin_delete_user(request):
    """
        Delete the user's account with username.
        means user.is_active = False
    """

    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin", "Agent"]

    try:
        # Retrieve the user
        user = User.objects.get(user_id=user_instance.id)
    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")

    # Validate the user's role
    get_user_role = getattr(user.role_id, "roles", None)
    if get_user_role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{get_user_role}' is not authorized.")

    email = request.data.get('email')

    if not email:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Email is required to delete a user.")

    dUser = DjangoUser.objects.filter(email=email).first()
    print(f"dUser: {dUser}")

    if dUser is None:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")

    try:
        if dUser.is_active:
            dUser.delete()
        else:
            return APIResponse.HTTP_400_BAD_REQUEST(message="User is not active to delete.")

        # Send email to user
        send_mail(
            f'Account Deleted',
            f'Your account has been deleted by {user.user_id.username} ({user.role_id.roles}). '
            f'Please contact support for further assistance.',
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
        )

        data = {
            "user_id": dUser.id,
            "email": dUser.email,
            "is_superuser": dUser.is_superuser,
            "is_staff": dUser.is_staff,
            "is_active": dUser.is_active,
        }

        return APIResponse.HTTP_200_OK(message=f"Account deleted successfully.", data=data)
    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
    except DjangoUser.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def activate_user(request):
    """
        Freeze the user's account with username.
        means user.is_active = False
    """
    # First, check if the user is authenticated via token
    token = request.COOKIES.get('token')  # Retrieve the token from cookies
    # print(f"token 1: {token}")
    if not token:
        token = request.headers.get('Authorization')  # Retrieve from Authorization header if not in cookies
        if token:
            token = token.split(' ')[1]  # Extract the token from 'Bearer <token>'

    if not token:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Authentication token is missing.")

    # print(f"token 2: {token}")
    try:
        # Check if token is valid
        token_instance = Token.objects.get(key=token)
        user_instance = token_instance.user  # Get the user associated with the token
        # print(f"user_instance: {user_instance}")
        userid = user_instance.id
        # print(f"""userid: {userid}""")

    except Token.DoesNotExist:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or expired token.")

    admin = User.objects.get(user_id=userid)
    # print(f"admin: {admin}")

    if admin.role_id.roles != 'Admin':
        return APIResponse.HTTP_401_UNAUTHORIZED(message="You are not authorized to perform this action.")

    username_or_email = request.data.get('username') or request.data.get('email')

    if '@' in username_or_email:
        username = username_or_email
    else:  # Otherwise, treat it as a username
        username = username_or_email

    try:

        user = DjangoUser.objects.get(username=username)
        user.is_active = True
        user.save()

        # Send email to user
        send_mail(
            'Account Un-locked',
            f'Your account has been Un-blocked. Please contact support for further assistance.',
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
        )

        data = {
            "user_id": user.id,
            "username": user.username,
            "email": user.email,
            "is_superuser": user.is_superuser,
            "is_staff": user.is_staff,
        }

        return APIResponse.HTTP_200_OK(message="Account Un-blocked successfully.", data=data)
    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['POST'])
def verify_otp_with_user_signup(request):
    global free_play_instance
    email = request.data.get('email')
    otp = request.data.get('otp')

    if not email or not otp:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Email and OTP are required.")

    # Verify OTP
    stored_otp = cache.get(f"otp_{email}")
    if stored_otp is None:
        return APIResponse.HTTP_400_BAD_REQUEST(message="OTP has expired or was not found.")
    if str(stored_otp) != str(otp):
        return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid OTP.")

    # Retrieve signup data from the cache
    cache_key = f"signup_data_{email}"
    signup_data = cache.get(cache_key)
    if not signup_data:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Sign-up data has expired. Please restart the sign-up process.")

    django_user_data = signup_data['django_user_data']
    user_form_data = signup_data['user_form_data']
    role_obj = signup_data['role_obj']
    country_obj = signup_data['country_obj']
    level_obj = signup_data['level_obj']

    if not django_user_data or not user_form_data or not role_obj or not country_obj or not level_obj:
        return APIResponse.HTTP_400_BAD_REQUEST(
            message="Sign-up data is incomplete. Please restart the sign-up process.")

    try:
        # Generate referral key uuid4 without hyphens
        referral_key = str(uuid.uuid4().hex).upper()

        # Filter all spins and randomly select one between 3 and 5 items, then assign it to the user.
        spin_queryset = Spin.objects.all()

        # Ensure there are enough spins available to select from.
        if spin_queryset.count() < 3:
            raise ValueError("Not enough spins available to select a random spin.")

        # Randomly select a number between 3 and 5 spins.
        random_spin_list = random.sample(list(spin_queryset), random.randint(3, 5))

        # Select the first spin from the randomly chosen spins.
        selected_spin = random_spin_list[0]

        # Create the custom user
        user_form = UserForm(data=user_form_data)

        if user_form.is_valid():

            # Create Django User
            django_user = DjangoUser.objects.create(**django_user_data)

            if not django_user:
                return APIResponse.HTTP_400_BAD_REQUEST(message="Error creating Django user.")

            # Set user ID for the custom user
            user_form_data['user_id'] = django_user.id

            custom_user = user_form.save(commit=False)
            custom_user.user_id = django_user  # Link to the Django user
            custom_user.role_id = role_obj  # Assign the role
            custom_user.country_id = country_obj  # Assign the country
            custom_user.user_level = level_obj  # Assign the level
            custom_user.is_verified_license = False  # Default license verification to False
            custom_user.spin_id = selected_spin  # Assign the randomly selected spin
            custom_user.referral_key = referral_key.upper()
            custom_user.email = django_user.email

            # Subscription Plan
            subscription_plan = get_object_or_404(SubscriptionPlan, pro_status='Free')
            custom_user.subscription_plan = subscription_plan

            # Randomly select between 3 and 5 free plays
            random_free_plays_between_3_and_5 = random.randint(3, 5)

            # Handle first-time sign-up logic
            if custom_user.user_id.email:

                # Validate and process the wallet form data
                wallet_history = WalletTransactionHistory.objects.create(
                    payment_method='Card',
                    payment_status='Approved',
                    transaction_amount=0
                )

                wallet = Wallet.objects.create(
                    current_balance=0,
                    total_amount=0
                )
                wallet.wallet_transaction_history_id.add(wallet_history)

                if wallet and wallet_history:
                    custom_user.wallet_id = wallet
                    custom_user.save()

                    free_plays = FreePlayForm({
                        "user": custom_user,
                        "free_plays": random_free_plays_between_3_and_5,
                        "spins_left": random_free_plays_between_3_and_5,
                        "expires_at": datetime.now() + timedelta(days=30)
                    })

                    if free_plays.is_valid():
                        free_play_instance = free_plays.save(commit=False)
                        free_play_instance.save()
                    else:
                        return APIResponse.HTTP_400_BAD_REQUEST(message="FreePlay form validation failed.",
                                                                data=free_plays.errors)

        else:
            return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid form data.", data=user_form.errors)

        # Send welcome email to user
        send_mail(
            'Account Created',
            f'Your account has been created. You can now access your account.',
            settings.DEFAULT_FROM_EMAIL,
            [django_user.email],
            fail_silently=False,
        )

        data = {
            "user_id": str(custom_user.id),
            "user_name": custom_user.user_id.username,
            "email": custom_user.user_id.email,
            "referral_key": custom_user.referral_key,
            "role": custom_user.role_id.roles,
            "country": custom_user.country_id.country,
            "level": custom_user.user_level.level,
            "first_name": custom_user.first_name,
            "last_name": custom_user.last_name,
            "experience_points": custom_user.experience_points,
            "is_verified_license": custom_user.is_verified_license,
            "plan": custom_user.subscription_plan.pro_status,
            "free_plays": [
                {
                    "free_plays": free_play_instance.free_plays,
                    "spins_left": free_play_instance.spins_left,
                    "expires_at": free_play_instance.expires_at
                }
            ],
            "wallet_account": [
                {
                    "current_balance": custom_user.wallet_id.current_balance,
                    "total_amount": custom_user.wallet_id.total_amount
                }
            ]
        }

        return APIResponse.HTTP_201_CREATED(message="User created successfully.", data=data)

    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"Error creating user: {str(e)}")


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_user_with_licensees_and_increases_xp_levels(request):
    # First, check if the user is authenticated via token
    token = request.COOKIES.get('token')  # Retrieve the token from cookies
    # print(f"token 1: {token}")
    if not token:
        token = request.headers.get('Authorization')  # Retrieve from Authorization header if not in cookies
        if token:
            token = token.split(' ')[1]  # Extract the token from 'Bearer <token>'

    if not token:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Authentication token is missing.")

    # print(f"token 2: {token}")
    try:
        # Check if token is valid
        token_instance = Token.objects.get(key=token)
        user_instance = token_instance.user  # Get the user associated with the token
        # print(f"user_instance: {user_instance}")
        userid = user_instance.id
        # print(f"""userid: {userid}""")

    except Token.DoesNotExist:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or expired token.")

    try:
        # Retrieve the user instance from the database
        user = User.objects.get(user_id=userid)

        # Check if the user exists
        if not user:
            return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")

        # Bind the form to the request data
        form = UpdateUserLicenseForm(request.data, request.FILES, instance=user)

        if form.is_valid():
            try:
                # Save the form and handle the user level upgrade automatically
                updated_user = form.save(commit=False)
                updated_user.save()

                # Return a successful response with updated user data
                response_data = {
                    "is_verified_license": updated_user.is_verified_license,
                    "user_level": updated_user.user_level.level_code if updated_user.user_level else None,
                    **updated_user.to_dict(),
                }

                # Return a successful response using the custom handler
                return APIResponse.HTTP_200_OK(data=response_data, message="User updated successfully.")

            except ValueError as e:
                return APIResponse.HTTP_400_BAD_REQUEST(message="Error updating user: " + str(e))

        else:
            # Return validation errors using the custom handler
            return APIResponse.HTTP_400_BAD_REQUEST(data=form.errors, message="Validation errors.")

    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def phone_verification_and_get_free_xp(request):
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin", "Agent", "User"]

    try:
        user_obj = User.objects.get(user_id=user_instance.id)
    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")

    # Validate the user's role
    get_user_role = getattr(user_obj.role_id, "roles", None)
    if get_user_role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{get_user_role}' is not authorized.")

    # Bind the form to the request data
    form = UpdateUserPhoneAndGetFreeXPForm(request.data, instance=user_obj)

    if not form.is_valid():
        return APIResponse.HTTP_400_BAD_REQUEST(data=form.errors, message="Validation errors.")

    try:
        # Save the form and handle the user level upgrade automatically
        updated_user = form.save(commit=False)
        updated_user.save()

        # Return a successful response with updated user data
        response_data = {
            "is_phone_verified": updated_user.is_phone_verified,
            "phone": updated_user.phone,
            **updated_user.to_dict(),
        }

        # Return a successful response using the custom handler
        return APIResponse.HTTP_200_OK(data=response_data,
                                       message="Phone verification and free XP granted successfully.")
    except ValueError as e:
        return APIResponse.HTTP_400_BAD_REQUEST(message=str(e))
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=str(e))


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_user_personal_information_api(request):
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin", "Agent", "User"]

    try:
        user_obj = User.objects.get(user_id=user_instance.id)
    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")

    # Validate the user's role
    get_user_role = getattr(user_obj.role_id, "roles", None)
    if get_user_role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{get_user_role}' is not authorized.")

    userid = user_instance.id

    first_name = request.data.get('first_name')
    last_name = request.data.get('last_name')
    username = request.data.get('username')
    dob = request.data.get('dob')

    updated_user = User.objects.filter(user_id=userid).first()

    try:
        django_user = DjangoUser.objects.get(id=userid)
        django_user.username = username

        # Update the user
        updated_user.first_name = first_name
        updated_user.last_name = last_name
        updated_user.date_of_birth = dob
        updated_user.update()
        django_user.save()

        # Return a successful response with updated user data
        response_data = {
            "id": updated_user.id,
            "first_name": updated_user.first_name,
            "last_name": updated_user.last_name,
            "email": updated_user.email,
            "front_images": updated_user.front_images.url if updated_user.front_images else None,
            "back_images": updated_user.back_images.url if updated_user.back_images else None,
            "selected_documents": updated_user.selected_documents
        }

        # Return a successful response using the custom handler
        return APIResponse.HTTP_200_OK(data=response_data,
                                       message=f"User {updated_user.user_id.username} updated successfully.")
    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")

    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=str(e))


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_user_documents(request):
    # First, check if the user is authenticated via token
    token = request.COOKIES.get('token')  # Retrieve the token from cookies
    # print(f"token 1: {token}")
    if not token:
        token = request.headers.get('Authorization')  # Retrieve from Authorization header if not in cookies
        if token:
            token = token.split(' ')[1]  # Extract the token from 'Bearer <token>'

    if not token:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Authentication token is missing.")

    # print(f"token 2: {token}")
    try:
        # Check if token is valid
        token_instance = Token.objects.get(key=token)
        user_instance = token_instance.user  # Get the user associated with the token
        # print(f"user_instance: {user_instance}")
        userid = user_instance.id
        # print(f"""userid: {userid}""")

    except Token.DoesNotExist:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or expired token.")

    try:
        # Retrieve the user instance from the database
        user = User.objects.get(user_id=userid)

        # Check if the user exists
        if not user:
            return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")

        # Bind the form to the request data
        form = UpdateUserDocumentForm(request.data, request.FILES, instance=user)

        if form.is_valid():
            try:
                # Save the form and handle the user level upgrade automatically
                updated_user = form.save()

                # Return a successful response with updated user data
                response_data = {
                    "message": "Documents are updated successfully.",
                    "user": {
                        "id": updated_user.id,
                        "first_name": updated_user.first_name,
                        "last_name": updated_user.last_name,
                        "email": updated_user.email,
                        "front_images": updated_user.front_images.url if updated_user.front_images else None,
                        "back_images": updated_user.back_images.url if updated_user.back_images else None,
                        "selected_documents": updated_user.selected_documents
                    }
                }

                # Return a successful response using the custom handler
                return APIResponse.HTTP_200_OK(data=response_data, message="User updated successfully.")

            except ValueError as e:
                return APIResponse.HTTP_400_BAD_REQUEST(message="Error updating user: " + str(e))

        else:
            # Return validation errors using the custom handler
            return APIResponse.HTTP_400_BAD_REQUEST(data=form.errors, message="Validation errors.")

    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")


@api_view(['POST'])
def verify_otp(request):
    email = request.data.get('email')
    otp = request.data.get('otp')

    _, expiration_time = generate_otp()
    expiration_time.strftime('%Y-%m-%d %H:%M:%S %Z')

    if not email or not otp:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Email and OTP are required.")

    # Retrieve OTP from cache
    stored_otp = cache.get(f"otp_{email}")

    if stored_otp is None:
        return APIResponse.HTTP_400_BAD_REQUEST(message="OTP has expired or was not found.")

    if str(stored_otp) != str(otp):
        return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid OTP.")

    try:
        # Fetch the user by email
        user_instance = User.objects.get(user_id__email=email)

        # Mark the user as active after OTP verification
        user_instance.is_active = True
        user_instance.save()

        # You can also log the OTP verification if needed
        OTPVerification.objects.create(
            otp=otp,
            otp_created_at=datetime.now(),
            expire_at=str(expiration_time),
            verification_type=request.data.get('verification_type', 'OTP'),
        )

        return APIResponse.HTTP_200_OK(message="User verified successfully.", data={"email": email})

    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="User with this email does not exist.", data={"email": email})

    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An error occurred: {str(e)}")


@api_view(['POST'])
def refresh_otp(request):
    """
    Resend the OTP code to the user's email.
    """
    # Extract user email from the request body
    email = request.data.get('email')

    # Check if email is provided
    if not email:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Email is required.", data={"email": email})

    # Generate a new OTP and its expiration time
    otp, expiration_time = generate_otp()

    # Store OTP in cache with a 5-minute expiration
    cache.set(f"otp_{email}", otp, timeout=300)

    try:
        with transaction.atomic():
            # Try to get the user by email
            user_instance = User.objects.get(user_id__email=email)

            # Update the user's verification code with the new OTP
            user_instance.verification_code = otp
            user_instance.save()

            # Log the OTP verification attempt in the OTPVerification model
            OTPVerification.objects.create(
                otp=otp,
                otp_created_at=datetime.now(),
                expire_at=expiration_time,  # Store expiration time as a datetime object
                verification_type=request.data.get('verification_type', 'OTP'),
            )

            # Send the OTP to the user's email
            send_mail(
                'Email Verification OTP',
                f'Your OTP for email verification is: {otp}',
                settings.DEFAULT_FROM_EMAIL,
                [user_instance.email],
                fail_silently=False,
            )

            # Return the data with OTP and user details
            data = {
                "user_id": user_instance.id,
                "email": user_instance.email,
                "username": user_instance.user_id.username,
                "otp": otp,
            }

            return APIResponse.HTTP_200_OK(message="OTP resent successfully.", data=data)

    except User.DoesNotExist:
        # If the user is not found, return an error
        return APIResponse.HTTP_404_NOT_FOUND(message="User with this email does not exist.", data={"email": email})

    except IntegrityError:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message="An unexpected error occurred.")

    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['POST'])
def request_reset_password(request):
    """Send an OTP to the user's email for password reset."""

    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin", "Agent", "User"]

    try:
        user = User.objects.get(user_id=user_instance.id)
    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")

    # Validate the user's role
    get_user_role = getattr(user.role_id, "roles", None)
    if get_user_role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{get_user_role}' is not authorized.")

    email = request.data.get('email')

    if not email:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Email is required.")

    otp, expiration_time = generate_otp()

    try:

        # Create OTP verification object
        otp_verification = OTPVerification.objects.create(
            otp=otp,
            otp_created_at=datetime.now(),
            expire_at=expiration_time,  # Use the datetime object for expiration time
            verification_type=request.data.get('verification_type', 'OTP'),
        )

        # Save the user with the updated OTP verification ID
        user.otp_verification_id = otp_verification
        user.save()

        # Send the OTP to the user's email
        send_mail(
            'Password Reset Code',
            f'Your password reset code is: {otp}, and it will expire at {expiration_time}.',
            settings.DEFAULT_FROM_EMAIL,
            [email],
        )

        data = {
            "email": email,
            "otp": otp,
            "datetime": datetime.now(tz=UTC).__str__(),
        }

        return APIResponse.HTTP_200_OK(
            message=f"Password reset successfully {user.user_id.username}. "
                    f"Please check your email, and verify by the OTP.",
            data=data)

    except User.DoesNotExist:
        data = {
            "email": email,
            "datetime": datetime.now(tz=UTC).__str__(),
        }
        return APIResponse.HTTP_404_NOT_FOUND(message=f"Unable to find user. Please try again after few minutes.",
                                              data=data)


@api_view(['POST'])
def confirm_reset_password(request):
    """Verify the OTP and allow the user to reset their password."""
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin", "Agent", "User"]

    try:
        user_model = User.objects.get(user_id=user_instance.id)
    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")

    # Validate the user's role
    get_user_role = getattr(user_model.role_id, "roles", None)
    if get_user_role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{get_user_role}' is not authorized.")

    email = request.data.get('email')
    reset_code = request.data.get('otp')
    new_password = request.data.get('new_password')

    if not email or not reset_code or not new_password:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Email, reset code, and new password are required.")

    try:
        if reset_code != user_model.otp_verification_id.otp:
            return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid reset code.")

        # Reset password
        user = user_model.user_id
        user.set_password(new_password)
        user.save()

        # Clear the verification code
        user_model.otp_verification_id.otp = None
        user_model.save()

        # Send email to user
        send_mail(
            'Password Reset',
            f'Your password has been reset. Your new password is: {new_password}.',
            settings.DEFAULT_FROM_EMAIL,
            [email],
        )

        data = {
            "email": email,
            "new_password": new_password,
            "datetime": datetime.now(tz=UTC).__str__(),
        }

        return APIResponse.HTTP_200_OK(message="Password reset successfully.", data=data)
    except User.DoesNotExist:
        data = {
            "username": email,
            "newpassword": new_password,
            "datetime": datetime.now(tz=UTC).__str__(),
        }
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(
            message="Unable to find user. Please try again after few minutes.", data=data)


## Authorization & Authentication - APIs Completed
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def send_chat_to_agent(request):
    """
    Post Chat from User to Agent.
    If User is not active for 15 minutes, automatically delete all messages of that user.
    """
    # Retrieve token from cookies or headers
    token = request.COOKIES.get('token')  # Retrieve the token from cookies
    if not token:
        token = request.headers.get('Authorization')  # Retrieve from Authorization header
        if token:
            token = token.split(' ')[1]  # Extract token from 'Bearer <token>'

    if not token:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Authentication token is missing.")

    try:
        # Validate the token
        token_instance = Token.objects.get(key=token)
        user_instance = token_instance.user  # Authenticated user
        user_id = user_instance.id
    except Token.DoesNotExist:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or expired token.")

    # Fetch roles for validation
    agent_role = Role.objects.filter(roles="Agent").first()
    role = Role.objects.filter(roles="User").first()

    if not agent_role or not role:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message="Roles not properly configured.")

    # Fetch user and agent instances
    try:
        user = User.objects.get(user_id=user_id)
    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")

    try:
        agent_id = request.data.get('agent_id')
        if not agent_id:
            return APIResponse.HTTP_400_BAD_REQUEST(message="Agent ID is required.")

        agent = User.objects.get(id=agent_id)
    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="Agent not found.")

    # Validate bans
    if agent.is_banned_from_agent_chat:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Agent is banned from agent chat.")
    if user.is_banned_from_agent_chat:
        return APIResponse.HTTP_400_BAD_REQUEST(message="User is banned from agent chat.")

    # Validate roles
    if not agent.role_id or agent.role_id.roles != agent_role.roles:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid agent role.")

    if not user.role_id or user.role_id.roles != role.roles:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid user role.")

    # Combine and validate form data
    form = AgentChatForm(request.data, request.FILES)
    if not form.is_valid():
        return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid form data.", data=form.errors)

    try:
        # Update user's last active timestamp
        user.is_last_active = True
        user.update_last_active()
        user.save()

        # Save the chat message
        agent_chat = form.save(commit=False)
        agent_chat.user_id = user
        agent_chat.agent_id = agent
        agent_chat.save()

        return APIResponse.HTTP_200_OK(
            message=f"Message sent to {agent.user_id.username} successfully.",
            data={
                "user_id": agent_chat.user_id_id,
                "agent_id": agent_chat.agent_id_id,
                "message_content": agent_chat.message_content,
                "attachment_image": (
                    agent_chat.attachment_image.url if agent_chat.attachment_image else None
                ),
                "status": agent_chat.status,
                "created_at": agent_chat.agent_chat_created_at,
            },
        )
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(
            message=f"An unexpected error occurred: {str(e)}"
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def send_chat_to_user(request):
    """
    Post Chat from User to Agent.
    If User is not active for 15 minutes, automatically delete all messages of that user.
    """
    # Retrieve token from cookies or headers
    token = request.COOKIES.get('token')  # Retrieve the token from cookies
    if not token:
        token = request.headers.get('Authorization')  # Retrieve from Authorization header
        if token:
            token = token.split(' ')[1]  # Extract token from 'Bearer <token>'

    if not token:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Authentication token is missing.")

    try:
        # Validate the token
        token_instance = Token.objects.get(key=token)
        user_instance = token_instance.user  # Authenticated user
        user_id = user_instance.id
    except Token.DoesNotExist:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or expired token.")

    # Fetch roles for validation
    agent_role = Role.objects.filter(roles="Agent").first()
    role = Role.objects.filter(roles="User").first()

    if not agent_role or not role:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message="Roles not properly configured.")

    # Fetch user and agent instances
    try:
        agent = User.objects.get(user_id=user_id)
    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="Agent not found.")

    try:
        user_id = request.data.get('user_id')
        if not user_id:
            return APIResponse.HTTP_400_BAD_REQUEST(message="User ID is required.")

        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="Agent not found.")

    # Validate bans
    if agent.is_banned_from_agent_chat:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Agent is banned from agent chat.")

    if user.is_banned_from_agent_chat:
        return APIResponse.HTTP_400_BAD_REQUEST(message="User is banned from agent chat.")

    # Validate roles
    if not agent.role_id or agent.role_id.roles != agent_role.roles:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid agent role.")

    if not user.role_id or user.role_id.roles != role.roles:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid user role.")

    # Combine and validate form data
    form = AgentChatForm(request.data, request.FILES)
    if not form.is_valid():
        return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid form data.", data=form.errors)

    try:
        # Update user's last active timestamp
        user.is_last_active = True
        user.update_last_active()
        user.save()

        # Save the chat message
        agent_chat = form.save(commit=False)
        agent_chat.user_id = user
        agent_chat.agent_id = agent
        agent_chat.save()

        return APIResponse.HTTP_200_OK(
            message=f"Message sent to {user.user_id.username} successfully.",
            data={
                "user_id": agent_chat.user_id_id,
                "agent_id": agent_chat.agent_id_id,
                "message_content": agent_chat.message_content,
                "attachment_image": (
                    agent_chat.attachment_image.url if agent_chat.attachment_image else None
                ),
                "status": agent_chat.status,
                "created_at": agent_chat.agent_chat_created_at,
            },
        )
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(
            message=f"An unexpected error occurred: {str(e)}"
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def get_agent_chat_history(request):
    """
    Retrieve the chat history for an agent with the given user.
    """
    user_instance = AuthService.get_user_from_token(request)
    auth_user = AuthService.validate_user_role(user_instance, "Agent")  # receiver user

    # Retrieve the chat history for the user and agent
    chat_history = AgentChat.objects.filter(agent_id=auth_user.id).all()
    if chat_history is None:
        return APIResponse.HTTP_404_NOT_FOUND(message="No chat history found.")

    try:

        # Prepare the chat history data for response
        chat_data = [
            {
                'message_content': chat.message_content,
                'attachment_image': chat.attachment_image.url if chat.attachment_image else None,
                'status': chat.status,
                'created_at': chat.agent_chat_created_at,
            }
            for chat in chat_history
        ]

        return APIResponse.HTTP_200_OK(
            message="Agent chat history retrieved successfully.",
            data=chat_data
        )

    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(
            message=f"An unexpected error occurred: {str(e)}"
        )


@api_view(['GET'])
def get_global_chat_history(request):
    """
    Retrieve all global chat messages with user details, supporting pagination.
    """
    page = int(request.query_params.get('page', 1))  # Default page is 1
    limit = int(request.query_params.get('limit', 20))  # Default limit is 20

    try:
        # Retrieve all global chat messages ordered by creation date
        chat_history = GlobalChat.objects.all().order_by('global_chat_created_at')

        if not chat_history:
            # Ensure response is returned if no chat history found
            return APIResponse.HTTP_404_NOT_FOUND(message="No global chat history found.")

        # Pagination: Slice the queryset based on the page and limit
        start = (page - 1) * limit
        end = start + limit
        paginated_chat_history = chat_history[start:end]

        # Prepare the chat history data for response with user details
        chat_data = []
        for chat in paginated_chat_history:
            user_details = {
                'user_id': chat.user_id.id,
                'username': chat.user_id.user_id.username,
                'email': chat.user_id.email,
                'first_name': chat.user_id.first_name,
                'last_name': chat.user_id.last_name,
                'role': chat.user_id.role_id.roles,  # Assuming role_id is a foreign key to the Role model
                'last_active': chat.user_id.last_active,  # Assuming last_active is a datetime field
            }

            chat_data.append({
                'user': user_details,
                'message_content': chat.message_content,
                'created_at': chat.global_chat_created_at,
            })

        # Return response with pagination info
        return APIResponse.HTTP_200_OK(
            message="Global chat history retrieved successfully.",
            data={
                'chat_history': chat_data,
                'pagination': {
                    'page': page,
                    'limit': limit,
                    'total': chat_history.count(),
                }
            }
        )

    except Exception as e:
        # Catch any unexpected errors and return a response
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(
            message=f"An unexpected error occurred: {str(e)}"
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def activate_user_agent_chat(request):
    # Retrieve token from cookies or headers
    token = request.COOKIES.get('token')  # Retrieve the token from cookies
    if not token:
        token = request.headers.get('Authorization')  # Retrieve from Authorization header
        if token:
            token = token.split(' ')[1]  # Extract token from 'Bearer <token>'

    if not token:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Authentication token is missing.")

    try:
        # Validate the token
        token_instance = Token.objects.get(key=token)
        user_instance = token_instance.user  # Authenticated user
        user_id = user_instance.id
    except Token.DoesNotExist:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or expired token.")

    admin = User.objects.get(user_id=user_id)
    # print(f"admin: {admin}")

    if admin.role_id.roles != 'Admin':
        return APIResponse.HTTP_401_UNAUTHORIZED(message="You are not authorized to perform this action.")

    user = User.objects.get(id=request.data.get('user_id'))

    try:
        user.is_banned_from_agent_chat = False
        user.save()

        send_mail(
            'Account Un-blocked',
            f'Your account has been Un-blocked for agent chat by the admin. Reason: {request.data.get("reason")}',
            settings.DEFAULT_FROM_EMAIL,
            [user.user_id.email],
        )

        return APIResponse.HTTP_200_OK(message="User has been Un-blocked for agent chat.", data={
            "id": user.id,
            "username": user.user_id.username,
            "email": user.user_id.email,
            "is_live": user.is_last_active,
            "is_banned_from_agent_chat": user.is_banned_from_agent_chat
        })
    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def de_activate_user_agent_chat(request):
    # Retrieve token from cookies or headers
    token = request.COOKIES.get('token')  # Retrieve the token from cookies
    if not token:
        token = request.headers.get('Authorization')  # Retrieve from Authorization header
        if token:
            token = token.split(' ')[1]  # Extract token from 'Bearer <token>'

    if not token:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Authentication token is missing.")

    try:
        # Validate the token
        token_instance = Token.objects.get(key=token)
        user_instance = token_instance.user  # Authenticated user
        user_id = user_instance.id
    except Token.DoesNotExist:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or expired token.")

    admin = User.objects.get(user_id=user_id)
    # print(f"admin: {admin}")

    if admin.role_id.roles != 'Admin':
        return APIResponse.HTTP_401_UNAUTHORIZED(message="You are not authorized to perform this action.")

    user = User.objects.get(id=request.data.get('user_id'))

    try:
        user.is_banned_from_agent_chat = True
        user.save()

        send_mail(
            'Account blocked',
            f'Your account has been blocked for agent chat by the admin. Reason: {request.data.get("reason")}',
            settings.DEFAULT_FROM_EMAIL,
            [user.user_id.email],
        )

        return APIResponse.HTTP_200_OK(message="User has been blocked for agent chat.", data={
            "id": user.id,
            "username": user.user_id.username,
            "email": user.user_id.email,
            "is_live": user.is_last_active,
            "is_banned_from_agent_chat": user.is_banned_from_agent_chat
        })
    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['POST'])
def is_user_alive(request):
    """
    It may apply on agents, admins, and users.
    """
    agent_id = request.data.get('agent_id')
    user = User.objects.filter(id=agent_id).first()

    if user is None:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")

    try:
        is_last_active = "is" if user.is_last_active else "is not"
        return APIResponse.HTTP_200_OK(message=f"Agent {is_last_active} alive.", data={
            "is_agent_alive": user.is_last_active,
            **user.to_dict()
        })

    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_global_chats(request):
    """
    Retrieve all global chat messages with user details, supporting pagination.
    """
    # Retrieve token from cookies or headers
    token = request.COOKIES.get('token')  # Retrieve the token from cookies
    if not token:
        token = request.headers.get('Authorization')  # Retrieve from Authorization header
        if token:
            token = token.split(' ')[1]  # Extract token from 'Bearer <token>'

    if not token:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Authentication token is missing.")

    try:
        # Validate the token
        token_instance = Token.objects.get(key=token)
        user_instance = token_instance.user  # Authenticated user
        user_id = user_instance.id
    except Token.DoesNotExist:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or expired token.")

    page = int(request.query_params.get('page', 1))  # Default page is 1
    limit = int(request.query_params.get('limit', 20))  # Default limit is 20

    # Retrieve all global chat messages for the given user_id ordered by creation date
    user = User.objects.get(user_id=user_id)
    if not user:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")

    chat_history = GlobalChat.objects.filter(user_id=user).order_by('global_chat_created_at')

    if not chat_history.exists():
        # Ensure response is returned if no chat history found
        return APIResponse.HTTP_404_NOT_FOUND(message="No global chat history found.")

    # Pagination: Slice the queryset based on the page and limit
    start = (page - 1) * limit
    end = start + limit
    paginated_chat_history = chat_history[start:end]

    try:

        # Prepare the chat history data for response with user details
        chat_data = []
        for chat in paginated_chat_history:
            user_details = {
                'user_id': chat.user_id.id,
                'username': chat.user_id.user_id.username,  # Fixed this line
                'email': chat.user_id.email,
                'first_name': chat.user_id.first_name,
                'last_name': chat.user_id.last_name,
                'role': chat.user_id.role_id.roles,  # Assuming role_id is a foreign key to the Role model
                'last_active': chat.user_id.last_active,  # Assuming last_active is a datetime field
            }

            chat_data.append({
                'user': user_details,
                'message_content': chat.message_content,
                'created_at': chat.global_chat_created_at,
            })

        # Return response with pagination info
        return APIResponse.HTTP_200_OK(
            message="Global chat history retrieved successfully.",
            data={
                'chat_history': chat_data,
                'pagination': {
                    'page': page,
                    'limit': limit,
                    'total': chat_history.count(),
                }
            }
        )

    except Exception as e:
        # Catch any unexpected errors and return a response
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(
            message=f"An unexpected error occurred: {str(e)}"
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def send_message_to_global_chat(request):
    """
    Send a message to the global chat.
    The user is identified via the Authorization token.
    """
    # Retrieve token from Authorization header
    token = request.headers.get('Authorization')  # Retrieve from Authorization header
    if token:
        token = token.split(' ')[1]  # Extract token from 'Bearer <token>'

    if not token:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Authentication token is missing.")

    try:
        # Validate the token and fetch the authenticated user
        token_instance = Token.objects.get(key=token)
        user_instance = token_instance.user  # Authenticated user
        user_id = user_instance.id
    except Token.DoesNotExist:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or expired token.")

    # Combine form data without expecting user_id in the payload
    form = GlobalChatForm(request.data)

    user = User.objects.get(user_id=user_id)

    if not user:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")

    try:
        if form.is_valid():
            # Save the message with the authenticated user
            global_chat_obj = form.save(commit=False)
            global_chat_obj.user_id = user  # Assign authenticated user
            global_chat_obj.save()

            return APIResponse.HTTP_200_OK(
                message="Message sent successfully.",
                data={
                    "id": global_chat_obj.id,
                    "user": global_chat_obj.user_id.user_id.username,  # Replace with preferred user field
                    "message_content": global_chat_obj.message_content,
                    "is_pinned": global_chat_obj.is_pinned,
                    "created_at": global_chat_obj.global_chat_created_at,
                },
            )
        else:
            # Handle form validation errors
            return APIResponse.HTTP_400_BAD_REQUEST(
                message="Invalid form data.",
                data=form.errors
            )
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(
            message=f"An unexpected error occurred: {str(e)}"
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def agent_chat_users(request):
    """
    Retrieve the complete chat history between the authenticated user and agents.
    """
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin", "Agent"]

    # Verify user role
    try:
        current_user = User.objects.get(user_id=user_instance.id)
        role = getattr(current_user.role_id, "roles", None)
        if role not in allowed_roles:
            return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")
    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")

    # Fetch all chat history ordered by the latest timestamp
    chat_history = AgentChat.objects.all().order_by('-agent_chat_created_at')

    if not chat_history.exists():
        return APIResponse.HTTP_404_NOT_FOUND(message="No chat history found.")

    try:
        # Group conversations by agent and user
        grouped_chats = defaultdict(lambda: {"agent_details": None, "conversations": []})

        for chat in chat_history:
            # Determine the agent and user
            agent = (
                chat.user_id if getattr(chat.user_id.role_id, "roles", None) == "Agent" else chat.agent_id
            )
            if not agent:
                continue

            # Add agent details if not already added
            if not grouped_chats[agent.user_id.username]["agent_details"]:
                grouped_chats[agent.user_id.username]["agent_details"] = {
                    "id": agent.id,
                    "first_name": agent.first_name,
                    "last_name": agent.last_name,
                    "username": agent.user_id.username,
                    "status": chat.status,
                    "email": agent.email,
                    "profile_image": f"{settings.HOST}{agent.profile_image.url}" if agent.profile_image else None,
                    "role": getattr(agent.role_id, "roles", None),
                }

            # Add the conversation details
            sender_username = chat.user_id.user_id.username if chat.user_id else "System"
            receiver_username = chat.agent_id.user_id.username if chat.agent_id else "System"

            # Grouping conversations based on user
            if sender_username != user_instance.username:
                grouped_chats[sender_username]["conversations"].append({
                    'sender': sender_username,
                    'receiver': receiver_username,
                    'message': chat.message_content,
                    'status': chat.status,
                    'is_agent_send': chat.is_agent_send,
                    'created_at': time_ago(chat.agent_chat_created_at.strftime('%Y-%m-%d %H:%M:%S')),
                })

        # Format the response
        chat_data = [
            {
                'agent_details': details["agent_details"],
                'conversations': details["conversations"]
            }
            for details in grouped_chats.values()
        ]

        return APIResponse.HTTP_200_OK(
            message="Chat history between users and agents retrieved successfully.",
            data=chat_data
        )
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(
            message=f"An unexpected error occurred: {str(e)}"
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def get_admin_and_agent_chat_history(request):
    """
    Retrieve the chat history between a specific user and an agent.
    """
    try:
        # Authenticate and fetch the user
        user_instance = AuthService.get_user_from_token(request)
        if not user_instance:
            return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

        # Allowed roles
        allowed_roles = ["Admin", "Agent"]

        # Get the current user and validate role
        current_user = User.objects.get(user_id=user_instance.id)
        role = getattr(current_user.role_id, "roles", None)
        if role not in allowed_roles:
            return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")

        # Extract agent_id and user_id from request data
        agent_id = request.data.get("agent_id")
        user_id = request.data.get("user_id")

        if not agent_id or not user_id:
            return APIResponse.HTTP_400_BAD_REQUEST(message="Both 'agent_id' and 'user_id' are required.")

        # Fetch the specific user and agent instances
        try:
            agent = User.objects.get(id=agent_id, role_id__roles="Agent")
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return APIResponse.HTTP_404_NOT_FOUND(message="Agent or User not found.")

        # Fetch chat history where the user and agent are involved
        chat_history = AgentChat.objects.filter(
            (Q(agent_id=agent, user_id=user) | Q(user_id=user, agent_id=agent))
        ).order_by('agent_chat_created_at')

        if not chat_history.exists():
            return APIResponse.HTTP_404_NOT_FOUND(message="No chat history found between the specified user and agent.")

        # Prepare the chat history
        chat_data = [
            {
                'sender': chat.user_id.user_id.username if chat.user_id else "System",
                'receiver': chat.agent_id.user_id.username if chat.agent_id else "System",
                'message_content': chat.message_content,
                'attachment_image': chat.attachment_image.url if chat.attachment_image else None,
                'status': chat.status,
                'created_at': chat.agent_chat_created_at.strftime('%Y-%m-%d %H:%M:%S'),
            }
            for chat in chat_history
        ]

        return APIResponse.HTTP_200_OK(
            message="Chat history between the specified user and agent retrieved successfully.",
            data=chat_data
        )

    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(
            message=f"An unexpected error occurred: {str(e)}"
        )


## Chat Management System - APIs Completed


############################################################################################################


# Reviews Management System

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_reviews(request):
    """
    Retrieve all games with their reviews (if any), including user details and admin replies, supporting pagination.
    """
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin", "Agent", "User"]
    user = get_object_or_404(User, user_id=user_instance.id)

    # Validate the user's role
    role = getattr(user.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")

    page = int(request.query_params.get('page', 1))
    limit = int(request.query_params.get('limit', 20))

    try:
        games = Game.objects.order_by('-game_created_at').all()
        if not games.exists():
            return APIResponse.HTTP_404_NOT_FOUND(message="No games found.")

        response_data = []

        for game in games:
            game_reviews = GameReview.objects.filter(game_id=game).order_by('-review_posted_at')

            total_reviews = game_reviews.count()
            average_rating = game_reviews.aggregate(avg_rating=Avg('ratings'))['avg_rating'] or 0.0
            total_ratings = game_reviews.aggregate(total_rating=Sum('ratings'))['total_rating'] or 0

            start = (page - 1) * limit
            end = start + limit
            paginated_reviews = game_reviews[start:end]

            reviews_data = []
            for review in paginated_reviews:
                admin_reply = None
                if review.admin_replies_id:
                    admin_reply = {
                        'id': str(review.admin_replies_id.id),
                        'message_content': review.admin_replies_id.message_content,
                        'reply_posted_at': review.admin_replies_id.reply_posted_at.isoformat(),
                    }

                reviews_data.append({
                    'review_id': str(review.id),
                    'message_content': review.message_content,
                    'ratings': review.ratings,
                    'helpful_counter': review.helpful_counter,
                    'review_posted_at': review.review_posted_at.isoformat(),
                    'review_sent_by_user': review.user_id.to_dict(),
                    "is_admin_reply": review.admin_replies_id is not None,
                    'admin_reply': admin_reply,
                })

            response_data.append({
                "game_id": str(game.id),
                "game_name": game.game_name,
                "game_created_at": game.game_created_at.isoformat(),
                "reviews": reviews_data if reviews_data else None,
                "total_reviews": total_reviews,
                "average_rating": round(average_rating, 2),  # Rounded for better readability
                "total_ratings": total_ratings,
                "pagination": {
                    "page": page,
                    "limit": limit,
                    "total": total_reviews,
                }
            })

        return APIResponse.HTTP_200_OK(message="Game reviews retrieved successfully.", data=response_data)

    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_reviews_game_id(request):
    """
    Retrieve all game reviews with user details, associated games, and admin replies (if any), supporting pagination.
    """

    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    allowed_roles = ["Admin", "Agent", "User"]
    user = get_object_or_404(User, user_id=user_instance.id)

    role = getattr(user.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")

    page = int(request.query_params.get('page', 1))
    limit = int(request.query_params.get('limit', 20))
    game_id = request.query_params.get('game_id')

    try:
        game = Game.objects.filter(id=game_id).first()
        if not game:
            return APIResponse.HTTP_404_NOT_FOUND(message="Game not found.")

        game_reviews = GameReview.objects.filter(game_id=game.id).all().order_by('-review_posted_at')
        start = (page - 1) * limit
        end = start + limit
        paginated_reviews = game_reviews[start:end]

        reviews_data = []
        for review in paginated_reviews:
            helpful_reviews = ReviewHelpFull.objects.select_related('review_id').filter(review_id=review.id).all()
            not_helpful_reviews = ReviewNotHelpFull.objects.select_related('review_id').filter(
                review_id=review.id).all()

            helpful_reviews_data = [
                {
                    'id': str(review.id),
                    'helpful_review_sender': review.user_id.to_dict() if review.user_id else None,
                    'helpful_review_receiver': review.review_id.to_dict() if review.review_id else None,
                }
                for review in helpful_reviews
            ]

            not_helpful_reviews_data = [
                {
                    'id': str(review.id),
                    'not_helpful_review_sender': review.user_id.to_dict() if review.user_id else None,
                    'not_helpful_review_receiver': review.review_id.to_dict() if review.review_id else None,
                }
                for review in not_helpful_reviews
            ]

            helpful_replies = ReplyHelpFull.objects.filter(
                reply_id=review.admin_replies_id).all() if review.admin_replies_id else []
            not_helpful_replies = ReplyNotHelpFull.objects.filter(
                reply_id=review.admin_replies_id).all() if review.admin_replies_id else []

            helpful_replies_data = [
                {
                    'id': str(reply.id),
                    'helpful_reply_sender': reply.user_id.to_dict() if reply.user_id else None,
                    'helpful_reply_receiver': reply.reply_id.to_dict() if reply.reply_id else None,
                }
                for reply in helpful_replies
            ]

            not_helpful_replies_data = [
                {
                    'id': str(reply.id),
                    'not_helpful_reply_sender': reply.user_id.to_dict() if reply.user_id else None,
                    'not_helpful_reply_receiver': reply.reply_id.to_dict() if reply.reply_id else None,
                }
                for reply in not_helpful_replies
            ]

            reviews_data.append({
                'review_id': review.id,
                'message_content': review.message_content,
                'ratings_by': [
                    {
                        "user_id": str(rating.user.id),
                        "ratings": rating.rating,
                        "is_yes": rating.is_yes,
                    } for rating in review.ratings_data.all()  # Fetch from the through model
                ],
                'helpful_counter': review.helpful_counter,

                'total_helpful_reviews': helpful_reviews.count(),
                'helpful_reviews': helpful_reviews_data,
                'total_not_helpful_reviews': not_helpful_reviews.count(),
                'not_helpful_reviews': not_helpful_reviews_data,

                'review_posted_at': humanize.naturaltime(review.review_posted_at),
                'review_sent_by_user': review.user_id.to_dict(),

                "is_admin_reply": review.admin_replies_id is not None,

                "admin_reply": {
                    'total_helpful_reply_users': len(helpful_replies) if helpful_replies else 0,
                    'helpful_reply_users': helpful_replies_data,
                    'total_not_helpful_reply_users': len(not_helpful_replies) if not_helpful_replies else 0,
                    'not_helpful_reply_users': not_helpful_replies_data,
                    "admin_reply_details": review.admin_replies_id.to_dict() if review.admin_replies_id else None,
                } if review.admin_replies_id else None
            })

        response_data = {
            "total_reviews": game_reviews.count() + game_reviews.filter(admin_replies_id__isnull=False).count(),
            # Total reviews + admin replies
            "average_rating": round(game_reviews.aggregate(Avg('ratings'))['ratings__avg'] or 0, 2),
            "total_ratings": round(game_reviews.aggregate(Sum('ratings'))['ratings__sum'] or 0, 2),

            "game_id": str(game.id),
            "game_name": game.game_name,
            "game_created_at": game.game_created_at,
            "reviews": reviews_data,
            "pagination": {
                "page": page,
                "limit": limit,
                "total": game_reviews.count(),
            }
        }

        return APIResponse.HTTP_200_OK(message="Game reviews retrieved successfully.", data=response_data)

    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def post_game_review(request):
    """
    Retrieve all game reviews with user details, supporting pagination.
    """
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin", "Agent", "User"]

    user = get_object_or_404(User, user_id=user_instance.id)

    # Validate the user's role
    role = getattr(user.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")

    game_id = request.data.get('game_id')
    game = Game.objects.filter(id=game_id).first()

    form = GameReviewForm(request.data)
    # print(f"""form data: {form.data}""")
    if not form.is_valid():
        return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid form data.")
    try:
        data = form.save(commit=False)
        data.user_id = user
        data.game_id = game
        data.save()

        return APIResponse.HTTP_200_OK(message="Game reviews posted successfully.", data=form.data)
    except Game.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="Game not found.")
    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def toggle_review_helpfulness(request):
    """
    Allows a user to mark a review as helpful or not helpful.
    If the user has already marked it, it will be removed.
    If the user marks one type, the other type is removed automatically.
    """
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    allowed_roles = ["Admin", "Agent", "User"]
    user = get_object_or_404(User, user_id=user_instance.id)

    role = getattr(user.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")

    review_id = request.query_params.get('review_id')
    action = request.query_params.get('action')  # 'helpful' or 'not_helpful'

    if action not in ["helpful", "not_helpful"]:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid action. Choose either 'helpful' or 'not_helpful'.")

    review = GameReview.objects.filter(id=review_id).first()
    if not review:
        return APIResponse.HTTP_404_NOT_FOUND(message="Review not found.")

    try:
        # Remove the opposite action if it exists
        if action == "helpful":
            ReviewNotHelpFull.objects.filter(review_id=review, user_id=user).delete()
            existing_helpful = ReviewHelpFull.objects.filter(review_id=review, user_id=user).first()
            if existing_helpful:
                existing_helpful.delete()
                return APIResponse.HTTP_200_OK(message="You have removed your helpful mark.", data={
                    'review_id': review.id,
                    'total_helpful_reviews': review.review_help_full.count(),  # Use the related name in lowercase
                    'total_not_helpful_reviews': review.review_not_help_full.count(),
                    # Use the related name in lowercase
                })
            else:
                return APIResponse.HTTP_200_OK(message="You have marked this review as helpful.", data={
                    'review_id': review.id,
                    'total_helpful_reviews': review.review_help_full.count(),  # Use the related name in lowercase
                    'total_not_helpful_reviews': review.review_not_help_full.count(),
                    # Use the related name in lowercase
                })

        elif action == "not_helpful":
            ReviewHelpFull.objects.filter(review_id=review, user_id=user).delete()
            existing_not_helpful = ReviewNotHelpFull.objects.filter(review_id=review, user_id=user).first()
            if existing_not_helpful:
                existing_not_helpful.delete()
                return APIResponse.HTTP_200_OK(message="You have removed your not helpful mark.", data={
                    'review_id': review.id,
                    'total_helpful_reviews': review.review_help_full.count(),  # Use the related name in lowercase
                    'total_not_helpful_reviews': review.review_not_help_full.count(),
                    # Use the related name in lowercase
                })
            else:
                return APIResponse.HTTP_200_OK(message="You have marked this review as not helpful.", data={
                    'review_id': review.id,
                    'total_helpful_reviews': review.review_help_full.count(),  # Use the related name in lowercase
                    'total_not_helpful_reviews': review.review_not_help_full.count(),
                    # Use the related name in lowercase
                })

    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def toggle_reply_helpfulness(request):
    """
    Allows a user to mark a reply as helpful or not helpful.
    If the user has already marked it, it will be removed.
    If the user marks one type, the other type is removed automatically.
    """
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    allowed_roles = ["Admin", "Agent", "User"]
    user = get_object_or_404(User, user_id=user_instance.id)

    role = getattr(user.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")

    reply_id = request.query_params.get('reply_id')
    action = request.query_params.get('action')  # 'helpful' or 'not_helpful'

    if action not in ["helpful", "not_helpful"]:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid action. Choose either 'helpful' or 'not_helpful'.")

    reply = AdminReply.objects.filter(id=reply_id).first()
    if not reply:
        return APIResponse.HTTP_404_NOT_FOUND(message="Reply not found.")

    try:
        # Remove the opposite action if it exists
        if action == "helpful":
            ReplyNotHelpFull.objects.filter(reply_id=reply, user_id=user).delete()
            existing_helpful = ReplyHelpFull.objects.filter(reply_id=reply, user_id=user).first()
            if existing_helpful:
                existing_helpful.delete()
                return APIResponse.HTTP_200_OK(message="You have removed your helpful mark.", data={
                    'reply_id': reply.id,
                    'total_helpful_replies': reply.reply_help_full.count(),  # Use the related name in lowercase
                    'total_not_helpful_replies': reply.reply_not_help_full.count(),  # Use the related name in lowercase
                })
            else:
                return APIResponse.HTTP_200_OK(message="You have marked this reply as helpful.", data={
                    'reply_id': reply.id,
                    'total_helpful_replies': reply.reply_help_full.count(),  # Use the related name in lowercase
                    'total_not_helpful_replies': reply.reply_not_help_full.count(),  # Use the related name in lowercase
                })

        elif action == "not_helpful":
            ReplyHelpFull.objects.filter(reply_id=reply, user_id=user).delete()
            existing_not_helpful = ReplyNotHelpFull.objects.filter(reply_id=reply, user_id=user).first()
            if existing_not_helpful:
                existing_not_helpful.delete()
                return APIResponse.HTTP_200_OK(message="You have removed your not helpful mark.", data={
                    'reply_id': reply.id,
                    'total_helpful_replies': reply.reply_help_full.count(),  # Use the related name in lowercase
                    'total_not_helpful_replies': reply.reply_not_help_full.count(),  # Use the related name in lowercase
                })
            else:
                return APIResponse.HTTP_200_OK(message="You have marked this reply as not helpful.", data={
                    'reply_id': reply.id,
                    'total_helpful_replies': reply.reply_help_full.count(),  # Use the related name in lowercase
                    'total_not_helpful_replies': reply.reply_not_help_full.count(),  # Use the related name in lowercase
                })
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_game_review(request):
    """
    Delete a game review based on user_id, game_id, and review_id.
    """

    print(f"request: {request}")

    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin", "Agent", "User"]

    auth_user = get_object_or_404(User, user_id=user_instance.id)

    # Validate the user's role
    role = getattr(auth_user.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")

    # Retrieve data from request body
    review_id = request.query_params.get('review_id')

    # Validate required fields
    if not all([review_id]):
        return APIResponse.HTTP_400_BAD_REQUEST(
            message="Missing required parameters: review_id.")

    # Fetch the review
    review = get_object_or_404(GameReview, id=review_id)
    print(f"review: {review}")

    if review is None:
        return APIResponse.HTTP_404_NOT_FOUND(
            message="Game review not found or you don't have permission to delete it.")

    try:
        data = {
            'review': {
                'review_id': review.id,
                'message_content': review.message_content,
            }
        }

        # Delete the review
        review.delete()

        return APIResponse.HTTP_200_OK(message="Review deleted successfully.", data=data)
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_game_review_ratings(request):
    """
    Update the ratings or helpful counter of a game review.
    """
    token = request.COOKIES.get('token') or request.headers.get('Authorization', '').split(' ')[-1]
    if not token:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Authentication token is missing.")

    try:
        user_id = Token.objects.get(key=token).user.id  # Logged-in user only
        user = User.objects.filter(user_id=user_id).first()
        if not user:
            return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
    except Token.DoesNotExist:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or expired token.")

    review_id, ratings, is_yes = request.data.get('review_id'), request.data.get('ratings'), bool(
        request.data.get('is_yes'))
    if not review_id:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Missing required parameter: review_id.")

    review = GameReview.objects.filter(id=review_id).first()
    if not review:
        return APIResponse.HTTP_404_NOT_FOUND(message="Game review not found with the provided review_id.")

    if user == review.user_id:
        return APIResponse.HTTP_400_BAD_REQUEST(message="You have already rated this game review.")

    try:
        review.is_yes = is_yes

        # Update helpful counter
        if is_yes:
            review.helpful_counter += 1
        elif review.helpful_counter > 0:
            review.helpful_counter -= 1
        else:
            review.helpful_counter = 0  # Ensure it stays at 0 if decrementing from 0

        # Handle ratings if provided
        if ratings:
            try:
                review.ratings += Decimal(str(ratings))
            except (ValueError, TypeError):
                return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid ratings value.")

        # Add the current user to the user
        review.user_id = user
        review.save()

        return APIResponse.HTTP_200_OK(
            message="Game review ratings updated successfully.",
            data={
                'review_id': review.id,
                'message_content': review.message_content,
                'ratings': str(review.ratings),
                'helpful_counter': review.helpful_counter,
                'is_yes': review.is_yes,
                'rated_by_users': review.user_id.to_dict() if review.user_id else None
            }
        )
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def post_admin_reply(request):
    """
    Post an admin reply to a game review.
    """
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin", "Agent"]

    try:
        user = User.objects.get(user_id=user_instance.id)
    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")

    # Validate the user's role
    role = getattr(user.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")

    game_review_id = request.data.get('game_review_id')
    review = GameReview.objects.filter(id=game_review_id).first()

    if not review:
        return APIResponse.HTTP_404_NOT_FOUND(message="Game review not found.")
    print(f"review: {review}")

    form = AdminReplyForm(request.data)
    if not form.is_valid():
        return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid form data.", data=form.errors)
    print(f"form: {form}")

    try:
        if form.is_valid():
            data = form.save(commit=False)
            data.admin_id = user
            data.game_review_id = review
            data.save()

            # **Link the admin reply to the GameReview**
            review.admin_replies_id = data
            review.save()

            return APIResponse.HTTP_200_OK(message="Admin reply posted successfully.", data=data.to_dict())

    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['GET'])
def get_admin_replies(_):
    """
    Retrieve all game reviews that have corresponding admin replies, structured appropriately.
    """
    try:
        # Fetch all game reviews
        game_reviews = GameReview.objects.select_related('user_id__user_id').all()

        # Fetch all admin replies
        admin_replies = AdminReply.objects.select_related('admin_id__user_id').all()

        # Map admin replies to their corresponding IDs
        admin_replies_map = {
            reply.id: {
                "id": reply.id,
                "game_review_sent_by": reply.admin_id.user_id.username,
                "message_content": reply.message_content,
                "helpful_counter": reply.helpful_counter,
                "reply_posted_at": reply.reply_posted_at,
            }
            for reply in admin_replies
        }

        # Serialize game reviews and include associated admin replies
        reviews_data = [
            {
                "admin_reply": {
                    **admin_replies_map[review.admin_replies_id.id],
                    "admin_reply_to": {
                        "id": review.id,
                        "player": review.user_id.user_id.username,
                        "message_content": review.message_content,
                        "ratings": review.ratings,
                        "helpful_counter": review.helpful_counter,
                        "review_posted_at": review.review_posted_at,
                    },
                }
            }
            for review in game_reviews if review.admin_replies_id and review.admin_replies_id.id in admin_replies_map
        ]

        if not reviews_data:
            return APIResponse.HTTP_200_OK(
                message="No admin replies found for any game reviews.", data=[]
            )

        return APIResponse.HTTP_200_OK(
            message="Admin replies with related game reviews retrieved successfully.",
            data=reviews_data,
        )
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(
            message=f"An unexpected error occurred: {str(e)}"
        )


@api_view(['PUT'])
def update_admin_reply(request):
    """
    Update an existing admin reply by its ID.
    """
    try:
        # Get the reply ID from the request data
        admin_reply_id_pk = request.data.get('id')
        if not admin_reply_id_pk:
            return APIResponse.HTTP_400_BAD_REQUEST(message="Admin reply ID is required.")

        # Fetch the admin reply to be updated
        try:
            admin_reply = AdminReply.objects.get(id=admin_reply_id_pk)
        except AdminReply.DoesNotExist:
            return APIResponse.HTTP_404_NOT_FOUND(message="Admin reply not found.")

        # Use the form to validate and update the admin reply
        form = AdminReplyForm(request.data, instance=admin_reply)
        if form.is_valid():
            form.save()
            return APIResponse.HTTP_200_OK(
                message="Admin reply updated successfully.",
                data={
                    "id": admin_reply.id,
                    "admin_id": admin_reply.admin_id.id,
                    "message_content": admin_reply.message_content,
                    "helpful_counter": admin_reply.helpful_counter,
                    "reply_posted_at": admin_reply.reply_posted_at,
                },
            )
        else:
            return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid form data.", data=form.errors)

    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_admin_reply(request):
    """
    Retrieve all game reviews with user details, supporting pagination.
    """

    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin", "Agent", "User"]

    try:
        user = User.objects.get(user_id=user_instance.id)
    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")

    # Validate the user's role
    role = getattr(user.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")

    pk_id = request.query_params.get('id')

    if not pk_id:
        return APIResponse.HTTP_404_NOT_FOUND(message="Admin reply ID is required.")

    admin_reply = AdminReply.objects.filter(id=pk_id).first()

    if not admin_reply:
        return APIResponse.HTTP_404_NOT_FOUND(message="Admin reply not found.")

    try:

        data = {
            "id": admin_reply.id,
            "admin_id": admin_reply.admin_id.id,
            "message_content": admin_reply.message_content,
            "helpful_counter": admin_reply.helpful_counter,
            "reply_posted_at": admin_reply.reply_posted_at
        }

        admin_reply.delete()

        return APIResponse.HTTP_200_OK(message="Admin reply deleted successfully.", data=data)
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


# Reviews Management System

############################################################################################################

@api_view(['GET'])
def get_available_games(_):
    """
    Retrieve all available games.
    """
    try:
        # Fetch all games from the Game model
        available_games = Game.objects.order_by('-game_created_at').all()

        # Serialize the data manually or use a serializer
        games_data = [
            {
                "id": str(game.id),
                "game_id": game.game_id,
                "game_name": game.game_name,
                "game_description": game.game_description,
                "game_image": f"{settings.HOST}{game.game_image.url}" if game.game_image else None,
                "game_video": f"{settings.HOST}{game.game_video.url}" if game.game_video else None,
                "game_price": game.game_price,
                "android_game_url": game.android_game_url,
                "ios_game_url": game.ios_game_url,
                "browser_game_url": game.browser_game_url,
                "upcoming_status": game.upcoming_status,
                "transfer_score_percentage": game.transfer_score_percentage,
                "redeem_score_percentage": game.redeem_score_percentage,
                "free_scores": game.free_scores,
                "is_free": game.is_free,
                "is_banned": game.is_active,
                "country_name": ", ".join([country.country for country in game.country.all()]),
                # Convert list to string
            }
            for game in available_games
        ]

        return APIResponse.HTTP_200_OK(message="Available games retrieved successfully.", data=games_data)
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['GET'])
def get_available_games_unblocked(_):
    """
    Retrieve all available games that are not blocked.
    """
    try:
        # Fetch all games from the Game model excluding blocked ones
        available_games = Game.objects.order_by('-game_created_at').exclude(is_active=True).all()

        # Serialize the data manually or use a serializer
        games_data = [
            {
                "id": str(game.id),
                "game_id": game.game_id,
                "game_name": game.game_name,
                "game_description": game.game_description,
                "game_image": f"{settings.HOST}{game.game_image.url}" if game.game_image else None,
                "game_video": f"{settings.HOST}{game.game_video.url}" if game.game_video else None,
                "game_price": game.game_price,
                "android_game_url": game.android_game_url,
                "ios_game_url": game.ios_game_url,
                "browser_game_url": game.browser_game_url,
                "upcoming_status": game.upcoming_status,
                "transfer_score_percentage": game.transfer_score_percentage,
                "redeem_score_percentage": game.redeem_score_percentage,
                "free_scores": game.free_scores,
                "is_free": game.is_free,
                "country_name": ", ".join([country.country for country in game.country.all()]),
                # Convert list to string
            }
            for game in available_games
        ]

        return APIResponse.HTTP_200_OK(message="Available unblocked games retrieved successfully.", data=games_data)
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_available_games_by_admin_and_agent_tokens(request):
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin", "Agent"]

    user = get_object_or_404(User, user_id=user_instance.id)

    # Validate the user's role
    role = getattr(user.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")

    # Fetch all games from the Game model
    available_games = Game.objects.filter(created_by_user_id=user).all()
    if available_games is None:
        return APIResponse.HTTP_404_NOT_FOUND(message="Available games not found for the user.")

    try:

        # Serialize the data manually or use a serializer
        games_data = [
            {
                "id": str(game.id),
                "game_id": game.game_id,
                "game_name": game.game_name,
                "game_description": game.game_description,
                "game_image": f"{settings.HOST}{game.game_image.url}" if game.game_image else None,
                "game_video": f"{settings.HOST}{game.game_video.url}" if game.game_video else None,
                "game_price": game.game_price,
                "android_game_url": game.android_game_url,
                "ios_game_url": game.ios_game_url,
                "browser_game_url": game.browser_game_url,
                "upcoming_status": game.upcoming_status,
                "transfer_score_percentage": game.transfer_score_percentage,
                "redeem_score_percentage": game.redeem_score_percentage,
                "free_scores": game.free_scores,
                "is_free": game.is_free,
                "countries": [country.country for country in game.country.all()],
            }
            for game in available_games
        ]

        return APIResponse.HTTP_200_OK(message="Available games retrieved successfully.", data=games_data)
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['GET'])
def get_all_free_games(_):
    """
    Retrieve all available games.
    """
    try:
        # Fetch all games from the Game model
        available_games = Game.objects.filter(is_free=True).all()

        # Serialize the data manually or use a serializer
        games_data = [
            {
                "id": str(game.id),
                "game_id": game.game_id,
                "game_name": game.game_name,
                "game_description": game.game_description,
                "game_image": game.game_image.url if game.game_image else None,
                "game_video": game.game_video.url if game.game_video else None,
                "game_price": game.game_price,
                "android_game_url": game.android_game_url,
                "ios_game_url": game.ios_game_url,
                "browser_game_url": game.browser_game_url,
                "upcoming_status": game.upcoming_status,
                "transfer_score_percentage": game.transfer_score_percentage,
                "redeem_score_percentage": game.redeem_score_percentage,
                "free_scores": game.free_scores,
                "is_free": game.is_free,
                "countries": [country.country for country in game.country.all()],
            }
            for game in available_games
        ]

        return APIResponse.HTTP_200_OK(message="Free games retrieved successfully.", data=games_data)
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['GET'])
def get_trending_games(_):
    """
    Retrieve all available games.
    """
    try:
        # Fetch all games from the Game model
        available_games = Game.objects.filter(is_trending=True)

        # Serialize the data manually or use a serializer
        games_data = [
            {
                "id": str(game.id),
                "game_id": game.game_id,
                "game_name": game.game_name,
                "game_description": game.game_description,
                "game_image": game.game_image.url if game.game_image else None,
                "game_video": game.game_video.url if game.game_video else None,
                "game_price": game.game_price,
                "android_game_url": game.android_game_url,
                "ios_game_url": game.ios_game_url,
                "browser_game_url": game.browser_game_url,
                "upcoming_status": game.upcoming_status,
                "transfer_score_percentage": game.transfer_score_percentage,
                "redeem_score_percentage": game.redeem_score_percentage,
                "countries": [country.country for country in game.country.all()],
            }
            for game in available_games
        ]

        return APIResponse.HTTP_200_OK(message="Trending games retrieved successfully.", data=games_data)
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['GET'])
def get_upcoming_games(request):
    """
        This function retrieves all upcoming games.
        Args:
                request (HTTPRequest): The request object.
        Returns:
            1.
                {
                    "status": 200,
                    "message": "Upcoming games retrieved successfully.",
                    "data": [
                        {
                            "id": "346d4284-368d-4dca-8825-ed0d93181910",
                            "game_id": "PUBG1B2B3B5",
                            "game_name": "PUBG",
                            "game_description": "amazing game",
                            "game_image": "/media/default-game.jpg",
                            "game_video": "/media/game_videos/Screenshot_2024-12-20_160823.png",
                            "game_price": 600,
                            "android_game_url": "https://www.veed.io/edit/933b0227-43ec-4ada-b45a-0d09d145b850/convert?
                                                source=%2Fconvert%2Fvideo-converter",
                            "ios_game_url": "https://www.veed.io/edit/933b0227-43ec-4ada-b45a-0d09d145b850/convert?
                                                source=%2Fconvert%2Fvideo-converter",
                            "browser_game_url": "https://www.veed.io/edit/933b0227-43ec-4ada-b45a-0d09d145b850/convert?
                                                source=%2Fconvert%2Fvideo-converter",
                            "upcoming_status": true,
                            "transfer_score_percentage": 0,
                            "redeem_score_percentage": 0,
                            "countries": []
                        }
                    ]
                }
            2.
                {
                    "status": 404,
                    "message": "Upcoming games not found."
                }
    """

    available_games = Game.objects.filter(upcoming_status=True)
    # ---------------------------------------- validating parameters ------------------
    if not available_games:
        return APIResponse.HTTP_404_NOT_FOUND(message="Upcoming games not found.")
    # ------------------------------------------ validating completed ------------------

    games_data = [
        {
            "id": str(game.id),
            "game_id": game.game_id,
            "game_name": game.game_name,
            "game_description": game.game_description,
            "game_image": request.build_absolute_uri(game.game_image.url) if game.game_image else None,
            "game_video": request.build_absolute_uri(game.game_video.url) if game.game_video else None,
            "game_price": game.game_price,
            "android_game_url": game.android_game_url,
            "ios_game_url": game.ios_game_url,
            "browser_game_url": game.browser_game_url,
            "upcoming_status": game.upcoming_status,
            "transfer_score_percentage": game.transfer_score_percentage,
            "redeem_score_percentage": game.redeem_score_percentage,
            "countries": [country.country for country in game.country.all()],
            "gradient_style": game.gradient_style,
        }
        for game in available_games
    ]
    return APIResponse.HTTP_200_OK(message="Upcoming games retrieved successfully.", data=games_data)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def add_game(request):
    """
    Add a new game.
    """
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin"]
    user_instance = get_object_or_404(User, user_id=user_instance.id)

    # Validate the user's role
    role = getattr(user_instance.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")

    form = GameForm(request.POST, request.FILES)

    try:
        if form.is_valid():
            # Create the game instance without saving to the database
            game_instance = form.save(commit=False)
            game_instance.created_by_user_id = user_instance

            # Fetch the country instance from request data
            country_name = request.POST.get("country_name")
            country_instance = Country.objects.filter(country=country_name).first()

            if not country_instance:
                return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid country name provided.")

            game_instance.save()  # Save the game instance to the database

            # Assign the country to the ManyToManyField
            game_instance.country.set([country_instance])  # Use set() for ManyToManyField
            game_instance.save()

            game = Game.objects.filter(game_id=game_instance.game_id).first()
            if not game:
                return APIResponse.HTTP_400_BAD_REQUEST(message="Game not found.")

            return APIResponse.HTTP_200_OK(message="Game added successfully.", data=game.to_dict())
        else:
            return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid form data.", data=form.errors)
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def add_game_rating(request):
    """
    Add or update a game rating (1.0 to 10.0).
    """
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    allowed_roles = ["Admin", "User", "Agent"]
    user_instance = get_object_or_404(User, user_id=user_instance.id)

    role = getattr(user_instance.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")

    form = GameRatingForm(request.data)  # Use request.data for better handling of JSON

    try:
        if form.is_valid():
            rating_value = form.cleaned_data['rating']
            game_instance = form.cleaned_data['game_id']

            # Ensure rating range is between 1.0 and 10.0 (inclusive)
            if rating_value < 1.0 or rating_value > 10.0:
                return APIResponse.HTTP_400_BAD_REQUEST(message="Rating must be between 1.0 and 10.0.")

            # Check if the user has already rated the game
            game_rating_instance = GameRating.objects.filter(game_id=game_instance, user_id=user_instance).first()

            if game_rating_instance:
                # Decrement case: If the user wants to remove their rating
                if rating_value == 0:
                    # Remove the rating
                    game_rating_instance.delete()

                    # Update total ratings and average rating for the game
                    total_ratings = GameRating.objects.filter(game_id=game_instance).count()
                    average_rating = GameRating.objects.filter(game_id=game_instance).aggregate(Avg('rating'))[
                        'rating__avg']

                    # Update game instance with total and average ratings
                    game_instance.total_ratings = total_ratings
                    game_instance.average_rating = average_rating
                    game_instance.save()

                    return APIResponse.HTTP_200_OK(message="Rating removed successfully.",
                                                   data=game_rating_instance.to_dict())

                else:
                    # Update existing rating
                    game_rating_instance.rating = rating_value
                    game_rating_instance.save()

                    # Update total ratings and average rating for the game
                    total_ratings = GameRating.objects.filter(game_id=game_instance).count()
                    average_rating = GameRating.objects.filter(game_id=game_instance).aggregate(Avg('rating'))[
                        'rating__avg']

                    # Update game instance with total and average ratings
                    game_instance.total_ratings = total_ratings
                    game_instance.average_rating = average_rating
                    game_instance.save()

                    return APIResponse.HTTP_200_OK(message="Rating updated successfully.",
                                                   data=game_rating_instance.to_dict())
            else:
                # Add new rating
                game_instance = form.save(commit=False)
                game_instance.user_id = user_instance
                game_instance.save()

                # Increment total ratings and update average rating
                total_ratings = GameRating.objects.filter(game_id=game_instance.game_id).count()
                average_rating = GameRating.objects.filter(game_id=game_instance.game_id).aggregate(Avg('rating'))[
                    'rating__avg']

                # Update game instance with total and average ratings
                game_instance.game_id.total_ratings = total_ratings
                game_instance.game_id.average_rating = average_rating
                game_instance.game_id.save()

                return APIResponse.HTTP_200_OK(message="Rating added successfully.", data=game_instance.to_dict())

        else:
            return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid form data.", data=form.errors)
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")

@api_view(['GET'])
def get_game_rating(request):
    """
    Get a list of game ratings with pagination and optional filtering by rating_id.
    """
    # Retrieve query parameters for filtering and pagination
    rating_id = request.query_params.get('rating_id', None)

    # Ensure game_ratings is always a queryset
    if rating_id:
        game_ratings = GameRating.objects.filter(id=rating_id)  # ✅ Keep as a queryset
    else:
        game_ratings = GameRating.objects.all()

    if not game_ratings.exists():  # ✅ Check if queryset is empty
        return APIResponse.HTTP_404_NOT_FOUND(message="No game ratings found.")

    try:
        to_dict = [game_rating.to_dict() for game_rating in game_ratings]
        print(f"to_dict: {to_dict}")

        for game_rating in to_dict:
            game = Game.objects.filter(id=game_rating['game_id']).first()
            if game:
                game_rating['game_name'] = game.game_name

        # Prepare the game data
        game_data = [
            {
                "total_reviews": game.game_reviews_id.count(),
                "game_ratings_count": game_ratings.count(),
                "average_rating": game_ratings.aggregate(average_rating=Avg('rating'))['average_rating'] or 0,
                "total_ratings": game_ratings.aggregate(total_ratings=Sum('rating'))['total_ratings'] or 0,
                "game_ratings_average": game_ratings.aggregate(average_rating=Avg('rating'))['average_rating'] or 0,
                "game_ratings_total": game_ratings.aggregate(total_ratings=Sum('rating'))['total_ratings'] or 0,
                **game.to_dict(),
            }
        ]

        data = {
            "games": game_data,
            "game_ratings": to_dict,
            "total_ratings": game_ratings.aggregate(total_ratings=Sum('rating'))['total_ratings'] or 0,
            "average_rating": game_ratings.aggregate(average_rating=Avg('rating'))['average_rating'] or 0,
        }

        return APIResponse.HTTP_200_OK(message="Game ratings retrieved successfully.", data=data)

    except Game.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="Game not found.")
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")

# TODO: update and delete game only admin and agent revise this login again
@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_game(request):
    """
    Update an existing game based on game_id.
    """
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    allowed_roles = ["Admin"]

    # Fetch current user
    current_user = User.objects.filter(user_id=user_instance.id).first()
    if current_user is None:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")

    # Validate user role
    role = getattr(current_user.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")

    # Extract game_id
    game_id = request.data.get('game_id')
    if not game_id:
        return APIResponse.HTTP_400_BAD_REQUEST(message="game_id is required.")

    # Find the game instance with proper error handling
    try:
        game = Game.objects.get(game_id=game_id, created_by_user_id=current_user)
    except Game.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="Game not found or you are not the creator.")

    # Try updating the game
    try:
        # ✅ Use `instance=game` so existing values are retained for missing fields
        form = GameForm(request.data or None, request.FILES or None, instance=game)

        if form.is_valid():
            form.save()  # Save the updated game
            return APIResponse.HTTP_200_OK(message="Game updated successfully.", data=game.to_dict())
        else:
            return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid form data.", data=form.errors)

    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def redeem_game_player_scores_to_wallet(request):
    """
    Redeem game scores to the user's wallet from game scores(dollars) to wallet.
    """
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    allowed_roles = ["User"]

    # Fetch current user
    current_user = User.objects.filter(user_id=user_instance.id).first()
    if current_user is None:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")

    # Validate user role
    role = getattr(current_user.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")

    l_0, l_1, l_2, l_3, l_4 = return_level_scores()
    free, premium, elite = return_subscriptions()

    REDEMPTION_SCORE_ON_LEVEL_0 = l_0.redemption_score_on_level
    REDEMPTION_SCORE_ON_LEVEL_1 = l_1.redemption_score_on_level
    REDEMPTION_SCORE_ON_LEVEL_2 = l_2.redemption_score_on_level
    REDEMPTION_SCORE_ON_LEVEL_3 = l_3.redemption_score_on_level
    REDEMPTION_SCORE_ON_LEVEL_4 = l_4.redemption_score_on_level

    LEVEL_CODES = [l_0.level_code, l_1.level_code, l_2.level_code, l_3.level_code, l_4.level_code]

    FREE_SUBSCRIPTIONS_CHOICE = free.pro_status
    PREMIUM_SUBSCRIPTIONS_CHOICE = premium.pro_status
    ELITE_SUBSCRIPTIONS_CHOICE = elite.pro_status

    REDEMPTION_ON_FREE_SUBSCRIPTION_PERCENTAGE = free.redemption_on_free_subscription
    REDEMPTION_ON_PREMIUM_SUBSCRIPTION_PERCENTAGE = premium.redemption_on_free_subscription
    REDEMPTION_ON_ELITE_SUBSCRIPTION_PERCENTAGE = elite.redemption_on_free_subscription

    game_uuid = request.data.get('game_id')
    player_username = request.data.get('player_username')

    if not game_uuid or not player_username:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Missing required fields.")

    try:
        game = Game.objects.get(game_id=game_uuid)
        if game is None:
            return APIResponse.HTTP_404_NOT_FOUND(message="Invalid game name.")

        user = User.objects.get(id=current_user.id)
        if user is None:
            return APIResponse.HTTP_404_NOT_FOUND(message="Invalid user name.")

        player = Player.objects.filter(user_id=user, game_id=game, username=player_username).first()
        print(f"player: {player}")

        if player is None:
            return APIResponse.HTTP_404_NOT_FOUND(message="Invalid player username.")

        free_game = game.is_free

        # validate the user levels
        """
            REDEEM ON LEVELS (daily):
            # Level 0 => 100$ (scores) only
            # Level 1 => 200$ (scores) only
            # Level 2 => 500$ (scores) only
            # Level 3 => 800$ (scores) only
            # Level 4 => 5000$ (scores) only
        """

        wallet = user.wallet_id

        if not game or not user:
            data = {
                "username": user.user_id.username,
                "datetime": datetime.now(tz=UTC).__str__(),
            }
            return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid username", data=data)
        if not player:
            return APIResponse.HTTP_404_NOT_FOUND(message="Player not found.")

        # Redemption scores for each level
        level_redemption_scores = {
            LEVEL_CODES[0]: REDEMPTION_SCORE_ON_LEVEL_0,
            LEVEL_CODES[1]: REDEMPTION_SCORE_ON_LEVEL_1,
            LEVEL_CODES[2]: REDEMPTION_SCORE_ON_LEVEL_2,
            LEVEL_CODES[3]: REDEMPTION_SCORE_ON_LEVEL_3,
            LEVEL_CODES[4]: REDEMPTION_SCORE_ON_LEVEL_4,
        }

        # Redemption percentages for each subscription plan
        subscription_percentages = {
            FREE_SUBSCRIPTIONS_CHOICE: REDEMPTION_ON_FREE_SUBSCRIPTION_PERCENTAGE,
            PREMIUM_SUBSCRIPTIONS_CHOICE: REDEMPTION_ON_PREMIUM_SUBSCRIPTION_PERCENTAGE,
            ELITE_SUBSCRIPTIONS_CHOICE: REDEMPTION_ON_ELITE_SUBSCRIPTION_PERCENTAGE,
        }

        today_date = datetime.now().date()

        # Compare only the date parts (ignore time)
        if wallet.last_transaction_date.date() == today_date:
            return APIResponse.HTTP_400_BAD_REQUEST(
                message="You have already redeemed your score today. Please try again tomorrow."
            )

        # Proceed with the redemption process if the user has not redeemed today
        if user.user_level.level_code in level_redemption_scores:
            required_score = level_redemption_scores[user.user_level.level_code]
            free_scores = player.free_scores
            player_scores = player.score

            # Handle free scores redemption
            if free_game:
                if free_scores >= required_score:
                    if user.subscription_plan.pro_status in subscription_percentages:
                        # Get the percentage for the user's subscription type
                        redemption_percentage = subscription_percentages[user.subscription_plan.pro_status]

                        # Redeem 10% of free scores
                        redeemable_score = int(free_scores) * 0.1

                        wallet_history = WalletTransactionHistory.objects.create(
                            payment_method="Game to Wallet Transaction",
                            payment_status='Approved',
                            transaction_amount=redeemable_score
                        )

                        # Update wallet balances
                        wallet.total_amount += redeemable_score
                        wallet.wallet_transaction_history_id.add(wallet_history)
                        wallet.last_transaction_date = datetime.now().date()  # Set last transaction date to today

                        # Add remaining free scores to experience points: remaining 90%
                        remaining_score_to_xp = free_scores - redeemable_score

                        """
                        Free:               -> remaining_score_to_xp
                        Premium(Pro): 2     -> remaining_score_to_xp * 2
                        Elite: 3            -> remaining_score_to_xp * 3
                        """
                        # 90 * 2 = 90
                        total_xp = max(
                            remaining_score_to_xp * (
                                1 if user.subscription_plan.pro_status == FREE_SUBSCRIPTIONS_CHOICE  # Free
                                else 2 if user.subscription_plan.pro_status == PREMIUM_SUBSCRIPTIONS_CHOICE
                                else 3),
                            0
                        )

                        # 90 * 50 = 4500
                        total_xp = total_xp * redemption_percentage

                        user.experience_points += total_xp

                        # Save changes
                        wallet.save()
                        user.save()
                        game.save()

                        game_transaction_history = GameTransactionHistory.objects.create(
                            game_id=game,
                            payment="Game to Wallet Transaction",
                            transaction_amount=redeemable_score,
                        )

                        player.game_transaction_history_id.add(game_transaction_history)
                        player.free_scores = 0
                        player.save()

                        return APIResponse.HTTP_200_OK(
                            message="Score successfully redeemed from the game.",
                            data={
                                "username": user.user_id.username,
                                "new_scores": player.score,
                                "datetime": datetime.now(tz=UTC).__str__()
                            },
                        )
                    else:
                        data = {
                            "username": user.user_id.username,
                            "datetime": datetime.now(tz=UTC).__str__(),
                        }
                        return APIResponse.HTTP_422_UNPROCESSABLE_ENTITY(
                            message="You don't have enough scores to redeem.",
                            data=data
                        )
                else:
                    return APIResponse.HTTP_400_BAD_REQUEST(
                        message=f"Score `{free_scores}` not enough for level. At least {required_score} "
                                f"scores are required to redeem."
                    )

            # Handle paid scores redemption
            else:
                if player_scores >= required_score:
                    if user.subscription_plan.pro_status in subscription_percentages:
                        # Get the percentage for the user's subscription type
                        redemption_percentage = subscription_percentages[user.subscription_plan.pro_status]

                        # Update wallet balances
                        wallet.total_amount += required_score
                        wallet.last_transaction_date = datetime.now().date()  # Set last transaction date to today

                        # Calculate XP from remaining scores
                        remaining_score_to_xp = player_scores - required_score  # 102 - 100 = 2

                        """
                        Free:               -> remaining_score_to_xp
                        Premium(Pro): 2     -> remaining_score_to_xp * 2
                        Elite: 3            -> remaining_score_to_xp * 3
                        """

                        # 2*2 = 4
                        total_xp = max(
                            remaining_score_to_xp * (
                                1 if user.subscription_plan.pro_status == FREE_SUBSCRIPTIONS_CHOICE
                                else 2 if user.subscription_plan.pro_status == PREMIUM_SUBSCRIPTIONS_CHOICE
                                else 3),
                            0
                        )

                        total_xp = total_xp * redemption_percentage
                        user.experience_points += total_xp

                        # Check license verification and upgrade user level
                        if (
                                user.driving_license_front_image
                                and user.driving_license_back_image
                                and user.is_verified_license
                        ):
                            user.user_level.level = "Level 1"
                            user.user_level.level_code = "L1"

                        wallet_history = WalletTransactionHistory.objects.create(
                            payment_method="Game to Wallet Transaction",
                            payment_status='Approved',
                            transaction_amount=required_score
                        )

                        # Update wallet balances
                        wallet.wallet_transaction_history_id.add(wallet_history)

                        # Save changes
                        wallet.save()
                        user.save()
                        game.save()

                        game_transaction_history = GameTransactionHistory.objects.create(
                            game_id=game,
                            payment="Game to Wallet Transaction",
                            transaction_amount=required_score,
                        )

                        player.game_transaction_history_id.add(game_transaction_history)
                        player.score = 0
                        player.save()

                        # Construct a response message
                        plan_name = {
                            FREE_SUBSCRIPTIONS_CHOICE: "Free",
                            PREMIUM_SUBSCRIPTIONS_CHOICE: "Premium",
                            ELITE_SUBSCRIPTIONS_CHOICE: "Elite",
                        }[user.subscription_plan.pro_status]

                        return APIResponse.HTTP_200_OK(
                            message="Score successfully redeemed from the game.",
                            data={
                                "username": user.user_id.username,
                                "new_scores": player.score,
                                "datetime": datetime.now(tz=UTC).__str__(),
                                "plan_name": plan_name,
                            },
                        )
                    else:
                        return APIResponse.HTTP_400_BAD_REQUEST(
                            message=f"Invalid subscription plan `{user.subscription_plan.pro_status}`."
                        )
                else:
                    return APIResponse.HTTP_400_BAD_REQUEST(
                        message=f"Score `{player_scores}` not enough for level `{user.user_level.level}`. "
                                f"At least {required_score} scores are required to redeem."
                    )
        else:
            return APIResponse.HTTP_400_BAD_REQUEST(
                message=f"Invalid user level code `{user.user_level.level_code}`."
            )
    except Player.DoesNotExist:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Player not found.")
    except User.DoesNotExist:
        return APIResponse.HTTP_400_BAD_REQUEST(message="User not found.")
    except Game.DoesNotExist:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Game not found.")
    except Wallet.DoesNotExist:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Wallet not found.")
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['GET'])
def get_game_transaction_history(_):
    """
    Retrieve all game transaction histories along with their associated games.
    """
    try:
        # Fetch all transaction histories
        histories = GameTransactionHistory.objects.select_related('game_id').all()

        # Serialize the data
        histories_data = [
            {
                "transaction_id": str(history.id),
                "game": {
                    "id": str(history.game_id.id),
                    "game_id": history.game_id.game_id,
                    "game_name": history.game_id.game_name,
                    "game_description": history.game_id.game_description,
                    "game_price": history.game_id.game_price,
                    "game_image": history.game_id.game_image.url if history.game_id.game_image else None,
                    "game_video": history.game_id.game_video.url if history.game_id.game_video else None,
                    "upcoming_status": history.game_id.upcoming_status,
                    "is_trending": history.game_id.is_trending,
                },
                "payment": history.payment,
                "transaction_amount": history.transaction_amount,
                "transaction_date": history.transaction_date,
                "order_id": history.order_id,
                "withdrawal_percentage_tax": history.withdrawal_percentage_tax,
            }
            for history in histories
        ]

        return APIResponse.HTTP_200_OK(message="Game transaction history retrieved successfully.", data=histories_data)
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['GET'])
def get_game_player_by_username(request):
    """
    Retrieve games by username, players by game_id, or all games with players if no filter is provided.
    """
    try:
        # Extract query parameters
        game_id = request.data.get('game_id', None)
        username = request.data.get('username', None)

        if game_id:
            # If game_id is provided, fetch all players of that game
            players = Player.objects.filter(game_id=game_id)
            data = [
                {
                    "player_id": player.id,
                    "username": player.username,
                    "nick_name": player.nick_name,
                    "score": player.score,
                    "status": player.status,
                    "is_banned": player.is_banned,
                    "game": {
                        "id": str(player.game_id.id),
                        "game_name": player.game_id.game_name,
                        "game_description": player.game_id.game_description,
                    },
                }
                for player in players
            ]
            return APIResponse.HTTP_200_OK(
                message=f"Players for game_id {game_id} retrieved successfully.",
                data=data,
            )

        elif username:
            # If username is provided, fetch all games of that user
            players = Player.objects.filter(username=username)
            data = [
                {
                    "game_id": str(player.game_id.id),
                    "game_name": player.game_id.game_name,
                    "game_description": player.game_id.game_description,
                    "player": {
                        "id": player.id,
                        "nick_name": player.nick_name,
                        "score": player.score,
                    },
                }
                for player in players
            ]
            return APIResponse.HTTP_200_OK(
                message=f"Games for username {username} retrieved successfully.",
                data=data,
            )

        else:
            # If neither game_id nor username is provided, fetch all players with their games
            players = Player.objects.select_related('game_id').all()
            data = [
                {
                    "player_id": player.id,
                    "username": player.username,
                    "nick_name": player.nick_name,
                    "score": player.score,
                    "status": player.status,
                    "is_banned": player.is_banned,
                    "game": {
                        "id": str(player.game_id.id),
                        "game_name": player.game_id.game_name,
                        "game_description": player.game_id.game_description,
                    },
                }
                for player in players
            ]
            return APIResponse.HTTP_200_OK(
                message="All players with their games retrieved successfully.",
                data=data,
            )

    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(
            message=f"An unexpected error occurred: {str(e)}"
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def player_to_player_redemption(request):
    """
    Transfers scores between two players belonging to the authenticated user.
    """
    try:
        # Authenticate and fetch the user
        user_instance = AuthService.get_user_from_token(request)
        if not user_instance:
            return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

        # Validate user role
        user = AuthService.validate_user_role(user_instance, "User")
        if not user:
            return APIResponse.HTTP_403_FORBIDDEN(message="Unauthorized. Only 'User' role can perform this action.")

        # Retrieve required player UUIDs from request
        player_1_uuid = request.data.get('player_1_uuid')
        player_2_uuid = request.data.get('player_2_uuid')

        if not player_1_uuid or not player_2_uuid:
            return APIResponse.HTTP_400_BAD_REQUEST(message="Both player_1_uuid and player_2_uuid are required.")

        # Ensure both players exist and belong to the authenticated user
        try:
            player_1 = Player.objects.select_related("game_id").get(id=player_1_uuid, user_id=user.id)
            player_2 = Player.objects.select_related("game_id").get(id=player_2_uuid, user_id=user.id)
        except Player.DoesNotExist:
            return APIResponse.HTTP_404_NOT_FOUND(message="One or both players do not belong to the specified user.")

        # Ensure players are not banned
        if player_1.is_banned or player_2.is_banned:
            return APIResponse.HTTP_400_BAD_REQUEST(message="One or both players are banned from score transactions.")

        # Ensure both players are active
        if player_1.status != 'active' or player_2.status != 'active':
            return APIResponse.HTTP_400_BAD_REQUEST(message="Both players must be active to redeem scores.")

        # Retrieve game details for `player_1`
        game = player_1.game_id
        transfer_score_percentage = game.transfer_score_percentage

        # Validate transfer percentage
        if transfer_score_percentage < 0 or transfer_score_percentage > 100:
            return APIResponse.HTTP_400_BAD_REQUEST(
                message="Invalid transfer score percentage. Must be between 0 and 100."
            )

        # Calculate percentage for deduction and remaining transfer
        percentage_deducted = transfer_score_percentage / 100
        percentage_remaining = 1 - percentage_deducted

        # Handle transfer logic for free_scores or score based on game type
        transfer_amount = 0
        if game.is_free:
            if player_1.free_scores <= 0:
                return APIResponse.HTTP_400_BAD_REQUEST(message="Player 1 does not have enough free scores to transfer.")
            transfer_amount = int(player_1.free_scores * percentage_remaining)
            player_2.free_scores += transfer_amount
            player_1.free_scores = 0  # Reset free_scores for player_1
        else:
            if player_1.score <= 0:
                return APIResponse.HTTP_400_BAD_REQUEST(message="Player 1 does not have enough score to transfer.")
            transfer_amount = int(player_1.score * percentage_remaining)
            player_2.score += transfer_amount
            player_1.score = 0  # Reset score for player_1

        # Save changes
        player_1.save()
        player_2.save()

        # Prepare response data
        data = {
            "player_1": player_1.to_dict(),
            "player_2": player_1.to_dict(),
            "transfer_amount": transfer_amount,
        }

        return APIResponse.HTTP_200_OK(
            message=f"Scores transferred successfully from {player_1.username} to {player_2.username}.",
            data=data
        )

    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
    except Player.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="One or both players do not exist.")
    except Game.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="Game associated with the player does not exist.")
    except ValueError:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid data provided in request.")
    except Exception as e:
        logging.error(f"Error in player_to_player_redemption: {str(e)}")
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def get_all_games_under_user_freeplays(request):
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)

    # Validate user's role
    user = AuthService.validate_user_role(user_instance, "User")

    # Retrieve the user by UUID
    user = User.objects.get(id=user.id)

    # Retrieve the user's free play record
    free_play = FreePlay.objects.filter(user=user).first()

    if not free_play:
        return APIResponse.HTTP_404_NOT_FOUND(message="No freeplay record found for the user.")

    # Get the free_plays value
    free_plays_amount = free_play.free_plays

    # Retrieve games with a price between 0 and free_plays_amount
    games = Game.objects.filter(game_price__gte=0, game_price__lte=free_plays_amount)

    if games is None:
        return APIResponse.HTTP_404_NOT_FOUND(
            message=f"No games found within {user.user_id.username}'s free play range. "
                    f"Free play amount: ${free_plays_amount}")
    try:
        # pagination
        page = int(request.query_params.get('page', 1))
        limit = int(request.query_params.get('limit', 20))

        start = (page - 1) * limit
        end = start + limit

        games = games[start:end]

        # Prepare response data
        data = {
            "user": user.to_dict() if user else "No user found.",
            "games": [game.to_dict() for game in games],
            "pagination": {
                "total_pages": math.ceil(games.count() / limit),
                "current_page": page,
                "limit": limit,
                "total_count": games.count()
            }
        } if games else "No games found."

        return APIResponse.HTTP_200_OK(
            message="Games retrieved successfully within free play range.",
            data=data
        )

    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="User with the given UUID does not exist.")
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


############################################################################################################


## Admin Game Panel Management System
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def analytics(request):  ##
    """
    Show total number of users, players, games, and transactions.
    """
    ##
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin", "Agent"]

    # print(f"user_instance.role_id: {user_instance.id}")
    current_user = User.objects.get(user_id=user_instance.id)

    # Validate the user's role
    role = getattr(current_user.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")

    try:
        total_users = User.objects.count()
        total_players = Player.objects.count()
        total_games = Game.objects.count()
        total_transactions = GameTransactionHistory.objects.count()

        data = {
            "total_users": total_users,
            "total_players": total_players,
            "total_games": total_games,
            "total_transactions": total_transactions,
        }

        return APIResponse.HTTP_200_OK(
            message="Successfully fetched analytics.", data=data
        )

    except Exception as e:
        data = {
            "datetime": datetime.now(tz=UTC).__str__(),
        }
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(
            message=f"Unable to get panel scores. Please try again after few minutes.{str(e)}", data=data)






@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_player_by_admin(request):
    """
    API to create a new player.
    """
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin", "Agent", "User"]

    current_user = User.objects.get(user_id=user_instance.id)

    # Validate the user's role
    role = getattr(current_user.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")
    auth_user = current_user

    username = request.data.get('username')
    nickname = request.data.get('nickname')
    password = request.data.get('password')
    game_id = request.data.get('game_id')
    game = Game.objects.filter(game_id=game_id).first()

    if not game:
        return APIResponse.HTTP_404_NOT_FOUND(message="Game not found.")

    if not (username and nickname and password and game_id):
        return APIResponse.HTTP_400_BAD_REQUEST(
            message="Missing required fields: username, nickname, password, and game_id are mandatory."
        )

    # Validate username
    if ' ' in username:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Username must not contain spaces.")
    if not username.isalnum() and not all(char in ['_', '-'] for char in username):
        return APIResponse.HTTP_400_BAD_REQUEST(
            message="Username can only contain letters, numbers, underscores, or hyphens."
        )
    if len(username) < 3 or len(username) > 20:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Username must be between 3 and 20 characters.")

    # Check if the player already exists
    if Player.objects.filter(username=username, game_id=game).exists():
        return APIResponse.HTTP_503_SERVICE_UNAVAILABLE(message="Username already exists.")

    # Create the Player
    player = Player.objects.create(
        username=username,
        nick_name=nickname,
        password=make_password(password),
        user_id=current_user,
        game_id=game,
        created_by=current_user,
    )

    # Trigger the notification signal with the correct instance
    player_created_signal.send(sender=Player, instance=player, user=current_user)

    # Return response
    response_data = {
        'status': 200,
        'message': f"Player created for user '{user_instance.first_name} {user_instance.last_name}' successfully",
        "data": {
            "username": username,
            "datetime": datetime.now(tz=UTC).__str__(),
            "nickname": nickname,
            "score": 0
        }
    }

    return Response(response_data, status=200)




@api_view(['POST'])
@permission_classes([IsAuthenticated])
def reset_game_password(request):
    """
    Synchronous API to reset the password of a game.
    """
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    allowed_roles = ["Admin", "Agent", "User"]
    current_user = User.objects.get(user_id=user_instance.id)

    if not current_user:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")

    # Validate the user's role
    role = getattr(current_user.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")

    username = request.data.get('username')
    new_password = request.data.get('new_password')
    game_id = request.data.get('game_id')

    if not (username and new_password and game_id):             # Validate required fields
        return APIResponse.HTTP_400_BAD_REQUEST(
            message="Missing required fields: username, game_id, and new_password are mandatory.")
    try:
        # Reset the password synchronously
        admin_panel = AdminGamePanel()
        is_changed_password = async_to_sync(admin_panel.reset_game_password)(current_user=current_user, username=username, new_password=new_password, game_id=game_id)

        send_mail(
            "Game Password Reset",
            f"Hi, \n\nYour game password has been reset "
            f"\n\nBest regards,\nCasinoze Team",
            settings.EMAIL_HOST_USER,
            [current_user.user_id.email],
            fail_silently=False
        )

        return APIResponse.HTTP_200_OK(message="Game password reset successfully.", data=is_changed_password)
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def reset_game_password_by_agent(request):
    """
    Synchronous API to reset the password of a game.
    """
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    allowed_roles = ["Admin", "Agent", "User"]
    current_user = User.objects.get(user_id=user_instance.id)

    if not current_user:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")

    # Validate the user's role
    role = getattr(current_user.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")

    username = request.data.get('username')
    new_password = request.data.get('new_password')
    game_id = request.data.get('game_id')

    if not (username and new_password and game_id):             # Validate required fields
        return APIResponse.HTTP_400_BAD_REQUEST(
            message="Missing required fields: username, game_id, and new_password are mandatory.")
    try:
        # Reset the password synchronously
        panel = AgentGamePanel()
        is_changed_password = async_to_sync(panel.reset_game_password)(current_user=current_user,
                                                                             username=username,
                                                                             new_password=new_password,
                                                                             game_id=game_id)
        if is_changed_password:
            send_mail(
                "Game Password Reset",
                f"Hi, \n\nYour game password has been reset "
                f"\n\nBest regards,\nCasinoze Team",
                settings.EMAIL_HOST_USER,
                [current_user.user_id.email],
                fail_silently=False
            )

            return APIResponse.HTTP_200_OK(message="Game password reset successfully.", data=is_changed_password)
        return APIResponse.HTTP_404_NOT_FOUND(message="Game or player does not existed.", data=is_changed_password)
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def notifications(request):
    """
    API Endpoint to get user-specific notifications.
    Returns the notifications of the logged-in user with pagination.
    """
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    allowed_roles = ["Admin", "User", "Agent"]

    try:
        current_user = User.objects.get(user_id=user_instance.id)
    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")

    role = getattr(current_user.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")

    # Get query parameters for pagination
    page = int(request.GET.get('page', 1))
    limit = int(request.GET.get('limit', 10))
    offset = (page - 1) * limit

    try:
        notifications_queryset = Notification.objects.filter(user=current_user).order_by('-created_at')[
                                 offset:offset + limit]

        read_notifications = []
        unread_notifications = []

        for notification in notifications_queryset:
            notification_data = {
                "id": str(notification.id),
                "notification_type": notification.notification_type,
                "message": notification.message,
                "is_read": notification.is_read,
                "created_at": humanize.naturaltime(notification.created_at),
                "created_by": notification.user.user_id.username if notification.user else None,
            }
            if notification.is_read:
                read_notifications.append(notification_data)
            else:
                unread_notifications.append(notification_data)

        return APIResponse.HTTP_200_OK(
            message="Successfully fetched notifications.",
            data={
                "read_notifications": read_notifications,
                "unread_notifications": unread_notifications,
            }
        )
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(
            message=f"Unable to get notifications. Please try again after a few minutes. {str(e)}"
        )


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def player_has_been_notified(request):
    """
    API Endpoint to get panel scores.
    Returns the scores of users with specific roles and usernames.
    """
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin", "User", "Agent"]
    current_user = User.objects.get(user_id=user_instance.id)

    # Validate the user's role
    role = getattr(current_user.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")

    username = request.data.get("username")
    player = get_object_or_404(Player, username=username)

    try:
        if not player.is_notified_read:
            APIResponse.HTTP_404_NOT_FOUND(
                message="Player is already notified."
            )

        player.is_notified_read = False
        player.save()

        return APIResponse.HTTP_200_OK(
            message="Player has been notified.",
            data=model_to_dict(player)
        )
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(
            message=f"Unable to get players. Please try again after a few minutes. {str(e)}"
        )


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def all_player_has_been_notified(request):
    """
    API Endpoint to update the notification status for all players associated with the authenticated user.
    """
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin", "User", "Agent"]

    try:
        current_user = User.objects.get(user_id=user_instance.id)
    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")

    # Validate the user's role
    role = getattr(current_user.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")

    auth_user = current_user

    try:
        # Get all players created by the authenticated user
        players = Player.objects.filter(created_by=auth_user)

        if not players:
            return APIResponse.HTTP_404_NOT_FOUND(message="No players found for the authenticated user.")

        # Update the notification status for all players
        players.update(is_notified_read=False)

        # Collect updated player data
        updated_players_data = [model_to_dict(player) for player in players]

        return APIResponse.HTTP_200_OK(
            message="All players have been notified.",
            data=updated_players_data
        )

    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(
            message=f"Unable to update players. Please try again after a few minutes. {str(e)}"
        )


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def game_has_been_notified(request):
    """
    API Endpoint to get panel scores.
    Returns the scores of users with specific roles and usernames.
    """
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin", "User", "Agent"]
    current_user = User.objects.get(user_id=user_instance.id)

    # Validate the user's role
    role = getattr(current_user.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")

    game_id = request.data.get("game_id")

    try:
        game = get_object_or_404(Game, game_id=game_id)
        game.is_notified_read = False
        game.save()

        data = {
            "game_id": game.game_id,
            "game_name": game.game_name,
            "is_notified_read": game.is_notified_read,
        }

        return APIResponse.HTTP_200_OK(
            message="Game has been notified.",
            data=data
        )

    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(
            message=f"Unable to get games. Please try again after a few minutes. {str(e)}"
        )


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def all_game_has_been_notified(request):
    """
    API Endpoint to update the notification status for all games created by the authenticated user.
    """
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin", "User", "Agent"]

    try:
        current_user = User.objects.get(user_id=user_instance.id)
    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")

    # Validate the user's role
    role = getattr(current_user.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")

    auth_user = current_user

    try:
        # Filter games by the 'created_by' field which should refer to the User model
        games = Game.objects.filter(created_by_user_id=auth_user)

        if not games:
            return APIResponse.HTTP_404_NOT_FOUND(message="No games found for the authenticated user.")

        # Update the notification status for all games
        games.update(is_notified_read=False)

        # Prepare data for the response
        games_data = [{
            "game_id": game.id,
            "game_name": game.game_name,
            "is_notified_read": game.is_notified_read,
        } for game in games]

        return APIResponse.HTTP_200_OK(
            message="All games have been notified.",
            data=games_data
        )

    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(
            message=f"Unable to get games. Please try again after a few minutes. {str(e)}"
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_panel_scores(request):  ##
    """
    API Endpoint to get panel scores.
    Returns the scores of users with specific roles and usernames.
    """
    ##
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin"]
    current_user = User.objects.get(user_id=user_instance.id)

    # Validate the user's role
    role = getattr(current_user.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")

    try:
        # Get query parameters
        limit = int(request.GET.get('limit', 10))  # Default limit is 10

        # Get scores synchronously
        admin_panel = AdminGamePanel()
        scores = async_to_sync(admin_panel.get_panel_scores_by_role)(role_name=role, limit=limit)

        return APIResponse.HTTP_200_OK(message="Successfully fetched panel scores.", data=scores)

    except Exception as e:
        data = {
            "datetime": datetime.now(tz=UTC).__str__(),
        }
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(
            message=f"Unable to get panel scores. Please try again after few minutes.{str(e)}", data=data)


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def add_score_to_player_account(request):  ##
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin"]
    current_user = User.objects.get(user_id=user_instance.id)

    # Validate the user's role
    role = getattr(current_user.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")

    username = request.data.get('username')
    score = request.data.get('score')
    game_id = request.data.get('game_id')

    if not (username and score and game_id):
        return APIResponse.HTTP_400_BAD_REQUEST(
            message="Missing required fields."
        )

    try:

        # Get scores synchronously
        admin_panel = AdminGamePanel()
        scores = async_to_sync(admin_panel.add_score_to_player_account)(username, score, game_id)

        return APIResponse.HTTP_200_OK(message="Successfully added score to player account.", data=scores)

    except Exception as e:
        data = {
            "datetime": datetime.now(tz=UTC).__str__(),
        }
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(
            message=f"Unable to add score to player account. Please try again after few minutes.{str(e)}", data=data)


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def redeem_score_from_player_account(request):  ##
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin"]
    current_user = User.objects.get(user_id=user_instance.id)

    # Validate the user's role
    role = getattr(current_user.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")

    username = request.data.get('username')
    score = request.data.get('score')
    game_id = request.data.get('game_id')

    if not (username and score and game_id):
        return APIResponse.HTTP_400_BAD_REQUEST(
            message="Missing required fields."
        )

    try:

        # Get scores synchronously
        admin_panel = AdminGamePanel()
        scores = async_to_sync(admin_panel.redeem_score_from_player_account)(username, score, game_id)

        return APIResponse.HTTP_200_OK(message="Successfully redeemed score from player account.", data=scores)

    except Exception as e:
        data = {
            "datetime": datetime.now(tz=UTC).__str__(),
        }
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(
            message=f"Unable to redeem score from player account. Please try again after few minutes.{str(e)}", data=data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_all_players_accounts(request):
    """
    API endpoint to fetch all game accounts, excluding players with no creator.

    Returns:
        JsonResponse: List of game accounts with their details.
    """
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin", "Agent", "User"]
    current_user = User.objects.get(user_id=user_instance.id)

    role = getattr(current_user.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")

    search = request.query_params.get('search', '').strip().lower()

    try:
        # Initialize admin panel and fetch data
        admin_panel = AdminGamePanel()
        result = async_to_sync(admin_panel.get_all_games_accounts)(search)

        # Respond with data
        return APIResponse.HTTP_200_OK(
            message="Game accounts retrieved successfully.",
            data=result
        )

    except Exception as e:
        logging.error(f"Error in get_all_games_accounts API: {str(e)}")
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(
            message=f"An unexpected error occurred: {str(e)}"
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_all_my_created_players_by_admin(request):
    """
    API to retrieve all players created by a specific user with the Admin role,
    including search and pagination functionality.
    """
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)

    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    allowed_roles = ["Admin"]
    user = User.objects.get(user_id=user_instance.id)

    role = getattr(user.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")

    # Get page, page_size, and search query from request query params
    page = int(request.query_params.get('page', 1))
    page_size = int(request.query_params.get('page_size', 10))
    search = request.query_params.get('search', '').strip().lower()

    try:
        # Fetch all players asynchronously
        admin_panel = AdminGamePanel()
        players = async_to_sync(admin_panel.get_all_my_created_players)(user.id)

        if not players:
            return APIResponse.HTTP_404_NOT_FOUND(message="No players found.")

        # Apply search filter if the search parameter is provided
        if search:
            players = [
                player for player in players
                if search in player.get('game_name', '').lower() or
                   search in player.get('player', {}).get('username', '').lower() or
                   search in player.get('player', {}).get('nick_name', '').lower()
            ]

        if not players:  # Check again after filtering
            return APIResponse.HTTP_404_NOT_FOUND(message="No players match the search criteria.")

        # Apply pagination
        paginator = Paginator(players, page_size)
        try:
            paginated_players = paginator.get_page(page)  # Get the requested page
        except InvalidPath:
            return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid page number.")

        # Serialize paginated data
        response_data = {
            "players": paginated_players.object_list,  # Use object_list for the paginated players
            "pagination": {
                "current_page": paginated_players.number,
                "total_pages": paginator.num_pages,
                "page_size": page_size,
                "has_next": paginated_players.has_next(),
                "has_previous": paginated_players.has_previous(),
                "next_page": paginated_players.next_page_number() if paginated_players.has_next() else None,
                "previous_page": paginated_players.previous_page_number() if paginated_players.has_previous() else None,
                "pages": list(range(1, paginator.num_pages + 1)),
            },
        }

        return APIResponse.HTTP_200_OK(message="Players retrieved successfully.", data=response_data)

    except ValueError as ve:
        return APIResponse.HTTP_400_BAD_REQUEST(message=str(ve))
    except Exception as e:
        logging.error(f"Unexpected error in API: {str(e)}")
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message="An unexpected error occurred.")


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_all_my_created_games_by_admin(request):
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin", "Agent", "User"]
    user = get_object_or_404(User, user_id=user_instance.id)

    # Validate the user's role
    role = getattr(user.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")

    # Get page, page_size, and search query from request query params
    page = int(request.query_params.get('page', 1))
    page_size = int(request.query_params.get('page_size', 10))
    search = request.query_params.get('search', '').strip().lower()

    try:
        # Fetch all players asynchronously
        admin_panel = AdminGamePanel()
        games = admin_panel.get_all_my_created_games(user.id)

        if games is None:
            return APIResponse.HTTP_404_NOT_FOUND(message="No games found.")

        # Apply search filter if the search parameter is provided
        if search:
            games = [
                game for game in games
                if search in game.get('game_name', '').strip().lower() or \
                   search in str(game.get('game_id', '')).strip().lower() or \
                   search in str(game.get('game_price', '')).strip().lower()
            ]

        if games is None:  # Check again after filtering
            return APIResponse.HTTP_404_NOT_FOUND(message="No games match the search criteria.")

        # Apply pagination
        paginator = Paginator(games, page_size)
        try:
            paginated_games = paginator.get_page(page)  # Get the requested page
        except InvalidPage:
            return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid page number.")

        # Serialize paginated data
        response_data = {
            "games": paginated_games.object_list,  # reverse the order of the games
            "pagination": {
                "current_page": paginated_games.number,
                "total_pages": paginator.num_pages,
                "page_size": page_size,
                "has_next": paginated_games.has_next(),
                "has_previous": paginated_games.has_previous(),
                "next_page": paginated_games.next_page_number() if paginated_games.has_next() else None,
                "previous_page": paginated_games.previous_page_number() if paginated_games.has_previous() else None,
                "pages": list(range(1, paginator.num_pages + 1)),
            },
        }

        return APIResponse.HTTP_200_OK(message=f"Games retrieved successfully for '{user.user_id.username}'.",
                                       data=response_data)

    except ValueError as ve:
        return APIResponse.HTTP_400_BAD_REQUEST(message=str(ve))
    except Exception as e:
        logging.error(f"Error: {str(e)}")
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def get_player_score(request):
    try:
        # Validate input
        username = request.data.get('username')
        ##
        # username = request.data.get('username')
        if not username:
            return APIResponse.HTTP_400_BAD_REQUEST(message="Username is required.")

        # Authenticate and fetch the user
        user_instance = AuthService.get_user_from_token(request)
        if not user_instance:
            return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

        # Allowed roles
        allowed_roles = ["Admin", "Agent", "User"]
        current_user = User.objects.get(user_id=user_instance.id)

        # Validate the user's role
        role = getattr(current_user.role_id, "roles", None)
        if role not in allowed_roles:
            return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")

        ##
        if not username:
            data = {
                "username": username,
                "datetime": datetime.now(tz=UTC).__str__(),
            }
            return APIResponse.HTTP_400_BAD_REQUEST(message="Missing required fields: 'username'.", data=data)

        # Fetch data from AdminGamePanel
        admin_panel = AdminGamePanel()
        data = admin_panel.get_player_score(username=username)

        if not data:
            json = {
                "username": username,
                "datetime": datetime.now(tz=UTC).__str__(),
            }
            return APIResponse.HTTP_422_UNPROCESSABLE_ENTITY(
                message="Unable to find user. Please create user first.",
                data=json
            )
        else:
            if data.get("errors"):
                return APIResponse.HTTP_400_BAD_REQUEST(message=data.get("errors"), data=json)

            data = {
                **data,
                "datetime": datetime.now(tz=UTC).__str__(),
            }
            return APIResponse.HTTP_200_OK(message="Score retrieved successfully", data=data)

    except Exception as e:
        logging.error(f"Error in get_game_score API: {str(e)}")
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_game_stats(request):
    ##
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin"]
    current_user = User.objects.get(user_id=user_instance.id)

    # Validate the user's role
    role = getattr(current_user.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")
    # print(f"Authenticated user's role: {user_role}")
    ##
    """
    Get statistics of all games and their users,
    and all users and their associated games.

    Returns:
        JsonResponse: Games with their users and users with their games.
    """
    try:
        # Get all games with related players
        games = Game.objects.prefetch_related('players').all()
        games_with_users = [
            {
                "game_id": str(game.id),
                "game_name": game.game_name,
                "total_games": game.players.count(),
                "players": [
                    {
                        "player_id": str(player.id),
                        "username": player.username,
                        "nick_name": player.nick_name,
                        "score": player.score,
                    }
                    for player in game.players.all()
                ]
            }
            for game in games
        ]

        # Get all users with related games
        users = User.objects.prefetch_related('players__game_id').all()
        users_with_games = [
            {
                "user_id": str(user.id),
                "username": user.user_id.username,
                "total_players": user.players.count(),
                "games": [
                    {
                        "game_id": str(player.game_id.id),
                        "game_name": player.game_id.game_name,
                        "score": player.score,
                    }
                    for player in user.players.all()
                ]
            }
            for user in users
        ]

        # Prepare the final response
        data = {
            "games_with_users": games_with_users,
            "users_with_games": users_with_games,
        }

        return APIResponse.HTTP_200_OK(message="Game stats retrieved successfully.", data=data)

    except Exception as e:
        logging.error(f"Error in get_game_stats API: {str(e)}")
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def block_player(request):
    ##

    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin", "Agent"]

    # print(f"user_instance.role_id: {user_instance.id}")
    current_user = User.objects.get(user_id=user_instance.id)

    # Validate the user's role
    role = getattr(current_user.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")

    player_username = request.data.get('player_username')
    player = Player.objects.get(username=player_username)

    try:
        if player.is_banned:
            player.is_banned = False
            player.save()
        else:
            player.is_banned = True
            player.save()

        data = {
            "player_id": str(player.id),
            "username": player.username,
            "nick_name": player.nick_name,
            "score": player.score,
            "is_banned": player.is_banned,
            "status": player.status,
        }
        banned = "banned" if player.is_banned else "unbanned"

        return APIResponse.HTTP_200_OK(message=f"Player '{player.username}' {banned} successfully.", data=data)
    except Player.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message=f"Player {player_username} not found.")
    except Exception as e:
        logging.error(f"Error: {str(e)}")
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def block_game(request):
    ##
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin", "Agent"]

    # print(f"user_instance.role_id: {user_instance.id}")
    current_user = User.objects.get(user_id=user_instance.id)

    # Validate the user's role
    role = getattr(current_user.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")

    game_id = request.data.get('game_id')
    game = Game.objects.filter(game_id=game_id).first()

    if game is None:
        return APIResponse.HTTP_404_NOT_FOUND(
            message=f"Please provide correct game id or Game not found. Try again to provide correct game id.")

    try:
        if game.is_active:
            game.is_active = False
            game.save()
        else:
            game.is_active = True
            game.save()

        data = {
            "game_id": str(game.id),
            "game_name": game.game_name,
            "game_description": game.game_description,
            "game_image": game.game_image.url if game.game_image else "N/A",
            "game_video": game.game_video.url if game.game_video else "N/A",
            "game_price": game.game_price,
            "is_active": game.is_active,
        }

        banned = "banned" if game.is_active else "unbanned"

        return APIResponse.HTTP_200_OK(message=f"Game '{game.game_name}' {banned} successfully.", data=data)
    except Game.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message=f"Game not found.")
    except Exception as e:
        logging.error(f"Error: {str(e)}")
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def is_free_game(request):
    ##
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin", "Agent"]

    # print(f"user_instance.role_id: {user_instance.id}")
    current_user = User.objects.get(user_id=user_instance.id)

    # Validate the user's role
    role = getattr(current_user.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")

    game_id = request.data.get('game_id')
    game = Game.objects.filter(game_id=game_id).first()

    if game is None:
        return APIResponse.HTTP_404_NOT_FOUND(
            message=f"Please provide correct game id or Game not found. Try again to provide correct game id.")

    try:
        if game.is_free:
            game.is_free = False
            game.save()
        else:
            game.is_free = True
            game.save()

        data = {
            "game_id": str(game.id),
            "game_name": game.game_name,
            "game_description": game.game_description,
            "game_image": game.game_image.url if game.game_image else "N/A",
            "game_video": game.game_video.url if game.game_video else "N/A",
            "game_price": game.game_price,
            "is_active": game.is_active,
            "is_free": game.is_free,
        }

        free = "is free" if game.is_free else "is not free"

        return APIResponse.HTTP_200_OK(message=f"Game '{game.game_name}' {free} successfully.", data=data)
    except Game.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message=f"Game not found.")
    except Exception as e:
        logging.error(f"Error: {str(e)}")
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def upcoming_status(request):
    ##
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin", "Agent"]

    # print(f"user_instance.role_id: {user_instance.id}")
    current_user = User.objects.get(user_id=user_instance.id)

    # Validate the user's role
    role = getattr(current_user.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")

    game_id = request.data.get('game_id')
    game = Game.objects.filter(game_id=game_id).first()

    if game is None:
        return APIResponse.HTTP_404_NOT_FOUND(
            message=f"Please provide correct game id or Game not found. Try again to provide correct game id.")

    try:
        if game.upcoming_status:
            game.upcoming_status = False
            game.save()
        else:
            game.upcoming_status = True
            game.save()

        data = {
            "game_id": str(game.id),
            "game_name": game.game_name,
            "game_description": game.game_description,
            "game_image": game.game_image.url if game.game_image else "N/A",
            "game_video": game.game_video.url if game.game_video else "N/A",
            "game_price": game.game_price,
            "is_active": game.is_active,
            "is_free": game.is_free,
            "message_upcoming_status": game.upcoming_status,
        }

        message_upcoming_status = "is set to upcoming status" \
            if game.upcoming_status else "is not set to upcoming status"

        return APIResponse.HTTP_200_OK(message=f"Game '{game.game_name}' "
                                               f"{message_upcoming_status} successfully.", data=data)
    except Game.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message=f"Game not found.")
    except Exception as e:
        logging.error(f"Error: {str(e)}")
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def is_trending(request):
    ##
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin", "Agent"]

    # print(f"user_instance.role_id: {user_instance.id}")
    current_user = User.objects.get(user_id=user_instance.id)

    # Validate the user's role
    role = getattr(current_user.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")

    game_id = request.data.get('game_id')
    game = Game.objects.filter(game_id=game_id).first()

    if game is None:
        return APIResponse.HTTP_404_NOT_FOUND(
            message=f"Please provide correct game id or Game not found. Try again to provide correct game id.")

    try:
        if game.is_trending:
            game.is_trending = False
            game.save()
        else:
            game.is_trending = True
            game.save()

        data = {
            "game_id": str(game.id),
            "game_name": game.game_name,
            "game_description": game.game_description,
            "game_image": game.game_image.url if game.game_image else "N/A",
            "game_video": game.game_video.url if game.game_video else "N/A",
            "game_price": game.game_price,
            "is_active": game.is_active,
            "is_free": game.is_free,
            "message_is_trending": game.is_trending,
        }

        message_is_trending = "is set to trending status" if game.is_trending else "is not set to trending status"

        return APIResponse.HTTP_200_OK(message=f"Game '{game.game_name}' "
                                               f"{message_is_trending} successfully.", data=data)
    except Game.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message=f"Game not found.")
    except Exception as e:
        logging.error(f"Error: {str(e)}")
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


from django.core.exceptions import ObjectDoesNotExist
import logging


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_player(request):
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin", "Agent"]

    try:
        current_user = User.objects.get(user_id=user_instance.id)
    except ObjectDoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="Authenticated user not found.")

    # Validate the user's role
    role = getattr(current_user.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")

    # Validate request body
    player_username = request.data.get('player_username')
    if not player_username:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Missing required parameter: 'player_username'.")

    try:
        player = Player.objects.get(username=player_username)

        if player.is_banned:
            return APIResponse.HTTP_400_BAD_REQUEST(
                message=f"Player '{player.username}' is banned. Please unban the player first.")

        # Capture data before deletion
        data = {
            "player_id": str(player.id),
            "username": player.username,
            "nick_name": player.nick_name,
            "score": player.score,
            "is_banned": player.is_banned,
            "status": player.status,
        }

        player.delete()
        return APIResponse.HTTP_200_OK(message=f"Player '{player.username}' deleted successfully.", data=data)

    except Player.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message=f"Player '{player_username}' not found.")
    except Exception as e:
        logging.error(f"Error: {str(e)}")
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_game(request):
    """
    Delete a game if the user is authorized and the game is inactive.
    """
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    allowed_roles = ["Admin"]

    # Get the current user
    try:
        current_user = User.objects.get(user_id=user_instance.id)
        print(f"current_user :{current_user}")
    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="Authenticated user not found.")

    # Validate the user's role
    role = getattr(current_user.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")

    game_id = request.data.get('game_id')
    print(f"game_id {game_id}")
    # Fetch the game instance

    game = Game.objects.filter(game_id=game_id, created_by_user_id=current_user).first()
    if not game:
        return APIResponse.HTTP_404_NOT_FOUND(
            message="Please provide a correct game ID or Game not found. Try again."
        )

    if game.is_active:
        return APIResponse.HTTP_400_BAD_REQUEST(
            message=f"Game '{game.game_name}' is active. Please inactivate the game first."
        )

    try:
        # Get game data BEFORE deleting it
        if game.id:
            game_data = game.to_dict()
        else:
            game_data = None

        game.delete()

        return APIResponse.HTTP_200_OK(
            message=f"Game '{game.game_name}' deleted successfully.",
            data=game_data
        )

    except Game.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="Game not found.")
    except Exception as e:
        logging.error(f"Error: {str(e)}")
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


# Set up logging
logger = logging.getLogger(__name__)


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_game_by_admin_agent(request):
    """
    Update a game by admin or agent.
    """
    # Retrieve user instance from token
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin", "Agent"]
    current_user = User.objects.get(user_id=user_instance.id)

    # Validate the user's role
    role = getattr(current_user.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")

    # Extract game data from the request
    game_id = request.data.get('game_id')
    game_name = request.data.get('game_name')
    game_description = request.data.get('game_description')

    # Check if game image and video are in the request files
    game_image = request.FILES.get('game_image', None)
    game_video = request.FILES.get('game_video', None)

    game_price = request.data.get('game_price')
    android_game_url = request.data.get('android_game_url')
    ios_game_url = request.data.get('ios_game_url')
    browser_game_url = request.data.get('browser_game_url')
    upcoming_status_req = request.data.get('upcoming_status_req')
    is_trending_req = request.data.get('is_trending_req')
    score = request.data.get('score')
    transfer_score_percentage = request.data.get('transfer_score_percentage')
    redeem_score_percentage = request.data.get('redeem_score_percentage')
    is_free = request.data.get('is_free')
    gradient_style = request.data.get('gradient_style')

    # Fetch the game instance
    game = Game.objects.filter(game_id=game_id, created_by_user_id=current_user.id).first()
    if not game:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Game not found!")

    try:
        # Updating game fields
        game.game_id = game_id
        game.game_name = game_name
        game.game_description = game_description

        if game_image:
            game.game_image = game_image

        if game_video:
            game.game_video = game_video

        game.game_price = game_price
        game.android_game_url = android_game_url
        game.ios_game_url = ios_game_url
        game.browser_game_url = browser_game_url
        game.upcoming_status = upcoming_status_req
        game.is_trending = is_trending_req
        game.score = score
        game.transfer_score_percentage = transfer_score_percentage
        game.redeem_score_percentage = redeem_score_percentage
        game.is_free = is_free
        game.gradient_style = gradient_style

        game.save()

        # Prepare the response data
        data = game.to_dict()

        # Return the successful response
        return APIResponse.HTTP_200_OK(message="Game updated successfully.", data=data)

    except UnicodeDecodeError as e:
        logger.error(f"UnicodeDecodeError: {str(e)}")
        return APIResponse.HTTP_400_BAD_REQUEST(message="Error in decoding file. Please upload a valid file format.")

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_conversation_messages(request):
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin", "Agent"]

    try:
        # Retrieve the user
        user = User.objects.get(user_id=user_instance.id)
    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")

    # Validate the user's role
    role = getattr(user.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")

    # Fetch conversations the user is part of (either as a user or agent)
    conversations = MessageConversation.objects.all()
    user_conversations = conversations.values('user')
    agent_conversations = conversations.values('agent')

    if not conversations.exists():
        return APIResponse.HTTP_404_NOT_FOUND(message="No conversations found!")

    # Retrieve messages from these conversations
    messages = Message.objects.filter(
        Q(sender__in=user_conversations) & Q(receiver__in=agent_conversations) |
        Q(sender__in=agent_conversations) & Q(receiver__in=user_conversations),
        status='sent'
    ).order_by('-timestamp')

    if not messages.exists():
        return APIResponse.HTTP_404_NOT_FOUND(message="No messages found for this user.")

    # Prepare the data for the response
    try:
        data = []
        grouped_conversations = {}

        for conversation in conversations:
            # Initialize user_details and agent_details in case the conditions are not met
            user_details = {}
            agent_details = {}

            # Check if the conversation is with a user or agent
            if conversation.user.role_id.roles == "User":
                user_details = {
                    "id": conversation.user.id,
                    "first_name": conversation.user.first_name,
                    "last_name": conversation.user.last_name,
                    "username": conversation.user.user_id.username,
                    "email": conversation.user.email,
                    "profile_image": f"{settings.HOST}{conversation.user.profile_image.url}"
                    if conversation.user.profile_image else None,
                    "role": conversation.user.role_id.roles if conversation.user.role_id else "N/A"
                }
            if conversation.agent.role_id.roles == "Agent":
                agent_details = {
                    "id": conversation.agent.id,
                    "first_name": conversation.agent.first_name,
                    "last_name": conversation.agent.last_name,
                    "username": conversation.agent.user_id.username,
                    "email": conversation.agent.email,
                    "profile_image": f"{settings.HOST}{conversation.agent.profile_image.url}"
                    if conversation.agent.profile_image else None,
                    "role": conversation.agent.role_id.roles if conversation.agent.role_id else "N/A"
                }

            # Only proceed if at least one of the details (user or agent) is non-empty
            if user_details or agent_details:
                # Create a unique key based on user_details and agent_details
                conversation_key = (frozenset(user_details.items()), frozenset(agent_details.items()))

                if conversation_key not in grouped_conversations:
                    # Initialize a new group for this user-agent pair
                    grouped_conversations[conversation_key] = {
                        "id": conversation.conversation_id,
                        "user_details": user_details,
                        "agent_details": agent_details,
                        "messages": [],
                    }

                # Retrieve the messages for this conversation
                conversation_messages = messages.filter(
                    Q(sender=conversation.user, receiver=conversation.agent) |
                    Q(sender=conversation.agent, receiver=conversation.user)
                ).order_by('-timestamp')

                # Check if there are messages and fetch the last message
                if conversation_messages.exists():
                    last_message = conversation_messages.first()
                    last_message_content = last_message.message_content
                    last_message_timestamp = last_message.timestamp
                    message_type = last_message.message_type
                    time_ago_req = humanize.naturaltime(last_message_timestamp)

                    # Add last message details
                    grouped_conversations[conversation_key]["last_message"] = {
                        "content": last_message_content,
                        "time_ago": time_ago_req,
                        "message_type": message_type,
                        "unread_message_count": conversation_messages.filter(is_seen=False).count(),
                    }

                    # Add conversation messages to the group
                    grouped_conversations[conversation_key]["messages"].extend(
                        [{
                            **message_data,
                            'message_content': f"{settings.HOST}/media/{message_data['message_content']}"
                            if message_data['message_type'] == "image" else message_data['message_content'],
                            "time_ago": humanize.naturaltime(message_data['timestamp'])
                        } for message_data in conversation_messages.values(
                            'sender', 'receiver', 'message_type', 'message_content',
                            'status', 'is_seen', 'is_send_by_agent', 'timestamp'
                        )]
                    )

                else:
                    # If no messages found for the conversation
                    grouped_conversations[conversation_key]["last_message"] = {
                        "content": "No messages",
                        "time_ago": "N/A",
                    }

        # Convert grouped conversations into a list of data
        for group in grouped_conversations.values():
            data.append({
                "conversations": group
            })

        return APIResponse.HTTP_200_OK(message="Messages fetched successfully.", data=data)

    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"Error fetching messages: {str(e)}")


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_conversation_messages_by_conversation_id(request):
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin", "Agent"]

    try:
        # Retrieve the user
        user = User.objects.get(user_id=user_instance.id)
    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")

    # Validate the user's role
    role = getattr(user.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")

    conversation_id = request.query_params.get('id', None)

    conversations = MessageConversation.objects.filter(conversation_id=conversation_id).all()

    if not conversations.exists():
        return APIResponse.HTTP_404_NOT_FOUND(message="No conversations found!")

    # Fetch messages for the given conversation
    user_conversations = conversations.values('user')
    agent_conversations = conversations.values('agent')

    # Retrieve the messages between user and agent
    messages = Message.objects.filter(
        Q(sender__in=user_conversations) & Q(receiver__in=agent_conversations) |
        Q(sender__in=agent_conversations) & Q(receiver__in=user_conversations),
        status='sent'
    ).order_by('-timestamp')

    if not messages.exists():
        return APIResponse.HTTP_404_NOT_FOUND(message="No messages found for this user.")

    # Prepare the data for the response
    try:
        # Mark all messages as seen for this user
        messages.update(is_seen=True)

        data = {}
        for conversation in conversations:
            # Get user and agent details
            user_details = {
                **conversation.user.to_dict()
            }

            agent_details = {
                **conversation.agent.to_dict()
            }

            # Retrieve messages for this specific conversation
            conversation_messages = messages.filter(
                Q(sender=conversation.user, receiver=conversation.agent) |
                Q(sender=conversation.agent, receiver=conversation.user)
            ).order_by('-timestamp')

            # Last message and time calculation
            if conversation_messages.exists():
                last_message = conversation_messages.first()
                last_message_content = last_message.message_content
                last_message_timestamp = last_message.timestamp
                message_type = last_message.message_type
                time_ago_req = humanize.naturaltime(last_message_timestamp)

                # Append conversation data with messages
                data = {
                    "conversations": {
                        "id": conversation.conversation_id,
                        "user_details": user_details,
                        "agent_details": agent_details,
                        "last_message": {
                            "content": last_message_content if last_message_content else "No messages",
                            "time_ago": time_ago_req,
                            'message_type': message_type,
                            "unread_message_count": conversation_messages.filter(is_seen=False).count()
                        },
                        "messages": [
                            {
                                **message_data,
                                'message_content': f"{settings.HOST}/media/{message_data['message_content']}"
                                if message_data['message_type'] == "image" else message_data['message_content'],
                                "time_ago": humanize.naturaltime(message_data['timestamp'])
                            }
                            for message_data in conversation_messages.values(
                                'sender', 'receiver', 'message_type', 'message_content',
                                'status', 'is_seen', 'is_send_by_agent', 'timestamp'
                            )
                        ]
                    },
                }
            else:
                data = {
                    "conversations": {
                        "id": conversation.conversation_id,
                        "user_details": user_details,
                        "agent_details": agent_details,
                        "last_message": "No messages",
                        "time_ago": "N/A",
                    },
                    "messages": []
                }
        return APIResponse.HTTP_200_OK(message="Messages fetched successfully.", data=data)

    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"Error fetching messages: {str(e)}")


import os
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from django.conf import settings
import humanize


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def send_message_to_agent(request):
    """
    API endpoint to send a message to a conversation.
    """

    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(
            message="Invalid or missing authentication token."
        )

    # Allowed roles
    allowed_roles = ["Admin", "Agent"]

    try:
        user = User.objects.get(user_id=user_instance.id)
    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")

    # Validate user's role
    role = getattr(user.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(
            message=f"User role '{role}' is not authorized."
        )

    # Extract data from the request
    sender_id = request.data.get("sender_id")
    receiver_id = request.data.get("receiver_id")
    conversation_id = request.data.get("conversation_id")
    message_type = request.data.get("message_type", "text")

    # Handle Image Upload
    message_content = request.data.get("message_content")  # Default for text messages
    if message_type == "image" and "message_content" in request.FILES:
        uploaded_file = request.FILES["message_content"]
        file_path = f"messages/{uploaded_file.name}"
        saved_path = default_storage.save(file_path, ContentFile(uploaded_file.read()))
        message_content = saved_path  # Store relative path in DB

    try:
        sender = User.objects.get(id=sender_id)
        receiver = User.objects.get(id=receiver_id)

        # Set is_send_by_agent flag based on sender/receiver roles
        is_send_by_agent = sender.role_id.roles in ["Agent", "Admin"]

        # Check if conversation already exists
        conversation = MessageConversation.objects.filter(
            user=sender, agent=receiver, conversation_id=conversation_id
        ).first()

        if not conversation:
            # Create a new conversation if none exists
            conversation = MessageConversation.objects.create(
                user=sender, agent=receiver
            )

        # Create message data
        message_data = {
            "message_content": message_content,
            "receiver": receiver,
            "message_type": message_type,
            "is_send_by_agent": is_send_by_agent,
        }

        # Save the message
        form = MessageForm(message_data)
        if form.is_valid():
            message = form.save(sender=sender)
            conversation.last_message_at = message.timestamp
            conversation.save()

            # Prepare response data
            data = {
                "conversations": {
                    "id": conversation.conversation_id,
                    "user_details": {
                        "id": conversation.user.id,
                        "first_name": conversation.user.first_name,
                        "last_name": conversation.user.last_name,
                        "username": conversation.user.user_id.username,
                        "email": conversation.user.email,
                        "profile_image": (
                            f"{settings.HOST}{conversation.user.profile_image.url}"
                            if conversation.user.profile_image
                            else None
                        ),
                        "role": (
                            conversation.user.role_id.roles
                            if conversation.user.role_id
                            else "N/A"
                        ),
                    },
                    "agent_details": {
                        "id": conversation.agent.id,
                        "first_name": conversation.agent.first_name,
                        "last_name": conversation.agent.last_name,
                        "username": conversation.agent.user_id.username,
                        "email": conversation.agent.email,
                        "profile_image": (
                            f"{settings.HOST}{conversation.agent.profile_image.url}"
                            if conversation.agent.profile_image
                            else None
                        ),
                        "role": (
                            conversation.agent.role_id.roles
                            if conversation.agent.role_id
                            else "N/A"
                        ),
                    },
                    "messages": [
                        {
                            "message_id": message.message_id,
                            "sender": message.sender.user_id.username,
                            "receiver": message.receiver.user_id.username,
                            "message_content": (
                                f"{settings.HOST}/media/{message.message_content}"
                                if message_type == "image"
                                else message.message_content
                            ),
                            "status": message.status,
                            "timestamp": humanize.naturaltime(message.timestamp),
                            "message_type": message.message_type,
                            "is_send_by_agent": message.is_send_by_agent,
                        },
                    ],
                    "last_message": {
                        "content": (
                            f"{settings.HOST}/media/{message.message_content}"
                            if message_type == "image"
                            else message.message_content
                        ),
                        "time_ago": humanize.naturaltime(message.timestamp),
                        "message_type": message.message_type,
                        "unread_message_count": 1,
                    },
                }
            }

            return APIResponse.HTTP_201_CREATED(
                message="Message sent successfully.", data=[data]
            )
        else:
            return APIResponse.HTTP_400_BAD_REQUEST(
                message="Invalid data", data=form.errors
            )

    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="Receiver not found.")
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(
            message=f"An unexpected error occurred: {str(e)}"
        )


## Admin Game Panel Management System

############################################################################################################

## Spin Wheel Management System
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_spin_wheel(request):
    user_instance = AuthService.get_user_from_token(request)      # Authenticate and fetch the user
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")
    allowed_roles = ["Admin" ,"Agent","User"]                                     # Allowed roles
    current_user = User.objects.get(user_id=user_instance.id)
    role = getattr(current_user.role_id, "roles", None)           # Validate the user's role
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")
    try:
        spins = Spin.objects.all()
        if not spins:                                             # Check if no spins exist
            return APIResponse.HTTP_404_NOT_FOUND(message="Spin wheel not found.")
        data = []                                                  # Prepare the data for each spin
        for spin in spins:
            spin_data = {
                "id": str(spin.id),
                "prizes": [
                    {
                        "prize_id": prize.prize_id,
                        "name": prize.name,
                        "quantity": prize.quantity,
                        "image": prize.image.url if prize.image else None,  # Assuming the image field is present
                        "probability": prize.probability,
                        "is_active": prize.is_active
                    }
                    for prize in spin.prizes_id.all()
                ],
                "last_spin_checked": spin.last_spin_checked,
                "spin_history": [
                    {
                        "history_id": str(history.id),
                        "prize_name": history.prize_id.name,
                        "created_at": history.created_at
                    }
                    for history in spin.spin_history_id.all()
                ],
            }
            data.append(spin_data)
        return APIResponse.HTTP_200_OK(
            message="Spin retrieved successfully.",
            data=data
        )

    except Exception as e:
        logging.error(f"Error in get_spin_wheel API: {str(e)}")
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(
            message=f"An unexpected error occurred: {str(e)}"
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def spin_history(request):
    user_instance = AuthService.get_user_from_token(request)              # Authenticate and fetch the user
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")
    allowed_roles = ["Admin","Agent","User"]                              # Allowed roles
    current_user = User.objects.get(user_id=user_instance.id)
    role = getattr(current_user.role_id, "roles", None)                   # Validate the user's role
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")
    try:
        spins_history = SpinHistory.objects.all()                          # Fetch all records from SpinHistory
        if not spins_history:
            return APIResponse.HTTP_404_NOT_FOUND(message="Spin history not found.")
        data = []                                                          # Prepare the data for each spin history
        for spin in spins_history:
            spin_data = {
                "id": str(spin.id),
                "prize": {                                            # prize is a ForeignKey, so access it directly
                    "prize_id": spin.prize_id.prize_id,               # Accessing prize_id from related Prize model
                    "name": spin.prize_id.name,
                    "quantity": spin.prize_id.quantity,
                    "image": spin.prize_id.image.url if spin.prize_id.image else None,
                    "probability": spin.prize_id.probability,
                    "is_active": spin.prize_id.is_active
                },
                "created_at": spin.created_at                        # Include the creation timestamp
            }
            data.append(spin_data)
        return APIResponse.HTTP_200_OK(
            message="Spin history retrieved successfully.",
            data=data
        )

    except Exception as e:
        logging.error(f"Error in spin_history API: {str(e)}")
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(
            message=f"An unexpected error occurred: {str(e)}"
        )


## Spin Wheel Management System

############################################################################################################


# Prize Management URLs
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_prizes(request):
    """
    Get all prizes

    This endpoint will get only token of admin and agent
    if not authorized then return 403
    if token is invalid then return 401
    """
    user_instance = AuthService.get_user_from_token(request)              # Authenticate and fetch the user
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")
    allowed_roles = ["Admin", "Agent"]                                    # Allowed roles
    current_user = User.objects.get(user_id=user_instance.id)
    role = getattr(current_user.role_id, "roles", None)                   # Validate the user's role
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")
    try:
        prizes = Prize.objects.all()[:10]                                  # Get prizes, limited to 10 items
        data = [
            {
                "id": prize.id,
                "prize_id": prize.prize_id,
                "name": prize.name,
                "quantity": prize.quantity,
                "probability": prize.probability,
                "is_active": prize.is_active,
                "image": prize.image.url if prize.image else None,
            }
            for prize in prizes
        ]
        return APIResponse.HTTP_200_OK(message="Prizes retrieved successfully.", data=data)
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_prize(request):
    user_instance = AuthService.get_user_from_token(request)            # Authenticate and fetch the user
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")
    allowed_roles = ["Admin", "Agent"]                                  # Allowed roles
    current_user = User.objects.get(user_id=user_instance.id)
    role = getattr(current_user.role_id, "roles", None)                 # Validate the user's role
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")
    try:
        prize_id = request.data.get('prize_id')
        prize = Prize.objects.filter(id=prize_id).first()                # Fetch the prize by ID
        if not prize:
            return APIResponse.HTTP_404_NOT_FOUND(message="Prize not found.")
        prize.delete()
        data = {
            "id": prize.id,
            "prize_id": prize.prize_id,
            "name": prize.name,
            "quantity": prize.quantity,
            "probability": prize.probability,
        }
        return APIResponse.HTTP_200_OK(message="Prize deleted successfully.", data=data)
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_prize(request):
    ##
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")
    # print(f"user_instance: {user_instance}")
    # Allowed roles
    allowed_roles = ["Admin", "Agent"]
    # print(f"user_instance.role_id: {user_instance.id}")
    current_user = User.objects.get(user_id=user_instance.id)

    # Validate the user's role
    role = getattr(current_user.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")
    # print(f"Authenticated user's role: {user_role}")
    ##
    try:
        prize_id = request.data.get('prize_id')

        # Fetch the prize by ID
        prize = Prize.objects.filter(id=prize_id).first()

        if not prize:
            return APIResponse.HTTP_404_NOT_FOUND(message="Prize not found.")

        # Initialize the form with the prize instance and request data
        form = UpdatePrizeForm(request.data, instance=prize)

        if form.is_valid():
            prize = form.save()
            return APIResponse.HTTP_200_OK(message="Prize updated successfully.", data={"prize_id": prize.id})
        else:
            return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid data", data=form.errors)

    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def get_prize_by_id(request):
    user_instance = AuthService.get_user_from_token(request)    # Authenticate and fetch the user
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")
    allowed_roles = ["Admin", "Agent"]                        # Allowed roles
    current_user = User.objects.get(user_id=user_instance.id)
    role = getattr(current_user.role_id, "roles", None)       # Validate the user's role
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")
    try:
        prize_id = request.data.get('prize_id')
        prize = Prize.objects.filter(id=prize_id).first()
        if not prize:
            return APIResponse.HTTP_404_NOT_FOUND(message="Prize not found.")
        data = {
            "prize_id": prize.prize_id,
            "name": prize.name,
            "quantity": prize.quantity,
            "probability": prize.probability,
            "is_active": prize.is_active,
            "image": prize.image.url if prize.image else None,
        }
        return APIResponse.HTTP_200_OK(message="Prize retrieved successfully.", data=data)
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_prize(request):
    user_instance = AuthService.get_user_from_token(request)    # Authenticate and fetch the user
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")
    allowed_roles = ["Admin", "Agent"]                          # Allowed roles
    current_user = User.objects.get(user_id=user_instance.id)
    role = getattr(current_user.role_id, "roles", None)          # Validate the user's role
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")
    try:
        # Initialize the form with both request data and files (to handle file uploads)
        form = CreatePrizeForm(request.data, files=request.FILES)
        if form.is_valid():
            result = form.save()
            data = {
                "id": result.id,
                "prize_id": result.prize_id,
                "name": result.name,
                "quantity": result.quantity,
                "probability": result.probability,
            }

            return APIResponse.HTTP_200_OK(message="Prize created successfully.", data=data)
        else:
            return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid data", data=form.errors)

    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")




############################################################################################################
# Promo Code Management System
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_promo_codes(request):
    user_instance = AuthService.get_user_from_token(request)                        # Authenticate and fetch the user
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")
    user = AuthService.validate_user_role(user_instance, "User")
    if not user:
        return APIResponse.HTTP_404_NOT_FOUND("User not found with token")
    limit = int(request.GET.get('limit', 10))
    promos = PromoCode.objects.filter(sender_user_id=user.id).all().order_by('-promo_code_created_at')[:limit]
    if not promos.exists():
        return APIResponse.HTTP_404_NOT_FOUND(message="No promo codes found.")
    try:
        data = []
        for promo in promos:
            receiver_obj = promo.receiver_user_id                             # Get receiver user details if available
            res = {
                "id": str(promo.id),
                "promo_code": promo.promo_code,
                "bonus_percentage": promo.bonus_percentage,
                "promo_code_created_at": promo.promo_code_created_at,
                "is_expired": promo.is_expired,
                "users": {
                    "sender": {
                        "id": str(user.id) if user else None,
                        "username": user.user_id.username if user else None,
                        "first_name": user.first_name if user else None,
                        "last_name": user.last_name if user else None,
                        "email": user.email if user else None,
                        "phone_number": user.phone if user else None,
                        "profile_image": user.profile_image.url if user and user.profile_image else None,
                    },
                    "receiver": {
                        "id": str(receiver_obj.id) if receiver_obj else None,
                        "username": receiver_obj.user_id.username if receiver_obj else None,
                        "first_name": receiver_obj.first_name if receiver_obj else None,
                        "last_name": receiver_obj.last_name if receiver_obj else None,
                        "email": receiver_obj.email if receiver_obj else None,
                        "phone_number": receiver_obj.phone if receiver_obj else None,
                        "profile_image": receiver_obj.profile_image.url if receiver_obj and
                                                                           receiver_obj.profile_image else None,
                    } if receiver_obj else None
                }
            }
            data.append(res)
        return APIResponse.HTTP_200_OK(message="Promo codes retrieved successfully.", data=data)
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def get_promo_code_by_id(request):
    user_instance = AuthService.get_user_from_token(request)                     # Authenticate and fetch the user
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")
    user = AuthService.validate_user_role(user_instance, "User")
    if not user:
        return APIResponse.HTTP_404_NOT_FOUND("User not found with token")
    promo_id = request.query_params.get('promo_id')
    promo = get_object_or_404(PromoCode, id=promo_id, sender_user_id=user.id)
    try:
        data = {
            "id": str(promo.id),
            "promo_code": promo.promo_code,
            "bonus_percentage": promo.bonus_percentage,
            "promo_code_created_at": promo.promo_code_created_at,
            "users": {
                "sender": {
                    "id": str(promo.sender_user_id.id),
                    "username": promo.sender_user_id.user_id.username,
                    "first_name": promo.sender_user_id.first_name,
                    "last_name": promo.sender_user_id.last_name,
                    "email": promo.sender_user_id.email,
                    "phone_number": promo.sender_user_id.phone,
                    "profile_image": promo.sender_user_id.profile_image.url
                    if promo.sender_user_id.profile_image else None,
                } if promo.sender_user_id else None,
                "receiver": {
                    "id": str(promo.receiver_user_id.id) if promo.receiver_user_id else None,
                    "username": promo.receiver_user_id.user_id.username if promo.receiver_user_id else None,
                    "first_name": promo.receiver_user_id.first_name if promo.receiver_user_id else None,
                    "last_name": promo.receiver_user_id.last_name if promo.receiver_user_id else None,
                    "email": promo.receiver_user_id.email if promo.receiver_user_id else None,
                    "phone_number": promo.receiver_user_id.phone if promo.receiver_user_id else None,
                    "profile_image": promo.receiver_user_id.profile_image.url
                    if promo.receiver_user_id and promo.receiver_user_id.profile_image else None,
                } if promo.receiver_user_id else None
            }
        }
        return APIResponse.HTTP_200_OK(message="Promo code retrieved successfully.", data=data)

    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_promo_code(request):
    user_instance = AuthService.get_user_from_token(request)                 # Authenticate and fetch the user
    if not user_instance:
        return APIResponse.HTTP_400_BAD_REQUEST(message="User not authenticated.")
    auth_user = AuthService.validate_user_role(user_instance, "User")
    if not auth_user:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found with token")
    form = PromoCodeForm(request.data)
    if not form.is_valid():
        return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid data", data=form.errors)
    if PromoCode.objects.filter(sender_user_id=auth_user.id).exists():  # Check if the sender already has a promo code
        return APIResponse.HTTP_400_BAD_REQUEST(message="User already has a promo code.")
    try:
        if form.is_valid():
            uuid_gen = str(uuid.uuid4().hex).upper()
            promo = form.save(commit=False)
            promo.promo_code = uuid_gen
            promo.sender_user_id = auth_user                          # Assign the sender to the promo code
            promo.save()
            # Generate a verification link
            verification_url = (f"http://127.0.0.1:8000/api/v1/promo-code/verify-promo-code/?promo_code="
                                f"{promo.promo_code}")
            # Generate QR code for the verification link
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(verification_url)
            qr.make(fit=True)
            qr_image = qr.make_image(fill_color="black", back_color="white")       # Render the QR code as an image
            qr_folder = os.path.join(settings.MEDIA_ROOT, 'qrcode')      # Ensure the directory exists in the media root
            os.makedirs(qr_folder, exist_ok=True)
            qr_file_path = os.path.join(qr_folder, f"qr_{promo.promo_code}.png")#SavetheQR code tothe 'qrcode' directory
            qr_image.save(qr_file_path)
            qr_code_url = f"{settings.MEDIA_URL}qrcode/qr_{promo.promo_code}.png" # Generate the QR code URL
            response_data = {
                "id": str(promo.id),
                "promo_code": promo.promo_code,
                "bonus_percentage": promo.bonus_percentage,
                "promo_code_created_at": promo.promo_code_created_at,
                "verification_url": verification_url,
                "qr_code": f"data:image/png;base64,{qr_code_url}"
            }
            return APIResponse.HTTP_200_OK(message=f"Promo code created successfully for {auth_user.user_id.username}.",
                                           data=response_data)
        else:
            return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid data", data=form.errors)
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def verify_promo_code(request):
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")
    auth_user = AuthService.validate_user_role(user_instance, "User")              # receiver user
    if not auth_user:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found with token")
    promo_code = request.query_params.get('promo_code') or request.data.get('promo_code')
    promo = PromoCode.objects.filter(promo_code=promo_code).first()
    if not promo:
        return APIResponse.HTTP_404_NOT_FOUND(message="Promo code not found.")
    if not promo.is_expired:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Promo code has expired.")
    if auth_user.id == promo.sender_user_id.id:                      # Check that sender and receiver are not the same
        return APIResponse.HTTP_400_BAD_REQUEST(message="Sender and receiver cannot be the same.")
    if promo.receiver_user_id:                         # Check if the promo code already has a receiver (it should not)
        return APIResponse.HTTP_400_BAD_REQUEST(message="Promo code has already been used.")
    try:
        promo.receiver_user_id = auth_user  # Assign the receiver user to the promo code and mark it as expired
        promo.is_expired = True
        promo.save()
        data = {                                        # Prepare response data
            "id": str(promo.id),
            "promo_code": promo.promo_code,
            "bonus_percentage": promo.bonus_percentage,
            "promo_code_created_at": promo.promo_code_created_at,
            "users": {
                "creator": promo.sender_user_id.user_id.username,
                "receiver": auth_user.user_id.username
            }
        }
        return APIResponse.HTTP_200_OK(message=f"Promo code verified successfully by {auth_user.user_id.username}.",
                                       data=data)
    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="Sender or receiver user not found.")
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_promo_code(request):
    user_instance = AuthService.get_user_from_token(request)                      # Authenticate and fetch the user\
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")
    user = AuthService.validate_user_role(user_instance, "User")
    if not user:
        return APIResponse.HTTP_404_NOT_FOUND("User not found with token")
    promo_id = request.query_params.get('promo_id')
    promo = get_object_or_404(PromoCode, id=promo_id, sender_user_id=user.id)
    try:
        promo.delete()
        data = {
            "id": promo_id,
            "promo_code": promo.promo_code,
            "bonus_percentage": promo.bonus_percentage,
            "promo_code_created_at": promo.promo_code_created_at,
        }
        return APIResponse.HTTP_200_OK(message=f"Promo code deleted successfully by {user.user_id.username}.",
                                       data=data)
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")

# Promo Code Management System

############################################################################################################
# Level Management System
@api_view(['GET'])
def get_levels(request):
    try:
        limit = int(request.GET.get('limit', 10))
        levels = Level.objects.all()[:limit]
        if not levels:
            return APIResponse.HTTP_404_NOT_FOUND(message="No levels found.")
        data = [
            {
                "id": str(level.id),
                "level": level.level,
                "level_code": level.level_code,
                "level_created_at": level.level_created_at,
            }
            for level in levels
        ]
        return APIResponse.HTTP_200_OK(message="Levels retrieved successfully.", data=data)
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['GET'])
def get_level_by_id(request):
    try:
        level_id = request.data.get('level_id')
        level = get_object_or_404(Level, id=level_id)
        return APIResponse.HTTP_200_OK(message="Level retrieved successfully.", data=model_to_dict(level))
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['POST'])
def create_level(request):
    try:
        form = LevelForm(request.data)
        if form.is_valid():
            level = form.save()
            return APIResponse.HTTP_200_OK(
                message="Level created successfully.", data=model_to_dict(level)
            )
        else:
            return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid data", data=form.errors)
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['DELETE'])
def delete_level(request):
    try:
        level_id = request.data.get('level_id')
        level = get_object_or_404(Level, id=level_id)
        if not level:
            return APIResponse.HTTP_404_NOT_FOUND(message="Level not found.")
        level.delete()
        return APIResponse.HTTP_200_OK(message="Level deleted successfully.", data=model_to_dict(level))
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['PUT'])
def update_level(request):
    try:
        level_id = request.data.get('level_id')
        level = get_object_or_404(Level, id=level_id)
        if not level:
            return APIResponse.HTTP_404_NOT_FOUND(message="Level not found.")
        form = LevelForm(request.data, instance=level)
        if form.is_valid():
            updated_level = form.save()
            return APIResponse.HTTP_200_OK(
                message="Level updated successfully.", data=model_to_dict(updated_level)
            )
        else:
            return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid data", data=form.errors)
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


# Level Management System

############################################################################################################

# Referral Management System
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_referral_code(request):
    """
    Create a referral code.
    """

    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)

    # Validate user's role
    user = AuthService.validate_user_role(user_instance, "User")

    # Generate a unique referral key
    referral_key = str(uuid.uuid4().hex).upper()
    random_quantity_between_80_100 = random.randint(80, 100)

    try:

        referral = Referral.objects.create(
            user_id=user,
            quantity=int(random_quantity_between_80_100),
            referral_key=referral_key
        )

        # print(f"""referral: {referral}""")

        data = referral.to_dict()

        return APIResponse.HTTP_200_OK(message="Referral key has been generated successfully.", data=data)
    except ValidationError as e:
        return APIResponse.HTTP_400_BAD_REQUEST(message=f"Validation error: {e}")
    except Referral.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="Referral code not found.")
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An error occurred: {e}")



@api_view(['POST'])
@permission_classes([IsAuthenticated])
def get_referral_codes(request):
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)

    # Validate user's role
    user = AuthService.validate_user_role(user_instance, "User")

    sender_id = user.id

    try:
        user = User.objects.filter(id=sender_id).first()

        if not user:
            return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")

        # Fetch referrals for the user
        referrals_qs = Referral.objects.filter(user_id=user)

        if not referrals_qs.exists():
            return APIResponse.HTTP_404_NOT_FOUND(message="Referral code not found.")

        # Pagination logic
        page = request.GET.get('page', 1)
        limit = request.GET.get('limit', 10)

        paginator = Paginator(referrals_qs, limit)

        try:
            referrals_page = paginator.page(page)
        except PageNotAnInteger:
            referrals_page = paginator.page(1)
        except EmptyPage:
            return APIResponse.HTTP_400_BAD_REQUEST(message="Page number out of range.")

        # Convert paginated results to dictionary format
        referrals_data = [ref.to_dict() for ref in referrals_page]

        data = {
            "referrals": referrals_data,
            "pagination": {
                "current_page": referrals_page.number,
                "has_next": referrals_page.has_next(),
                "has_previous": referrals_page.has_previous(),
                "total_pages": paginator.num_pages,
                "total_items": paginator.count
            }
        }

        return APIResponse.HTTP_200_OK(message="Referral codes retrieved successfully.", data=data)

    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def verify_referral_code(request):
    """
    Verify the provided referral code.
    """
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)

    # Validate user's role
    receiver_user = AuthService.validate_user_role(user_instance, "User")

    referral_key = request.data.get('referral_key')
    if not referral_key:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Referral key is required.")

    # Check if the referral key exists
    ref = Referral.objects.filter(referral_key=referral_key).first()
    if not ref:
        return APIResponse.HTTP_404_NOT_FOUND(message="Referral key not found.")

    user = User.objects.filter(id=receiver_user.id).first()

    # Ensure sender and receiver are not the same
    if ref.user_id.id == user.id:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Sender and receiver cannot be the same.")

    # Check if the receiver has already used this referral key
    if ref.receiver_user_id.filter(id=receiver_user.id).exists():
        return APIResponse.HTTP_400_BAD_REQUEST(message="User has already used this referral key.")

    try:

        # Add the receiver user to the referral
        ref.receiver_user_id.add(receiver_user)
        ref.save()

        # Split the referral quantity
        total_quantity = ref.quantity  # Assume this is 100 for example
        receiver_amount = total_quantity * Decimal('0.8')  # 80%
        sender_amount = total_quantity * Decimal('0.2')  # 20%

        # Update the receiver's wallet
        if hasattr(receiver_user, 'wallet_id'):
            receiver_wallet = receiver_user.wallet_id
            receiver_wallet.current_balance += receiver_amount
            receiver_wallet.total_amount += receiver_amount
            receiver_wallet.save()
        else:
            return APIResponse.HTTP_400_BAD_REQUEST(message="Receiver user does not have a wallet.")

        # Update the sender's wallet
        sender_user = ref.user_id
        if hasattr(sender_user, 'wallet_id'):
            sender_wallet = sender_user.wallet_id
            sender_wallet.current_balance += sender_amount
            sender_wallet.total_amount += sender_amount
            sender_wallet.save()
        else:
            return APIResponse.HTTP_400_BAD_REQUEST(message="Sender user does not have a wallet.")

        # Prepare response data
        data = {
            "id": str(ref.id),
            "sender_user": {
                "id": str(sender_user.id),
                "username": sender_user.user_id.username,
                "email": sender_user.email,
                "amount_added": sender_amount,
            },
            "quantity": ref.quantity,
            "referral_key": ref.referral_key,
            "receiver_user": {
                "id": str(receiver_user.id),
                "username": receiver_user.user_id.username,
                "email": receiver_user.email,
                "amount_added": receiver_amount,
            },
            "referral_created_at": ref.referral_created_at,
            "referral_expiry_date": ref.referral_expiry_date,
        }

        return APIResponse.HTTP_200_OK(message="Referral key verified and amounts added to wallets.", data=data)

    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An error occurred: {str(e)}")



@api_view(['POST'])
@permission_classes([IsAuthenticated])
def get_all_referrals_by_username(request):
    """
    Retrieve all referrals associated with the given username.
    """
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)

    # Validate user's role
    sender_user = AuthService.validate_user_role(user_instance, "User")

    username = sender_user.user_id.username

    user = User.objects.filter(user_id__username=username).first()
    if not user:
        return APIResponse.HTTP_404_NOT_FOUND(message=f"No user found with {username}")

    referrals = Referral.objects.filter(user_id=sender_user.id)

    if not referrals.exists():
        return APIResponse.HTTP_404_NOT_FOUND(f"No referrals found for user '{username}'.")
    try:
        data = [
            {
                "id": str(ref.id),
                "sender_user_id": {
                    "id": ref.user_id.id,
                    "username": ref.user_id.user_id.username,
                    "email": ref.user_id.email,
                },
                "referral_key": ref.referral_key,
                "quantity": ref.quantity,
                "receiver_user_id": [
                    {
                        "id": receiver.id,
                        "username": receiver.user_id.username,
                        "email": receiver.email,
                    }
                    for receiver in ref.receiver_user_id.all()
                ],
                "referral_created_at": ref.referral_created_at.strftime('%Y-%m-%d %H:%M:%S'),
            }
            for ref in referrals
        ]
        return APIResponse.HTTP_200_OK(message=f"Referrals retrieved successfully for user '{username}'.", data=data)

    except Exception as e:
        return APIResponse.HTTP_400_BAD_REQUEST(f"An error occurred: {e}")


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_all_referrals(request):
    """
        Deletes all referral records from the database base on the user_id.
    """

    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)

    # Validate user's role
    sender_user = AuthService.validate_user_role(user_instance, "User")

    user_id = sender_user.id

    all_referrals = Referral.objects.filter(user_id=user_id)
    total_referrals = all_referrals.count()

    try:

        data = [all_referrals.to_dict() for all_referrals in all_referrals]

        all_referrals.delete()

        return APIResponse.HTTP_200_OK(message=f"All {total_referrals} referrals have been deleted successfully.",
                                       data=data)

    except Referral.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="No referrals found to delete.")
    except Exception as e:
        return APIResponse.HTTP_400_BAD_REQUEST(message=f"An error occurred while deleting referrals: {e}")


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_referral_by_key(request):
    """
        Deletes a referral record based on the referral key.
    """
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)

    # Validate user's role
    sender_user = AuthService.validate_user_role(user_instance, "User")

    referral_key = request.data.get('referral_key')
    if not referral_key:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Referral key is required.")

    referral = Referral.objects.filter(referral_key=referral_key, user_id=sender_user.id).first()
    if not referral:
        return APIResponse.HTTP_404_NOT_FOUND(message=f"No Referral found with key{referral_key}")

    user = referral.user_id

    try:
        data = {
            "sender_user_id": user.to_dict() if user else None,
            "receiver_user_id": [receiver.to_dict() for receiver in referral.receiver_user_id.all()],
            "referral": referral.to_dict(),
        }
        referral.delete()

        return APIResponse.HTTP_200_OK(message=f"Referral with key '{referral_key}' has been deleted successfully.",
                                       data=data)
    except Referral.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message=f"No Referral found with key {referral_key}")
    except Exception as e:
        return APIResponse.HTTP_400_BAD_REQUEST(f"An error occurred: {e}")


# Referral Management System


############################################################################################################

# Wallet Management System
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_account_wallet(request):
    """
    Get details of the user's wallet.
    """
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")
    auth_user = AuthService.validate_user_role(user_instance, "User")
    if not auth_user:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found with token")
    user_id = auth_user.id
    username = request.GET.get('username')
    user = User.objects.filter(id=user_id).first()
    username = User.objects.filter(user_id__username=username).first()
    if user or username:
        user = user or username
    if not user:
        return APIResponse.HTTP_400_BAD_REQUEST(message="User ID or username is invalid.")
    wallet = user.wallet_id
    if not wallet:
        return APIResponse.HTTP_404_NOT_FOUND(message="Wallet not found.")
    try:
        data = wallet.to_dict()
        return APIResponse.HTTP_200_OK(message="Wallet retrieved successfully.", data=data)
    except Exception as e:
        return APIResponse.HTTP_400_BAD_REQUEST(message=f"An error occurred: {e}")


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_transaction_history(request):
    """
    Get wallet transaction history.
    """
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")
    auth_user = AuthService.validate_user_role(user_instance, "User")  # receiver user
    if not auth_user:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found with token")
    limit = int(request.GET.get('limit', 10))
    wallet = Wallet.objects.filter(id=auth_user.wallet_id.id).first()
    if not wallet:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Wallet not found.")
    transactions = wallet.wallet_transaction_history_id.all()[:limit]
    try:
        paginator = Paginator(transactions, limit)
        page_number = request.GET.get('page')
        page_obj = paginator.get_page(page_number)
        data = {
            "wallet_id": str(wallet.id),
            "current_balance": wallet.current_balance,
            "total_amount": wallet.total_amount,
            "last_transaction_date": wallet.last_transaction_date.strftime(
                '%Y-%m-%d %H:%M:%S') if wallet.last_transaction_date else None,
            "withdrawal_percentage_tax": wallet.withdrawal_percentage_tax,
            "order_id": wallet.order_id,
            "wallet_transaction_history": [
                {
                    "id": str(tx.id),
                    "payment_method": tx.payment_method,
                    "transaction_amount": tx.transaction_amount,
                    "payment_status": tx.payment_status,
                    "payment": tx.payment,
                    "transaction_date": tx.transaction_date.strftime('%Y-%m-%d %H:%M:%S')
                } for tx in page_obj
            ],
            "pagination": {
                "next": page_obj.next_page_number() if page_obj.has_next() else None,
                "previous": page_obj.previous_page_number() if page_obj.has_previous() else None,
                "count": paginator.count,
                "total_pages": paginator.num_pages,
                "current_page": page_obj.number,
            }
        }

        return APIResponse.HTTP_200_OK(message="Transaction history retrieved successfully.", data=data)
    except Exception as e:
        return APIResponse.HTTP_400_BAD_REQUEST(message=f"An error occurred: {e}")


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def pay_by_link(request):
    """
    Generate a payment link and a corresponding QR code for a transaction.
    """
    user_instance = AuthService.get_user_from_token(request)
    auth_user = AuthService.validate_user_role(user_instance, "User")  # receiver user
    wallet_id = request.data.get('wallet_id')
    transaction_amount = request.data.get('transaction_amount')
    payment_method = request.data.get('payment_method')
    if not all([wallet_id, transaction_amount, payment_method]):
        return APIResponse.HTTP_400_BAD_REQUEST(
            message="All fields (wallet_id, transaction_amount, payment_method) are required."
        )

    wallet = get_object_or_404(Wallet, id=wallet_id)
    user = User.objects.filter(id=auth_user.id, wallet_id=wallet).all()

    if not user:
        return APIResponse.HTTP_400_BAD_REQUEST(
            message="User has not wallet, please create the Wallet first."
        )
    try:
        order_id = str(uuid.uuid4().hex).upper()
        data = {
            'payment_method': payment_method,
            'payment_status': 'Pending',
            'transaction_amount': transaction_amount,
            'payment': 'Debit',
            'order_id': order_id,
        }
        form = WalletTransactionHistoryForm(data)
        if form.is_valid():
            transaction_form = form.save()
            wallet.wallet_transaction_history_id.add(transaction_form)
            wallet.last_transaction_date = transaction_form.transaction_date
            transaction_form.order_id = data['order_id']
            # Generate payment link
            payment_link = f"{settings.PAYMENT_BASE_URL_LINK}/?order-id={transaction_form.order_id}"
            # Generate QR code for the payment link
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(payment_link)
            qr.make(fit=True)
            qr_image = qr.make_image(fill_color="black", back_color="white")  # Render the QR code as an image
            qr_folder = os.path.join(settings.MEDIA_ROOT, 'qrcode')   # Ensure the directory exists in the media root
            os.makedirs(qr_folder, exist_ok=True)
            qr_file_path = os.path.join(qr_folder, f"qr_{transaction_form.order_id}.png")
            qr_image.save(qr_file_path)

            # Generate the QR code URL
            qr_code_url = f"{settings.MEDIA_URL}qrcode/qr_{transaction_form.order_id}.png"
            wallet.save()

            payment_signal.send(
                sender=Wallet,
                user=auth_user,
                notification_type="Pay by link",
                message="Pay by link and QR Code has been generated"
            )

            data = {
                "order_id": transaction_form.order_id,
                "transaction_history_id": str(transaction_form.id),
                "payment_link": payment_link,
                "qr_code_url": f"{settings.HOST}{qr_code_url}",
            }

            return APIResponse.HTTP_200_OK(message="Payment link and QR code generated successfully.", data=data)
        else:
            return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid data for transaction.")
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An error occurred: {e}")


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def verify_payment_by_order_id(request):
    """
    Verify payment by its ID.
    """
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    user = AuthService.validate_user_role(user_instance, "User")  # receiver user

    order_id = request.query_params.get('order_id')

    if not order_id:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Payment ID is invalid.")

    print(f"user.wallet_id: {user.wallet_id}")
    wallet = Wallet.objects.filter(id=user.wallet_id.id, order_id=order_id).first()
    print(f"wallet: {wallet}")

    if wallet is None:
        return APIResponse.HTTP_404_NOT_FOUND(
            message="Wallet or order id not found."
                    "Please check the order ID or create a wallet account first."
        )
    transaction_history = wallet.wallet_transaction_history_id.all()
    if not transaction_history.exists():
        return APIResponse.HTTP_404_NOT_FOUND(message="No transaction history found for this order ID.")
    try:
        transactions = [                        # Build the transaction history data
            {
                "id": str(tx.id),
                "payment_method": tx.payment_method,
                "transaction_amount": tx.transaction_amount,
                "payment_status": tx.payment_status,
                "payment": tx.payment,
                "transaction_date": tx.transaction_date.strftime('%Y-%m-%d %H:%M:%S'),
            }
            for tx in transaction_history
        ]
        data = {                               # Build the wallet data for the response
            "wallet_id": str(wallet.id),
            "current_balance": wallet.current_balance,
            "total_amount": wallet.total_amount,
            "last_transaction_date": wallet.last_transaction_date.strftime(
                '%Y-%m-%d %H:%M:%S') if wallet.last_transaction_date else None,
            "withdrawal_percentage_tax": wallet.withdrawal_percentage_tax,
            "order_id": wallet.order_id,
            "user": {
                "id": user.id,
                "username": user.user_id.username,
                "first_name": user.first_name,
                "last_name": user.last_name
            },
            "wallet_transaction_history": transactions,

        }
        return APIResponse.HTTP_200_OK(message="Transaction history retrieved successfully.", data=data)
    except Exception as e:
        return APIResponse.HTTP_400_BAD_REQUEST(message=f"An error occurred: {e}")


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def withdraw_money_from_user_account_wallet(request):
    """
    Admin only: Withdraw money from a user's wallet.
    """
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    user = AuthService.validate_user_role(user_instance, "User")  # receiver user
    form = WalletTransactionHistoryFormUpdated(request.data)
    if not form.is_valid():
        return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid data", data=form.errors)
    wallet_id = user.wallet_id.id
    transaction_amount = form.cleaned_data['transaction_amount']
    payment_method = form.cleaned_data['payment_method']
    if not transaction_amount or not payment_method:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Missing required fields.")
    wallet = Wallet.objects.filter(id=wallet_id).first()
    if not wallet:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Wallet not found.")
    if wallet.total_amount <= 0:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Wallet balance is empty.")
    try:
        # Calculate the maximum withdrawal limit (5x the current balance)
        current_balance = wallet.current_balance
        max_withdrawal_amount = current_balance * 5
        if transaction_amount > max_withdrawal_amount:
            return APIResponse.HTTP_400_BAD_REQUEST(
                message=f"Transaction amount must be less than or equal to {max_withdrawal_amount} "
                        f"(5 times the current balance)."
            )
        # Calculate withdrawal tax
        withdrawal_tax = transaction_amount * (wallet.withdrawal_percentage_tax / 100)\
        # Check if the wallet has enough balance for the tax
        if ((transaction_amount + withdrawal_tax) > wallet.total_amount > 0 and
                0 < wallet.current_balance < (transaction_amount + withdrawal_tax)):
            return APIResponse.HTTP_400_BAD_REQUEST(
                message=f"Insufficient wallet balance. Total and current amount must cover the "
                        f"withdrawal amount and the tax.",
                data={
                    "transaction_amount": transaction_amount,
                    "withdrawal_tax": withdrawal_tax,
                    "wallet": wallet.to_dict(),
                }
            )
        # Deduct the tax directly from the wallet balance, and update the current balance
        wallet.total_amount -= (withdrawal_tax + transaction_amount)
        wallet.current_balance -= (withdrawal_tax + transaction_amount)
        wallet.last_transaction_date = datetime.now()
        # Generate a unique order ID
        order_id = str(uuid.uuid4().hex).upper()
        # Create a transaction history object
        transaction_obj = WalletTransactionHistory.objects.create(
            payment_method=payment_method,
            payment_status="Approved",
            transaction_amount=transaction_amount,
            payment="Debit",
            order_id=order_id,
            withdrawal_percentage_tax=wallet.withdrawal_percentage_tax,
        )
        # Update wallet and associate transaction history
        wallet.wallet_transaction_history_id.add(transaction_obj)
        wallet.order_id = transaction_obj.order_id
        wallet.save()
        # Prepare response data
        data = {
            "transaction_amount": transaction_amount,
            "withdrawal_tax": withdrawal_tax,
            "wallet_id": wallet_id,
            "payment_method": payment_method,
            "last_transaction_date": wallet.last_transaction_date.strftime('%Y-%m-%d %H:%M:%S'),
            "previous_balance": current_balance,
            "current_balance": wallet.current_balance,
            "user": user.to_dict(),
        }

        payment_signal.send(
            sender=Wallet,
            user=user,
            notification_type = "Withdraw money from user Account",
            message = "Withdraw money from user Account successfully"
        )

        return APIResponse.HTTP_200_OK(
            message=f"Withdrew money from user wallet successfully by {user.user_id.username}.",
            data=data
        )
    except Exception as e:
        return APIResponse.HTTP_400_BAD_REQUEST(message=f"An error occurred: {e}")


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def deposit_money_to_user_account_wallet(request):
    """
    Admin only: Add money to a user's wallet.
    """
    user_instance = AuthService.get_user_from_token(request)
    user = AuthService.validate_user_role(user_instance, "User")  # Receiver user

    form = WalletTransactionHistoryFormUpdated(request.data)
    if not form.is_valid():
        return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid data", data=form.errors)

    wallet = user.wallet_id
    if not wallet:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Wallet not found.")

    transaction_amount = form.cleaned_data['transaction_amount']
    payment_method = form.cleaned_data['payment_method']
    payment = request.data.get('payment')

    if transaction_amount < 5:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Transaction amount must be greater than $5.")

    try:
        # Card Payment Verification
        if payment == "Card" and (not user.driving_license_front_image or
                                  not user.driving_license_back_image or
                                  not user.is_verified_license):
            return APIResponse.HTTP_400_BAD_REQUEST(
                message="User is not verified. Please verify your driving license or relevant documents."
            )

        previous_balance = wallet.current_balance
        has_received_bonus = Bonus.objects.filter(user_id=user).exists()  # Check if the user already got a bonus

        # ✅ First-time deposit validation: Minimum $50 required
        if previous_balance == 0 and not has_received_bonus:
            if transaction_amount < 50:
                return APIResponse.HTTP_400_BAD_REQUEST(
                    message="First-time deposit must be at least $50."
                )

            # First deposit with bonus (double the deposit)
            bonus = Bonus.objects.create(user_id=user, amount=transaction_amount)
            wallet.current_balance = transaction_amount * 2
            print("Bonus applied: First-time deposit doubled.")
        else:
            # ✅ Subsequent deposits: No bonus, just add amount normally
            wallet.current_balance += transaction_amount
            bonus = None
            print("No bonus applied. Regular deposit.")

        wallet.total_amount = wallet.current_balance
        wallet.last_transaction_date = datetime.now()

        # Create transaction record
        order_id = str(uuid.uuid4().hex).upper()
        transaction_obj = WalletTransactionHistory.objects.create(
            payment_method=payment_method,
            payment_status="Approved",
            transaction_amount=transaction_amount,
            payment=payment,
            order_id=order_id,
            withdrawal_percentage_tax=wallet.withdrawal_percentage_tax,
        )

        wallet.wallet_transaction_history_id.add(transaction_obj)
        wallet.order_id = transaction_obj.order_id
        wallet.save()

        data = {
            "transaction_amount": transaction_amount,
            "wallet_id": wallet.id,
            "payment_method": payment_method,
            "last_transaction_date": wallet.last_transaction_date,
            "previous_balance": previous_balance,
            "current_balance": wallet.current_balance,
            "bonus": bonus.to_dict() if bonus else None,  # Only send if bonus applied
            "payment": transaction_obj.payment,
            "user": user.to_dict(),
        }

        payment_signal.send(
            sender=Wallet,
            user=user,
            notification_type="Deposit Money",
            message="Deposit Money from user Acccount"
        )
        return APIResponse.HTTP_200_OK(
            message=f"Deposit money into {user.user_id.username}'s wallet successfully.",
            data=data
        )

    except Exception as e:
        return APIResponse.HTTP_400_BAD_REQUEST(message=f"An error occurred: {e}")


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_order_status(request):
    """
    Get wallet transaction history.
    """
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")
    auth_user = AuthService.validate_user_role(user_instance, "User")  # receiver user
    if not auth_user:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found with token")
    limit = int(request.GET.get('limit', 10))
    order_id = request.query_params.get('order_id')
    wallet = Wallet.objects.filter(id=auth_user.wallet_id.id, order_id=order_id).first()
    if not wallet:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Wallet not found.")
    transactions = wallet.wallet_transaction_history_id.all()[:limit]
    try:
        data = [
            {
                "wallet_id": str(wallet.id),
                "current_balance": wallet.current_balance,
                "total_amount": wallet.total_amount,
                "last_transaction_date": wallet.last_transaction_date.strftime(
                    '%Y-%m-%d %H:%M:%S') if wallet.last_transaction_date else None,
                "withdrawal_percentage_tax": wallet.withdrawal_percentage_tax,
                "order_id": wallet.order_id,
                "wallet_transaction_history": [
                    {
                        "id": str(tx.id),
                        "payment_method": tx.payment_method,
                        "transaction_amount": tx.transaction_amount,
                        "payment_status": tx.payment_status,
                        "payment": tx.payment,
                        "transaction_date": tx.transaction_date.strftime('%Y-%m-%d %H:%M:%S')
                    } for tx in transactions
                ]
            } for wallet in Wallet.objects.filter(id=auth_user.wallet_id.id)
        ]
        return APIResponse.HTTP_200_OK(message="Transaction history retrieved successfully.", data=data)
    except Exception as e:
        return APIResponse.HTTP_400_BAD_REQUEST(message=f"An error occurred: {e}")


# Wallet Management System


############################################################################################################

## Agent Panel Management System



@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_player_by_agent(request):
    """
    API to create a new player.
    """
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    user = AuthService.validate_user_role(user_instance, "Agent")
    if not user:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found with token")

    username = request.data.get('username')
    nickname = request.data.get('nickname')
    password = request.data.get('password')
    game_id = request.data.get('game_id')
    game = Game.objects.filter(game_id=game_id).first()

    if not game:
        return APIResponse.HTTP_404_NOT_FOUND(message="Game not found.")

    if not (username and nickname and password and game_id):
        return APIResponse.HTTP_400_BAD_REQUEST(
            message="Missing required fields: username, nickname, password, and game_id are mandatory."
        )

    # Validate username
    if ' ' in username:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Username must not contain spaces.")
    if not username.isalnum() and not all(char in ['_', '-'] for char in username):
        return APIResponse.HTTP_400_BAD_REQUEST(
            message="Username can only contain letters, numbers, underscores, or hyphens."
        )
    if len(username) < 3 or len(username) > 20:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Username must be between 3 and 20 characters.")

    # Check if the player already exists
    if Player.objects.filter(username=username, game_id=game).exists():
        return APIResponse.HTTP_503_SERVICE_UNAVAILABLE(message="Username already exists.")

    # Create the Player
    player = Player.objects.create(
        username=username,
        nick_name=nickname,
        password=make_password(password),
        user_id=user,
        game_id=game,
        created_by=user,
    )

    # Trigger the notification signal with the correct instance
    player_created_signal.send(sender=Player, instance=player, user=user)

    # Return response
    response_data = {
        'status': 200,
        'message': f"Player created for user '{user_instance.first_name} {user_instance.last_name}' successfully",
        "data": {
            "username": username,
            "datetime": datetime.now(tz=UTC).__str__(),
            "nickname": nickname,
            "score": 0
        }
    }

    return Response(response_data, status=200)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_all_my_created_players_agent(request):
    """
    API to retrieve all players created by a specific user with the Admin role,
    including search and pagination functionality.
    """
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")
    allowed_roles = ["Agent"]
    user = User.objects.filter(user_id=user_instance.id).first()
    if not user:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
    role = getattr(user.role_id, "roles", None)
    if role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{role}' is not authorized.")
    # Get page, page_size, and search query from request query params
    page = int(request.query_params.get('page', 1))
    page_size = int(request.query_params.get('page_size', 10))
    search = request.query_params.get('search', '').strip().lower()

    try:
        # Fetch all players asynchronously
        panel = AgentGamePanel()
        players = async_to_sync(panel.get_all_my_created_players)(user.id)
        # print(f"players: {players}")

        if not players:  # Check if the list is empty or None
            return APIResponse.HTTP_404_NOT_FOUND(message="No players found.")

        # Apply search filter if the search parameter is provided
        if search:
            players = [
                player for player in players
                if search in player.get('game_name', '').lower() or
                   search in player.get('player', {}).get('username', '').lower() or
                   search in player.get('player', {}).get('nick_name', '').lower()
            ]

        if not players:  # Check again after filtering
            return APIResponse.HTTP_404_NOT_FOUND(message="No players match the search criteria.")

        # Apply pagination
        paginator = Paginator(players, page_size)
        try:
            paginated_players = paginator.get_page(page)  # Get the requested page
        except InvalidPath:
            return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid page number.")

        # Serialize paginated data
        response_data = {
            "players": paginated_players.object_list,  # Use object_list for the paginated players
            "pagination": {
                "current_page": paginated_players.number,
                "total_pages": paginator.num_pages,
                "page_size": page_size,
                "has_next": paginated_players.has_next(),
                "has_previous": paginated_players.has_previous(),
                "next_page": paginated_players.next_page_number() if paginated_players.has_next() else None,
                "previous_page": paginated_players.previous_page_number() if paginated_players.has_previous() else None,
                "pages": list(range(1, paginator.num_pages + 1)),  # Create list of page numbers
            },
        }

        return APIResponse.HTTP_200_OK(message="Players retrieved successfully.", data=response_data)

    except ValueError as ve:
        return APIResponse.HTTP_400_BAD_REQUEST(message=str(ve))
    except Exception as e:
        logging.error(f"Unexpected error in API: {str(e)}")
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message="An unexpected error occurred.")


## Agent Panel Management System


############################################################################################################
@csrf_exempt
def test_get_games(request):
    if request.method == "GET":
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer 320c10ae2315b7c094283697e069317f6a47d614"
        }
        response = requests.get(f"{settings.BASE_API_URL}/games/get-available-games/", headers=headers)
        data = response.json()  # Parse the API response

        if data['status'] == 200:
            try:
                games = data['data']
                return render(request, 'test_get_games.html', context={"data": games})

            except ValueError:
                context = {"games": []}
                return render(request, 'test_get_games.html', context=context)

    # Default render for non-GET methods or failed requests
    return render(request, 'test_get_games.html', context={"games": []})


############################################################################################################

## User Management System
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_player_by_user(request):
    """
    API to create a new player.
    """
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    user = AuthService.validate_user_role(user_instance, "User")
    if not user:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found with token")

    username = request.data.get('username')
    nickname = request.data.get('nickname')
    password = request.data.get('password')
    game_id = request.data.get('game_id')
    game = Game.objects.filter(id=game_id).first()

    if not game:
        return APIResponse.HTTP_404_NOT_FOUND(message="Game not found.")

    if not (username and nickname and password and game_id):
        return APIResponse.HTTP_400_BAD_REQUEST(
            message="Missing required fields: username, nickname, password, and game_id are mandatory."
        )

    # Validate username
    if ' ' in username:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Username must not contain spaces.")
    if not username.isalnum() and not all(char in ['_', '-'] for char in username):
        return APIResponse.HTTP_400_BAD_REQUEST(
            message="Username can only contain letters, numbers, underscores, or hyphens."
        )
    if len(username) < 3 or len(username) > 20:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Username must be between 3 and 20 characters.")

    # Check if the player already exists
    if Player.objects.filter(username=username, game_id=game).exists():
        return APIResponse.HTTP_503_SERVICE_UNAVAILABLE(message="Username already exists.")

    # Create the Player
    player = Player.objects.create(
        username=username,
        nick_name=nickname,
        password=make_password(password),
        user_id=user,
        game_id=game,
        created_by=user,
    )

    # Trigger the notification signal with the correct instance
    player_created_signal.send(sender=Player, instance=player, user=user)

    # Return response
    response_data = {
        'status': 200,
        'message': f"Player created for user '{user_instance.first_name} {user_instance.last_name}' successfully",
        "data": {
            "username": username,
            "datetime": datetime.now(tz=UTC).__str__(),
            "nickname": nickname,
            "score": 0
        }
    }

    return Response(response_data, status=200)


@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def get_all_my_accounts(request):
    """
    API to retrieve all players created by a specific user with the Agent role.
    Query Parameters:
        player_created_by (str): The ID of the user who created the players.
    Returns:
        JSON response with a list of players or an appropriate error message.
    """
    try:
        # Authenticate user and validate role
        user_instance = AuthService.get_user_from_token(request)
        if not user_instance:
            return APIResponse.HTTP_401_UNAUTHORIZED(message="User not authenticated.")
        user = AuthService.validate_user_role(user_instance, "User")
        if not user:
            return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
        panel = UserGamePanel()
        players = async_to_sync(panel.get_all_my_accounts)(user.id)  # Pass user ID to the method
        if players:
            return APIResponse.HTTP_200_OK(message="Players retrieved successfully.", data=players)
        else:
            return APIResponse.HTTP_404_NOT_FOUND(message="No players found for the given user.")
    except ValueError as ve:
        return APIResponse.HTTP_400_BAD_REQUEST(message=str(ve))
    except Exception as e:
        logging.error(f"Unexpected error in API: {str(e)}")
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message="An unexpected error occurred.")


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_score(request):

    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="User not authenticated.")

    user = AuthService.validate_user_role(user_instance, "User")
    if not user:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")

    try:
        username = request.data.get('username')
        score = int(request.data.get('score'))
        game_id = request.data.get('game_id')

        if not username or not score or not game_id:
            return APIResponse.HTTP_400_BAD_REQUEST(message="Missing required parameters.")
        result = UserGamePanel.update_score(user_instance, username, score, game_id, user.id)

        if isinstance(result, dict) and "id" in result:
            return APIResponse.HTTP_200_OK(message="Player score updated successfully.", data=result)
        else:
            return APIResponse.HTTP_404_NOT_FOUND(message=result.get("message"))
    except Exception as e:
        logging.error(f"Unexpected error in API: {str(e)}")
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message="An unexpected error occurred.")

@api_view(['POST'])
def check_email(request):
    """
    :param:email get request as a param
    check if email is existed or not.
    """
    email = request.query_params.get("email")

    if email is None:
        return APIResponse.HTTP_404_NOT_FOUND(message="Email is required.")

    try:
        if request.method == "POST":
            django_user = DjangoUser.objects.filter(email=email).first()

            if django_user is None:
                return APIResponse.HTTP_404_NOT_FOUND(message="Django User is not found.")

            user = User.objects.get(user_id=django_user)

            if user is None:
                return APIResponse.HTTP_404_NOT_FOUND(message="User is not found.")

            data = {
                "is_email_verified": True,
                **user.to_dict()
            }

            return APIResponse.HTTP_200_OK(message=f"Email checked successfully for {email}", data=data)
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"Error: {e}", data=email)


@api_view(['POST'])
def verify_email(request):
    """
         This function generates a new OTP and sends it to the user's email.
         Args:
             request (HttpRequest): The request object containing the email.
         Payload:
             {
                 "email": "user@email.com"
             }
         Returns:
             1. if the email founds then
                 {
                "status": 200,
                "message": "OTP resent successfully.",
                "data": {
                    "user_id": "9b03dcbb-e3a3-454f-93b6-15096801bb56",
                    "email": "amaar@gmail.com",
                    "username": "AmmarHussain",
                    "otp": "728636"
                }
             2. if the email is not provided, we return a response with the following message and status code
                 {
                    "status": 400,
                    "message": "Email is required.",
                    "data": {
                        "email": ""
                    }
                }
             3. if email not found in the database, we return a response with the following message and status code
                 {
                    "status": 404,
                    "message": "User with this email does not exist.",
                    "data": {
                        "email": "amar@gmail.com"
                    }
                }
            4. if there is an error sending the OTP, we return a response with the following message and status code
                {
                    "status": 500,
                    "message": "An error occurred while sending the OTP.",
                    "data": {
                        "email": "amar@gmail.com"
                        }
                }
            5. if there is  IntegrityError, we return a response with the following message and status code
                {
                    "status": 500,
                    "message": "An unexpected error occurred.",
                    "data": {
                        "email": "amar@gmail.com"
                        }
                }
            6. if userinstance not found, we return a response with the following message and status code
                {
                    "status": 404,
                    "message": "User with this email does not exist.",
                        "data": {
                            "email": "amar@gmail.com"
                        }
                }

    """
    # ---------------------------------------- Validating  Parameters --------------------------------
    email = request.data.get('email')
    print("verfiy otp hit")
    if not email:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Email is required.", data={"email": email})

    otp, expiration_time = generate_otp()
    cache.set(f"otp_{email}", otp, timeout=300)  # try:
    with transaction.atomic():
        user_instance = User.objects.get(user_id__email=email)
        if not user_instance:
            return APIResponse.HTTP_404_NOT_FOUND(message="User with this email does not exist.", data={"email": email})
        # ---------------------------------------- Validating Completed ---------------------------------
        user_instance.verification_code = otp  # Update the verification code
        user_instance.save()
        OTPVerification.objects.create(
            otp=otp,
            otp_created_at=datetime.now(),
            expire_at=expiration_time,  # Store expiration time as a datetime object
            verification_type=request.data.get('verification_type', 'OTP'),
        )
        send_mail(
            'Email Verification OTP',
            f'Your OTP for email verification is: {otp}',
            settings.DEFAULT_FROM_EMAIL,
            [user_instance.email],
            fail_silently=False,
        )
        data = {
            "user_id": user_instance.id,
            "email": user_instance.email,
            "username": user_instance.user_id.username,
            "otp": otp,
        }
        print("data on email verification")
        print(data)
        return APIResponse.HTTP_200_OK(message="OTP resent successfully.", data=data)


@api_view(['GET'])
def get_game_by_name(request):
    """
    This function retrieves details of a single game by its name.

    Args:
        game_name (str): The unique name of the game.

    Returns:
        1.
            {
                "status": 200,
                "message": "Game details retrieved successfully.",
                "data": {
                    "id": "346d4284-368d-4dca-8825-ed0d93181910",
                    "game_id": "PUBG1B2B3B5",
                    "game_name": "PUBG",
                    "game_description": "amazing game",
                    "game_image": "/media/default-game.jpg",
                    "game_video": "/media/game_videos/Screenshot_2024-12-20_160823.png",
                    "game_price": 600,
                    "android_game_url": "https://www.veed.io/edit/933b0227-43ec-4ada-b45a-0d09d145b850/convert?",
                    "ios_game_url": "https://www.veed.io/edit/933b0227-43ec-4ada-b45a-0d09d145b850/convert?",
                    "browser_game_url": "https://www.veed.io/edit/933b0227-43ec-4ada-b45a-0d09d145b850/convert?",
                    "upcoming_status": false,
                    "transfer_score_percentage": 0,
                    "redeem_score_percentage": 0,
                    "free_scores": 0,
                    "is_free": true,
                    "countries": []
                }
            }
        2.
            {
                "status": 404,
                "message": "Game not found."
            }
    """

    game_name = request.query_params.get('game_name')

    game = Game.objects.filter(game_name=game_name).first()
    if not game:
        return APIResponse.HTTP_404_NOT_FOUND(message="Game not found.")
    players = Player.objects.filter(game_id=game.id)
    game_reviews = GameReview.objects.filter(game_id=game.id).all()

    def get_star_rating(rating):
        full_stars = int(rating)  # Number of full stars
        half_star = 1 if rating - full_stars >= 0.5 else 0  # Half star if rating is >= 0.5
        empty_stars = 5 - full_stars - half_star  # Remaining empty stars
        return full_stars, half_star, empty_stars

    formatted_reviews = [
        {
            "id": str(review.id),
            "user": review.user_id.user_id.username,  # Assuming 'User' model has a username field
            "message_content": review.message_content,
            "profile_image": request.build_absolute_uri(
                review.user_id.profile_image.url) if review.user_id.profile_image else "/media/default-user.jpg",
            "ratings": get_star_rating(review.ratings),
            "helpful_counter": review.helpful_counter,
            "is_yes": review.is_yes,
            "review_posted_at": review.review_posted_at.strftime("%Y-%m-%d %H:%M:%S"),
        }
        for review in game_reviews
    ]

    user_has_account = False
    game_data = {
        "id": str(game.id),
        "game_id": game.game_id,
        "game_name": game.game_name,
        "game_description": game.game_description,
        "game_image": request.build_absolute_uri(game.game_image.url) if game.game_image else None,
        "game_video": game.game_video.url if game.game_video else None,
        "game_price": game.game_price,
        "android_game_url": game.android_game_url,
        "ios_game_url": game.ios_game_url,
        "browser_game_url": game.browser_game_url,
        "upcoming_status": game.upcoming_status,
        "transfer_score_percentage": game.transfer_score_percentage,
        "redeem_score_percentage": game.redeem_score_percentage,
        "gradient_style": game.gradient_style,
        "free_scores": game.free_scores,
        "is_free": game.is_free,
        "total_players": players.count(),
        "game_reviews": formatted_reviews,
        "countries": [country.country for country in game.country.all()],
        "user_has_account": user_has_account,
    }

    # user_instance = AuthService.get_user_from_token(request)
    # if user_instance:
    #     user = AuthService.validate_user_role(user_instance, "User")
    #     if user:
    #         game_data["is_authenticated"] = True
    #         user_has_account = models.Player.objects.filter(
    #             username=user.user_id.username, game_id=game.id
    #         ).exists()
    #         game_data["user_has_account"] = user_has_account

    return APIResponse.HTTP_200_OK(message="Game details retrieved successfully.", data=game_data)


@api_view(['POST'])
def handle_payment(request):
    """
    Handle different payment methods.
    """
    user = request.user
    payment_method = request.data.get('payment_method')
    # Validate payment method
    if payment_method not in ['CashApp', 'Paypal', 'Chine', 'Crypto', 'Payment With Card']:
        return Response({"message": "Invalid payment method."}, status=400)

    data = request.data
    data['user'] = user.id

    # Handle Crypto payment method specifics
    if payment_method == 'Crypto':
        coin = data.get('coin')
        network = data.get('network')
        if not coin or not network:
            return Response({"message": "Coin and Network are required for Crypto payment."}, status=400)
    # Handle Payment With Card specifics for verified users
    if payment_method == 'Payment With Card':
        if not user.is_verified:
            return Response({"message": "Payment with cards is only available for verified users."}, status=403)

    serializer = serializers.PaymentSerializer(data=data)
    if serializer.is_valid():
        serializer.save()
        return Response({"message": "Payment handled successfully."}, status=200)
    return Response(serializer.errors, status=400)


@api_view(['GET'])
def landing_page_data(request):
    try:
        games = Game.objects.all()
        top_rated_games_obj = games.filter(is_trending=True)
        upcoming_games_obj = games.filter(upcoming_status=True)
        user = User.objects.all()
        player_games = Player.objects.all()
        matching_user_players = player_games.filter(user_id__in=user)
        all_games = []
        all_games_obj = Game.objects.all()
        for game in all_games_obj:
            all_games.append({
                "id": game.id,
                "game_name": game.game_name,
                "game_image": request.build_absolute_uri(game.game_image.url) if game.game_image else None,
                "game_video": request.build_absolute_uri(game.game_video.url) if game.game_video else None,
                "gradient_style": game.gradient_style,  ##
                "game_description": game.game_description,
                "game_created_at": game.game_created_at.date(),
                "game_price": game.game_price,
                "android_game_url": game.android_game_url,
                "ios_game_url": game.ios_game_url,
                "browser_game_url": game.browser_game_url,
                "score": game.score,
            })
        popular_games_obj = matching_user_players
        if not top_rated_games_obj:
            return APIResponse.HTTP_404_NOT_FOUND(message="Top-rated games not found.")
        top_rated = []
        for game in top_rated_games_obj:
            top_rated.append({
                "id": game.id,
                "game_name": game.game_name,
                "game_image": request.build_absolute_uri(game.game_image.url) if game.game_image else None,
                "game_video": request.build_absolute_uri(game.game_video.url) if game.game_video else None,
                "gradient_style": game.gradient_style,
            })
        upcoming_game = []
        # Populate upcoming games
        for game in upcoming_games_obj:
            upcoming_game.append({
                "id": game.id,
                "game_name": game.game_name,
                "game_image": request.build_absolute_uri(game.game_image.url) if game.game_image else None,
                "game_video": request.build_absolute_uri(game.game_video.url) if game.game_video else None,
                "game_created_at": game.game_created_at.date(),
                "gradient_style": game.gradient_style,
            })
        game_ids = popular_games_obj.values_list('game_id', flat=True).distinct()  # Get unique game ids
        game_players = []
        for game_id in game_ids:
            game = Game.objects.get(id=game_id)  # Get game details
            players = Player.objects.filter(game_id=game_id)
            print(game)
            game_players = {
                "id": game.id,
                "game_name": game.game_name,
                "game_description": game.game_description,
                "game_image": request.build_absolute_uri(game.game_image.url) if game.game_image else None,
                "game_video": request.build_absolute_uri(game.game_video.url) if game.game_video else None,
                "game_price": game.game_price,
                "android_game_url": game.android_game_url,
                "gradient_style": game.gradient_style,  ##
                "ios_game_url": game.ios_game_url,
                "browser_game_url": game.browser_game_url,
                "score": game.score,
                "total_players": players.count(),
                "players": [
                    {
                        "id": player.id,
                        "user_id": player.user_id.id,
                        "user_first_name": player.user_id.first_name,
                        "user_last_name": player.user_id.last_name,
                        "user_email": player.user_id.email,
                        "user_image": player.user_id.profile_image.url if player.user_id.profile_image else None,
                    } for player in players
                ]
            }
        reviews = GameReview.objects.all()
        game_reviews = games.all()
        game_reviews_list = []
        for game in game_reviews:
            reviews = game.game_reviews_id.all()
            game = {
                "id": game.id,
                "game_name": game.game_name,
                "game_description": game.game_description,
                "game_image": request.build_absolute_uri(game.game_image.url) if game.game_image else None,
                "game_video": request.build_absolute_uri(game.game_video.url) if game.game_video else None,
                "game_price": game.game_price,
                "gradient_style": game.gradient_style,
                "android_game_url": game.android_game_url,
                "ios_game_url": game.ios_game_url,
                "browser_game_url": game.browser_game_url,
                "score": game.score,
                "total_reviews": reviews.count(),
                "reviews": [
                    {
                        "id": review.id,
                        "user_id": review.user_id.id,
                        "user_first_name": review.user_id.first_name,
                        "user_last_name": review.user_id.last_name,
                        "user_email": review.user_id.email,
                        "user_image": review.user_id.profile_image.url if review.user_id.profile_image else None,
                        "message_content": review.message_content,
                        "ratings": review.ratings,
                        "review_posted_at": review.review_posted_at,
                        "helpful_counter": review.helpful_counter,

                    } for review in reviews
                ]
            }

            game_reviews_list.append(game)
        data = {
            "all_games": all_games,
            "top_rated": top_rated,
            "upcoming_games": upcoming_game,
            "popular_games": game_players,
            "game_reviews": game_reviews_list,
        }
        return APIResponse.HTTP_200_OK(message="Landing page data retrieved successfully.", data=data)
    except Exception as e:
        return APIResponse.HTTP_400_BAD_REQUEST(message=f"An error occurred: {e}")
