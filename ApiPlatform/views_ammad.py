# ------------------------------------------------ Site packages -------------------------------------#
import logging,os,random,uuid,qrcode,requests,threading,json,time
from django.middleware.csrf import get_token
from rest_framework.authentication import TokenAuthentication

from CoinsSellingPlatformProject import settings
from datetime import datetime,timedelta
from celery.utils.time import timezone
from decimal import Decimal
from dateutil.tz import UTC
#------------------------------------------------ Django packages --------------------------------------------#
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.contrib.auth.models import User as DjangoUser
from rest_framework.decorators import permission_classes, authentication_classes
from rest_framework.permissions import IsAuthenticated
from django.core.files.storage import default_storage
from django.contrib.auth.hashers import make_password
from rest_framework.generics import get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from rest_framework.authtoken.models import Token  # noqa
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.shortcuts import redirect
from django.forms import model_to_dict
from asgiref.sync import async_to_sync
from django.core.mail import send_mail
from django.shortcuts import render
from django.core.cache import cache
from django.contrib import messages
from django.utils import timezone
from django.db import transaction
from django.db.models import Sum, Count

from .models import GamePlay
from .serializers import AgentChatSerializer, PaymentSerializer
# ------------------------------------------------ Our custom written functions -------------------------------------#
# from PanelsHandler.panel_handler import PanelHandler, ProxySettings
from .utils import generate_otp, delete_inactive_user_messages, delete_all_referrals_after_given_time
from .login_attempt_middleware import LoginAttemptMiddleware
from .app_views.admin_game_panel import AdminGamePanel
from .app_views.agent_game_panel import AgentGamePanel
from .app_views.user_game_panel import UserGamePanel
from .auth_service import AuthService
from .api_handler import APIResponse
from . import forms, models
from .email_domains import  valid_domains

###
####################    INITIALIZING THE PANEL HANDLER     ####################


# panel_handler = PanelHandler(
#     proxy=ProxySettings(server="http://23.95.150.34:6003", username="kerctuyt", password="qqinspxrxdss"), timeout=60000)
#
# async def main():
#     await panel_handler.initialize_panels()
#     await panel_handler.get_active_panels().create_player(username="test", password="test")


####################    INITIALIZING THE PANEL HANDLER     ####################
def ban_ip(ip, reason="Exceeded request limit"):
    """
        Ban an IP address for a specified reason and set the ban to expire after 1 hour.

        Args:
            ip (str): The IP address to be banned.
            reason (str, optional): The reason for banning the IP. Default is "Exceeded request limit."

        Returns:
            A response indicating the IP has been temporarily banned:
            {
                    "message": "Too many requests. Please try again later.",
                    "status": 429,
                    "data": None
            }
    """
    ban_expiry = timezone.now() + timedelta(hours=1)
    models.BannedIP.objects.create(ip_address=ip, reason=reason, ban_expiry=ban_expiry)
    return APIResponse.HTTP_429_TOO_MANY_REQUESTS(message="Too many requests. Please try again later.")

def return_level_scores():
    """
          Retrieve and return all levels with specific level codes.
          Returns:
              1. All available Level objects
              2. A level not found error if the level code is not found then it will redirect to 404 page.
    """
    l_0 = get_object_or_404(models.Level, level_code='L0')
    l_1 = get_object_or_404(models.Level, level_code='L1')
    l_2 = get_object_or_404(models.Level, level_code='L2')
    l_3 = get_object_or_404(models.Level, level_code='L3')
    l_4 = get_object_or_404(models.Level, level_code='L4')
    return l_0, l_1, l_2, l_3, l_4


def return_subscriptions():
    """
        Return
            1. Returns All subscription plans.
            2. A subscription plan not found error if the subscription plan is not found then it will redirect to
                404 page.
    """
    free = get_object_or_404(models.SubscriptionPlan, pro_status='Free')
    premium = get_object_or_404(models.SubscriptionPlan, pro_status='Premium')
    elite = get_object_or_404(models.SubscriptionPlan, pro_status='Elite')

    return free, premium, elite


###################################### FRONTEND MANAGEMENT SYSTEM ##################################################
# from django.views.decorators.http import require_GET
@api_view(['GET'])
def get_games_data(request):
    # Fetch the games data from the database
    all_games = models.Game.objects.all()
    upcoming_games = models.Game.objects.filter (upcoming_status=True)
    popular_games = models.Game.objects.filter(is_trending=True)
    top_rated_games = models.Game.objects.filter(is_trending=True)

    # Prepare data in dictionary format
    games_data = {
        'all_games': list(all_games.values('id', 'game_name', 'game_image', 'game_price')),
        'upcoming_games': list(upcoming_games.values('id', 'game_name', 'game_image', 'game_price')),
        'popular_games': list(popular_games.values('id', 'game_name', 'game_image', 'game_price')),
        'top_rated_games': list(top_rated_games.values('id', 'game_name', 'game_image', 'game_price')),
    }

    # Return data as JSON
    print("her....")
    # print(f'games_data: {games_data}')
    return APIResponse.HTTP_200_OK(data=games_data)


def verification(request):
    return render(request, 'waiting-for-your-verification.html')


def global_chat(request):
    return render(request, 'partials/global-chat/base.html')

def global_chat(request):
  return render(request, 'partials/global-chat/index.html')

def terms_and_conditions(request):
    return render(request, 'terms-and-conditions.html')


def waitlist(request):
    return render(request, 'waitlist.html')


@csrf_exempt
@api_view(['POST'])
def join_waitlist(request):
    return APIResponse.HTTP_200_OK(message="You have joined the waitlist.")


def play_games(request, game_name):
    return render(
        request=request,
        template_name='partials/top-rated-games/play-games.html',
        context={'game_name': game_name}
    )

def reviews_and_rating(request):
    return render(request, 'partials/reviews-and-rating/base.html')


def full_review(request, review_name):
    return render(
        request=request,
        template_name='partials/reviews-and-rating/full-reviews/base.html',
        context={'review_name': review_name}
    )


def upgrade_your_plan(request):
    return render(request, 'upgradePlan.html')


def privacy_policy(request):
    return render(request, 'privacy_policy.html')


def view_trending_games(request):
    return render(request, 'partials/trending_games/base.html')


def view_popular_games(request):
    return render(request, 'partials/popular-games/base.html')


def view_game_history(request):
    return render(request, 'partials/game-history/base.html')


def view_all_games(request):
    return render(request, 'partials/all-games/base.html')


def faqs(request):
    return render(request, 'faqs.html')


def view_over_view(request):
    return render(request, 'partials/over_view/base.html')


def redeem(request):
    return render(request, 'partials/redeem/base.html')


def score_board(request):
    return render(request, 'partials/score-board/base.html')

def transfer(request):
    return render(request, 'partials/transfer/base.html')



####### DASHBOARDS
## USER

def user_index(request):
    return render(request, 'dashboards/user/base.html')


def user_detail_index(request):
    return render(request, 'dashboards/user/user-detail.html')


def wallet(request):
    return render(request, 'dashboards/user/wallet.html')

def add_payment(request):
    return render(request, 'dashboards/user/add-payment.html')

def payment_method(request):
    return render(request, 'dashboards/user/payment-method.html')

def wallet_history(request):
    return render(request, 'dashboards/user/wallet-history.html')


def game_detail_index(request):
    return render(request, 'dashboards/user/game-detail.html')


####### DASHBOARDS
## USER



####### DASHBOARDS
## ADMIN

def admin_index(request):
    """
    Admin dashboard handler.
    Validates cookies, checks token, and renders the admin dashboard or redirects to login.
    """

    # Retrieve cookies
    token = request.COOKIES.get('token')
    is_logged_in = request.COOKIES.get('is_logged_in')

    # Validate token and is_logged_in
    if is_logged_in == "true" and token:
        headers = {"Authorization": f"Token {token}"}
        api_response = requests.post(f"{settings.BASE_API_URL}/profile/", headers=headers)

        if api_response.status_code == 200:
            # Successful API response, render the dashboard
            profile_data = api_response.json().get('data', {})
            return render(request, 'dashboards/admin/index.html', {"data": profile_data})
        else:
            # API validation failed, clear cookies and redirect
            response = redirect('CoinsSellingPlatformApp:admin_login')
            response.delete_cookie('is_logged_in')
            response.delete_cookie('token')
            response.delete_cookie('remember_me')
            response.delete_cookie('expiration_time')
            return response
    else:
        # Missing or invalid cookies, redirect to log in
        return redirect('CoinsSellingPlatformApp:admin_login')

def admin_login(request):
    token = request.COOKIES.get('token')
    is_logged_in = request.COOKIES.get('is_logged_in')

    # Check if cookies are expired or invalid
    if is_logged_in == "true" and token:
        return redirect('CoinsSellingPlatformApp:admin_dashboard_index')

    # Clear any residual cookies
    response = render(request, 'dashboards/admin/login.html')
    response.delete_cookie('expiration_time')
    response.delete_cookie('is_logged_in')
    response.delete_cookie('token')
    response.delete_cookie('remember_me')
    return response

def admin_login_process(request):
    errors = {}
    loading = False

    if request.method == "POST":
        loading = True
        email_or_username = request.POST.get('email_or_username')
        password = request.POST.get('password')
        remember_me = request.POST.get('remember_me')

        if not email_or_username:
            errors['email_or_username'] = 'Please enter your email or username.'
        if not password:
            errors['password'] = 'Please enter your password.'

        if errors:
            return render(request, 'dashboards/admin/login.html', {"errors": errors, "loading": loading})

        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        body = {"username_or_email": email_or_username, "password": password}

        try:
            response = requests.post(f"{settings.BASE_API_URL}/login/", headers=headers, data=json.dumps(body))
            data = response.json()

            if response.status_code == 200:
                role = data.get("data", {}).get("role", "")
                token = data.get("data", {}).get("token", "")

                if role == "Admin" and token:
                    response = redirect('CoinsSellingPlatformApp:admin_dashboard_index')

                    # Define the cookie duration
                    cookie_duration = 60 * 60 * 24 * 15 if remember_me else 60 * 60 * 24  # 15 days or 24 hours
                    next_expiration_time = int(time.time()) + cookie_duration  # Current time + duration

                    # Set cookies
                    response.set_cookie('expiration_time', next_expiration_time, max_age=cookie_duration, secure=True,
                                        httponly=True)
                    response.set_cookie('is_logged_in', 'true', max_age=cookie_duration, secure=True, httponly=True,
                                        samesite='Lax')
                    response.set_cookie('token', token, max_age=cookie_duration, secure=True, httponly=True)
                    response.set_cookie('remember_me', remember_me, max_age=cookie_duration, secure=True, httponly=True)

                    return response
                else:
                    errors['non_field_errors'] = 'You are not authorized to access this page.'
            else:
                errors['non_field_errors'] = data.get("message", "Login failed.")
        except json.JSONDecodeError:
            errors['non_field_errors'] = 'Invalid response from the server. Please try again later.'
        except Exception as e:
            errors['non_field_errors'] = 'An unexpected error occurred. Please try again later.'

        return render(request, 'dashboards/admin/login.html', {"errors": errors, "loading": loading})

    return render(request, 'dashboards/admin/login.html', {"errors": errors, "loading": loading})

def admin_logout(request):
    """
    Clears cookies and redirects to the login page.
    """
    response = redirect('CoinsSellingPlatformApp:admin_login_process')
    response.delete_cookie('expiration_time')
    response.delete_cookie('is_logged_in')
    response.delete_cookie('token')
    response.delete_cookie('remember_me')
    return response

def user_profile_regular(request):
    # Check if the user is logged in by looking for the 'is_logged_in' cookie
    # Get the token from cookies
    token = request.COOKIES.get('token')
    is_logged_in = request.COOKIES.get('is_logged_in')

    # Set up the Authorization header with the token
    headers = {
        "Authorization": f"Token {token}",  # Correct format for token-based auth
    }

    if is_logged_in == 'true' and token:
        # Call the profile API endpoint, passing headers with Authorization token
        response = requests.post(f"{settings.BASE_API_URL}/profile/", headers=headers)
        print(f"response.status_code: {response.status_code}")

        if response.status_code == 200:
            # Profile data received successfully
            profile_data = response.json()['data']

            # Pass profile data to the template
            return render(request, 'dashboards/admin/user_profile_regular.html', {"data": profile_data})
        else:
            # If the API call fails, clear cookies and redirect to the login page
            print(f"Error: {response.status_code}, {response.text}")
            response = redirect('CoinsSellingPlatformApp:admin_login')

            # Optionally clear cookies
            response.delete_cookie('is_logged_in')
            response.delete_cookie('token')
            return response
    else:
        # If the user is not logged in (cookie is missing or false), redirect to log-in
        return redirect('CoinsSellingPlatformApp:admin_login')

def update_user_phone(request):
    if request.method == 'POST':
        start_time = time.time()

        phone = request.POST.get('phone')
        token = request.COOKIES.get('token')
        is_logged_in = request.COOKIES.get('is_logged_in')

        if not phone:
            messages.error(request, "Phone number is required.")

            return redirect('CoinsSellingPlatformApp:admin_dashboard_index')

        if is_logged_in == 'true' and token:
            headers = {"Authorization": f"Token {token}"}
            try:
                response = requests.put(
                    f"{settings.BASE_API_URL}/phone-verification-and-get-free-xp/",
                    headers=headers,
                    data={"phone": phone}
                )

                elapsed_time = time.time() - start_time
                if elapsed_time < 5:
                    time.sleep(5 - elapsed_time)  # Ensure at least 5 seconds delay

                if response.status_code == 200:
                    messages.success(request, response.json().get('message', 'Phone updated successfully!'))
                else:
                    messages.error(request, response.json().get('message', 'Failed to update phone.'))
                return redirect('CoinsSellingPlatformApp:admin_dashboard_index')

            except requests.RequestException:
                messages.error(request, "An error occurred while contacting the server.")
                return redirect('CoinsSellingPlatformApp:admin_dashboard_index')
        else:
            return redirect('CoinsSellingPlatformApp:admin_login')

    return APIResponse.HTTP_405_METHOD_NOT_ALLOWED(message="Only POST method is allowed.")

def update_user_personal_information(request):
    if request.method == 'POST':

        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        username = request.POST.get('username')
        dob = request.POST.get('dob')

        # Get the token and login status from cookies
        token = request.COOKIES.get('token')
        is_logged_in = request.COOKIES.get('is_logged_in')

        # Validate inputs
        if not first_name or not last_name or not username or not dob:
            # Adding error message using messages framework
            messages.error(request, "All fields are required.")
            return redirect('CoinsSellingPlatformApp:admin_dashboard_index')

        if is_logged_in == 'true' and token:
            # Set up the Authorization header
            headers = {
                "Authorization": f"Token {token}",  # Correct format for token-based auth
            }

            try:
                # Make the PUT request to the external API
                response = requests.put(
                    f"{settings.BASE_API_URL}/update-user-personal-information-api/",
                    headers=headers,
                    data={
                        "first_name": first_name,
                        "last_name": last_name,
                        "username": username,
                        "dob": dob,
                    }
                )
                print(f"response.status_code: {response.status_code}")
                print(f"Body: {response.text}")

                if response.status_code == 200:
                    # Parse the profile data from the API response
                    profile_data = response.json().get('data', {})
                    success_message = response.json().get('message', {})
                    # Adding success message using messages framework
                    messages.success(request, success_message)
                else:
                    # API returned an error, parse the message
                    error_message = response.json().get('message', {})
                    # Adding error message using messages framework
                    messages.error(request, error_message)

                # Redirect to the admin dashboard with the messages
                return redirect('CoinsSellingPlatformApp:admin_dashboard_index')

            except requests.RequestException as e:
                # Handle exception
                messages.error(request, "An error occurred while contacting the server.")
                return redirect('CoinsSellingPlatformApp:admin_dashboard_index')

        else:
            # Redirect to log-in if not logged in
            return redirect('CoinsSellingPlatformApp:admin_login')

    else:
        return APIResponse.HTTP_405_METHOD_NOT_ALLOWED(message="Only POST method is allowed.")

def request_password(request):
    if request.method == 'POST':
        # Retrieve phone number from POST data
        email = request.POST.get('email')
        print(f"email: {email}")

        # Get the token and login status from cookies
        token = request.COOKIES.get('token')
        is_logged_in = request.COOKIES.get('is_logged_in')

        # Validate inputs
        if not email:
            # Adding error message using messages framework
            messages.error(request, "Email is required.")
            return redirect('CoinsSellingPlatformApp:user_profile_regular')

        if is_logged_in == 'true' and token:
            # Set up the Authorization header
            headers = {
                "Authorization": f"Token {token}",  # Correct format for token-based auth
            }

            try:
                # Make the PUT request to the external API
                response = requests.post(
                    f"{settings.BASE_API_URL}/request-reset-password/",
                    headers=headers,
                    data={"email": email}
                )
                print(f"response.status_code: {response.status_code}")
                print(f"Body: {response.text}")

                # Handle the API response
                profile_data = {}
                success_message = None
                error_message = None

                if response.status_code == 200:
                    # Parse the profile data from the API response
                    profile_data = response.json().get('data', {})
                    success_message = response.json().get('message', {})
                    # Adding success message using messages framework
                    messages.success(request, success_message)
                    print(f"success_message: {success_message}")
                else:
                    # API returned an error, parse the message
                    error_message = response.json().get('message', {})
                    # Adding error message using messages framework
                    messages.error(request, error_message)

                # Redirect to the admin dashboard with the messages
                return redirect('CoinsSellingPlatformApp:user_profile_regular')

            except requests.RequestException as e:
                # Handle exception
                messages.error(request, "An error occurred while contacting the server.")
                return redirect('CoinsSellingPlatformApp:user_profile_regular')

        else:
            # Redirect to log-in if not logged in
            return redirect('CoinsSellingPlatformApp:admin_login')

    else:
        return APIResponse.HTTP_405_METHOD_NOT_ALLOWED(message="Only POST method is allowed.")


def confirm_requested_password(request):
    if request.method == 'POST':
        # Retrieve phone number from POST data
        email = request.POST.get('email')
        otp = request.POST.get('otp')
        new_password = request.POST.get('new_password')

        # Get the token and login status from cookies
        token = request.COOKIES.get('token')
        is_logged_in = request.COOKIES.get('is_logged_in')

        # Validate inputs
        if not email or not otp or not new_password:
            # Adding error message using messages framework
            messages.error(request, "All fields are required.")
            return redirect('CoinsSellingPlatformApp:user_profile_regular')

        if is_logged_in == 'true' and token:
            # Set up the Authorization header
            headers = {
                "Authorization": f"Token {token}",  # Correct format for token-based auth
            }

            try:
                # Make the PUT request to the external API
                response = requests.post(
                    f"{settings.BASE_API_URL}/confirm-reset-password/",
                    headers=headers,
                    data={
                        "email": email,
                        "otp": otp,
                        "new_password": new_password
                    }
                )
                print(f"response.status_code: {response.status_code}")
                print(f"Body: {response.text}")

                # Handle the API response
                profile_data = {}
                success_message = None
                error_message = None

                if response.status_code == 200:
                    # Parse the profile data from the API response
                    profile_data = response.json().get('data', {})
                    success_message = response.json().get('message', {})
                    # Adding success message using messages framework
                    messages.success(request, success_message)
                    print(f"success_message: {success_message}")
                else:
                    # API returned an error, parse the message
                    error_message = response.json().get('message', {})
                    # Adding error message using messages framework
                    messages.error(request, error_message)

                # Redirect to the admin dashboard with the messages
                return redirect('CoinsSellingPlatformApp:user_profile_regular')

            except requests.RequestException as e:
                # Handle exception
                messages.error(request, "An error occurred while contacting the server.")
                return redirect('CoinsSellingPlatformApp:user_profile_regular')

        else:
            # Redirect to log-in if not logged in
            return redirect('CoinsSellingPlatformApp:admin_login')

    else:
        return APIResponse.HTTP_405_METHOD_NOT_ALLOWED(message="Only POST method is allowed.")



def my_players(request):
    # Get the token and login status from cookies
    token = request.COOKIES.get('token')
    is_logged_in = request.COOKIES.get('is_logged_in')

    # Set up the Authorization header with the token
    headers = {
        "Authorization": f"Token {token}",
    }

    if is_logged_in == 'true' and token:
        try:
            # Check for page and limit in query params
            page = int(request.GET.get('page', 1))
            limit = int(request.GET.get('page_size', 10))
            search = request.POST.get('search', '').strip()

            # Construct the API URL
            base_url = f"{settings.BASE_API_URL}/admin-game-panel/get-all-my-created-players/"
            api_url = f"{base_url}?page={page}&page_size={limit}"

            # Include the search parameter only if it's provided
            if search:
                api_url += f"&search={search}"

            # Fetch the players' data using API
            response = requests.get(api_url, headers=headers)

            games_response = requests.get(f"{settings.BASE_API_URL}/games/get-available-games/", headers=headers)
            users_response = requests.get(f"{settings.BASE_API_URL}/get-all-users/", headers=headers)

            if response.status_code == 200:
                default_data = response.json().get('data', [])
            else:
                default_data = []

            if games_response.status_code == 200:
                game_data = games_response.json().get('data', [])
            else:
                game_data = []

            if users_response.status_code == 200:
                user_data = users_response.json().get('data', [])
            else:
                user_data = []

            # Render the template with data
            return render(request, 'dashboards/admin/user-list-compact.html', {
                "data": default_data,
                "games": game_data,
                "users": user_data,
                "pagination": {
                    "current_page": page,
                    "page_size": limit,
                },
                "search_term": search,  # Pass the search term back to the template
            })

        except requests.RequestException as e:
            # Handle request exceptions (e.g., network errors)
            return render(request, 'dashboards/admin/user-list-compact.html', {
                "error": "Failed to load data. Please try again later.",
            })
    else:
        # If the user is not logged in, redirect to the login page
        return redirect('CoinsSellingPlatformApp:admin_login')

def block_my_players(request, player_username):
    # Get the token and login status from cookies
    token = request.COOKIES.get('token')
    is_logged_in = request.COOKIES.get('is_logged_in')

    # Set up the Authorization header with the token
    headers = {
        "Authorization": f"Token {token}",
    }

    if is_logged_in == 'true' and token:
        try:

            # Fetch the players' data using API
            response = requests.put(
                f"{settings.BASE_API_URL}/admin-game-panel/block-player/",
                headers=headers,
                data={
                    "player_username": player_username
                }
            )

            data = response.json()

            if response.status_code == 200:
                messages.success(request, data['message'])
                return redirect('CoinsSellingPlatformApp:my_players')
            else:
                messages.error(request, data['message'])
                return redirect('CoinsSellingPlatformApp:my_players')


        except requests.exceptions.RequestException as e:
            messages.error(request, f"Error while connecting to API: {str(e)}")
            return redirect('CoinsSellingPlatformApp:my_players')

        except json.JSONDecodeError:
            messages.error(request, "Invalid response from the server. Please try again later.")
            return redirect('CoinsSellingPlatformApp:my_players')

        except Exception as e:
            messages.error(request, "An unexpected error occurred. Please try again later.")
            return redirect('CoinsSellingPlatformApp:my_players')
    else:
        # If the user is not logged in, redirect to the login page
        return redirect('CoinsSellingPlatformApp:admin_login')

def delete_my_players(request, player_username):
    # Get the token and login status from cookies
    token = request.COOKIES.get('token')
    is_logged_in = request.COOKIES.get('is_logged_in')

    # Set up the Authorization header with the token
    headers = {
        "Authorization": f"Token {token}",
    }

    if is_logged_in == 'true' and token:
        try:

            # Fetch the players' data using API
            response = requests.delete(
                f"{settings.BASE_API_URL}/admin-game-panel/delete-player/",
                headers=headers,
                data={
                    "player_username": player_username
                }
            )

            data = response.json()
            print(f"""data: {data}""")

            if response.status_code == 200:
                messages.success(request, data['message'])
                return redirect('CoinsSellingPlatformApp:my_players')
            else:
                messages.error(request, data['message'])
                return redirect('CoinsSellingPlatformApp:my_players')


        except requests.exceptions.RequestException as e:
            messages.error(request, f"Error while connecting to API: {str(e)}")
            return redirect('CoinsSellingPlatformApp:my_players')

        except json.JSONDecodeError:
            messages.error(request, "Invalid response from the server. Please try again later.")
            return redirect('CoinsSellingPlatformApp:my_players')

        except Exception as e:
            messages.error(request, "An unexpected error occurred. Please try again later.")
            return redirect('CoinsSellingPlatformApp:my_players')
    else:
        # If the user is not logged in, redirect to the login page
        return redirect('CoinsSellingPlatformApp:admin_login')

def change_game_player_password(request):
    loading = False

    # Get the token and login status from cookies
    token = request.COOKIES.get('token')
    is_logged_in = request.COOKIES.get('is_logged_in')

    # Set up the Authorization header with the token
    headers = {
        "Authorization": f"Token {token}",
    }

    if not is_logged_in == 'true' or not token:
        return redirect('CoinsSellingPlatformApp:admin_login')

    if request.method == "POST":
        loading = True
        username = request.POST.get('username')
        new_password = request.POST.get('new_password')

        if not username or not new_password:
            messages.error(request, "All fields are required.")
            return redirect('CoinsSellingPlatformApp:change_game_player_password')

        body = {
            "username": username,
            "new_password": new_password,
        }

        try:
            response = requests.post(
                f"{settings.BASE_API_URL}/admin-game-panel/reset-game-password/",
                headers=headers,
                json=body  # Ensure JSON format for API compatibility
            )
            data = response.json()
            print(f"data: {data}")

            if response.status_code == 200:
                messages.success(request, "Player password changed successfully.")
                return redirect('CoinsSellingPlatformApp:my_players')
            else:
                messages.error(request, data.get("message", "Failed to change player password. Please try again later."))
                return redirect('CoinsSellingPlatformApp:my_players')
        except requests.exceptions.RequestException as e:
            messages.error(request, f"Error: {str(e)}")
            return redirect('CoinsSellingPlatformApp:my_players')
        except json.JSONDecodeError:
            messages.error(request, "Invalid response from the server. Please try again later.")
            return redirect('CoinsSellingPlatformApp:my_players')
        except Exception as e:
            messages.error(request, "An unexpected error occurred. Please try again later.")
            return redirect('CoinsSellingPlatformApp:my_players')

    return redirect('CoinsSellingPlatformApp:my_players')

def add_player_data(request):
    loading = False

    # Get the token and login status from cookies
    token = request.COOKIES.get('token')
    is_logged_in = request.COOKIES.get('is_logged_in')

    # Set up the Authorization header with the token
    headers = {
        "Authorization": f"Token {token}",
    }

    if not is_logged_in == 'true' or not token:
        return redirect('CoinsSellingPlatformApp:admin_login')

    if request.method == "POST":
        loading = True
        user_id = request.POST.get('user_id')
        username = request.POST.get('username')
        nickname = request.POST.get('nickname')
        password = request.POST.get('password')
        game_id = request.POST.get('game_id')

        if not all([user_id, username, nickname, password, game_id]):
            messages.error(request, "All fields are required.")
            return redirect('CoinsSellingPlatformApp:my_players')

        body = {
            "user_id": user_id,
            "username": username,
            "nickname": nickname,
            "password": password,
            "game_id": game_id
        }

        try:
            response = requests.post(
                f"{settings.BASE_API_URL}/admin-game-panel/create-player/",
                headers=headers,
                json=body  # Ensure JSON format for API compatibility
            )
            data = response.json()
            if response.status_code == 200:
                messages.success(request, "Player created successfully!")
                return redirect('CoinsSellingPlatformApp:my_players')
            else:
                messages.error(request, data.get("message", "Player creation failed."))
                return redirect('CoinsSellingPlatformApp:my_players')
        except requests.exceptions.RequestException as e:
            messages.error(request, f"Error while connecting to API: {str(e)}")
            return redirect('CoinsSellingPlatformApp:my_players')
        except json.JSONDecodeError:
            messages.error(request, "Invalid response from the server. Please try again later.")
            return redirect('CoinsSellingPlatformApp:my_players')
        except Exception as e:
            messages.error(request, "An unexpected error occurred. Please try again later.")
            return redirect('CoinsSellingPlatformApp:my_players')

    return redirect('CoinsSellingPlatformApp:my_players')


## GAMES ROUTES

def add_game_data(request):
    token = request.COOKIES.get('token')
    is_logged_in = request.COOKIES.get('is_logged_in')

    if not (is_logged_in == 'true' and token):
        messages.error(request, "You must be logged in to add a game.")
        return redirect('CoinsSellingPlatformApp:admin_login')

    if request.method == "POST":
        missing_fields = []

        # Required fields
        required_fields = ['game_id', 'game_name', 'game_price']

        for field in required_fields:
            if not request.POST.get(field):
                missing_fields.append(field)

        # Check for required file fields
        if not request.FILES.get('game_image'):
            missing_fields.append('game_image')
        if not request.FILES.get('game_video'):
            missing_fields.append('game_video')

        if missing_fields:
            messages.error(request, f"Missing fields: {', '.join(missing_fields)}")
            return redirect('CoinsSellingPlatformApp:my_games')

        try:
            headers = {"Authorization": f"Token {token}"}

            # Prepare body data with required and optional fields
            body = {key: request.POST[key] for key in required_fields}

            # Include optional fields if provided
            optional_fields = [
                'game_description', 'android_game_url', 'ios_game_url',
                'browser_game_url', 'upcoming_status', 'is_trending',
                'transfer_score_percentage', 'redeem_score_percentage'
            ]

            for field in optional_fields:
                if request.POST.get(field):
                    body[field] = request.POST[field]

            # Handle boolean fields
            body['upcoming_status'] = True if request.POST.get('upcoming_status') == 'on' else False
            body['is_trending'] = True if request.POST.get('is_trending') == 'on' else False

            files = {
                'game_image': request.FILES['game_image'],
                'game_video': request.FILES['game_video']
            }

            # Make the request
            response = requests.post(
                f"{settings.BASE_API_URL}/games/add-game/",
                headers=headers,
                data=body,
                files=files
            )

            # Log raw response details
            print(f"Response Status Code: {response.status_code}")
            print(f"Response Content: {response.content}")

            if response.status_code == 200:
                try:
                    response_data = response.json()  # Attempt to parse JSON
                    messages.success(request, response_data["message"])
                except ValueError:
                    messages.error(request, "Unexpected server response. Please try again.")
            else:
                messages.error(request, f"Error {response.status_code}: {response.content.decode('utf-8')}")
        except Exception as e:
            messages.error(request, f"An error occurred: {e}")

        return redirect('CoinsSellingPlatformApp:my_games')

    return redirect('CoinsSellingPlatformApp:my_games')

def my_games(request):
    # Get the token and login status from cookies
    token = request.COOKIES.get('token')
    is_logged_in = request.COOKIES.get('is_logged_in')

    # Set up the Authorization header with the token
    headers = {
        "Authorization": f"Token {token}",
    }

    if is_logged_in == 'true' and token:
        try:
            # Check for page and limit in query params
            page = int(request.GET.get('page', 1))
            limit = int(request.GET.get('page_size', 10))
            search = request.POST.get('search', '').strip()

            # Construct the API URL
            base_url = f"{settings.BASE_API_URL}/admin-game-panel/get-all-my-created-games/"
            api_url = f"{base_url}?page={page}&page_size={limit}"

            # Include the search parameter only if it's provided
            if search:
                api_url += f"&search={search}"

            # Fetch the players' data using API
            response = requests.get(api_url, headers=headers)

            if response.status_code == 200:
                default_data = response.json().get('data', [])
            else:
                default_data = []

            # Render the template with data
            return render(request, 'dashboards/admin/game-list-compact.html', {
                "data": default_data,
                "pagination": {
                    "current_page": page,
                    "page_size": limit,
                },
                "search_term": search,  # Pass the search term back to the template
            })

        except requests.RequestException as e:
            # Handle request exceptions (e.g., network errors)
            return render(request, 'dashboards/admin/game-list-compact.html', {
                "error": "Failed to load data. Please try again later.",
            })
    else:
        # If the user is not logged in, redirect to the login page
        return redirect('CoinsSellingPlatformApp:admin_login')

def block_my_games(request, game_id):
    # Get the token and login status from cookies
    token = request.COOKIES.get('token')
    is_logged_in = request.COOKIES.get('is_logged_in')

    # Set up the Authorization header with the token
    headers = {
        "Authorization": f"Token {token}",
    }

    if is_logged_in == 'true' and token:
        try:

            # Fetch the players' data using API
            response = requests.put(
                f"{settings.BASE_API_URL}/admin-game-panel/block-game/",
                headers=headers,
                data={
                    "game_id": game_id
                }
            )

            data = response.json()

            if response.status_code == 200:
                messages.success(request, data['message'])
                return redirect('CoinsSellingPlatformApp:my_games')
            else:
                messages.error(request, data['message'])
                return redirect('CoinsSellingPlatformApp:my_games')


        except requests.exceptions.RequestException as e:
            messages.error(request, f"Error: {str(e)}")
            return redirect('CoinsSellingPlatformApp:my_games')

        except json.JSONDecodeError:
            messages.error(request, "Invalid response from the server. Please try again later.")
            return redirect('CoinsSellingPlatformApp:my_games')

        except Exception as e:
            messages.error(request, "An unexpected error occurred. Please try again later.")
            return redirect('CoinsSellingPlatformApp:my_games')
    else:
        # If the user is not logged in, redirect to the login page
        return redirect('CoinsSellingPlatformApp:admin_login')

def is_free_game_admin(request, game_id):
    # Get the token and login status from cookies
    token = request.COOKIES.get('token')
    is_logged_in = request.COOKIES.get('is_logged_in')

    # Set up the Authorization header with the token
    headers = {
        "Authorization": f"Token {token}",
    }

    if is_logged_in == 'true' and token:
        try:

            # Fetch the players' data using API
            response = requests.put(
                f"{settings.BASE_API_URL}/admin-game-panel/is-free-game/",
                headers=headers,
                data={
                    "game_id": game_id
                }
            )

            data = response.json()

            if response.status_code == 200:
                messages.success(request, data['message'])
                return redirect('CoinsSellingPlatformApp:my_games')
            else:
                messages.error(request, data['message'])
                return redirect('CoinsSellingPlatformApp:my_games')


        except requests.exceptions.RequestException as e:
            messages.error(request, f"Error: {str(e)}")
            return redirect('CoinsSellingPlatformApp:my_games')

        except json.JSONDecodeError:
            messages.error(request, "Invalid response from the server. Please try again later.")
            return redirect('CoinsSellingPlatformApp:my_games')

        except Exception as e:
            messages.error(request, "An unexpected error occurred. Please try again later.")
            return redirect('CoinsSellingPlatformApp:my_games')
    else:
        # If the user is not logged in, redirect to the login page
        return redirect('CoinsSellingPlatformApp:admin_login')

def upcoming_status_game_admin(request, game_id):
    # Get the token and login status from cookies
    token = request.COOKIES.get('token')
    is_logged_in = request.COOKIES.get('is_logged_in')

    # Set up the Authorization header with the token
    headers = {
        "Authorization": f"Token {token}",
    }

    if is_logged_in == 'true' and token:
        try:

            # Fetch the players' data using API
            response = requests.put(
                f"{settings.BASE_API_URL}/admin-game-panel/upcoming/",
                headers=headers,
                data={
                    "game_id": game_id
                }
            )

            data = response.json()

            if response.status_code == 200:
                messages.success(request, data['message'])
                return redirect('CoinsSellingPlatformApp:my_games')
            else:
                messages.error(request, data['message'])
                return redirect('CoinsSellingPlatformApp:my_games')


        except requests.exceptions.RequestException as e:
            messages.error(request, f"Error: {str(e)}")
            return redirect('CoinsSellingPlatformApp:my_games')

        except json.JSONDecodeError:
            messages.error(request, "Invalid response from the server. Please try again later.")
            return redirect('CoinsSellingPlatformApp:my_games')

        except Exception as e:
            messages.error(request, "An unexpected error occurred. Please try again later.")
            return redirect('CoinsSellingPlatformApp:my_games')
    else:
        # If the user is not logged in, redirect to the login page
        return redirect('CoinsSellingPlatformApp:admin_login')

def is_trending_game_admin(request, game_id):
    # Get the token and login status from cookies
    token = request.COOKIES.get('token')
    is_logged_in = request.COOKIES.get('is_logged_in')

    # Set up the Authorization header with the token
    headers = {
        "Authorization": f"Token {token}",
    }

    if is_logged_in == 'true' and token:
        try:

            # Fetch the players' data using API
            response = requests.put(
                f"{settings.BASE_API_URL}/admin-game-panel/trending/",
                headers=headers,
                data={
                    "game_id": game_id
                }
            )

            data = response.json()

            if response.status_code == 200:
                messages.success(request, data['message'])
                return redirect('CoinsSellingPlatformApp:my_games')
            else:
                messages.error(request, data['message'])
                return redirect('CoinsSellingPlatformApp:my_games')


        except requests.exceptions.RequestException as e:
            messages.error(request, f"Error: {str(e)}")
            return redirect('CoinsSellingPlatformApp:my_games')

        except json.JSONDecodeError:
            messages.error(request, "Invalid response from the server. Please try again later.")
            return redirect('CoinsSellingPlatformApp:my_games')

        except Exception as e:
            messages.error(request, "An unexpected error occurred. Please try again later.")
            return redirect('CoinsSellingPlatformApp:my_games')
    else:
        # If the user is not logged in, redirect to the login page
        return redirect('CoinsSellingPlatformApp:admin_login')

def delete_my_game(request, game_id):
    # Get the token and login status from cookies
    token = request.COOKIES.get('token')
    is_logged_in = request.COOKIES.get('is_logged_in')

    # Set up the Authorization header with the token
    headers = {
        "Authorization": f"Token {token}",
    }

    if is_logged_in == 'true' and token:
        try:

            # Fetch the players' data using API
            response = requests.delete(
                f"{settings.BASE_API_URL}/admin-game-panel/delete-game/",
                headers=headers,
                data={
                    "game_id": game_id
                }
            )

            data = response.json()
            print(f"""data: {data}""")

            if response.status_code == 200:
                messages.success(request, data['message'])
                return redirect('CoinsSellingPlatformApp:my_games')
            else:
                messages.error(request, data['message'])
                return redirect('CoinsSellingPlatformApp:my_games')


        except requests.exceptions.RequestException as e:
            messages.error(request, f"Error while connecting to API: {str(e)}")
            return redirect('CoinsSellingPlatformApp:my_games')

        except json.JSONDecodeError:
            messages.error(request, "Invalid response from the server. Please try again later.")
            return redirect('CoinsSellingPlatformApp:my_games')

        except Exception as e:
            messages.error(request, "An unexpected error occurred. Please try again later.")
            return redirect('CoinsSellingPlatformApp:my_games')
    else:
        # If the user is not logged in, redirect to the login page
        return redirect('CoinsSellingPlatformApp:admin_login')

def update_my_game(request, game_id):
    # Get the token and login status from cookies
    token = request.COOKIES.get('token')
    is_logged_in = request.COOKIES.get('is_logged_in')

    # Set up the Authorization header with the token
    headers = {
        "Authorization": f"Token {token}",
    }

    if is_logged_in == 'true' and token:
        if request.method == "POST":
            try:
                # Prepare body data for the API request
                body = {"game_id": game_id}

                # Include optional fields if provided
                optional_fields = [
                    'game_name', 'game_description', 'game_price',
                    'android_game_url', 'ios_game_url', 'browser_game_url',
                    'transfer_score_percentage', 'redeem_score_percentage'
                ]
                for field in optional_fields:
                    if field in request.POST and request.POST[field]:
                        body[field] = request.POST[field]

                # Handle boolean fields (checkbox values)
                body['upcoming_status'] = True if request.POST.get('upcoming_status') == 'on' else False
                body['is_trending'] = True if request.POST.get('is_trending') == 'on' else False
                body['is_free'] = True if request.POST.get('is_free') == 'on' else False

                # Include file fields if provided
                files = {}
                if 'game_image' in request.FILES:
                    files['game_image'] = request.FILES['game_image']
                if 'game_video' in request.FILES:
                    files['game_video'] = request.FILES['game_video']

                print(f"body: {body}")
                print(f"files: {files}")

                # Send the PUT request to the update API endpoint
                response = requests.put(
                    f"{settings.BASE_API_URL}/admin-game-panel/update-game/",
                    headers=headers,
                    data=body,
                    files=files
                )

                # Debugging logs for response
                print(f"Response Status Code: {response.status_code}")
                print(f"Response Content: {response.content.decode('utf-8')}")

                # Handle response based on status code
                if response.status_code == 200:
                    response_data = response.json()
                    messages.success(request, response_data["message"])
                else:
                    messages.error(request, f"Error {response.status_code}: {response.content.decode('utf-8')}")
            except Exception as e:
                messages.error(request, f"An error occurred: {e}")

            # Redirect to my_games after processing
            return redirect('CoinsSellingPlatformApp:my_games')

    else:
        # If the user is not logged in, redirect to the login page
        messages.error(request, "You must be logged in to update a game.")
        return redirect('CoinsSellingPlatformApp:admin_login')


## GAMES ROUTES

## AGENT CHATS

def my_agent_chat(request):
    # Get the token and login status from cookies
    token = request.COOKIES.get('token')
    is_logged_in = request.COOKIES.get('is_logged_in')

    # Set up the Authorization header with the token
    headers = {
        "Authorization": f"Token {token}",
    }

    if is_logged_in == 'true' and token:
        try:
            # Check for page and limit in query params
            page = int(request.GET.get('page', 1))
            limit = int(request.GET.get('page_size', 10))
            search = request.POST.get('search', '').strip()

            # Construct the API URL
            base_url = f"{settings.BASE_API_URL}/admin-game-panel/get-all-my-created-games/"
            api_url = f"{base_url}?page={page}&page_size={limit}"

            # Include the search parameter only if it's provided
            if search:
                api_url += f"&search={search}"

            # Fetch the players' data using API
            response = requests.get(api_url, headers=headers)

            if response.status_code == 200:
                default_data = response.json().get('data', [])
            else:
                default_data = []

            # Render the template with data
            return render(request, 'dashboards/admin/agent-chat-list-compact.html', {
                "data": default_data,
                "pagination": {
                    "current_page": page,
                    "page_size": limit,
                },
                "search_term": search,  # Pass the search term back to the template
            })

        except requests.RequestException as e:
            # Handle request exceptions (e.g., network errors)
            return render(request, 'dashboards/admin/agent-chat-list-compact.html', {
                "error": "Failed to load data. Please try again later.",
            })
    else:
        # If the user is not logged in, redirect to the login page
        return redirect('CoinsSellingPlatformApp:admin_login')


## AGENT CHATS

###################################### FRONTEND MANAGEMENT SYSTEM ##################################################



###################################### APIS MANAGEMENT SYSTEM ######################################################
## Authorization & Authentication - APIs Completed
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_all_users(request):
    """
    This function retrieves all users from the system. Only accessible by Admin and Agent roles.

    Args:
        request: The HTTP request object with authentication details.

    Returns:
        1.
            {
                "status": 200,
                "message": "Users fetched successfully.",
                "data": [
                    {
                        "id": "user1-id",
                        "email": "user1@example.com",
                        "first_name": "John",
                        "last_name": "Doe",
                        "role": "User"
                    },
                    ...
                ]
            }
        2.
            {
                "status": 401,
                "message": "Invalid or missing authentication token."
            }
        3.
            {
                "status": 403,
                "message": "User role 'Admin' is not  authorized."
            }
        4.
            {
                "status": 404,
                "message": "User not found."
            }
        5.
            {
                "status": 404,
                "message": "No users found for the Admin role."
            }

    """
    user_instance = AuthService.get_user_from_token(request)  # Authenticate and fetch the user
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")
    allowed_roles = ["Admin", "Agent"]
    user = User.objects.get(user_id=user_instance.id)  # Retrieve the authenticated user
    if not user:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
    user_role = getattr(user.role_id, "roles", None)  # Validate the user's role
    if user_role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{user_role}' is not authorized.")
    users = models.User.objects.filter(role_id=models.Role.objects.get(roles="User")).all()  # Fetch all users with the "User" role
    if not users:
        return APIResponse.HTTP_404_NOT_FOUND(message="No users found for the Admin role.")
    serializer = UserSerializer(users, many=True)  # Serialize queryset
    return APIResponse.HTTP_200_OK(data=serializer.data, message="Users fetched successfully.")


@api_view(['POST'])
def check_email(request):
    print("check_email hit...")
    email = request.data.get('email')
    print(email)
    if email:
        if DjangoUser.objects.filter(email=email).exists():
            return Response({'email_exists': True})
        else:
            return Response({'email_exists': False})
    return Response({'error': 'Invalid request data.'}, status=400)

import re
@api_view(['POST'])
def sign_up_api_view(request):
    """
           This function is used to sign up a new user. It creates a Django user and a custom user.
           It also generates an OTP and sends it to the user's email address.

           Args:
               request (HTTPRequest): The request object containing the user data.

           Payload:
               {
                 "user": {
                   "username": "Irshad",
                   "password": "pass@123",
                   "email": "irshad@gmail.com"
                 },
                 "first_name": "Irshad",
                 "last_name": "khan",
                 "email": "irshad@gmail.com",
                 "is_verified_license": true,
                 "gender": "M",
                 "date_of_birth": "1990-01-01",
                 "pro_status": "Free",
                 "waiting_list": false,
                 "experience_points": 10,
                 "user_level": 1,
                 "referral": false,
                 "referral_key": "referral_key",
                 "country_id": "62e58bc0-a794-4e4f-a7d0-86a842f60e23",
                 "role_id": "07e56a1f-2e18-41c7-8191-f7cff25236c6"
               }

           Returns:
               1. If the user is successfully created, it returns a response with a status code of 201 and a message
                   indicating that the user has been created.
                  {
                       "message": "OTP sent successfully.",
                       "status": 201,
                       "data": {
                           "otp_id": "b3b26d26-4c24-4d2d-aacc-28f6c6f941ae",
                           "otp": "150668",
                           "expire_at": "2024-11-29 13:05:21 UTC",
                           "email": "irshad@gmail.com",
                           "username": "Irshad",
                           "first_name": "Irshad",
                           "last_name": "khan"
                       }
                  }
               2. if the email domain is not in the valid domains list
                   {
                       "message": "Invalid email domain. Allowed domains include patterns like '@gmail.com', '@yahoo.com', etc.",
                       "status": 400,
                   }
               3. if not '@' symbol in the email
                   {
                       "message": "Invalid email format. Missing '@' symbol.",
                       "status": 400,
                   }
               4. if the email domain is not in the valid domains list
                   {
                       "message": "Invalid email domain. Allowed domains include patterns like
                       '@gmail.com', '@yahoo.com', etc.",
                       "status": 400,
                   }
               5. If the user already exists, it returns a response with a status code of 400 and a message
                   indicating that the user already exists.
                  {
                       "message": "Username already exists.",
                       "status": 400,
                   }
               6. If any of the required fields are missing, it returns a response with a status code of 400 and a message
                   indicating which fields are missing.
                   {
                       "message": "Username, Password, Email, First Name, and Last Name are required.",
                       "status": 400,
                   }
               7. If the email address is already in use, it returns a response with a status code of 400 and a message
                   indicating that the email address is already in use.
                   {
                       "message": "Email already exists.",
                       "status": 400,
                   }
               8. Internal server error:
                   {
                       "message": "An unexpected error occurred.",
                       "status": 500,
                   }
    """

    print("&&&&&&&&&&&&&&&&&&")
    print(request.data)
    # Extract data from request
    first_name = request.data.get('first_name')
    last_name = request.data.get('last_name')
    email = request.data.get('email')
    gender = request.data.get('gender')
    date_of_birth = request.data.get('date_of_birth')
    password = request.data.get('password')
    confirm_password = request.data.get('confirm_password')
    # Check if password and confirm_password match

    # Generate OTP and handle signup data
    otp, expiration_time = generate_otp()
    data = request.data
    if not data:
        return APIResponse.HTTP_400_BAD_REQUEST(message="No data provided.")
    expiration = expiration_time.strftime('%Y-%m-%d %H:%M:%S %Z')
    django_user_data = {
        'username': first_name + last_name,
        'first_name': first_name,
        'last_name': last_name,
        'email': email,
        'password': make_password(data['password']),
    }
    # Check if first_name is empty or contains invalid characters (only letters allowed)
    if not first_name or not re.match(r'^[A-Za-z]+$', first_name):
        error_message = "First name is required and must contain only letters."
        return  APIResponse.HTTP_400_BAD_REQUEST(message=error_message)
    if not last_name or not re.match(r'^[A-Za-z]+$', last_name):
        error_message = "Last name is required and must contain only letters."
        return  APIResponse.HTTP_400_BAD_REQUEST(message=error_message)
    # Check if the email already exists before generating OTP
    if not django_user_data['email']:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Email is required.")
    if '@' not in django_user_data['email']:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid email format. Missing '@' symbol.")
    domain = django_user_data['email'][django_user_data['email'].index('@'):]
    if domain not in valid_domains:
        return APIResponse.HTTP_400_BAD_REQUEST(
            message="Invalid email domain. Allowed domains include patterns like '@gmail.com', '@yahoo.com', etc.")
    if DjangoUser.objects.filter(email=django_user_data['email']).exists():
        return APIResponse.HTTP_400_BAD_REQUEST(message="Email already exists.")
    if DjangoUser.objects.filter(username=django_user_data['username']).exists():
        return APIResponse.HTTP_400_BAD_REQUEST(message="Username already exists.")
    if not gender or gender not in ['M', 'F', 'O']:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid gender. Allowed values are 'Male', 'Femail', 'Other'.")
    # Check if password and confirm_password empty or not
    if not password or not confirm_password:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Password and Confirm Password are required.")
    if password != confirm_password:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Password and Confirm Password doesn't matched.")
    print("after password check...")
    if not django_user_data['username'] or not django_user_data['password'] or not django_user_data['email'] or not \
    django_user_data['first_name'] or not django_user_data['last_name']:
        return APIResponse.HTTP_400_BAD_REQUEST(
            message="Username, Password, Email, First Name, and Last Name are required.")
    # check date of birth is not empty or
    if not date_of_birth:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Date of birth is required.")
    print(date_of_birth)

    ##

    dob = datetime.strptime(date_of_birth, "%Y-%m-%d")

    today = datetime.today()
    age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))

    if age < 18:
        return APIResponse.HTTP_400_BAD_REQUEST(message="You must be at least 18 years old.")
    if age > 100:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Age must be less than or equal to 100 years.")
    ##
    user_form_data = {
        key: value
        for key, value in data.items()
        if key in forms.UserForm.Meta.fields and key not in ['user_id', 'user_level', 'role', 'country']
    }
    role_text = data.get('role', 'User')
    country_text = data.get('country', 'United States')
    level_text = data.get('level', 'Level 0')
    role_obj = models.Role.objects.filter(roles=role_text).first()
    if not role_obj:
        return APIResponse.HTTP_400_BAD_REQUEST(message=f"Role '{role_text}' does not exist.")
    country_obj = models.Country.objects.filter(country=country_text).first()
    if not country_obj:
        return APIResponse.HTTP_400_BAD_REQUEST(message=f"Country '{country_text}' does not exist.")
    level_obj = models.Level.objects.filter(level=level_text).first()
    if not level_obj:
        return APIResponse.HTTP_400_BAD_REQUEST(message=f"Level '{level_text}' does not exist.")
    signup_data = {
        'django_user_data': django_user_data,
        'user_form_data': user_form_data,
        'role_obj': role_obj,
        'country_obj': country_obj,
        'level_obj': level_obj,
    }
    # # Proceed with the signup process
    # handle_code(signup_data)
    ##
    cache_key = f"signup_data_{django_user_data['email']}"
    cache.set(cache_key, signup_data, timeout=900)  # Cache for 15 minutes
    # --------------------------------------------------- validating parameters -----------------------------#
    otp_verification = models.OTPVerification.objects.create(
        otp=otp,
        otp_created_at=datetime.now(),
        expire_at=str(expiration_time),
        verification_type="OTP"
    )
    cache.set(f"otp_{django_user_data['email']}", otp, timeout=15000)  # 5 minutes timeout
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
        'gender': gender,
    }
    return APIResponse.HTTP_201_CREATED(message="OTP sent successfully.", data=response_data)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def upload_profiles_and_banners(request):
    """
        This function handles the profile and banner image upload for the authenticated user.
        Args:
            request (HTTPRequest): The request object containing the user's profile and banner images.
            The request should contain the following parameters:
                - user_profile: The user's profile image file.
                - banner: The user's banner image file.
        Payload:
            {
                "user_profile": "user_profile_image.jpg",
                "banner": "banner_image.jpg"
            }
        Returns:
                1.
                    {
                        "status": 200,
                        "message": "Profile and banner images updated successfully",
                        "data": {
                            "profile_image_url": "/media/user_profiles/AmmarHussain__a3caadbfe0ea43f08ce7
                            a4520347f637.jpg",
                            "banner_image_url": "/media/user_profiles/banners/AmmarHussain__942a1f2491a64
                            983acd75ada16c83bbb.jpg"
                        }
                    }

                2.
                    {
                        "status": 401,
                        "message": "Authentication token is missing"
                    }

                3.
                    {
                        "status": 401,
                        "message": "Invalid or expired token."
                    }

                4.
                    {
                        "status": 403,
                        "message": "User ID does not match the authenticated user."
                    }
                5.
                    {
                        "status": 400,
                        "message": "Profile or banner image are required"
                    }
                6.
                    {
                        "status": 500,
                        "message": "An error occurred: <error message>"
                    }

    """
    token = request.COOKIES.get('token')  # Retrieve the token from cookie # print(f"token 1: {token}")
    profile_image = request.FILES.get('user_profile')
    banner_image = request.FILES.get('banner')
    # ----------------------------------------------- Validating parameters-------------------------------
    if not token:
        token = request.headers.get('Authorization')  # Retrieve from Authorization header if not in cookies
        if token:
            token = token.split(' ')[1]  # Extract the token from 'Bearer <token>'
    if not token:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Authentication token is missing.")
    try:
        token_instance = Token.objects.get(key=token)  # Check if token is valid
        user_instance = token_instance.user  # Get the user associated with the token
        userid = user_instance.id  # print(f"""userid: {userid}""")
    except Token.DoesNotExist:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or expired token.")
    try:
        if str(user_instance.id) != str(userid):  # Ensure the user_id matches the token's user
            return APIResponse.HTTP_403_FORBIDDEN(message="User ID does not match the authenticated user.")
        user_instance = models.User.objects.get(user_id=userid)  # print(f"user_instance: {user_instance}")
    except models.User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message='User not found')
    if not profile_image or not banner_image:
        return APIResponse.HTTP_400_BAD_REQUEST(message='Profile or banner image are required')
    if profile_image:
        profile_file_name = f'{user_instance.user_id.username}__{uuid.uuid4().hex}.jpg'  # Generate a random filename
        profile_file_path = f'user_profiles/{profile_file_name}'
        file_path = default_storage.save(profile_file_path, profile_image)  # Save the image file
        user_instance.profile_image = file_path
    if banner_image:  # Handle banner image upload if provided
        banner_file_name = f'{user_instance.user_id.username}__{uuid.uuid4().hex}.jpg'  # Generate a random filename
        banner_file_path = f'user_profiles/banners/{banner_file_name}'
    # ------------------------------------------------- Validating Completed-----------------------------
    file_path = default_storage.save(banner_file_path, banner_image)
    user_instance.banner_image = file_path
    user_instance.save()
    return APIResponse.HTTP_200_OK(message='Profile and banner images updated successfully', data={
        'profile_image_url': f'{settings.MEDIA_URL}{user_instance.profile_image}',
        'banner_image_url': f'{settings.MEDIA_URL}{user_instance.banner_image}'
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def profile(request):
    """
        This function retrieves the user's profile data.
        Args:
            request (HTTPRequest): The request object containing the user's token.
        Returns:
            1.
                {
                    "status": 200,
                    "message": "User profile retrieved successfully.",
                    "data": {
                        "id": "fcda04f1-0174-4228-bcf3-792f3e6e6872",
                        "first_name": "Anas",
                        "last_name": "Khan",
                        "username": "anaskhan",
                        "email": "anas@gmail.com",
                        "profile": "/media/user_profiles/anaskhan__7057331667624391885bb5e0c36195e4.jpg",
                        "role": "User",
                        "dob": "1990-01-01",
                        "gender": "M",
                        "driving_license_front_image": null,
                        "driving_license_back_image": null,
                        "subscription_plan": {
                            "name": "Free",
                            "price": 0,
                            "duration": 0
                        },
                        "country": {
                            "country": "United States"
                        },
                        "phone": null,
                        "wallet": {
                            "id": "e3233fc2-335c-4477-86b1-4301b180a79f",
                            "current_balance": 0,
                            "total_amount": 0,
                            "payment_method": "Card",
                            "wallet_transaction_history": [
                                {
                                    "payment_method": "Card",
                                    "payment_status": "Approved",
                                    "transaction_amount": 0,
                                    "transaction_date": "2024-12-30T06:42:45.042976Z",
                                    "withdrawal_percentage_tax": 0,
                                    "payment": null
                                }
                            ]
                        }
                    }
                }
            2.
                {
                    "status": 401,
                    "message": "You are not authorized to perform this action."
                }
            3.
                {
                    "status": 401,
                    "message": "Invalid or expired token."
                }
            4.
                {
                    "status": 404,
                    "message": "User not found."
                }


    """

    # ------------------------------------------------ Validating Parameters -------------------------
    # print(f"Authorization Header: {request.headers.get('Authorization')}")
    allowed_roles = ["Admin", "Agent", "User"]
    print("user profile hit....")
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")
    user = AuthService.validate_user_role(user_instance, "User")
    if not user:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid token on profile.")
    print("skipppping on profile..... for token")
    user = models.User.objects.filter(user_id=user_instance.id).first()
    if not user:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
    user_role = getattr(user.role_id, "roles", None)      # Validate the user's role
    if user_role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{user_role}' is not authorized.")
    if user.wallet_id and user.wallet_id.wallet_transaction_history_id.exists():
        last_transaction = user.wallet_id.wallet_transaction_history_id.last()  # Get the last transaction
        last_payment_method = last_transaction.payment_method if last_transaction else None
    else:
        last_payment_method = None

    # ----------------------------------- Referrals -----------------------------------
    referrals = models.Referral.objects.filter(user_id=user)  # Get all referrals for the user
    total_referrals = referrals.count()

    referral_data = []
    for referral in referrals:
        # Extract data for each referral and its receivers
        receivers = referral.receiver_user_id.all()
        receiver_data = [{'username': receiver.user_id.username, 'email': receiver.email} for receiver in receivers]
        referral_data.append({
            'referral_key': referral.referral_key,
            'quantity': referral.quantity,
            'referral_created_at': referral.referral_created_at,
            'referral_expiry_date': referral.referral_expiry_date,
            'receivers': receiver_data
        })

    # ----------------------------------- Games Played -----------------------------------
    # Get the top 4 games based on the play count for the user
    # Get the first four games played by the user, ordered by the most recent
    favorite_games_obj = models.GamePlay.objects.filter(user=user).select_related('game').order_by('-played_at')[:5]

    favorite_games = []
    if favorite_games_obj:
        for game_play in favorite_games_obj:
            game = game_play.game
            favorite_games.append({
                "game_name": game.game_name,
                "game_description": game.game_description,
                "game_image":  game.game_image.url if game.game_image else None,  # Assuming there's a field for the game image
                "game_profit": game_play.profit,  # Assuming 'profit' is a field in the GamePlay model
            })
    else:
        favorite_games = []

    # Total Play Games
    total_played_games = models.GamePlay.objects.filter(user=user).count()
    # Total favorite games
    total_favorite_games = len(favorite_games)
    ## ----------------------------------- Wallet ------------------------------------------
    wallet = user.wallet_id
    # Calculate total deposit and withdrawal from WalletTransactionHistory
    transactions = wallet.wallet_transaction_history_id.all()

    total_deposit = transactions.filter(payment='Credit', payment_status='Approved').aggregate(
        total=Sum('transaction_amount')
    )['total'] or 0

    total_withdrawal = transactions.filter(payment='Debit', payment_status='Approved').aggregate(
        total=Sum('transaction_amount')
    )['total'] or 0

    # # Apply any bonus for crypto payments (if needed)
    # for transaction in transactions:
    #     if transaction.is_crypto_payment:
    #         transaction.apply_crypto_bonus()  # Apply 5% bonus to crypto payments

    # Calculate total_amount after bonus adjustments (considering crypto bonuses)
    # total_amount = total_deposit - total_withdrawal


    # ----------------------------------- User Profile -----------------------------------
    profile_data = {
        "id": user.id,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "username": user.user_id.username,
        "email": user.email,
        "profile":request.build_absolute_uri(user.profile_image.url) if  user.profile_image else None,
        "role": user.role_id.roles,
        "dob": user.date_of_birth,
        "gender": user.gender,
        "last_active": user.last_active.strftime('%d/%m/%Y %H:%M:%S'),
        "driving_license_front_image": user.driving_license_front_image.url if user.driving_license_front_image else None,
        "driving_license_back_image": user.driving_license_back_image.url if user.driving_license_back_image else None,
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
            "total_deposit": total_deposit,
            "total_withdrawal": total_withdrawal,
            "payment_method": "Stripe",  # Replace with dynamic payment method as per your business logic
            "wallet_transaction_history": [
                {
                    "payment_method": txn.payment_method if txn else None,
                    "payment_status": txn.payment_status if txn else None,
                    "transaction_amount": txn.transaction_amount if txn else None,
                    "transaction_date": txn.transaction_date if txn else None,
                    "withdrawal_percentage_tax": txn.withdrawal_percentage_tax if txn else None,
                    "payment": txn.payment if txn else None,
                } for txn in user.wallet_id.wallet_transaction_history_id.all()
            ] if user.wallet_id else None,
        } if user.wallet_id else None,
        "total_referrals": total_referrals,
        "referrals": referral_data,  # Include referral data directly in the profile
        "favorite_games": favorite_games,  # Include game data directly in the profile
        "total_favorite_games": total_favorite_games,
        "last_payment_method": last_payment_method,
        "total_played_games": total_played_games,
    }

    return APIResponse.HTTP_200_OK(message="User profile retrieved successfully.", data=profile_data)

from django.contrib.auth import login
from django.contrib.sessions.models import Session
from django.middleware.csrf import get_token
@api_view(['POST'])
def login_api_view(request):
    print('loign api hit....')
    """
    This function creates the login token which wither expires after 15 days (when remember me is passed in
    the incoming parameters) or after 24 hours.

    Args:
        request (HTTPRequest): The incoming request object.

    Payloads:
    {
        "username_or_email": "amir@gmail.com",
        "password": "pass@123",
        'remember_me': True/False/None (optional: default is False)
    }

    Returns:
    1. if we successfully authenticate the user, we return a response with the following data and status code 200:
        {
            status: 200
            message: "Login successful."
            data{
                "user_id": user.id,
                "username": django_user.username,
                "email": django_user.email,
                "is_superuser": django_user.is_superuser,
                "is_staff": django_user.is_staff,
                "token": token.key,  # Return the token for subsequent requests
            }
        }
    2. if the user is not authenticated, we return a response with the following message regarding the error and
       different status codes like these:
       1. 401 - Invalid username or password / Invalid credentials / User not found / Too many failed attempts.
       2. 400 - Username or email and password are required
       3. 403 - Reset password or wait for 30 minutes to login again /
                Your account is not active. Please contact support.
      4. 500 - Internal server error (with the error message)
    """

    # -------------------------------- Validating parameter ----------------------------------
    print("login backend hit... ")
    print(request.data)

    identifier = request.data.get('username_or_email', None)
    password = request.data.get('password', None)
    print(identifier, password)
    print("remember_me.... try....")
    remember_me = request.data.get('remember_me', False)
    print("rember_me......")
    print(remember_me)

    if not identifier or not password:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Username or email and password are required.")
    if '@' in identifier:
        domain = identifier[identifier.index('@'):]  #
        if domain in valid_domains:
            identifier = identifier     #
        else:
            return APIResponse.HTTP_400_BAD_REQUEST(
                message="Invalid email domain. Allowed domains include patterns like '@gmail.com', "
                        "'@yahoo.com', etc."
            )
        django_user = DjangoUser.objects.filter(email=identifier).first()
        if not django_user:
            print("inside first django.. check...")
            return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid email or password.")
    else:
        print("inside first django.. check... else")
        try:
            django_user = DjangoUser.objects.get(username=identifier)
        except DjangoUser.DoesNotExist:
            return Response({"message": "Invalid credentials."})
        print("inside first django.. check... 3333")

    if django_user is None:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid username or password.")
    user = models.User.objects.filter(user_id=django_user.id).first()
    if not user:
        return Response({"message": "Invalid username or password."}, status=401)
    if user.is_locked():
        return APIResponse.HTTP_403_FORBIDDEN(
            message="Reset password or wait for 30 minutes to login again."
        )
    if not django_user.is_active:
        send_mail(
            'Account Inactive',
            'Your account is inactive. Please contact support for activation.',
            settings.DEFAULT_FROM_EMAIL,
            [django_user.email],
        )
        return APIResponse.HTTP_403_FORBIDDEN(message="Your account is not active. Please contact support.")
    if getattr(user, 'is_frozen', False):
        return APIResponse.HTTP_403_FORBIDDEN(message="Your account is frozen. Please contact support.")

    # -------------------------------- Validating Completed ----------------------------------
    if django_user.check_password(password): # Authenticate user with the provided password
        user.reset_failed_attempts()
        # Generate or retrieve the token
        token, _ = Token.objects.get_or_create(user=django_user)
        # Log the user in (Django's session management)
        login(request, django_user)

        # Generate or get token
        token, _ = Token.objects.get_or_create(user=django_user)

        # Set session expiry based on "remember me" option
        if remember_me:
            request.session.set_expiry(1209600)  # 2 weeks
        else:
            request.session.set_expiry(3600)  # 1 hour

        response = Response({
            "message": "Login successful.",
            "token": token.key,
            # "role":role,
            "user": {
                "id": django_user.id,
                "username": django_user.username,
                "email": django_user.email
            }
        })


        return response



    else:
        # Handle failed login attempts
        if LoginAttemptMiddleware.handle_failed_login(user):
            return APIResponse.HTTP_403_FORBIDDEN(
                message="Too many failed attempts. Your account is locked for 30 minutes."
            )
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid credentials.")

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def de_activate_user(request):
    """
        This function freeze the user's account with username.
        means user.is_active = False
        Args:
            request (HTTPRequest): The request object containing the user's username or email.
            The request should contain the following parameters:
                - username: The user's username or email.
                - password: The user's password.
        Payload:
            {
              "username": "AmmarHussain",
              "email": "amaar@gmail.com"
            }

        Returns:
            1.
                {
                    "status": 200,
                    "message": "Account blocked successfully.",
                    "data": {
                        "user_id": 4,
                        "username": "AmmarHussain",
                        "email": "amaar@gmail.com",
                        "is_superuser": false,
                        "is_staff": false
                    }
                }
            2.
                {
                    "status": 401,
                    "message": "Authentication token is missing."
                }

            3.
                {
                    "status": 401,
                    "message": "Invalid or expired token."
                }
            4.
                {
                    "status": 401,
                    "message": "You are not authorized to perform this action."
                }
            5.
                {
                    "status": 400,
                    "message": "Invalid email domain. Allowed domains include patterns like '@gmail.com', "
                            "'@yahoo.com', etc."
                }
            6.
                 {
                    "status": 400,
                    "message": ""Username or email is required."
                }

            7.
                {
                    "status": 404,
                    "message": "User not found."
                }

            8.
               {
                    "status": 500,
                    "message": "An unexpected error occurred"
                }
            9.
                {
                    "status": 400,
                    "message": ""Username or email is required."
                }
    """
    token = request.COOKIES.get('token')            # Retrieve the token from cookies
    # ----------------------------------------------- Validate parameters ----------------------------------
    if not token:
        token = request.headers.get('Authorization')  # Retrieve from Authorization header if not in cookies
        if token:
            token = token.split(' ')[1]              # Extract the token from 'Bearer <token>'
    if not token:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Authentication token is missing.")
    # ----------------------------------------------- Validating Parameters ------------------------------------
    token_instance = Token.objects.get(key=token)       # check if token is valid
    if not token_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or expired token.")
    user_instance = token_instance.user                # Get the user associated with the token
    userid = user_instance.id
    if not userid:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="User not found.")
    admin = models.User.objects.filter(user_id=userid).first()    # print(f"admin: {admin}")
    if admin.role_id.roles != 'Admin':
        return APIResponse.HTTP_401_UNAUTHORIZED(message="You are not authorized to perform this action.")
    username_or_email = request.data.get('username') or request.data.get('email')
    if '@' in username_or_email:
        domain = username_or_email[username_or_email.index('@'):]       #
        if domain in valid_domains:
            username = username_or_email
        else:
            return APIResponse.HTTP_400_BAD_REQUEST(
                message="Invalid email domain. Allowed domains include patterns like '@gmail.com', "
                        "'@yahoo.com', etc."
            )
    else:
        username = username_or_email
        if not username:
                return APIResponse.HTTP_400_BAD_REQUEST(message="Username or email is required.")

    user = DjangoUser.objects.filter(username=username).first()
    if not user:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
    # ----------------------------------------------- Validating  Completed -------------------------------------
    user.is_active = False
    user.save()
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


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def activate_user(request):
    """
        This function un-freeze the user's account with username.This function gets the admin token and username
        or email to activate the user's account.
        means user.is_active = True

        Args:
            request (HTTPRequest): The request object containing the user's username or email.
            The request should contain the following parameters:
                - username: The user's username or email.
                - password: The user's password.
        Payload:
            {
              "username": "AmmarHussain",
              "email": "amaar@gmail.com"
            }
        Returns:
            1.
                {
                    "status": 200,
                    "message": "Account un-blocked successfully.",
                    "data": {
                        "user_id": 4,
                        "username": "AmmarHussain",
                        "email": "amaar@gmail.com",
                        "is_superuser": false,
                        "is_staff": false
                    }
                }
            2.
                {
                     "status": 401,
                     "message": "Authentication token is missing."
                }

            3.
                {
                    "status": 401,
                    "message": "Invalid or expired token."
                    }
            4.
                {
                    "status": 401,
                    "message": "You are not authorized to perform this action."
                }
            5.
                {
                    "status": 400,
                    "message": "Invalid email domain. Allowed domains include patterns like '@gmail.com', "
                            "'@yahoo.com', etc."
                }
            6.
                {
                    "status": 400,
                    "message": "Username or email is required."
                }
            7.
                {
                    "status": 404,
                    "message": "User not found."
                }
            8.
                {
                    "status": 500,
                    "message": "An unexpected error occurred"
                }
    """
    token = request.COOKIES.get('token')
    # ----------------------------------------------- Validating Parameters --------------------------------
    if not token:
        token = request.headers.get('Authorization')
        if token:
            token = token.split(' ')[1]  # Extract the token from 'Bearer <token>'
    if not token:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Authentication token is missing.")
    token_instance = Token.objects.get(key=token)
    if not token_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or expired token for admin.")
    user_instance = token_instance.user               # Get the user associated with the token
    userid = user_instance.id
    if not userid:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="User not found.")
    admin = models.User.objects.filter(user_id=userid).first()
    if admin.role_id.roles != 'Admin':
        return APIResponse.HTTP_401_UNAUTHORIZED(message="You are not authorized to perform this action.")
    username_or_email = request.data.get('username') or request.data.get('email')
    if '@' in username_or_email:
        domain = username_or_email[username_or_email.index('@'):]  #
        if domain in valid_domains:
            print(username_or_email)
            username = username_or_email
        else:
            return APIResponse.HTTP_400_BAD_REQUEST(
                message="Invalid email domain. Allowed domains include patterns like '@gmail.com', "
                        "'@yahoo.com', etc."
            )
    else:
        username = username_or_email
    if not username:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Username or email is required.")
    # ----------------------------------------------- Validating  Parameters ---------------------------------
    user = DjangoUser.objects.get(username=username)
    user.is_active = True
    user.save()
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

@api_view(['POST'])
def verify_otp_with_user_signup(request):
    """
        This function verifies the OTP sent to the user's email during the sign-up process.
        It checks if the OTP is valid and if the email is associated with a valid user.
        If the OTP is valid, it creates a new user with the provided data.
        If the email is not associated with a valid user, it creates a new user with the provided data and sends
        an email to the user.
        If the OTP is not valid, it returns an error message.

        Args:
            request (HTTPRequest): The incoming request object.

        Payloads:
        {
            "email": "amir@gmail.com",
            "otp": "123456"
        }
        Returns:
            1. if the OTP is valid and the email is associated with a valid user, we return a response
            with the following data and status code 201:
            {
                status: 201
                message: "User created successfully."
                data{
                    "user_id": user.id,
                    "user_name": custom_user.user_id.username,
                    "email": custom_user.user_id.email,
                    "referral_key": custom_user.referral_key,
                    "role": custom_user.role_id.roles,
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
            }
        2.
            1. if not email or not otp:
                 return APIResponse.HTTP_400_BAD_REQUEST(message="Email and OTP are required.")
            2. if OTP in None:
                 return APIResponse.HTTP_400_BAD_REQUEST(message="OTP has expired or was not found.")
            3. if otp is invalid:
                 return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid OTP.")
            4. if signup data not provide:
                 return APIResponse.HTTP_400_BAD_REQUEST(message="Sign-up data is incomplete. Please restart
                                                        the sign-up process.")
            5. if no django_user or not user_form_data or not role_obj or not country_obj or not level_obj:
                 return APIResponse.HTTP_400_BAD_REQUEST(message="ign-up data is incomplete. Please restart the
                                                        sign-up process.")
            6. if spinqueryset count is less than 3:
                 return APIResponse.HTTP_400_BAD_REQUEST(message="Not enough spins available to select a random spin.")
            7. if there is an error creating the user:
                 return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message="Error creating Django user.")
            8. if free_plays not created:
                 return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message="FreePlay form validation failed.")
            9. if form data is invalid:
                 return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid form data.")
            10. if there is an error creating the custom user:
                 return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message="Error creating user.")
            11. if not '@' symbol in the email:
                 return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid email format. Missing '@' symbol.")
    """
    print("function hit from frontend side...")
    email = request.data.get('email')
    otp = request.data.get('otp')
    print(email, otp)
    # -------------------------------- Validating parameter -------------------------------
    if not email or not otp:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Email and OTP are required.")
    if '@' not in email:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid email format. Missing '@' symbol.")
    stored_otp = cache.get(f"otp_{email}")   # Verify OTP
    if stored_otp is None:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Email not found or OTP has expired.")
    if str(stored_otp) != str(otp):
        return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid OTP.")
    cache_key = f"signup_data_{email}"  # Retrieve signup data from the cache
    print(f"cache_key: {cache_key}")
    print(f"signup_data_{email}")
    signup_data = cache.get(cache_key)
    print(f"signup data...")
    print(signup_data)
    if not signup_data:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Sign-up data has expired. Please restart the sign-up process.")
    django_user_data = signup_data['django_user_data']
    print("debugginng")
    print(f"django_user_data: {django_user_data}")
    user_form_data = signup_data['user_form_data']
    print(f"user_form_data: {user_form_data}")
    role_obj = signup_data['role_obj']
    country_obj = signup_data['country_obj']
    level_obj = signup_data['level_obj']
    if not django_user_data or not user_form_data or not role_obj or not country_obj or not level_obj:
        return APIResponse.HTTP_400_BAD_REQUEST(
            message="Sign-up data is incomplete. Please restart the sign-up process.")
    # ------------------------------------------- validating parameter -------------------------------

    referral_key = str(uuid.uuid4().hex).upper()  # GenerateSpin key uuid4 without hyphens
    spin_queryset = models.Spin.objects.all()   # Filter all spins and randomly select one between 3 and 5 items.
    if spin_queryset.count() < 3:      # Ensure there are enough spins available to select from.
        return APIResponse.HTTP_400_BAD_REQUEST(message="Not enough spins available to select a random spin.")
    random_spin_list = random.sample(list(spin_queryset), random.randint(3, 5))
    selected_spin = random_spin_list[0]      # Select the first spin from the randomly chosen spins.
    user_form = forms.UserForm(data=user_form_data)  # Create the custom user
    if user_form.is_valid():
        django_user = DjangoUser.objects.create(**django_user_data)  # Create Django User
        if not django_user:
            return APIResponse.HTTP_400_BAD_REQUEST(message="Error creating Django user.")
        user_form_data['user_id'] = django_user.id   # Set user ID for the custom user
        custom_user = user_form.save(commit=False)
        custom_user.user_id = django_user          # Link to the Django user
        custom_user.role_id = role_obj             # Assign the models.Role
        custom_user.country_id = country_obj       # Assign the models.Country
        custom_user.user_level = level_obj         # Assign the models.Level
        custom_user.is_verified_license = False    # Default license verification to False
        custom_user.spin_id = selected_spin        # Assign the randomly selected spin
        custom_user.referral_key = referral_key.upper()
        custom_user.email = django_user.email
        subscription_plan = get_object_or_404(models.SubscriptionPlan, pro_status='Free') # Subscription Plan
        custom_user.subscription_plan = subscription_plan
        random_free_plays_between_3_and_5 = random.randint(3, 5) # Randomly select between 3 and 5 free plays
        if custom_user.user_id.email:            # Handle first-time sign-up logic
            wallet_history = models.WalletTransactionHistory.objects.create(
                payment_method='Card',
                payment_status='Approved',
                transaction_amount=0
            )
            wallet = models.Wallet.objects.create(
                current_balance=0,
                total_amount=0
            )
            wallet.wallet_transaction_history_id.add(wallet_history)   # print(wallet, wallet_history)
            if wallet and wallet_history:
                custom_user.wallet_id = wallet
                custom_user.save()
                free_plays = forms.FreePlayForm({
                    "user": custom_user,
                    "free_plays": random_free_plays_between_3_and_5,
                    "spins_left": random_free_plays_between_3_and_5,
                    "expires_at": datetime.now() + timedelta(days=30)
                })
                if free_plays.is_valid():
                    free_play_instance = free_plays.save(commit=False)
                    free_play_instance.save()
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
                else:
                    print(f"Form errors: {free_plays.errors}")
                    return APIResponse.HTTP_400_BAD_REQUEST(message="FreePlay form validation failed.",
                                                            data=free_plays.errors)
    else:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid form data.", data=user_form.errors)


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_user_with_licensees_and_increases_xp_levels(request):
    """
        This function updates the user's profile with the provided licensees and increases the user's experience
        points and levels accordingly.
        Args:
            request (HTTPRequest): The request object containing the user's profile data.
        Payload:
            {
                "licensees": [
                    {
                        "driving_licence_front_image": "driving_licence_front_image.jpg",
                        "driving_licence_back_image": "driving_licence_back_image.jpg",
                        "experiences_points": 1000,
                    }
                ]
            }
        Returns:
            1.
                {    "message": "User updated successfully.",
                    "status": 200,
                    "data": {
                        "message": "User updated successfully.",
                        "user": {
                            "id": "eb415878-dc54-4831-b06e-4368f9122431",
                            "first_name": "Irshad",
                            "last_name": "khan",
                            "email": "irshad@gmail.com",
                            "experience_points": 95000,
                            "is_verified_license": true,
                            "user_level": "L1"
                        }
                    }
                }
            2.
                {
                    "status": 401,
                    "message": "Authentication token is missing."
                }
            3.
                {
                    "status":   401,
                    "message": "User not found."
                }
            4.
                {
                    "status": 400,
                    "message": "Validation errors."
                }
    """
    token = request.COOKIES.get('token')              # Retrieve the token from cookies  # print(f"token 1: {token}")
    if not token:
        token = request.headers.get('Authorization')  # Retrieve from Authorization header if not in cookies
        if token:
            token = token.split(' ')[1]               # Extract the token from 'Bearer <token>'
    if not token:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Authentication token is missing.") #print(f"token 2: {token}")
    token_instance = Token.objects.get(key=token)
    if not token_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or expired token.")
    user_instance = token_instance.user             # Get the user associated with the token
    userid = user_instance.id                       # print(f"""userid: {userid}""")
    if not userid:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="User not found.")
    user = models.User.objects.get(user_id=userid)        # Retrieve the user instance from the database
    if not user:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
    form = forms.UpdateUserLicenseForm(request.data, request.FILES, instance=user)
    # print("************************")
    # "You cannot increase your level because you don't have enough experience points.
    # print(form.data['experience_points'])
    if form.is_valid():
        updated_user = form.save(commit=False) # Save the form and handle the user models.Level upgrade automatically
        updated_user.save()
        response_data = {
            "message": "User updated successfully.",
            "user": {
                "id": updated_user.id,
                "first_name": updated_user.first_name,
                "last_name": updated_user.last_name,
                "email": updated_user.email,
                "experience_points": updated_user.experience_points,
                "is_verified_license": updated_user.is_verified_license,
                "user_level": updated_user.user_level.level_code if updated_user.user_level else None,
            }
        }
        return APIResponse.HTTP_200_OK(data=response_data, message="User updated successfully.")
    else:
        return APIResponse.HTTP_400_BAD_REQUEST(data=form.errors, message="Validation errors.")


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def phone_verification_and_get_free_xp(request):
    """
        This function updates the user's phone number and grants the user free experience points.
        Args:
            request (HTTPRequest): The request object containing the user's phone number.
            Get the user's phone number and grant the user free experience points.
        Payload:
            {
                "phone": "0123456789"
            }
        Returns:
            1.
                {
                    "status": 200,
                    "message": "Phone verification and free XP granted successfully.",
                    "data": {
                        "message": "Phone verification and free XP granted successfully.",
                        "user": {
                            "id": "9b03dcbb-e3a3-454f-93b6-15096801bb56",
                            "first_name": "Amaar",
                            "last_name": "Hussain",
                            "email": "amaar@gmail.com",
                            "phone": "03026677888",
                            "is_phone_verified": true,
                            "last_experience_points": 10.0,
                            "new_experience_points": 210.0,
                            "is_verified_license": false,
                            "user_level": "L0"
                        }
                    }
                }
            2.
                {
                    "status": 401,
                    "message": "Authentication token is missing."
                }
            3.
                {
                    "status": 401,
                    "message": "Invalid or expired token."
                }
            4.
                {
                    "status": 401,
                    "message": "You are not authorized to perform this action."
                }
            5.
                {    "status": 404,
                    "message": "User not found."
                }
            6.
                {
                    "status": 400,
                    "message": "Validation errors."
    """
    # ----------------------------------------------- Validating Parameters ----------------------------
    token = request.COOKIES.get('token')               # Retrieve the token from cookies
    if not token:
        token = request.headers.get('Authorization')     # Retrieve from Authorization header if not in cookies
        if token:
            token = token.split(' ')[1]                   # Extract the token from 'Bearer <token>'
    if not token:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Authentication token is missing.")
    try:
        token_instance = Token.objects.get(key=token)
        user_instance = token_instance.user  # Get the user associated with the token
        userid = user_instance.id
    except Token.DoesNotExist:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or expired token.")
    user = models.User.objects.get(user_id=userid)
    if not user:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
    # ------------------------------------------------ Validating Completed ------------------------------
    form = forms.UpdateUserPhoneAndGetFreeXPForm(request.data, instance=user)
    if form.is_valid():
        updated_user = form.save(commit=False)
        updated_user.save()
        response_data = {
            "message": "Phone verification and free XP granted successfully.",
            "user": {
                "id": updated_user.id,
                "first_name": updated_user.first_name,
                "last_name": updated_user.last_name,
                "email": updated_user.email,
                "phone": updated_user.phone,
                "is_phone_verified": updated_user.is_phone_verified,
                "last_experience_points": user.experience_points,
                "new_experience_points": updated_user.experience_points,
                "is_verified_license": updated_user.is_verified_license,
                "user_level": updated_user.user_level.level_code if updated_user.user_level else None,
            }
        }
        return APIResponse.HTTP_200_OK(data=response_data,
                                               message="Phone verification and free XP granted successfully.")
    else:
        return APIResponse.HTTP_400_BAD_REQUEST(data=form.errors, message="Validation errors.")

    #ValueError: Phone number is already verified.   # tomorrow we have solve this issue and the above function raise this error.


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_user_personal_information_api(request):
    """
    This function is used to update a user's personal information. Provide the token of the logged-in user.
    Args:
        request: The HTTP request object containing user details to update.
    Returns:
        1.
            {
                "status": 200,
                "message": "User information updated successfully.",
                "data": {
                    "id": "e974d9ee-8f41-4f24-ab9f-c76707e38236",
                    "first_name": "Irshad",
                    "last_name": "Hussain",
                    "email": "irsad@gmail.com",
                    "front_images": "https://example.com/front.jpg",
                    "back_images": "https://example.com/back.jpg",
                    "selected_documents": "Driving License"
                }
            }
        2.
            {
                "status": 401,
                "message": "Invalid or missing authentication token."
            }
        3.
            {
                "status": 403,
                "message": "User role 'Guest' is not authorized."
            }
        4.
            {
                "status": 404,
                "message": "User not found."
            }

    """
    user_instance = AuthService.get_user_from_token(request)  # Authenticate the user
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")
    allowed_roles = ["Admin", "Agent", "User"]
    try:
        user_obj = models.User.objects.get(user_id=user_instance.id)
    except models.User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
    user_role = getattr(user_obj.role_id, "roles", None)  # Validate user role
    if user_role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{user_role}' is not authorized.")
    userid = user_instance.id
    first_name = request.data.get('first_name')
    last_name = request.data.get('last_name')
    username = request.data.get('username')
    dob = request.data.get('dob')
    if not userid or not any([first_name, last_name, username, dob]):
        return APIResponse.HTTP_400_BAD_REQUEST(message="Missing required fields.")
    updated_user = models.User.objects.filter(user_id=userid).first()
    if not updated_user:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
    django_user = DjangoUser.objects.get(id=userid)
    if username:
        django_user.username = username
    if first_name:
        updated_user.first_name = first_name
    if last_name:
        updated_user.last_name = last_name
    if dob:
        updated_user.date_of_birth = dob
    updated_user.save()
    django_user.save()
    response_data = {
        "id": updated_user.id,
        "first_name": updated_user.first_name,
        "last_name": updated_user.last_name,
        "email": updated_user.email,
        "front_images": updated_user.front_images.url if updated_user.front_images else None,
        "back_images": updated_user.back_images.url if updated_user.back_images else None,
        "selected_documents": updated_user.selected_documents
    }
    return APIResponse.HTTP_200_OK(data=response_data, message="User information updated successfully.")


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_user_documents(request):
    """
        This function updates the user's documents.
        Args:
            request (HTTPRequest): The request object containing the user's documents.
        Payload:
            {
                "front_images": "front_images.jpg",
                "back_images": "back_images.jpg",
                "selected_documents": "selected_documents.pdf"
            }
        Returns:
            1.
                {
                    "status": 200,
                    "message": "User updated successfully.",
                    "data": {
                        "message": "User updated successfully.",
                        "user": {
                            "id": "9b03dcbb-e3a3-454f-93b6-15096801bb56",
                            "first_name": "Amaar",
                            "last_name": "Hussain",
                            "email": "amaar@gmail.com",
                            "front_images": "/media/user_profiles/documents/tariq_Mahmood3x3x_rlzOUrB.jpg",
                            "back_images": "/media/user_profiles/documents/default-game_SbTT2yp.jpg",
                            "selected_documents": "id_card"
                        }
                    }
                }
            2.
                {
                    "status": 401,
                    "message": "Authentication token is missing."
                }
            3.
                {
                    "status": 401,
                    "message": "Invalid or expired token."
                }
            4.
                {
                    "status": 401,
                    "message": "You are not authorized to perform this action."
                }
            5.
                {
                    "status": 404,
                    "message": "User not found."
                }
            6.
                {
                    "status": 400,
                    "message": "Validation errors."
                }
            7.
                {
                    "status": 404,
                    "message": "Token not found."
                }
    """
    # ----------------------------------------------- Validating Parameters -----------------------
    token = request.COOKIES.get('token')                # Retrieve the token from cookies #print(f"token 1: {token}")
    if not token:
        token = request.headers.get('Authorization')    # Retrieve from Authorization header if not in cookies
        if token:
            token = token.split(' ')[1]              # Extract the token from 'Bearer <token>'
    if not token:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Authentication token is missing.")
    try:
        token_instance = Token.objects.get(key=token)
        user_instance = token_instance.user  # Authenticated user
        user_id = user_instance.id
    except token.DoesNotExist:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or expired token.")
    user = models.User.objects.get(user_id=user_id)
    if not user:   # Check if the user exists for update documents
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
    # ------------------------------------------------ Validating Completed ---------------------------
    form = forms.UpdateUserDocumentForm(request.data, request.FILES, instance=user)
    if form.is_valid():
        updated_user = form.save()
        response_data = {
            "message": "User updated successfully.",
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
        return APIResponse.HTTP_200_OK(data=response_data, message="User updated successfully.")
    else:
        return APIResponse.HTTP_400_BAD_REQUEST(data=form.errors, message="Validation errors.")


@api_view(['POST'])
def verify_otp(request):
    """
        This function verifies the OTP sent to the user's email.
        Args:
            request (HttpRequest): The request object containing the email and OTP.
        Payload:
            {
                "email": "user@email.com",
                "otp": "123456"
            }
        Returns:
            1.
                {
                    "status": 200,
                    "message": "User verified successfully.",
                    "data": {
                        "email": "amaar@gmail.com"
                    }
                }

            2.
                {
                    "message": "Email and OTP are required.",
                    "data": {
                        "email": "user@email.com"
                        status":404
                    }
                }
            3.
                {
                    "message": "OTP has expired or was not found.",
                    "data": {
                        "email": "user@email.com"
                        "status":400
               }
            4.
                {
                    "message": "Invalid OTP.",
                    "data": {
                        "email": "user@email.com"
                        "status":400
                    }
                }
            5.
                {
                    "message": "User with this email does not exist.",
                    "data": {
                        "email": "user@email.com"
                        status":404
                    }
                }
            6.
                {
                    "message": "User verified successfully.",
                    "data": {
                        "email": "user@email.com"
                        "status":200
                    }
                }

    """
    email = request.data.get('email')
    otp = request.data.get('otp')
    print("hti... verify_otp")
    print(f"email: {email}, otp: {otp}")
    _, expiration_time = generate_otp()
    expiration = expiration_time.strftime('%Y-%m-%d %H:%M:%S %Z')
    #--------------------------------------------- Validating Parameters ------------------------------------
    if not email or not otp:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Email and OTP are required.")
    stored_otp = cache.get(f"otp_{email}")     # Retrieve OTP from cache
    print(f"stored_otp: {stored_otp}")
    if stored_otp is None:
        return APIResponse.HTTP_400_BAD_REQUEST(message="OTP has expired or was not found.")
    if str(stored_otp) != str(otp):
        return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid OTP.")
    #-------------------------------------------------- Validating Completed -----------------------------------

    user_instance = models.User.objects.get(user_id__email=email)  # Fetch the user by email
    user_instance.is_active = True  # Mark the user as active after OTP verification
    user_instance.save()
    models.OTPVerification.objects.create(
        otp=otp,
        otp_created_at=datetime.now(),
        expire_at=str(expiration_time),
        verification_type=request.data.get('verification_type', 'OTP'),
    )
    return APIResponse.HTTP_200_OK(message="User verified successfully for email verifcation.", data={"email": email})


@api_view(['POST'])
def refresh_otp(request):
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
    if not email:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Email is required.", data={"email": email})

    otp, expiration_time = generate_otp()
    cache.set(f"otp_{email}", otp, timeout=300) #try:
    with transaction.atomic():
       user_instance = models.User.objects.get(user_id__email=email)
       if not user_instance:
           return APIResponse.HTTP_404_NOT_FOUND(message="User with this email does not exist.", data={"email": email})
    # ---------------------------------------- Validating Completed ---------------------------------
       user_instance.verification_code = otp  # Update the verification code
       user_instance.save()
       models.OTPVerification.objects.create(
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
       return APIResponse.HTTP_200_OK(message="OTP resent successfully.", data=data)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def request_reset_password(request):   ##
    """
        This function generates a one-time password (OTP) and sends it to the user's email.
        The user can then use this OTP to reset their password.

        Args:
            request (HTTPRequest): The request object containing the email of the user.

        Payload:
            {
                "email": "user@example.com"
            }
        Returns:
            1.
                {
                    "status": 200,
                    "message": "Password reset successfully.",
                    "data": {
                        "email": "amaar@gmail.com",
                        "otp": "223710",
                        "datetime": "2024-12-24 07:50:06.692117+00:00"
                    }
                }
            2.
                {
                    "status": 400,
                    "message": "Email is required."
                }

            3.
                {
                    "status": 500,
                    "message": "Unable to find user. Please try again after few minutes."
                    data: {
                        "email": "amaar@gmail.com",
                        "datetime": "2024-12-24 07:50:06.692117+00:00"
                    }
                }
    """
    # ------------------------------------------------ Validate parameters ---------------------------
    user_instance = AuthService.get_user_from_token(request)
    auth_user = AuthService.validate_user_role(user_instance, "User")
    user = models.User.objects.get(id=auth_user.id)
    email = request.data.get('email')
    if not email:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Email is required.")
    if user.email != email:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message="Unable to find user.Provide the valid email")
    print("request reset password hit.... ")
    otp, expiration_time = generate_otp()
    # set otp
    cache.set(f"otp_{email}", otp, timeout=300)
    user = models.User.objects.filter(email=email).first()
    # -------------------------------------------------- Validate parameters -------------------------
    otp_verification = models.OTPVerification.objects.create(
        otp=otp,
        otp_created_at=datetime.now(),
        expire_at=expiration_time,  # Use the datetime object for expiration time
        verification_type=request.data.get('verification_type', 'OTP'),
    )
    user.otp_verification_id = otp_verification
    user.save()
    send_mail(
        'Password Reset Code',
        f'Your password reset code is: {otp}, and it will expire at {expiration_time}.',
        settings.DEFAULT_FROM_EMAIL,
        [email],
        fail_silently=False,
    )
    data =  {
        "email": email,
        "otp": otp,
        "datetime": datetime.now(tz=UTC).__str__(),
    }
    return APIResponse.HTTP_200_OK(message="Password reset successfully.", data=data)


from django.contrib.auth.hashers import make_password, check_password
@api_view(['POST'])
def confirm_reset_password(request):
    """
    This function confirms the OTP entered by the user and resets the password.
    Args:
        request (HTTPRequest): The request object containing the email, OTP, and new password.

    Payload:
            {
                "email": "user@example.com",
                "otp": "223710",
                "new_password": "password123",
                "confirm_password": "password123"
            }
    Returns:
        1.
            {
                "status": 200,
                "message": "Password reset successfully.",
                "data": {
                    "email": "user@example.com",
                    "new_password": "password123",
                    "datetime": "2024-12-24 08:25:56.076251+00:00"
                }
            }
        2.
             {
                "status": 400,
                "message": "Email, OTP, new password, and confirm password are required."
            }

        3.
            {
                "status": 400,
                "message": "New password and confirm password do not match."
            }

        4.
            {
                "status": 400,
                "message": "Invalid reset code."
            }

        5. if no user found with the email
            {
                "status": 404,
                "message": "User with this email does not exist."
            }

        6.
            {
                "status": 500,
                "message": "Unable to find user. Please try again after few minutes.",
                "data": {
                    "username": "user@example.com",
                    "new_password": "password123",
                    "datetime": "2024-12-24 08:25:56.076251+00:00"
                }
            }
    """

    print("confim reset password hit.... ")
    new_password = request.data.get('new_password')
    confirm_new_password = request.data.get('confirm_new_password')
    print("debugging.........")
    print(f"new password: {new_password}")
    print(f"confirm new password: {confirm_new_password}")
    email = request.data.get('email')
    print(new_password,confirm_new_password,email)
    user = DjangoUser.objects.get(email=email)
    if not user:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
    # --------------------------------------------------- Validating Parameters ----------------------------
    if new_password != confirm_new_password:
        return APIResponse.HTTP_400_BAD_REQUEST(message="New password and confirm password do not match.")

    # Hash the new password and save it
    user.password = make_password(new_password)
    user.save()

    user.refresh_from_db()

    # ✅ Check if the new password is set correctly
    if check_password(new_password, user.password):
        print("Password successfully updated in the database.")
    else:
        print("Error: Password was not updated correctly!")
    send_mail(
        'Password Reset',
        'Your password has been reset successfully.',
        settings.DEFAULT_FROM_EMAIL,
        [email],
        fail_silently=False,
    )
    data = {
        "email": email,
        "new_password": new_password,
        "datetime": datetime.now(tz=UTC).__str__(),
    }
    return APIResponse.HTTP_200_OK(message="Password reset successfully.", data=data)



@api_view(['POST'])
def  verify_email(request):
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
    cache.set(f"otp_{email}", otp, timeout=300) #try:
    with transaction.atomic():
       user_instance = models.User.objects.get(user_id__email=email)
       if not user_instance:
           return APIResponse.HTTP_404_NOT_FOUND(message="User with this email does not exist.", data={"email": email})
    # ---------------------------------------- Validating Completed ---------------------------------
       user_instance.verification_code = otp  # Update the verification code
       user_instance.save()
       models.OTPVerification.objects.create(
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



## Authorization & Authentication - APIs Completed
############################################################################################################
## Chat Management System - APIs Completed
# Start the thread when the application runs
thread = threading.Thread(target=delete_inactive_user_messages, daemon=True)
thread.start()

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def send_chat_to_agent(request):
    """
        This function sends a chat message to a user. If User is not active for 15 minutes, automatically delete
        all messages of that user.
        Args:
                request (HTTPRequest): The request object containing the user's token and chat message with attachment.
        Payload:
                {
                    "user_id": "9b03dcbb-e3a3-454f-93b6-15096801bb56",
                    "message_content": "Hello, how can I help you?",
                    "attachment_image": "attachment_image.jpg"
                    "status": "active"
                }
        Returns:
            1.
                {
                    "status": 200,
                    "message": "Message sent to AmmarHussain successfully.",
                    "data": {
                        "user_id": "9b03dcbb-e3a3-454f-93b6-15096801bb56",
                        "agent_id": "adc1f1de-caba-4616-9058-ee53bfb14e47",
                        "message_content": "This can occur for several reasons:",
                        "attachment_image": "/media/agent-user-chats/7_b1b844bf.jpg",
                        "status": "active",
                        "created_at": "2024-12-25T06:47:48.000967Z"
                    }
                }
            2.
                {
                    "status": 401,
                    "message": "Authentication token is missing."
                }
            3.
                {
                    "status": 401,
                    "message": "Invalid or expired token."
                }
            4.
                {
                    "status": 500,
                    "message":"Roles not properly configured."
                }
            5.
                {
                    "status": 404,
                    "message": "Agent not found."
                }
            6.
                {
                    "status": 400,
                    "message": "User ID is required."
                }
            7.
                {
                    "status": 400,
                    "message": "User not found."
                }
            8.
                {
                    "status": 400,
                    "message": "User is banned from agent chat."
                }
            9.
                {
                    "status": 400,
                    "message": "Agent is banned from agent chat."
                }
            10.
                {
                    "status": 400,
                    "message": "Invalid agent Role."
                }
            11.
                {
                    "status": 400,
                    "message": "Invalid user Role."
                }
            12.
                {
                    "status": 400,
                    "message": "Invalid form data."
                }

    """
    # Retrieve token from cookies or headers
    user_instance = AuthService.get_user_from_token(request)
    auth_user = AuthService.validate_user_role(user_instance, "User")
    # auth_user = AuthService.validate_user_role(user_instance, "Admin")
    user_role = models.Role.objects.filter(roles="User").first()
    # user_role = models.Role.objects.filter(roles="Admin").first()
    agent_role = models.Role.objects.filter(roles="Agent").first()
    if not agent_role or not user_role:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message="Roles not properly configured.")
    user = models.User.objects.get(id=auth_user.id)
    if not user:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
    agent = request.data.get('agent_id')
    if not agent:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Agent ID is required.")
    agent = models.User.objects.get(id=agent)
    if not agent:
        return APIResponse.HTTP_404_NOT_FOUND(message="Agent not found.")
    if not user:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
    if agent.is_banned_from_agent_chat:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Agent is banned from agent chat.")
    if user.is_banned_from_agent_chat:
        return APIResponse.HTTP_400_BAD_REQUEST(message="User is banned from agent chat.")
    if not agent.role_id or agent.role_id.roles != agent_role.roles:     # Validate roles
        return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid agent Role.")
    if not user.role_id or user.role_id.roles != user_role.roles:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid user Role.")
    form = forms.AgentChatForm(request.data, request.FILES)  # Combine and validate form data
    if not form.is_valid():
        return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid form data.", data=form.errors)
    # ----------------------------------------------- Validating Completed -------------------------------
    user.is_last_active = True                              # Update user's last active timestamp
    user.update_last_active()
    user.save()
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


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def send_chat_to_user(request):
    """
        This function sends a chat message to a user. If User is not active for 15 minutes, automatically delete
        all messages of that user.
        Args:
                request (HTTPRequest): The request object containing the user's token and chat message with attachment.
        Payload:
                {
                    "user_id": "9b03dcbb-e3a3-454f-93b6-15096801bb56",
                    "message_content": "Hello, how can I help you?",
                    "attachment_image": "attachment_image.jpg"
                    "status": "active"
                }
        Returns:
            1.
                {
                    "status": 200,
                    "message": "Message sent to AmmarHussain successfully.",
                    "data": {
                        "user_id": "9b03dcbb-e3a3-454f-93b6-15096801bb56",
                        "agent_id": "adc1f1de-caba-4616-9058-ee53bfb14e47",
                        "message_content": "This can occur for several reasons:",
                        "attachment_image": "/media/agent-user-chats/7_b1b844bf.jpg",
                        "status": "active",
                        "created_at": "2024-12-25T06:47:48.000967Z"
                    }
                }
            2.
                {
                    "status": 401,
                    "message": "Authentication token is missing."
                }
            3.
                {
                    "status": 401,
                    "message": "Invalid or expired token."
                }
            4.
                {
                    "status": 500,
                    "message":"Roles not properly configured."
                }
            5.
                {
                    "status": 404,
                    "message": "Agent not found."
                }
            6.
                {
                    "status": 400,
                    "message": "User ID is required."
                }
            7.
                {
                    "status": 400,
                    "message": "User not found."
                }
            8.
                {
                    "status": 400,
                    "message": "User is banned from agent chat."
                }
            9.
                {
                    "status": 400,
                    "message": "Agent is banned from agent chat."
                }
            10.
                {
                    "status": 400,
                    "message": "Invalid agent Role."
                }
            11.
                {
                    "status": 400,
                    "message": "Invalid user Role."
                }
            12.
                {
                    "status": 400,
                    "message": "Invalid form data."
                }

    """
    # Retrieve token from cookies or headers
    user_instance = AuthService.get_user_from_token(request)
    auth_user = AuthService.validate_user_role(user_instance, "Agent")
    user_role = models.Role.objects.filter(roles="User").first()
    agent_role = models.Role.objects.filter(roles="Agent").first()
    if not agent_role or not user_role:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message="Roles not properly configured.")
    agent = models.User.objects.get(id=auth_user.id)
    if not agent:
        return APIResponse.HTTP_404_NOT_FOUND(message="Agent not found.")
    user_id = request.data.get('user_id')
    if not user_id:
        return APIResponse.HTTP_400_BAD_REQUEST(message="User ID is required.")
    user = models.User.objects.get(id=user_id)
    if not user:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
    if agent.is_banned_from_agent_chat:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Agent is banned from agent chat.")
    if user.is_banned_from_agent_chat:
        return APIResponse.HTTP_400_BAD_REQUEST(message="User is banned from agent chat.")
    if not agent.role_id or agent.role_id.roles != agent_role.roles:     # Validate roles
        return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid agent Role.")
    if not user.role_id or user.role_id.roles != user_role.roles:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid user Role.")
    form = forms.AgentChatForm(request.data, request.FILES)  # Combine and validate form data
    if not form.is_valid():
        return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid form data.", data=form.errors)
    # ----------------------------------------------- Validating Completed -------------------------------
    user.is_last_active = True                              # Update user's last active timestamp
    user.update_last_active()
    user.save()
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


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def get_agent_chat_history(request):
    """
        This function retrieves the agent chat history for the authenticated agent.
        Args:
                request (HTTPRequest): The request object containing the agent's token.
        Returns:
            1.
            {
                "status": 200,
                "message": "Agent chat history retrieved successfully.",
                "data": [
                    {
                        "message_content": "This can occur for several reasons:",
                        "attachment_image": "/media/agent-user-chats/7_18f024f3.jpg",
                        "status": "active",
                        "created_at": "2024-12-25T06:08:12.811967Z"
                    },
                    {
                        "message_content": "This can occur for several reasons:",
                        "attachment_image": "/media/agent-user-chats/7_0d753f32.jpg",
                        "status": "active",
                        "created_at": "2024-12-25T06:34:54.063539Z"
                    },
                    {
                        "message_content": "This can occur for several reasons:",
                        "attachment_image": "/media/agent-user-chats/7_3c1d9317.jpg",
                        "status": "active",
                        "created_at": "2024-12-25T06:34:55.108941Z"
                    },
                ]
            }
        2.
            {
                "status": 401,
                "message": "Authentication token is missing."
            }
        3.
            {
                "status": 401,
                "message": "Invalid or expired token."
            }
        4.
            {
                "status": 500,
                "message": "Agent Role not found."
            }
        5.
            {
                "status": 400,
                "message": "You are not authorized to perform this action."
            }
        6.
            {
                "status": 404,
                "message": "No chat history found."
            }
    """
    # --------------------------------------- Validating Parameters --------------------
    user_instance = AuthService.get_user_from_token(request)
    auth_user = AuthService.validate_user_role(user_instance, "Agent")
    agent = models.User.objects.filter(id=auth_user.id).first()
    agent_role = models.Role.objects.filter(roles="Agent").first()
    if not agent:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
    print(agent.role_id)# Get the agent and user objects
    print(agent.role_id.roles)
    if not agent.role_id or agent.role_id.roles != agent_role.roles:
        return APIResponse.HTTP_400_BAD_REQUEST(message="You are not authorized to perform this action.")
    chat_history = models.AgentChat.objects.filter(agent_id=agent)       # Retrieve the chat history for the user and agent
    if not chat_history.exists():
        return APIResponse.HTTP_404_NOT_FOUND(message="No chat history found.")
    # --------------------------------------------- Vaidating Completed ------------------
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


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_global_chat_history(request):
    """
         This function retrieves the global chat history.
         Args:
                 request (HTTPRequest): The request object containing the page and limit query parameters.
         Payload:
                 {
                    "page": 1,
                    "limit": 20
                 }
         Returns:
             1.
                {
                    "status": 200,
                    "message": "Global chat history retrieved successfully.",
                    "data": {
                        "chat_history": [
                            {
                                "user": {
                                    "user_id": "9b03dcbb-e3a3-454f-93b6-15096801bb56",
                                    "username": "AmmarHussain",
                                    "email": "amaar@gmail.com",
                                    "first_name": "Amaar",
                                    "last_name": "Hussain",
                                    "models.Role": "User",
                                    "last_active": "2024-12-25T07:10:05.345616Z"
                                },
                                "message_content": "Hi there i am Anas khan",
                                "created_at": "2024-12-25T07:29:34.567480Z"
                            },
                            {
                                "user": {
                                    "user_id": "9b03dcbb-e3a3-454f-93b6-15096801bb56",
                                    "username": "AmmarHussain",
                                    "email": "amaar@gmail.com",
                                    "first_name": "Amaar",
                                    "last_name": "Hussain",
                                    "models.Role": "User",
                                    "last_active": "2024-12-25T07:10:05.345616Z"
                                },
                                "message_content": "Hi there i am Anas khan",
                                "created_at": "2024-12-25T07:32:00.614068Z"
                            },
                            {
                                "user": {
                                    "user_id": "9b03dcbb-e3a3-454f-93b6-15096801bb56",
                                    "username": "AmmarHussain",
                                    "email": "amaar@gmail.com",
                                    "first_name": "Amaar",
                                    "last_name": "Hussain",
                                    "models.Role": "User",
                                    "last_active": "2024-12-25T07:10:05.345616Z"
                                },
                                "message_content": "Hi there i am Anas khan",
                                "created_at": "2024-12-25T07:32:45.603464Z"
                            }
                        ],
                        "pagination": {
                            "page": 1,
                            "limit": 5,
                            "total": 3
                        }
                    }
                }
            2.
                {
                    "status": 404,
                    "message": "No global chat history found."
                }

    """
    page = int(request.query_params.get('page', 1))      # Default page is 1
    limit = int(request.query_params.get('limit', 20))   # Default limit is 20
    # ----------------------------------------------- Validating Parameters ----------
    user_instance = AuthService.get_user_from_token(request)
    auth_user = AuthService.validate_user_role(user_instance, "User")
    user = models.User.objects.filter(id=auth_user.id).first()
    if not user:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
    chat_history = models.GlobalChat.objects.all().order_by('global_chat_created_at')
    if not chat_history:
        return APIResponse.HTTP_404_NOT_FOUND(message="No global chat history found.")
    # ------------------------------------------------- Vaidating Completed --------------
    start = (page - 1) * limit      # Pagination: Slice the queryset based on the page and limit
    end = start + limit
    paginated_chat_history = chat_history[start:end]
    chat_data = []                  # Prepare the chat history data for response with user details
    for chat in paginated_chat_history:
        user_details = {
            'user_id': chat.user_id.id,
            'username': chat.user_id.user_id.username,
            'email': chat.user_id.email,
            'first_name': chat.user_id.first_name,
            'last_name': chat.user_id.last_name,
            'models.Role': chat.user_id.role_id.roles,  # Assuming role_id is a foreign key to the Role model
            'last_active': chat.user_id.last_active,    # Assuming last_active is a datetime field
        }
        chat_data.append({
            'user': user_details,
            'message_content': chat.message_content,
            'created_at': chat.global_chat_created_at,
        })
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


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def activate_user_agent_chat(request):
    """
         This function activates the agent chat for the user.
         Args:
                 request (HTTPRequest): The request object containing the user_id and agent_id.
         Payload:
                 {
                    "agent_id": "9b03dcbb-e3a3-454f-93b6-15096801bb56",
                    "reason": "One of My Greate Agent"
                }
         Returns:
             1.
                 {
                    "status": 200,
                    "message": "User has been Un-blocked for agent chat.",
                    "data": {
                        "id": "9b03dcbb-e3a3-454f-93b6-15096801bb56",
                        "username": "AmmarHussain",
                        "email": "amaar@gmail.com",
                        "is_live": true,
                        "is_banned_from_agent_chat": false
                    }
                }
            2.
                {
                    "status": 401,
                    "message": "Authentication token is missing."
                }
            3.
               {
                    "status":401,
                    "message":"Invalid or expired token",
                }
            4.
                 {
                    "status": 401,
                    "message": "You are not authorized to perform this action."
                }
            5.
                {
                    "status": 404,
                    "message": "User not found."
                }

    """
    user_instance = AuthService.get_user_from_token(request)
    auth_user = AuthService.validate_user_role(user_instance, "Admin")
    user_role = models.Role.objects.filter(roles="User").first()
    admin_role = models.Role.objects.filter(roles="Admin").first()
    if not admin_role or not user_role:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message="Roles not properly configured.")
    admin = models.User.objects.get(id=auth_user.id)
    if not admin:
        return APIResponse.HTTP_404_NOT_FOUND(message="Admin not found.")
    if admin.role_id.roles != 'Admin':
        return APIResponse.HTTP_401_UNAUTHORIZED(message="You are not authorized to perform this action.")
    user_id = request.data.get('user_id')
    if not user_id:
        return APIResponse.HTTP_400_BAD_REQUEST(message="User id is missing.")
    user = models.User.objects.filter(id=user_id).first()      # fetch the user object
    if not user:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
    #----------------------------------------------- Validating Completed ------------------------------------
    user.is_banned_from_agent_chat = False
    user.save()
    send_mail(
        'Account Un-blocked',
        f'Your account has been Un-blocked for agent chat by the admin. Reason: {request.data.get("reason")}',
        settings.DEFAULT_FROM_EMAIL,
        [user.user_id.email],
    )
    return APIResponse.HTTP_200_OK(message=f"User has been Un-blocked for {user.role_id.roles} chat.", data={
        "id": user.id,
        "username": user.user_id.username,
        "email": user.user_id.email,
        "is_live": user.is_last_active,
        "is_banned_from_agent_chat": user.is_banned_from_agent_chat
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def de_activate_user_agent_chat(request):
    """
         This function de-activates the agent chat for the user.
         Args:
                 request (HTTPRequest): The request object containing the user_id and agent_id.
         Payload:
                 {
                    "agent_id": "9b03dcbb-e3a3-454f-93b6-15096801bb56",
                    "reason": "Spamming"
                 }
         Returns:
             1.
                 {
                    "status": 200,
                    "message": "User has been blocked for agent chat.",
                    "data": {
                        "id": "9b03dcbb-e3a3-454f-93b6-15096801bb56",
                        "username": "AmmarHussain",
                        "email": "amaar@gmail.com",
                        "is_live": true,
                        "is_banned_from_agent_chat": true
                    }
                }
            2.
                {
                    "status": 401,
                    "message": "Authentication token is missing."
                }
            3.
                {
                    "status": 401,
                    "message": "Invalid or expired token."
                }
            4.
                {
                    "status": 401,
                    "message": "You are not authorized to perform this action."
                }
            5.
                {
                    "status": 404,
                    "message": "Admin not found with this token."
                }
            6.
                {
                    "status": 404,
                    "message": "User not found."
                }

    """
    user_instance = AuthService.get_user_from_token(request)
    auth_user = AuthService.validate_user_role(user_instance, "Admin")
    user_role = models.Role.objects.filter(roles="User").first()
    admin_role = models.Role.objects.filter(roles="Admin").first()
    if not admin_role or not user_role:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message="Roles not properly configured.")
    admin = models.User.objects.get(id=auth_user.id)
    if not admin:
        return APIResponse.HTTP_404_NOT_FOUND(message="Admin not found.")
    if admin.role_id.roles != 'Admin':
        return APIResponse.HTTP_401_UNAUTHORIZED(message="You are not authorized to perform this action.")
    user_id = request.data.get('user_id')
    if not user_id:
        return APIResponse.HTTP_400_BAD_REQUEST(message="User id is missing.")
    user = models.User.objects.filter(id=user_id).first()  # fetch the user object
    if not user:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
    user.is_banned_from_agent_chat = True
    user.save()
    send_mail(
        'Account blocked',
        f'Your account has been blocked for agent chat by the admin. Reason: {request.data.get("reason")}',
        settings.DEFAULT_FROM_EMAIL,
        [user.user_id.email],
    )
    return APIResponse.HTTP_200_OK(message=f"User has been blocked for {user.role_id.roles} chat.", data={
        "id": user.id,
        "username": user.user_id.username,
        "email": user.user_id.email,
        "is_live": user.is_last_active,
        "is_banned_from_agent_chat": user.is_banned_from_agent_chat
    })


@api_view(['POST'])
def is_agent_alive(request):
    """
        This function checks if the agent is alive or not.
        Args:
                request (HTTPRequest): The request object containing the agent_id.
        Payload:
                {
                    "agent_id": "9b03dcbb-e3a3-454f-93b6-15096801bb56",
                }
        Returns:
            1.
                {
                    "status": 200,
                    "message": "Agent is not alive.",
                    "data": {
                        "id": "adc1f1de-caba-4616-9058-ee53bfb14e47",
                        "username": "RashidHussain",
                        "email": "rashid@gmail.com",
                        "is_agent_alive": true
                    }
                }
            2.
                {
                    "status": 400,
                    "message": "Agent id is missing."
                }
            3.
                {
                    "status": 404,
                    "message": "Agent not found."
                }
        """
    agent_id = request.data.get('agent_id')
    #-------------------------------------------------------------- Validating Parameters --------------------
    if not agent_id:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Agent id is missing.")
    user = models.User.objects.filter(id=agent_id).first()
    if not user:
        return APIResponse.HTTP_404_NOT_FOUND(message="Agent not found.")
    #-------------------------------------------------------------- Validating Completed ---------------------
    if user.is_last_active is True:
        return APIResponse.HTTP_200_OK(message="Agent is alive.", data={
            "id": user.id,
            "username": user.user_id.username,
            "email": user.user_id.email,
            "is_live": user.is_last_active
        })
    else:
        return APIResponse.HTTP_200_OK(message="Agent is not alive.", data={
            "id": user.id,
            "username": user.user_id.username,
            "email": user.user_id.email,
            "is_agent_alive": True
        })


@api_view(['POST'])
def is_user_alive(request):
    """
        This function checks if the user is alive or not.
        Args:
                request (HTTPRequest): The request object containing the user_id.
        Payload:
                {
                    "user_id": "9b03dcbb-e3a3-454f-93b6-15096801bb56",
                }
        Returns:
            1.
                {
                    "status": 200,
                    "message": "User is alive.",
                    "data": {
                        "id": "9b03dcbb-e3a3-454f-93b6-15096801bb56",
                        "username": "AmmarHussain",
                        "email": "amaar@gmail.com",
                        "is_live": true
                    }
                }
            2.
                {
                    "status": 400,
                    "message": "User id is missing."

    """
    user_id = request.data.get('user_id')
    #-------------------------------------------------------------- Validating Parameters ------------
    if not user_id:
        return APIResponse.HTTP_400_BAD_REQUEST(message="User id is missing.")
    user = models.User.objects.filter(id=user_id).first()
    if not user:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
    #---------------------------------------------------------- Validating Completed -----------------
    if user.is_last_active is True:
        return APIResponse.HTTP_200_OK(message="User is alive.", data={
            "id": user.id,
            "username": user.user_id.username,
            "email": user.user_id.email,
            "is_live": user.is_last_active
        })
    else:
        return APIResponse.HTTP_200_OK(message="User is not alive.", data={
            "id": user.id,
            "username": user.user_id.username,
            "email": user.user_id.email,
            "is_agent_alive": True
        })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_global_chats(request):
    """
         This function retrieves all global chat messages for the authenticated user, supporting pagination.
         Args:
                 request (HTTPRequest): The request object containing the user_id.
         Returns:
             1.
                 {
                    "status": 200,
                    "message": "Global chat history retrieved successfully.",
                    "data": {
                        "chat_history": [
                            {
                                "user": {
                                    "user_id": "9b03dcbb-e3a3-454f-93b6-15096801bb56",
                                    "username": "AmmarHussain",
                                    "email": "amaar@gmail.com",
                                    "first_name": "Ammar",
                                    "last_name": "Hussain",
                                    "models.Role": "User",
                                    "last_active": "2021-08-15T12:00:00Z"
                                },
                                "message_content": "Hello, how can I help you?",
                                "created_at": "2021-08-15T12:00:00Z"
                            },
                            {
                                "user": {
                                    "user_id": "9b03dcbb-e3a3-454f-93b6-15096801bb56",
                                    "username": "AmmarHussain",
                                    "email": "amaar@gmail.com",
                                    "first_name": "Ammar",
                                    "last_name": "Hussain",
                                    "models.Role": "User",
                                    "last_active": "2021-08-15T12:00:00Z"
                                },
                                "message_content": "I need help with my order",
                                "created_at": "2021-08-15T12:00:00Z"
                            }
                        ],
                        "pagination": {
                            "page": 1,
                            "limit": 20,
                            "total": 2
                        }
                    }
                }
            2.
                {
                    "status": 401,
                    "message": "Authentication token is missing."
                }
            3.
                {
                    "status": 401,
                    "message": "Invalid or expired token."
                }
            4.
                {
                    "status": 404,
                    "message": "User not found."
                }
            5.
                {
                    "status": 404,
                    "message": "No global chat history found."
                }
    """
    page = int(request.query_params.get('page', 1))  # Default page is 1
    limit = int(request.query_params.get('limit', 20))  # Default limit is 20
    user_instance = AuthService.get_user_from_token(request)
    auth_user = AuthService.validate_user_role(user_instance, "User")
    user = models.User.objects.filter(id=auth_user.id).first()
    if not user:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
    chat_history = models.GlobalChat.objects.filter(user_id=user).order_by('global_chat_created_at')
    if not chat_history.exists():
        return APIResponse.HTTP_404_NOT_FOUND(message="No global chat history found.")
    #---------------------------------------------- validating completed -----------------------
    start = (page - 1) * limit
    end = start + limit
    paginated_chat_history = chat_history[start:end]
    chat_data = []
    for chat in paginated_chat_history:
        user_details = {
            'user_id': chat.user_id.id,
            'username': chat.user_id.user_id.username,   # Fixed this line
            'email': chat.user_id.email,
            'first_name': chat.user_id.first_name,
            'last_name': chat.user_id.last_name,
            'models.Role': chat.user_id.role_id.roles,  # Assuming role_id is a foreign key to the models.Role model
            'last_active': chat.user_id.last_active,    # Assuming last_active is a datetime field
        }
        chat_data.append({
            'user': user_details,
            'message_content': chat.message_content,
            'created_at': chat.global_chat_created_at,
        })
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


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def send_message_to_global_chat(request):
    """
        This function sends a message to the global chat.
        Args:
                request (HTTPRequest): The request object containing the message content and attachment image.
        Payload:
                {
                    "message_content": "Hello, this is a test message.",
                    "is_pinned": "True"
                }
        Returns:
            1.
                {
                    "status": 200,
                    "message": "Message sent successfully.",
                    "data": {
                        "id": "024a55c9-c521-405e-b78a-cea4ac1401f3",
                        "user": "AmmarHussain",
                        "message_content": "Hi there i am Anas khan",
                        "is_pinned": true,
                        "created_at": "2024-12-25T07:29:34.567480Z"
                    }
                }
            2.
                {
                    "status": 401,
                    "message": "Invalid or expired token."
                }

            3.
                {
                    "status": 404,
                    "message": "User not found."
                }
            4.
                {
                    "status": 400,
                    "message": "Invalid form data.",
                    "data": {
                        "message_content": [
                            "This field is required."
                        ]
                    }
                }
            5.
                {
                    "status": 400,
                    "message": "Invalid or expired token.",
                }
    """
    # ------------------------------------- validating parameters ------------------
    user_instance = AuthService.get_user_from_token(request)
    auth_user = AuthService.validate_user_role(user_instance, "User")
    if not auth_user:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or expired token.")
    user = models.User.objects.filter(id=auth_user.id).first()
    if not user:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
    # -------------------------------------- Validating Completed -------------------------
    form = forms.GlobalChatForm(request.data)
    if not form:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid form data.")
    if form.is_valid():
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

## Chat Management System - APIs Completed
############################################################################################################
# Reviews Management System
@api_view(['GET'])
def get_reviews(request):
    """
        This function retrieves all models.Game reviews with user details, supporting pagination.
        Args:
                request (HTTPRequest): The request object containing the page and limit.
        payload:
                {
                    "page": 1,
                    "limit": 20
                }
        Returns:
            {
                "status": 200,
                "message": "Game reviews retrieved successfully.",
                "data": {
                    "reviews": [
                        {
                            "game_details": null,
                            "review_id": "18124610-2f88-4c23-ace1-b3aab2c7965a",
                            "message_content": "Hello guys, how are you?",
                            "ratings": 0.0,
                            "helpful_counter": 0,
                            "review_posted_at": "2024-12-25T09:00:37.580352Z",
                            "review_sent_by_user": {
                                "user_id": "9b03dcbb-e3a3-454f-93b6-15096801bb56",
                                "username": "AmmarHussain",
                                "email": "amaar@gmail.com",
                                "first_name": "Amaar",
                                "last_name": "Hussain",
                                "models.Role": "User",
                                "last_active": "2024-12-25T07:10:05.345616Z"
                            },
                            "admin_reply": null
                        },
                        {
                            "game_details": null,
                            "review_id": "beab2824-6499-4b7c-ad37-3e881d1c8186",
                            "message_content": "Hello guys, how are you?",
                            "ratings": 0.0,
                            "helpful_counter": 0,
                            "review_posted_at": "2024-12-25T08:59:49.467683Z",
                            "review_sent_by_user": {
                                "user_id": "9b03dcbb-e3a3-454f-93b6-15096801bb56",
                                "username": "AmmarHussain",
                                "email": "amaar@gmail.com",
                                "first_name": "Amaar",
                                "last_name": "Hussain",
                                "models.Role": "User",
                                "last_active": "2024-12-25T07:10:05.345616Z"
                            },
                            "admin_reply": null
                        },
                    ],
                    "pagination": {
                        "page": 1,
                        "limit": 10,
                        "total": 5
                    }
                }
            }
        2.
            {
                "status": 404,
                "message": "No Game reviews found."
            }
        3.
            {

    """
    page = int(request.query_params.get('page', 1))
    limit = int(request.query_params.get('limit', 20))
    #-------------------------------------------------------------- Validating Parameters ----------
    game_reviews = models.GameReview.objects.select_related('user_id', 'game_id').all().order_by(
        '-review_posted_at')
    if not game_reviews.exists():
        return APIResponse.HTTP_404_NOT_FOUND(message="No Game reviews found.")
    # ---------------------------------------------------- Validating Completed --------------------
    start = (page - 1) * limit   # Pagination: Slice the queryset based on the page and limit
    end = start + limit
    paginated_reviews = game_reviews[start:end]
    reviews_data = []
    for review in paginated_reviews:
        user_details = {
            'user_id': review.user_id.id,
            'username': review.user_id.user_id.username,
            'email': review.user_id.email,
            'first_name': review.user_id.first_name,
            'last_name': review.user_id.last_name,
            'models.Role': review.user_id.role_id.roles,
            'last_active': review.user_id.last_active,
        }
        game_data = models.Game.objects.filter(game_reviews_id=review).first()
        game_details = {
            'game_id': game_data.id if game_data else None,
            'game_name': game_data.game_name if game_data else None,
            'game_created_at': game_data.game_created_at if game_data else None,
        } if game_data else None
        admin_reply = models.AdminReply.objects.filter(game_review_id=review).first()
        reply_data = None
        if admin_reply:
            reply_data = {
                'id': admin_reply.id,
                'admin_id': admin_reply.admin_id.id,
                'message_content': admin_reply.message_content,
                'helpful_counter': admin_reply.helpful_counter,
                'reply_posted_at': admin_reply.reply_posted_at,
            }
        reviews_data.append({
            'game_details': game_details,
            'review_id': review.id,
            'message_content': review.message_content,
            'ratings': review.ratings,
            'helpful_counter': review.helpful_counter,
            'review_posted_at': review.review_posted_at,
            'review_sent_by_user': user_details,
            'admin_reply': reply_data,
        })
    return APIResponse.HTTP_200_OK(message="Game reviews retrieved successfully.", data={
        'reviews': reviews_data,
        'pagination': {
            'page': page,
            'limit': limit,
            'total': game_reviews.count(),
        },
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def post_game_review(request):
    """
         This function posts a Game review for the authenticated user.
         Args:
                 request (HTTPRequest): The request object containing the game_id, message_content, and ratings.
         Returns:
             1.
                 {
                    "status": 200,
                    "message": "Game reviews posted successfully.",
                    "data": {
                        "message_content": "Hello guys, how are you?",
                        "game_id": "346d4284-368d-4dca-8825-ed0d93181910"
                    }
                }
            2.
                {
                    "status": 401,
                    "message": "Authentication token is missing."
                }
            3.
                {
                    "status": 401,
                    "message": "Invalid or expired token."
                }
            4.
                {
                    "status": 400,
                    "message": "Role is not properly configured."
                }
            5.
                {
                    "status": 400,
                    "message": "Game id is missing."
                }
            6.
                {
                    "status": 404,
                    "message": "User not found."
                }
            7.
                {
                    "status": 404,
                    "message": "Game not found."
                }
            8.
                {
                    "status": 400,
                    "message": "Invalid form data."
                }
    """
    #-------------------------------------------------------------- Validating Parameters ---------------------
    user_instance = AuthService.get_user_from_token(request)
    auth_user = AuthService.validate_user_role(user_instance, "User")
    if not auth_user:
                return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or expired token.")
    user_role = models.Role.objects.filter(roles="User").first()         # Fetch roles for validation
    if not user_role:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message="Role is not properly configured.")
    user = models.User.objects.filter(id=auth_user.id, role_id=user_role).get()  # Fetch user and agent instances
    if not user:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
    game_id = request.data.get('game_id')
    if not game_id:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Game id is missing.")
    game = models.Game.objects.filter(id=game_id).first()
    if not game:
        return APIResponse.HTTP_404_NOT_FOUND(message="Game not found.")
    #-------------------------------------------------------------- Validating Completed  -------------
    form = forms.GameReviewForm(request.data)
    if not form.is_valid():
        return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid form data.")
    data = form.save(commit=False)
    data.user_id = user
    data.game_id = game
    data.save()
    return APIResponse.HTTP_200_OK(message="Game review posted successfully.", data={
        "user_id": data.user_id.id,
        "game_id": data.game_id.id,
        "message_content": data.message_content,
    })


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_game_review(request):
    """
         This function deletes a Game review for the authenticated user.
        Args:
                request (HTTPRequest): The request object containing the review_id.
        Returns:
            1.
                 {
                    "status": 200,
                    "message": "Game review deleted successfully.",
                    "data": {
                        "review": {
                            "review_id": "18124610-2f88-4c23-ace1-b3aab2c7965a",
                            "message_content": "Hello guys, how are you?"
                        }
                    }
                }
            2.
                {
                    "status": 401,
                    "message": "Authentication token is missing."
                }
            3.
                {
                    "status": 401,
                    "message": "Invalid or expired token."
                }
            4.
                {
                    "status": 400,
                    "message": "Role is not properly configured."
                }
            5.
                {
                    "status": 400,
                    "message": "Missing required parameter: review_id."
                }
            6.
                {
                    "status": 400,
                    "message": "Missing required parameters: review_id."
                }
            7.
                {
                    "status": 404,
                    "message": "Game review not found with the provided review_id and user_id."
                }
    """
    user_instance = AuthService.get_user_from_token(request)
    auth_user = AuthService.validate_user_role(user_instance, "User")   # receiver user
    review_id = request.data.get('review_id')
    if not all([review_id]):
        return APIResponse.HTTP_400_BAD_REQUEST(
            message="Missing required parameters: review_id.")
    review = models.GameReview.objects.filter(id=review_id, user_id=auth_user.id).first()
    if review is None:
        return APIResponse.HTTP_404_NOT_FOUND(
            message="Game review not found or you don't have permission to delete it.")
    data = {
        'review': {
            'review_id': review.id,
            'message_content': review.message_content,
        }
    }
    review.delete()
    return APIResponse.HTTP_200_OK(message="Game review deleted successfully.", data=data)


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_game_review_ratings(request):
    """
         This function  updates the ratings or helpful counter of a Game review.
         Args:
                 request (HTTPRequest): The request object containing the review_id, ratings, and is_yes.
         Payload:
                 {
                    "review_id": "18124610-2f88-4c23-ace1-b3aab2c7965a",
                    "ratings": "4.5",
                    "is_yes": true
                }
         Returns:
             1.
                 {
                    "status": 200,
                    "message": "Game review ratings updated successfully.",
                    "data": {
                        "review_id": "18124610-2f88-4c23-ace1-b3aab2c7965a",
                        "message_content": "Hello guys, how are you?",
                        "ratings": "4.5",
                        "helpful_counter": 1,
                        "is_yes": true,
                        "rated_by_users": [
                            "9b03dcbb-e3a3-454f-93b6-15096801bb56"
                        ]
                    }
                }
            2.
                {
                    "status": 401,
                    "message": "Authentication token is missing."
                }
            3.
                {
                    "status": 401,
                    "message": "Invalid or expired token."
                }
            4.
                {
                 "status": 404,
                 "message": "User not found."
                }
            5.
                {
                    "status": 400,
                    "message": "Missing required parameter: review_id."
                }
            6.
                {
                    "status": 400,
                    "message": "Game review not found with the provided review_id."
                }
            7.
                {
                    "status": 404,
                    "message": "Game review not found with the provided review_id and user_id."
                }
            8.
                {
                    "status": 400,
                    "message": "You have already rated this Game review."
                }
    """

    user_instance = AuthService.get_user_from_token(request)
    auth_user = AuthService.validate_user_role(user_instance, "Admin")
    user = models.User.objects.filter(id=auth_user.id).first()
    if not user:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
    review_id, ratings, is_yes = (request.data.get('review_id'), request.data.get('ratings'),
                                  bool(request.data.get('is_yes')))
    if not review_id:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Missing required parameter: review_id.")
    review = models.GameReview.objects.filter(id=review_id).first()
    if not review:
        return APIResponse.HTTP_404_NOT_FOUND(message="Game review not found with the provided review_id.")
    if user in review.rated_by_user_id.all():  # Check if already rated by the logged-in user
        print(user)
        return APIResponse.HTTP_400_BAD_REQUEST(message="You have already rated this Game review.")
    # ---------------------------------------------- Validating Completed ----------------------
    review.is_yes = is_yes
    if is_yes:  # Update helpful counter
        review.helpful_counter += 1
    elif review.helpful_counter > 0:
        review.helpful_counter -= 1
    else:
        review.helpful_counter = 0  # Ensure it stays at 0 if decrementing from 0
    if ratings:  # Handle ratings if provided
        try:
            review.ratings += Decimal(str(ratings))
        except (ValueError, TypeError):
            return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid ratings value.")
    review.rated_by_user_id.add(user)  # Add the current user to the rated_by_user_id list
    review.save()
    return APIResponse.HTTP_200_OK(
        message="Game review ratings updated successfully.",
        data={
            'review_id': review.id,
            'message_content': review.message_content,
            'ratings': str(review.ratings),
            'helpful_counter': review.helpful_counter,
            'is_yes': review.is_yes,
            'rated_by_users': list(review.rated_by_user_id.values_list('id', flat=True)),  # Return user IDs
        }
    )


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_admin_reply_ratings(request):
    """
        This function updates the ratings or helpful counter of an Admin reply.
        Args:
                request (HTTPRequest): The request object containing the reply_id,ratings, is_yes.
        Payload:
                {
                    "reeply_id": "18124610-2f88-4c23-ace1-b3aab2c7965a",
                    "ratings": "4.5",
                    "is_yes": true
                }
        Returns:
            1.
                {
                    "status": 200,
                    "message": "Reply help counter updated successfully.",
                    "data": {
                        "review_id": "230c7e33-84ed-47c8-b6df-ea2e35c2cb9f",
                        "message_content": "Perfectly",
                        "helpful_counter": 1,
                        "is_yes": true,
                        "rated_by_users": [
                            "hafizkhan@gmail.com"
                        ]
                    }
                }
            2.
                {
                    "status": 401,
                    "message": "Authentication token is missing."
                }
            3.
                {
                    "status": 404,
                    "message": "User not found."
                }
            4.
                {
                    "status": 400,
                    "message": "Missing required parameter: reply_id."
                }
            5.
                {
                    "status": 400,
                    "message": "Reply not found with the provided reply_id."
                }
            6.
                {
                    "status": 401,
                    "message": "Invalid or expired token."
                }
            7.
                {
                    "status": 400,
                    "message": "You have already rated this reply."
                }
    """
    token = request.COOKIES.get('token') or request.headers.get('Authorization', '').split(' ')[-1]
    # ------------------------------ Validating Parameters ------------------------------------------
    if not token:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Authentication token is missing.")
    try:
        user_id = Token.objects.get(key=token).user.id                              # Logged-in user only
        user = models.User.objects.filter(user_id=user_id).first()
        if not user:
            return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
    except token.DoesNotExist:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or expired token.")
    reply_id, is_yes = request.data.get('reply_id'), bool(request.data.get('is_yes'))
    if not reply_id:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Missing required parameter: reply_id.")
    reply = models.AdminReply.objects.filter(id=reply_id, admin_id=user).first()
    if not reply:
        return APIResponse.HTTP_404_NOT_FOUND(message="Reply not found with the provided reply_id.")
    if user in reply.rated_by_user_id.all():                  # Check if already rated by that logged-in user
        return APIResponse.HTTP_400_BAD_REQUEST(message="You have already rated this reply.")
    # ----------------------------------------- validating Completed ------------------------------
    reply.is_yes = is_yes
    if is_yes:
        reply.helpful_counter += 1
    elif reply.helpful_counter > 0:
        reply.helpful_counter -= 1
    else:
        reply.helpful_counter = 0                                 # Ensure it stays at 0 if decrementing from 0
    reply.rated_by_user_id.add(user)
    reply.save()
    return APIResponse.HTTP_200_OK(
        message="Reply help counter updated successfully.",
        data={
            'review_id': reply.id,
            'message_content': reply.message_content,
            'helpful_counter': reply.helpful_counter,
            'is_yes': reply.is_yes,
            'rated_by_users': list(reply.rated_by_user_id.values_list('email', flat=True)),  # Return user IDs
        }
    )

@api_view(['GET'])

def get_game_rating(request):
    """
    Retrieve the overall rating for a specific game based on its game_id.

    Args:
        request: The HTTP request object containing query parameters.

    Returns:
        1.
            {
                "status": 200,
                "message": "Game rating retrieved successfully.",
                "data": {
                    "game_id": "123e4567-e89b-12d3-a456-426614174000",
                    "game_name": "Awesome Game",
                    "average_rating": 4.5,
                    "total_reviews": 10
                }
            }
        2.
            {
                "status": 400,
                "message": "Missing required parameter: game_id."
            }
        3.
            {
                "status": 404,
                "message": "Game not found with the provided game_id."
            }
        4.
            {
                "status": 404,
                "message": "No reviews found for the specified game."
            }
        5.
            {
                "status": 500,
                "message": "An unexpected error occurred: [error details]."
            }
    """
    # ------------------------------ Validating Parameters ------------------------
    game_id = request.query_params.get('game_id')
    if not game_id:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Missing required parameter: game_id.")
    game = models.Game.objects.filter(game_id=game_id).first()
    if not game:
        return APIResponse.HTTP_404_NOT_FOUND(message="Game not found with the provided game_id.")
    reviews = game.game_reviews_id.all()
    if not reviews.exists():
        return APIResponse.HTTP_404_NOT_FOUND(message="No reviews found for the specified game.")
    total_ratings = reviews.aggregate(total=Sum('ratings'))['total'] or 0   # Calculate average rating
    review_count = reviews.count()
    average_rating = total_ratings / review_count if review_count > 0 else 0
    return APIResponse.HTTP_200_OK(message="Game rating retrieved successfully.", data={
        'game_id': game.id,
        'game_name': game.game_name,
        'average_rating': round(average_rating, 2),
        'total_reviews': review_count,
    })



@api_view(['POST'])
@permission_classes([IsAuthenticated])
def post_admin_reply(request):
    """
        This function posts an Admin reply for a Game review.
        Args:
                request (HTTPRequest): The request object containing the game_review_id, message_content.
        Returns:
            1.
                {
                    "status": 200,
                    "message": "Admin reply posted successfully.",
                    "data": {
                        "message_content": "Perfectly",
                        "game_review_id": "3bc96cd9-910f-4648-a009-0e9c0762edd1"
                    }
                }
            2.
                {
                    "status": 401,
                    "message": "Authentication token is missing."
                }
            3.
                {
                    "status": 401,
                    "message": "Invalid or expired token."
                }
            4.
                {
                    "status": 404,
                    "message": "User not found."
                }
            5.
                {
                    "status": 400,
                    "message": "Game review not found."
                }
            6.
                {
                    "status": 400,
                    "message": "Role is not properly configured.",
                }
            7.
                {
                    "status": 400,
                    "message": "Invalid form data.",
                    "data": {
                        "message_content": [
                            "This field is required."
                        ]
                    }
                }

    """
    # ---------------------------------------------- Validating Parameters ----------------
    user_instance = AuthService.get_user_from_token(request)
    auth_user = AuthService.validate_user_role(user_instance, "Admin")
    user_role = models.Role.objects.filter(roles="Admin").first()                    # Fetch roles for validation
    if not user_role:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message="Role is not properly configured.")                                                         # Fetch user and agent instances
    user = models.User.objects.filter(id=auth_user.id, role_id=user_role).first()    #print(f"User: {user}")
    if not user:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
    game_review_id = request.data.get('game_review_id')
    review = models.GameReview.objects.filter(id=game_review_id).first()
    if not review:
        return APIResponse.HTTP_404_NOT_FOUND(message="Game review not found.")
    # ---------------------------------------------- Validating Completed --------------------------
    form = forms.AdminReplyForm(request.data)
    if not form.is_valid():
        return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid form data.", data=form.errors)
    if form.is_valid():
        data = form.save(commit=False)
        data.admin_id = user
        data.game_review_id = review
        data.save()
        return APIResponse.HTTP_200_OK(message="Admin reply posted successfully.", data=form.data)
    else:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid form data.", data=form.errors)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_admin_replies(request):
    """
        This function retrieves all admin replies with related models.Game reviews.
        Args:
                request (HTTPRequest):

        Returns:
            1.
                 {
                    "status": 200,
                    "message": "Admin replies with related Game reviews retrieved successfully.",
                    "data": [
                        {
                            "admin_reply": {
                                "id": "3bc96cd9-910f-4648-a009-0e9c0762edd1",
                                "game_review_sent_by": "admin1",
                                "message_content": "Perfectly",
                                "helpful_counter": 1,
                                "reply_posted_at": "2021-10-12T12:30:00Z"
                            },
                            "admin_reply_to": {
                                "id": "3bc96cd9-910f-4648-a009-0e9c0762edd1",
                                "models.Player": "player1",
                                "message_content": "I love this game",
                                "ratings": 5,
                                "helpful_counter": 2,
                                "review_posted_at": "2021-10-12T12:30:00Z"
                            }
                        },
                    ]
                 }
            2.
                {
                    "status": 401,
        """
    #
    user_instance = AuthService.get_user_from_token(request)
    auth_user = AuthService.validate_user_role(user_instance, "Admin")  # receiver user
    user_role = models.Role.objects.filter(roles="Admin").first()  # Fetch roles for validation
    if not user_role:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message="Role is not properly configured.")
    user = models.User.objects.filter(id=auth_user.id, role_id=user_role).first()  # print(f"User: {user}")
    if not user:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
    game_reviews = models.GameReview.objects.select_related('user_id__user_id').all()
    admin_replies = models.AdminReply.objects.select_related('admin_id__user_id').all()
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
    reviews_data = [
        {
            "admin_reply": {
                **admin_replies_map[review.admin_replies_id.id],
                "admin_reply_to": {
                    "id": review.id,
                    "models.Player": review.user_id.user_id.username,
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
            message="No admin replies found for any Game reviews.", data=[]
        )
    return APIResponse.HTTP_200_OK(
        message="Admin replies with related Game reviews retrieved successfully.",
        data=reviews_data,
    )



@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_admin_reply(request):
    """
    Update an existing admin reply by its ID.

    Args:
        request: The HTTP request object containing the reply update details.

    Returns:
        1.
            {
                "status": 200,
                "message": "Admin reply updated successfully.",
                "data": {
                    "id": "reply_id",
                    "admin_id": "admin_id",
                    "message_content": "Updated content",
                    "helpful_counter": 10,
                    "reply_posted_at": "2024-12-27 12:00:00"
                }
            }
        2.
            {
                "status": 400,
                "message": "Admin reply ID is required."
            }
        3.
            {
                "status": 404,
                "message": "Admin reply not found."
            }
        4.
            {
                "status": 400,
                "message": "Invalid form data.",
                "data": {
                    "message_content": ["This field is required."]
                }
            }
    """
    # ------------------------------------------------- Validating Parameters ---------------------------
    user_instance = AuthService.get_user_from_token(request)
    auth_user = AuthService.validate_user_role(user_instance, "Admin")  # receiver user
    user_role = models.Role.objects.filter(roles="Admin").first()  # Fetch roles for validation
    if not user_role:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message="Role is not properly configured.")
    user = models.User.objects.filter(id=auth_user.id, role_id=user_role).first()  # print(f"User: {user}")
    if not user:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
    admin_reply_id_pk = request.data.get('id')  # Extract the reply ID from request data
    if not admin_reply_id_pk:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Admin reply ID is required.")
    admin_reply = models.AdminReply.objects.get(id=admin_reply_id_pk)  # Fetch the reply
    if not admin_reply:
        return APIResponse.HTTP_404_NOT_FOUND(message="Admin reply not found.")
    # ------------------------------------------------- Validating Completed -----------------------------
    form = forms.AdminReplyForm(request.data, instance=admin_reply)  # Bind the form with instance data
    if form.is_valid():
        updated_admin_reply = form.save()  # Save the updated reply
        data = {
            "id": updated_admin_reply.id,
            "admin_id": updated_admin_reply.admin_id.id,
            "message_content": updated_admin_reply.message_content,
            "helpful_counter": updated_admin_reply.helpful_counter,
            "reply_posted_at": updated_admin_reply.reply_posted_at.strftime('%Y-%m-%d %H:%M:%S')
        }
        return APIResponse.HTTP_200_OK(
            message="Admin reply updated successfully.",
            data=data
        )
    else:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid form data.", data=form.errors)


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_admin_reply(request):
    """
        This function deletes an Admin reply.
        Args:
                request (HTTPRequest): The request object containing the id.
        Payload:
                {
                    "id": "3bc96cd9-910f-4648-a009-0e9c0762edd1"
                }
        Returns:
            1.
               {
                    "status": 200,
                    "message": "Admin reply deleted successfully.",
                    "data": {
                        "id": null,
                        "admin_id": "7966b776-e81f-4cac-b1db-ce00e30a7dd7",
                        "message_content": "Perfectly",
                        "helpful_counter": 0,
                        "reply_posted_at": "2024-12-25T12:14:54.631275Z"
                    }
               }
            2.
                {
                    "status": 401,
                    "message": "Authentication token is missing."
                }
            3.
                {
                    "status": 401,
                    "message": "Invalid or expired token."
                }
            4.
                {
                    "status": 404,
                    "message": "User not found or does not have the 'Admin' Role."
                }
            5.
                {
                    "status": 500,
                    "message": "Role is not properly configured."
                }
            6.
                {
                    "status": 404,
                    "message": "Admin reply not found."
                }
            7.
                {
                    "status": 404,
                    "message": "Admin reply ID is required."
                }

    """
    # ---------------------------------------------- Validating Parameters ----------

    user_instance = AuthService.get_user_from_token(request)
    auth_user = AuthService.validate_user_role(user_instance, "Admin")  # receiver user
    user_role = models.Role.objects.filter(roles="Admin").first()  # Fetch roles for validation
    if not user_role:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message="Role is not properly configured.")
    user_role = models.Role.objects.filter(roles="Admin").first()            # Fetch roles for validation
    if not user_role:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message="Role is not properly configured.")
    user = models.User.objects.get(id=auth_user.id, role_id=user_role)
    if not user:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found or does not have the 'Admin' Role.")
    pk_id = request.data.get('id')
    if not pk_id:
        return APIResponse.HTTP_404_NOT_FOUND(message="Admin reply ID is required.")
    admin_reply = models.AdminReply.objects.filter(id=pk_id, admin_id=user).first()
    if not admin_reply:
        return APIResponse.HTTP_404_NOT_FOUND(message="Admin reply not found.")
    # ---------------------------------------------- Validating Completed --------------------------
    admin_reply.delete()
    data = {
        "id": admin_reply.id,
        "admin_id": admin_reply.admin_id.id,
        "message_content": admin_reply.message_content,
        "helpful_counter": admin_reply.helpful_counter,
        "reply_posted_at": admin_reply.reply_posted_at
    }
    return APIResponse.HTTP_200_OK(message="Admin reply deleted successfully.", data=data)

# Reviews Management System
############################################################################################################
# Game Management System
@api_view(['GET'])
def get_available_games(request):
    """
        This function retrieves all available games.
        Args:
                request (HTTPRequest): The request object.
        Returns:
            1.
                {
                    "status": 200,
                    "message": "Available games retrieved successfully.",
                    "data": [
                        {
                            "id": "346d4284-368d-4dca-8825-ed0d93181910",
                            "game_id": "PUBG1B2B3B5",
                            "game_name": "PUBG",
                            "game_description": "amazing game",
                            "game_image": "/media/default-game.jpg",
                            "game_video": "/media/game_videos/Screenshot_2024-12-20_160823.png",
                            "game_price": 600,
                            "android_game_url": "https://www.veed.io/edit/933b0227-43ec-4ada-b45a-0d09d145b850/convert?source=%2Fconvert%2Fvideo-converter",
                            "ios_game_url": "https://www.veed.io/edit/933b0227-43ec-4ada-b45a-0d09d145b850/convert?source=%2Fconvert%2Fvideo-converter",
                            "browser_game_url": "https://www.veed.io/edit/933b0227-43ec-4ada-b45a-0d09d145b850/convert?source=%2Fconvert%2Fvideo-converter",
                            "upcoming_status": false,
                            "transfer_score_percentage": 0,
                            "redeem_score_percentage": 0,
                            "free_scores": 0,
                            "is_free": false,
                            "countries": []
                        }
                    ]
                }
            2.
                {
                    "status": 404,
                    "message": "Available games not found."
                }
    """
    available_games = models.Game.objects.all()
    # --------------------------------------------- Valiadating Parameters ----------
    if not available_games:
        return APIResponse.HTTP_404_NOT_FOUND(message="Available games not found.")
    # ------------------------------------- Validating Completed --------------------
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
            "free_scores": game.free_scores,
            "is_free": game.is_free,
            "countries": [country.country for country in game.country.all()],
            "gradient_style":game.gradient_style,
        }
        for game in available_games
    ]
    return APIResponse.HTTP_200_OK(message="Available games retrieved successfully.", data=games_data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_available_games_by_admin_and_agent_tokens(request):
    """
         This function retrieves all available games for the authenticated user.
         Args:
                 request (HTTPRequest): The request object. just give the adming token and agent token.
         Returns:
             1.
                 {
                    "status": 200,
                    "message": "Available games retrieved successfully.",
                    "data": [
                        {
                            "id": "604dc9ed-dbba-4e35-8d94-42318676252f",
                            "game_id": "1",
                            "game_name": "111",
                            "game_description": "sdafasdfas",
                            "game_image": "/media/game_images/Screenshot_2024-12-20_162740.png",
                            "game_video": "/media/game_videos/Screenshot_2024-12-20_160823_QQz4Gb1.png",
                            "game_price": 3000,
                            "android_game_url": "https://www.veed.io/edit/933b0227-43ec-4ada-b45a-0d09d145b850/convert?
                                            source=%2Fconvert%2Fvideo-converter",
                            "ios_game_url": "https://www.veed.io/edit/933b0227-43ec-4ada-b45a-0d09d145b850/convert?
                                            source=%2Fconvert%2Fvideo-converter",
                            "browser_game_url": "https://www.veed.io/edit/933b0227-43ec-4ada-b45a-0d09d145b850/convert?
                                            source=%2Fconvert%2Fvideo-converter",
                            "upcoming_status": false,
                            "transfer_score_percentage": 0,
                            "redeem_score_percentage": 0,
                            "free_scores": 0,
                            "is_free": false,
                            "countries": [
                                "United States"
                            ]
                        }
                    ]
                }
            2.
                {
                    "status": 401,
                    "message": "Authentication token is missing."
                }
            3.
                {
                    "status": 401,
                    "message": "Invalid or expired token."
                }
            4.
                {
                    "status": 404,
                    "message: "Role is not properly configured."
                }
            5.
                {
                    "status": 404,
                    "message": "User not found or does not have the 'Admin' or 'Agent' role."
                }
            6.
                {
                    "status": 404,
                    "message": "Available games not found for the user."
                }
            """
    # --------------------------------------------- validating Parameters ---------------
    user_instance = AuthService.get_user_from_token(request)
    auth_user = AuthService.validate_user_role(user_instance, "Admin")
    if not auth_user:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found or does not have the 'Admin' role.")
    user_roles = models.Role.objects.filter(roles__in=["Admin", "Agent"])
    if not user_roles:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message="Role is not properly configured.")
    user = models.User.objects.filter(id=auth_user.id, role_id__in=user_roles.values_list('id', flat=True)).first()
    if not user:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found or does not have the 'Admin' or 'Agent' role.")
    # ------------------------------------- Validating Completed ----------
    available_games = models.Game.objects.filter(created_by_user_id=user).all() # Fetch all games from the Game model
    if not available_games:
        return APIResponse.HTTP_404_NOT_FOUND(message="Available games not found for the user.")
    # ------------------------------------- Validating Completed --------------------------
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
            "gradient_style": game.gradient_style,
        }
        for game in available_games
    ]
    return APIResponse.HTTP_200_OK(message="Available games retrieved successfully.", data=games_data)


@api_view(['GET'])
def get_all_free_games(request):
    """
        This function retrieves all available games.
        Args:
                request (HTTPRequest): The request object.
        Returns:
            1.
                {
                    "status": 200,
                    "message": "Free games retrieved successfully.",
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
                            "upcoming_status": false,
                            "transfer_score_percentage": 0,
                            "redeem_score_percentage": 0,
                            "free_scores": 0,
                            "is_free": true,
                            "countries": []
                        }
                    ]
                }
            2.
                {
                        "status": 404,
                        "message": "Free games not found."
                }
    """
    available_games = models.Game.objects.filter(is_free=True).all()
    # -------------------------------------------------- validating parameters ------------------
    if not available_games:
        return APIResponse.HTTP_404_NOT_FOUND(message="Free games not found.")
    # ------------------------------------------------- validating completed ---------------------
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
            "free_scores": game.free_scores,
            "is_free": game.is_free,
            "countries": [country.country for country in game.country.all()],
            "gradient_style": game.gradient_style,
        }
        for game in available_games
    ]
    return APIResponse.HTTP_200_OK(message="Free games retrieved successfully.", data=games_data)

@api_view(['GET'])
def get_game_by_name(request, game_name):
    print(game_name)
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
    game = models.Game.objects.filter(game_name=game_name).first()
    if not game:
        return APIResponse.HTTP_404_NOT_FOUND(message="Game not found.")
    players = models.Player.objects.filter(game_id=game.id)
    game_reviews = models.GameReview.objects.filter(game_id=game.id).all()

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
            "profile_image": request.build_absolute_uri(review.user_id.profile_image.url) if review.user_id.profile_image else "/media/default-user.jpg",
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

##

@api_view(['GET'])
def get_trending_games(request):
    """
        This function retrieves all trending games.
        Args:
                request (HTTPRequest): The request object.

        Returns:
            1.
                {
                    "status": 200,
                    "message": "Trending games retrieved successfully.",
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
                            "upcoming_status": false,
                            "transfer_score_percentage": 0,
                            "redeem_score_percentage": 0,
                            "countries": []
                        }
                    ]
                }
            2.
                {
                    "status": 404,
                    "message": "Trending games not found."
                }

    """
    available_games = models.Game.objects.filter(is_trending=True)
    # --------------------------------------------- validating parameters ------------------
    if not available_games:
        return APIResponse.HTTP_404_NOT_FOUND(message="Trending games not found.")
    # ------------------------------------- validating completed ----------------------------
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
    return APIResponse.HTTP_200_OK(message="Trending games retrieved successfully.", data=games_data)

@api_view(['GET'])
def get_game_image(request, game_id):
    """
    Serve game image binary data directly from the database.
    """
    game = get_object_or_404(models.Game, id=game_id)
    if game.game_image:
        with open(game.game_image.path, 'rb') as image_file:
            return APIResponse.HTTP_200_OK(image_file.read(), content_type="image/jpeg")
    return APIResponse.HTTP_404_NOT_FOUND("image not found")  # Image not found

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

    available_games = models.Game.objects.filter(upcoming_status=True)
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
        This function adds a new Game.
        Args:
                request (HTTPRequest): The request object.
        Payload:
                {
                    "game_id": "GTA-6-345",
                    "game_name": "GTA-6-345",
                    "game_description": "Battle Ground description",
                    "game_price": "1080",
                    "android_game_url": "https://www.veed.io/edit/933b0227-43ec-4ada-b45a-0d09d145b850/convert?
                                        source=%2Fconvert%2Fvideo-converter",
                    "ios_game_url": "https://www.veed.io/edit/933b0227-43ec-4ada-b45a-0d09d145b850/convert?source=%
                                       2Fconvert%2Fvideo-converter",
                    "browser_game_url": "https://www.veed.io/edit/933b0227-43ec-4ada-b45a-0d09d145b850/convert?source=
                                        %2Fconvert%2Fvideo-converter",
                    "upcoming_status": "False",
                    "transfer_score_percentage": "10",
                    "redeem_score_percentage": "10",
                    "score": "200",
                    "is_free": "True"
                }
        Returns:
            1.
                {
                    "status": 200,
                    "message": "Game added successfully.",
                    "data": {
                        "game_id": "GTA-6-345",
                        "game_name": "GTA-6-345",
                        "game_description": "Battle Ground description",
                        "game_price": "1080",
                        "android_game_url": "https://www.veed.io/edit/933b0227-43ec-4ada-b45a-0d09d145b850/convert?
                                             source=%2Fconvert%2Fvideo-converter",
                        "ios_game_url": "https://www.veed.io/edit/933b0227-43ec-4ada-b45a-0d09d145b850/convert?
                                            source=%2Fconvert%2Fvideo-converter",
                        "browser_game_url": "https://www.veed.io/edit/933b0227-43ec-4ada-b45a-0d09d145b850/convert?
                                            source=%2Fconvert%2Fvideo-converter",
                        "upcoming_status": "False",
                        "transfer_score_percentage": "10",
                        "redeem_score_percentage": "10",
                        "score": "200",
                        "is_free": "True"
                    }
                }
            2.
                {
                    "status": 401,
                    "message": "Authentication credentials were not provided."
                }
            3.
                {
                    "status": 401,
                    "message": "Invalid or expired token."
                }
            4.
                 {
                    "status": 404,
                    "message": "User not found or does not have the 'Admin' or 'Agent' role."
                 }
            5.
                {
                     "status": 404,
                     "message": "Could not find the user."
                 }
            6.
                {
                    "status": 400,
                    "message": "Invalid form data.",
                    "data": {
                        "game_description": [
                            "This field is required."
                        ],
                        "game_price": [
                            "This field is required."
                        ]
                    }
                }
            7.
                {
                    "status": 400
                    "message": "Invalid form data.",
                    "data": {
                            "game_id": [
                                "Game with this Game id already exists."
                            ]
                    }
                }
    """
    # -------------------------------------------- Validating Parmaeters ------------------
    print("Hit add game.....")
    user_instance = AuthService.get_user_from_token(request)
    print("hit game......")
    print(user_instance)
    # auth_user = AuthService.validate_user_role(user_instance, "Admin")
    auth_user = AuthService.validate_user_role(user_instance, "Agent")
    if not auth_user:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or expired token.")
    user_role = models.Role.objects.filter(roles="Admin" or "Agent").first()  # Fetch roles for validation
    print(f"user_role {user_role}")
    if not user_role:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message="Role is not properly configured.")
    user = models.User.objects.filter(id=auth_user.id, role_id=user_role).first()
    ## the below condition is not working handle this
    if not user:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found or does not have the 'Admin' or 'Agent' role.")
    country = models.Country.objects.get(country=settings.COUNTRY)
    if not country:
        return APIResponse.HTTP_404_NOT_FOUND(message="Country not found.")
    # -------------------------------------------- Validating Completed -------------------------------
    form = forms.GameForm(request.POST, request.FILES)
    if form.is_valid():
        # Format the game name
        game_instance = form.save(commit=False)
        game_instance.game_name = game_instance.game_name.strip().lower().replace(' ', '-')
        game_instance = form.save(commit=False)
        game_instance.created_by_user_id = user
        game_instance.save()                               # Save the Game instance to the database
        game_instance.country.set([country])
        game_instance.save()                               # Save the changes
        return APIResponse.HTTP_200_OK(message="Game added successfully.", data=form.data)
    else:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid form data.", data=form.errors)


@api_view(['PUT'])
def update_game(request):
    """
        This function updates a Game.
        Args:
                request (HTTPRequest): The request object.
        payload:
                {
                    "game_id": "GTA-6-345",
                    "game_name": "PUBG - Battle Ground",
                    "game_description": "PUBG - Battle Ground description",
                    "game_image": "/media/game_images/default-game_Rq2mUW3.jpg",
                    "game_video": "/media/game_videos/tariq_Mahmood3x3x_iEr1C9p.jpg",
                    "game_price": 1080,
                    "android_game_url": "https://www.veed.io/edit/933b0227-43ec-4ada-b45a-0d09d145b850/convert?
                        source=%2Fconvert%2Fvideo-converter",
                    "ios_game_url": "https://www.veed.io/edit/933b0227-43ec-4ada-b45a-0d09d145b850/convert?
                        source=%2Fconvert%2Fvideo-converter",
                    "browser_game_url": "https://www.veed.io/edit/933b0227-43ec-4ada-b45a-0d09d145b850/convert?
                        source=%2Fconvert%2Fvideo-converter",
                    "upcoming_status": true,
                    "transfer_score_percentage": 3,
                    "redeem_score_percentage": 10,
                    "countries": [
                        "United States"
                    ]
                }
        Returns:
            1.
                {
                    "status": 200,
                    "message": "game updated successfully.",
                    "data": {
                        "id": "fcf07988-1d51-4d4f-a503-cda077b30c20",
                        "game_id": "GTA-6-345",
                        "game_name": "PUBG - Battle Ground",
                        "game_description": "PUBG - Battle Ground description",
                        "game_image": "/media/game_images/default-game_Rq2mUW3.jpg",
                        "game_video": "/media/game_videos/tariq_Mahmood3x3x_iEr1C9p.jpg",
                        "game_price": 1080,
                        "android_game_url": "https://www.veed.io/edit/933b0227-43ec-4ada-b45a-0d09d145b850/convert?
                            source=%2Fconvert%2Fvideo-converter",
                        "ios_game_url": "https://www.veed.io/edit/933b0227-43ec-4ada-b45a-0d09d145b850/convert?
                            source=%2Fconvert%2Fvideo-converter",
                        "browser_game_url": "https://www.veed.io/edit/933b0227-43ec-4ada-b45a-0d09d145b850/convert?
                        source=%2Fconvert%2Fvideo-converter",
                        "upcoming_status": true,
                        "transfer_score_percentage": 3,
                        "redeem_score_percentage": 10,
                        "countries": [
                            "United States"
                        ]
                    }
                }
            2.
                 {
                    "status": 400,
                    "message": "game_id is required.",
                }
            3.
                {
                    "status": 404,
                    "message": "Game not found."
                }
            4.
                {
                    "status": 400,
                    "message": "Invalid form data.",
                    "data": {
                        "game_description": [
                            "This field is required."
                        ],
                        "game_price": [
                            "This field is required."
                        ]
                    }
                }
    """
    game_id = request.data.get('game_id')
    # -------------------------------------------- Validating Parameters ---------------------------
    if not game_id:
        return APIResponse.HTTP_400_BAD_REQUEST(message="game_id is required.")
    game = models.Game.objects.filter(game_id=game_id).first()
    if not game:
        return APIResponse.HTTP_404_NOT_FOUND(message="Game not found.")
    # -------------------------------------------- Validating Completed ------------------------------
    form = forms.GameForm(request.data, request.FILES, instance=game)
    if form.is_valid():
        form.save()
        updated_game = {
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
            "gradient_style": game.gradient_style,
        }
        return APIResponse.HTTP_200_OK(message="game updated successfully.", data=updated_game)
    else:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid form data.", data=form.errors)


@api_view(['DELETE'])
def delete_game(request):
    """
       This function deletes a Game.
       Args:
               request (HTTPRequest): The request object.
       payload:
               {
                   "game_id": "GTA-6-345"
            }
       Returns:
           1.
               {
                    "status": 200,
                    "message": "models.Game deleted successfully.",
                    "data": {
                        "id": "fcf07988-1d51-4d4f-a503-cda077b30c20",
                        "game_id": "GTA-6-345",
                        "game_name": "PUBG - Battle Ground",
                        "game_description": "PUBG - Battle Ground description",
                        "game_image": "/media/game_images/default-game_Rq2mUW3.jpg",
                        "game_video": "/media/game_videos/tariq_Mahmood3x3x_iEr1C9p.jpg",
                        "game_price": 1080,
                        "android_game_url": "https://www.veed.io/edit/933b0227-43ec-4ada-b45a-0d09d145b850/convert?source=%2Fconvert%2Fvideo-converter",
                        "ios_game_url": "https://www.veed.io/edit/933b0227-43ec-4ada-b45a-0d09d145b850/convert?source=%2Fconvert%2Fvideo-converter"
                    }
              }
          2.
                {
                    "status": 400,
                    "message": "game_id is required.",
                }
          3.
                {
                    "status": 404,
                    "message": "Game doesnot exists."
                }

    """
    game_id = request.data.get('game_id')
    # -------------------------------------------- Validating Parameters ---------------------------
    if not game_id:
        return APIResponse.HTTP_400_BAD_REQUEST(message="game_id is required.")
    game = models.Game.objects.get(game_id=game_id)
    if not game:
        return APIResponse.HTTP_404_NOT_FOUND(message="Game doesnot exists.")
    #--------------------------------------------- Validating Completed ---------------------------
    form = forms.GameForm(instance=game)
    data = {
        "id": str(game.id),
        "game_id": game.game_id,
        "game_name": game.game_name,
        "game_description": game.game_description,
        "game_image": game.game_image.url if game.game_image else None,
        "game_video": game.game_video.url if game.game_video else None,
        "game_price": game.game_price,
        "android_game_url": game.android_game_url,
        "ios_game_url": game.ios_game_url,
    }
    form.delete()
    return  APIResponse.HTTP_200_OK(message='Game deleted successfully.', data=data)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def redeem_game_player_scores_to_wallet(request):
    """
         This function redeems the scores of a player to the wallet of the user.
         Args:
                 request (HTTPRequest): The request object.
         payload:
                 {
                     "game_id": "GTA-6-345",
                     "player_username": "tariq_mahmoud"
                 }
         Returns:
             1.
                 {
                    "status": 200,
                    "message": "Score successfully redeemed from the models.Game.",
                    "data": {
                        "username": "RashidHussain",
                        "new_scores": 500.0,
                        "datetime": "2024-12-26 08:31:28.540874+00:00"
                    }
                }
             2.
                 {
                    "status": 401,
                    "message": "Authentication token is missing."
                }
             3.
                 {
                    "status": 401,
                    "message": "Invalid or expired token."
                }
             4.
                 {
                    "status": 404,
                    "message": "User not found."
                 }
             5.
                {
                    "status": 404,
                    "message": "Game not found."
                }
             6.
                {
                    "status": 404,
                    "message": "Player with username does not exists in database."
                }
             7.
                {
                    "status": 404,
                    "message": "Invalid Player username."
                }
            8.
                {
                    "status: 400,
                    "message":"You have already redeemed your score today. Please try again tomorrow."
                }
            9.
                {
                    "status": 400,
                    "message": "Score `0.0` not enough for Level. At least 100  scores are required to redeem."
                }
            10.
                {
                    "status": 422,
                    "message":"You don't have enough scores to redeem."
                }
            11.
                {
                    "status": 400,
                    "message": "Invalid subscription plan.",
                }

    """
    # Variables to be used in the redemption process
    l_0, l_1, l_2, l_3, l_4 = return_level_scores()
    free, premium, elite = return_subscriptions()
    redemption_score_on_level_0 = l_0.redemption_score_on_level
    redemption_score_on_level_1 = l_1.redemption_score_on_level
    redemption_score_on_level_2 = l_2.redemption_score_on_level
    redemption_score_on_level_3 = l_3.redemption_score_on_level
    redemption_score_on_level_4 = l_4.redemption_score_on_level
    level_codes = [l_0.level_code, l_1.level_code, l_2.level_code, l_3.level_code, l_4.level_code]
    free_subscription_choice = free.pro_status
    premium_subscription_choice = premium.pro_status
    elite_subscription_choice = elite.pro_status
    redemption_on_free_subscription_percentage = free.redemption_on_free_subscription
    redemption_on_premium_subscription_percentage = premium.redemption_on_free_subscription
    redemption_on_elite_subscription_percentage = elite.redemption_on_free_subscription
    # ------------------------------------ Variables Definition Completed -------------------------
            # Get the user from the token
    user_instance = AuthService.get_user_from_token(request)
    auth_user = AuthService.validate_user_role(user_instance, "User")
    if not auth_user:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or expired token.")
    user_role = models.Role.objects.filter(roles="User").first()  # Fetch roles for validation
    if not user_role:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message="Role is not properly configured.")
    # ------------------------------- Validating Parameters -----------------------------------
    user = models.User.objects.filter(id=auth_user.id).first()
    if not user:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
    user_uuid = user.id
    if not user_uuid:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
    game_uuid = request.data.get('game_id')                # Get the game_id from the request data

    player_username = request.data.get('player_username')
    if not game_uuid or not player_username:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Missing required fields.")
    game = models.Game.objects.filter(game_id=game_uuid).first()
    if not game:
        return APIResponse.HTTP_404_NOT_FOUND(message="Game not found.")
    user = models.User.objects.filter(id=user_uuid).first()
    if not user:
            return APIResponse.HTTP_404_NOT_FOUND(message=f"Invalid username.", data = {
                "username": user.user_id.username,
                "datetime": datetime.now(tz=UTC).__str__(),
            })
    player_username_in_db = models.Player.objects.filter(username=player_username).first()
    if not player_username_in_db:
        return APIResponse.HTTP_404_NOT_FOUND(message="Player with username does not exists in database.")
    player = models.Player.objects.filter(user_id=user, game_id=game, username=player_username).first()
    print("player get.....")
    if not player:
        return APIResponse.HTTP_404_NOT_FOUND(message="Invalid Player username.", data = {
            "username": models.Player.username,
            "datetime": datetime.now(tz=UTC).__str__(),
        })
    free_game = game.is_free
    wallet = user.wallet_id
    """
        REDEEM ON LEVELS (daily):
        # models.Level 0 => 100$ (scores) only
        # models.Level 1 => 200$ (scores) only
        # models.Level 2 => 500$ (scores) only
        # models.Level 3 => 800$ (scores) only
        # models.Level 4 => 5000$ (scores) only
    """
    if not game or not user:
        data = {
            "username": user.user_id.username,
            "datetime": datetime.now(tz=UTC).__str__(),
        }
        return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid username", data=data)
    level_redemption_scores = {                                # Redemption scores for each Level
        level_codes[0]: redemption_score_on_level_0,
        level_codes[1]: redemption_score_on_level_1,
        level_codes[2]: redemption_score_on_level_2,
        level_codes[3]: redemption_score_on_level_3,
        level_codes[4]: redemption_score_on_level_4,
    }                                                          # Redemption percentages for each subscription plan
    subscription_percentages = {
        premium_subscription_choice: redemption_on_premium_subscription_percentage,
        free_subscription_choice: redemption_on_free_subscription_percentage,
        elite_subscription_choice: redemption_on_elite_subscription_percentage,
    }
    today_date = datetime.now().date()
    if wallet.last_transaction_date.date() == today_date:       # Compare only the date parts (ignore time)
        return APIResponse.HTTP_400_BAD_REQUEST(
            message="You have already redeemed your score today. Please try again tomorrow."
        )
    if user.user_level.level_code in level_redemption_scores:
        required_score = level_redemption_scores[user.user_level.level_code]
        free_scores = player.free_scores
        player_scores = player.score
        if free_game:
            if free_scores >= required_score:
                if user.subscription_plan.pro_status in subscription_percentages:
                    redemption_percentage = subscription_percentages[user.subscription_plan.pro_status]
                    # Redeem 10% of free scores
                    redeemable_score = int(free_scores) * 0.1
                    wallet_history = models.WalletTransactionHistory.objects.create(
                        payment_method="Game to Wallet Transaction",
                        payment_status='Approved',
                        transaction_amount=redeemable_score
                    )
                    wallet.total_amount += redeemable_score                          # update the wallet
                    wallet.wallet_transaction_history_id.add(wallet_history)
                    wallet.last_transaction_date = datetime.now().date()           # Set last transaction date to today
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
                            1 if user.subscription_plan.pro_status == free_subscription_choice          #free
                            else 2 if user.subscription_plan.pro_status == premium_subscription_choice  # Premium (Pro)
                            else 3),
                            0
                            )
                    # 90 * 50 = 4500
                    total_xp = total_xp * redemption_percentage
                    user.experience_points += total_xp
                    wallet.save()                               # Save changes to wallet and user
                    user.save()
                    game.save()
                    game_transaction_history = models.GameTransactionHistory.objects.create(
                        game_id=game,
                        payment="Game to Wallet Transaction",
                        transaction_amount=redeemable_score,
                    )
                    player.game_transaction_history_id.add(game_transaction_history)
                    player.free_scores = 0
                    player.save()
                    return APIResponse.HTTP_200_OK(
                        message="Score successfully redeemed from the Game.",
                        data={
                            "username": user.user_id.username,
                            "new_scores": player.score,
                            "datetime": datetime.now(tz=UTC).__str__()
                        },
                    )
                else:
                    data ={
                        "username":user.user_id.username,
                        "datetime": datetime.now(tz=UTC).__str__(),
                    }
                    return APIResponse.HTTP_422_UNPROCESSABLE_ENTITY(
                        message = "You don't have enough scores to redeem.", data=data
                    )
            else:
                return APIResponse.HTTP_400_BAD_REQUEST(
                    message=f"Score `{free_scores}` not enough for Level. At least {required_score}"
                            f" scores are required to redeem."
                )
        else:                                                                       # Handle paid scores redemption
            if player_scores >= required_score:
                if user.subscription_plan.pro_status in subscription_percentages:  # Get the percentage for the user's
                    redemption_percentage = subscription_percentages[user.subscription_plan.pro_status]
                    wallet.total_amount += required_score                          # Update wallet balances
                    wallet.last_transaction_date = datetime.now().date()          # Set last transaction date to today
                    # Calculate XP from remaining scores
                    remaining_score_to_xp = player_scores - required_score       # 102 - 100 = 2
                    """
                    Free:               -> remaining_score_to_xp
                    Premium(Pro): 2     -> remaining_score_to_xp * 2
                    Elite: 3            -> remaining_score_to_xp * 3
                    """
                    # 2*2 = 4
                    total_xp = max(
                        remaining_score_to_xp * (1 if user.subscription_plan.pro_status == free_subscription_choice   # Free
                                                 else 2 if user.subscription_plan.pro_status == premium_subscription_choice  # Premium (Pro)
                                                    else 3),
                                                    0
                                                )
                    total_xp = total_xp * redemption_percentage
                    user.experience_points += total_xp
                    # Check license verification and upgrade user models.Level
                    if (
                            user.driving_license_front_image
                            and user.driving_license_back_image
                            and user.is_verified_license
                    ):
                        user.user_level.models.Level = "Level 1"
                        user.user_level.level_code = "L1"
                    wallet_history = models.WalletTransactionHistory.objects.create(
                        payment_method="Game to Wallet Transaction",
                        payment_status='Approved',
                        transaction_amount=required_score
                    )
                    wallet.wallet_transaction_history_id.add(wallet_history)      # Update wallet balances
                    wallet.save()
                    user.save()
                    game.save()
                    game_transaction_history = models.GameTransactionHistory.objects.create(
                        game_id=game,
                        payment="Game to Wallet Transaction",
                        transaction_amount=required_score,
                    )
                    player.game_transaction_history_id.add(game_transaction_history)
                    player.score = 0
                    player.save()
                    return APIResponse.HTTP_200_OK(
                        message="Score successfully redeemed from the Game.",
                        data={
                            "username": user.user_id.username,
                            "new_scores": player.socre,
                            "datetime": datetime.now(tz=UTC).__str__()
                        },
                    )
                else:
                    return APIResponse.HTTP_400_BAD_REQUEST(
                        message=f"Invalid subscription plan `{user.subscription_plan.pro_status}`."
                    )
            else:
                return APIResponse.HTTP_400_BAD_REQUEST(
                    message=f"Score `{player_scores}` not enough for Level `{user.user_level.models.Level}`"
                                     f". At least  {required_score}  scores are required to redeem."
                )


@api_view(['GET'])
def get_game_transaction_history(_):
    """
        This function retrieves all game transaction histories from the database.
        it takes user token as a parameter and returns the game transaction history.
        Args:
            None
        Returns:
           1.
                {
                    "status": 200,
                    "message": "Game transaction history retrieved successfully.",
                    "data": [
                    {
                        "transaction_id": "4787e51e-f894-43e9-948c-117bd62da81e",
                        "models.Game": {
                            "id": "7e353abe-0190-4464-bc9c-2c946151144d",
                            "game_id": "GTA-6-345",
                            "game_name": "GTA-6-345",
                            "game_description": "Battle Ground description",
                            "game_price": 1080,
                            "game_image": "/media/game_images/default-game_Ib1K1LN.jpg",
                            "game_video": "/media/game_videos/tariq_Mahmood3x3x_uQDYL5Q.jpg",
                            "upcoming_status": false,
                            "is_trending": false
                        },
                        "payment": "Game to Wallet Transaction",
                        "transaction_amount": 100,
                        "transaction_date": "2024-12-26T08:21:50.003788Z",
                        "order_id": null,
                        "withdrawal_percentage_tax": 0
                    },
                    {
                        "transaction_id": "6e235a17-824b-4f67-8bcb-52f3b5870a81",
                        "models.Game": {
                            "id": "7e353abe-0190-4464-bc9c-2c946151144d",
                            "game_id": "GTA-6-345",
                            "game_name": "GTA-6-345",
                            "game_description": "Battle Ground description",
                            "game_price": 1080,
                            "game_image": "/media/game_images/default-game_Ib1K1LN.jpg",
                            "game_video": "/media/game_videos/tariq_Mahmood3x3x_uQDYL5Q.jpg",
                            "upcoming_status": false,
                            "is_trending": false
                        },
                        "payment": "Game to Wallet Transaction",
                        "transaction_amount": 60,
                        "transaction_date": "2024-12-26T08:31:28.524916Z",
                        "order_id": null,
                        "withdrawal_percentage_tax": 0
                    }
                ]
        }
    2.
        {
            "status": 404,
            "message": "No game transaction history found."
        }

    """
    histories = models.GameTransactionHistory.objects.select_related('game_id').all()
    if not histories:
        return APIResponse.HTTP_404_NOT_FOUND(message="No game transaction history found.")
    histories_data = [
        {
            "transaction_id": str(history.id),
            "models.Game": {
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


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_game_player_by_username(request):
    """
        This function retrieves all players of a game or all games of a user.
        It takes user token as a parameter and returns the game transaction history.
        Args:
            game_uuid(str): The game_uuid of the game for which players are to be retrieved.
        Payload:
                {
                "game_uuid": "7e353abe-0190-4464-bc9c-2c946151144d"
            }
        Returns:
            1.
                {
                    "status": 200,
                    "message": "Players for game_id 7e353abe-0190-4464-bc9c-2c946151144d retrieved successfully.",
                    "data": [
                        {
                            "player_id": "5f4c8bce-ab9c-47a8-bc29-b800cd48b06d",
                            "username": "rashidhussain",
                            "nick_name": "rashidkhan",
                            "score": 500.0,
                            "status": "active",
                            "is_banned": false,
                            "models.Game": {
                                "id": "7e353abe-0190-4464-bc9c-2c946151144d",
                                "game_name": "GTA-6-345",
                                "game_description": "Battle Ground description"
                            }
                        }
                    ]
                }
            2.
                {
                    "status": 400,
                    "message": "Game ID is required."
                }
            3.
                {
                    "status": 400,
                    "message": "Username is required."
                }
            4.
                {
                    "status": 404,
                    "message": "No players found for rashidhussain."
                }
            5.
                {
                    "status": 404,
                    "message": "No players found."
                }
    """
    game_uuid = request.data.get('game_uuid', None)
    if not game_uuid:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Game ID is required.")
    username = request.data.get('username', None)
    if not username:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Username is required.")
    if game_uuid:
        players = models.Player.objects.filter(game_id=game_uuid)
        data = [
            {
                "player_id": player.id,
                "username": player.username,
                "nick_name": player.nick_name,
                "score": player.score,
                "status": player.status,
                "is_banned": player.is_banned,
                "models.Game": {
                    "id": str(player.game_id.id),
                    "game_name": player.game_id.game_name,
                    "game_description": player.game_id.game_description,
                },
            }
            for player in players
        ]
        return APIResponse.HTTP_200_OK(
            message=f"Players for {game_uuid} retrieved successfully.",
            data=data,
        )
    elif username:                                 # If username is provided, fetch all games of that user
        players = models.Player.objects.filter(username=username)
        if not players:
            return APIResponse.HTTP_404_NOT_FOUND(message=f"No players found for {username}.")
        data = [
            {
                "game_uuid": str(player.game_uuid.id),
                "game_name": player.game_uuid.game_name,
                "game_description": player.game_uuid.game_description,
                "player": {
                    "id": player.id,
                    "nick_name": player.nick_name,
                    "score": player.score,
                },
            }
            for player in players
        ]
        return APIResponse.HTTP_200_OK(
            message=f"Games for {username} retrieved successfully.",
            data=data,
        )
    else:                        # If neither game_uuid nor username is provided, fetch all players with their games
        players = models.Player.objects.select_related('game_uuid').all()
        if not players:
            return APIResponse.HTTP_404_NOT_FOUND(message="No players found.")
        data = [
            {
                "player_id": player.id,
                "username": player.username,
                "nick_name": player.nick_name,
                "score": player.score,
                "status": player.status,
                "is_banned": player.is_banned,
                "models.Game": {
                    "id": str(player.game_uuid.id),
                    "game_name": player.game_uuid.game_name,
                    "game_description": player.game_uuid.game_description,
                },
            }
            for player in players
        ]
        return APIResponse.HTTP_200_OK(
            message="All players with their games retrieved successfully.",
            data=data,
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def game_to_game_redemption(request):
    """
        This function takes two player UUIDs and transfers scores from one player to another.
        it takes user token as a parameter and returns the game transaction history.
        These players must belong to the same user.
        Args:
            player_1_uuid(str): The player_1_uuid of the player from which scores are to be transferred.
            player_2_uuid(str): The player_2_uuid of the player to which scores are to be transferred.
        Payload:
                {
                "player_1_uuid": "5f4c8bce-ab9c-47a8-bc29-b800cd48b06d",
                "player_2_uuid": "5f4c8bce-ab9c-47a8-bc29-b800cd48b06d"
            }
        Returns:
            1.
                {
                    "status": 200,
                    "message": "Scores transferred successfully from AmmarHussain to IkramHussain.",
                    "data": {
                        "player_1": {
                            "player_id": "ae667197-1928-461c-828c-769cbfdb97f0",
                            "username": "AmmarHussain",
                            "nick_name": "ammar11",
                            "free_scores": 0,
                            "score": 0.0,
                            "status": "active",
                            "is_banned": false,
                            "game": {
                                "id": "7e353abe-0190-4464-bc9c-2c946151144d",
                                "game_id": "GTA-6-345",
                                "game_name": "GTA-6-345",
                                "game_description": "Battle Ground description"
                            }
                        },
                        "player_2": {
                            "player_id": "9be3c1ef-22ef-4bfc-a04f-d30728ea5981",
                            "username": "IkramHussain",
                            "nick_name": "ikram11",
                            "free_scores": 0.0,
                            "score": 0.0,
                            "status": "active",
                            "is_banned": false,
                            "game": {
                                "id": "7e353abe-0190-4464-bc9c-2c946151144d",
                                "game_id": "GTA-6-345",
                                "game_name": "GTA-6-345",
                                "game_description": "Battle Ground description"
                            }
                        }
                    }
                }
            2.
                {
                    "status": 400,
                    "message": "Player UUIDs are required."
                    }
            3.
                {
                    "status": 400,
                    "message": "One or both players do not belong to the specified user."
                }
            4.
                {
                    "status": 400,
                    "message": "Both players must be active to redeem scores."
                }

    """
    user_instance = AuthService.get_user_from_token(request)                # Authenticate and fetch the user
    user = AuthService.validate_user_role(user_instance, "User")
    player_1_uuid = request.data.get('player_1_uuid')
    player_2_uuid = request.data.get('player_2_uuid')
    # ------------------------------------------- Validating Parameters ----------------------------
    if not player_1_uuid or not player_2_uuid:
        return APIResponse.HTTP_400_BAD_REQUEST(message=" Player UUIDs are required.")
    player_1 = models.Player.objects.filter(id=player_1_uuid, user_id=user.id).first()
    player_2 = models.Player.objects.filter(id=player_2_uuid, user_id=user.id).first()
    if not player_1 or not player_2:
        return APIResponse.HTTP_400_BAD_REQUEST(message="One or both players do not belong to the specified user.")
    if player_1.status != 'active' or player_2.status != 'active':
        return APIResponse.HTTP_400_BAD_REQUEST(message="Both players must be active to redeem scores.")
    game = models.Game.objects.get(id=player_1.game_id.id)
    transfer_score_percentage = game.transfer_score_percentage
    percentage_deducted = transfer_score_percentage / 100   # Calculate percentage for deduction and remaining
    percentage_remaining = 1 - percentage_deducted
    # -------------------------------------------------- Validating Completed -----------------------------
    if game.is_free:                            # Handle transfer logic for free_scores or score based on game type
        transfer_amount = int(player_1.free_scores * percentage_remaining)  # Deduct and transfer free_scores
        player_2.free_scores += transfer_amount
        player_1.free_scores = 0                                            # Reset free_scores for player_1
    else:
        transfer_amount = int(player_1.score * percentage_remaining)       # Deduct and transfer scores
        player_2.score += transfer_amount
        player_1.score = 0                                                  # Reset score for player_1
    player_1.save()
    player_2.save()
    data = {
        "player_1": {
            "player_id": player_1.id,
            "username": player_1.username,
            "nick_name": player_1.nick_name,
            "free_scores": player_1.free_scores,
            "score": player_1.score,
            "status": player_1.status,
            "is_banned": player_1.is_banned,
            "game": {
                "id": str(player_1.game_id.id),
                "game_id": str(player_1.game_id.game_id),
                "game_name": player_1.game_id.game_name,
                "game_description": player_1.game_id.game_description,
            }
        },
        "player_2": {
            "player_id": player_2.id,
            "username": player_2.username,
            "nick_name": player_2.nick_name,
            "free_scores": player_2.free_scores,
            "score": player_2.score,
            "status": player_2.status,
            "is_banned": player_2.is_banned,
            "game": {
                "id": str(player_2.game_id.id),
                "game_id": str(player_2.game_id.game_id),
                "game_name": player_2.game_id.game_name,
                "game_description": player_2.game_id.game_description,
            },
        },
    }
    return APIResponse.HTTP_200_OK(
        message=f"Scores transferred successfully from {player_1.username} to {player_2.username}.",
        data=data
    )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def get_all_games_under_user_freeplays(request):
    """
        This function retrieves all games with a price between 0 and the user's free play amount.
        It takes user token as a parameter and returns the game transaction history.
        Args:
            None
        Returns:
            1.
                {
                    "status": 200,
                    "message": "Games retrieved successfully within free play range.",
                    "data": {
                        "user": {
                            "user_id": "9b03dcbb-e3a3-454f-93b6-15096801bb56",
                            "username": "AmmarHussain",
                            "email": "amaar@gmail.com",
                            "free_plays": 3
                        },
                        "games": [
                            {
                                "game_id": "3c44143c-ca19-4942-95ae-6e910d9f8ed7",
                                "game_name": "Need for Speed",
                                "game_description": "sdafsadfasdfsdafa",
                                "game_price": 1,
                                "is_free": true
                            }
                        ]
                    }
                }
            2 .
                {
                    "status": 401,
                    "message": "User not authenticated."
                }
            3.
                {
                    "status": 401,
                    "message": "User not authorized."
                }
            4.
                {
                    "status": 404,
                    "message": "No FreePlay record found for the user."
                }
            5.
                {
                    "status": 404,
                    "message": "No games found within AmmarHussain's free play range. Free play amount: $3"
                }

    """
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="User not authenticated.")
    user = AuthService.validate_user_role(user_instance, "User")
    if not user:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="User not authorized.")
    user = models.User.objects.get(id=user.id)
    if not user:
        return APIResponse.HTTP_404_NOT_FOUND(message="User with the given UUID does not exist.")
    free_play = models.FreePlay.objects.filter(user=user).first()
    if not free_play:
        return APIResponse.HTTP_404_NOT_FOUND(message="No FreePlay record found for the user.")
    free_plays_amount = free_play.free_plays    # Retrieve games with a price between 0 and free_plays_amount
    games = models.Game.objects.filter(game_price__gte=0, game_price__lte=free_plays_amount)
    if not games.exists():
        return APIResponse.HTTP_404_NOT_FOUND(
            message=f"No games found within {user.user_id.username}'s free play range. "
                    f"Free play amount: ${free_plays_amount}")
    data = {
        "user": {
            "user_id": str(user.id),
            "username": user.user_id.username,
            "email": user.email,
            "free_plays": free_plays_amount,
        },
        "games": [
            {
                "game_id": str(game.id),
                "game_name": game.game_name,
                "game_description": game.game_description,
                "game_price": game.game_price,
                "is_free": game.is_free,
            } for game in games
        ],
    }
    return APIResponse.HTTP_200_OK(
        message="Games retrieved successfully within free play range.",
        data=data
    )

############################################################################################################


## Admin Game Panel Management System
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_player_by_admin(request):
    """
    API to create a new player by an agent.
    """
    print("create plaer by admin hit....")
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    print(f"user_instance: {user_instance}")

    # Validate user's role
    auth_user = AuthService.validate_user_role(user_instance, "Admin")
    print(f"auth_user: {auth_user}")

    # Extract data from the request
    user_id = request.data.get('user_id')
    username = request.data.get('username')
    nickname = request.data.get('nickname')
    password = request.data.get('password')
    game_id = request.data.get('game_id')
    player_created_by = auth_user.id
    score = 0
    status = 'active'
    is_banned = False

    # Validate required fields
    if not (user_id and username and password and game_id and player_created_by):
        return APIResponse.HTTP_400_BAD_REQUEST(
            message="Missing required fields: user_id, username, password, player_created_by, and game_id are mandatory."
        )

    # Validate user's role
    user = AuthService.validate_user_uuid_role(user_id, "User")
    print(f"User: {user}")
    print(f"User: {user.id}")

    try:
        # Call the create_player method
        panel = AdminGamePanel()
        response_data = async_to_sync(panel.create_player)(
            user_id=user.id,
            username=username,
            nick_name=nickname,
            password=password,
            score=score,
            status=status,
            is_banned=is_banned,
            game_id=game_id,
            created_by=player_created_by,
        )

        # Return the successful response
        return APIResponse.HTTP_200_OK(
            message="Player created successfully.",
            data=response_data
        )

    except models.User.DoesNotExist:
        return APIResponse.HTTP_400_BAD_REQUEST(message="User with the given UUID does not exist.")
    except models.Player.DoesNotExist:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Player with the given UUID does not exist.")
    except models.Game.DoesNotExist:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Game with the given UUID does not exist.")
    except Exception as e:
        # Handle unexpected errors
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(
            message=f"User not created. Please try again after a few minutes. {str(e)}",
            data={
                "username": username,
                "datetime": datetime.now(tz=UTC).__str__(),
                "nickname": nickname,
                "score": 0
            }
        )

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def reset_game_password(request):
    """
    Synchronous API to reset the password of a game.
    """
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")
    print(f"user_instance: {user_instance}")

    # Allowed roles
    allowed_roles = ["Admin", "Agent", "User"]

    print(f"user_instance.role_id: {user_instance.id}")
    current_user = models.User.objects.get(user_id=user_instance.id)

    # Validate the user's role
    user_role = getattr(current_user.role_id, "roles", None)
    if user_role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{user_role}' is not authorized.")
    print(f"Authenticated user's role: {user_role}")

    # Proceed with the authenticated user
    auth_user = user_instance
    print(f"auth_user: {auth_user}")

    # Extract data from request
    username = request.data.get('username')
    new_password = request.data.get('new_password')

    # Validate required fields
    if not (username and new_password):
        return APIResponse.HTTP_400_BAD_REQUEST(
            message="Missing required fields: username and new_password are mandatory.")

    try:

        # Reset the password synchronously
        admin_panel = AdminGamePanel()
        game, player = async_to_sync(admin_panel.reset_game_password)(username=username, new_password=new_password)

        data = {
            "id": str(player.id),
            "username": player.username,
            "change_password_by": user_role,
            "game": player.game_id.game_name,
            "score": player.score,
            "new_password": player.password,
        }

        send_mail(
            "Game Password Reset",
            f"Hello {player.user_id.user_id.username},\n\nYour game password has been reset to: {new_password}\n\nBest regards,\nCoin Selling Platform Team",
            settings.EMAIL_HOST_USER,
            [player.user_id.email],
            fail_silently=False
        )

        return APIResponse.HTTP_200_OK(message="Game password reset successfully.", data=data)

    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_panel_scores(request):   ##
    """
    API Endpoint to get panel scores.
    Returns the scores of users with specific roles and usernames.
    """
    ##
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")
    print(f"user_instance: {user_instance}")

    # Allowed roles
    allowed_roles = ["Admin"]

    print(f"user_instance.role_id: {user_instance.id}")
    current_user = User.objects.get(user_id=user_instance.id)

    # Validate the user's role
    user_role = getattr(current_user.role_id, "roles", None)
    if user_role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{user_role}' is not authorized.")
    print(f"Authenticated user's role: {user_role}")

    # Proceed with the authenticated user
    auth_user = user_instance
    print(f"auth_user: {auth_user}")
    ##
    try:
        # Get query parameters
        # role_name = request.GET.get(user_role, 'Admin')  # Default role is 'admin'
        limit = int(request.GET.get('limit', 10))  # Default limit is 10

        # Get scores synchronously
        admin_panel = AdminGamePanel()
        # scores = async_to_sync(admin_panel.get_panel_scores_by_role)(role_name=role_name, limit=limit)
        scores = async_to_sync(admin_panel.get_panel_scores_by_role)(role_name=user_role, limit=limit)
        print("*********************************************")
        print(type(scores))
        data= {
            "datetime": datetime.now(tz=UTC).__str__(),
            'score': int(float(scores.strip()))
        }
        return APIResponse.HTTP_200_OK(
            message= "Successfully fetched panel scores.",data=data
        )

    except Exception as e:
        data= {
            "datetime": datetime.now(tz=UTC).__str__(),
        }
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"Unable to get panel scores. Please try again after few minutes.{str(e)}",data=data)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def redeem_score_from_game(request):
    """
    API endpoint to redeem or update a player's score for a given game.

    Args:
        request (Request): The request object containing `username`, `score`, and `game_id`.

    Returns:
        JsonResponse: Success or error response.
    """
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["User"]
    current_user = models.User.objects.get(user_id=user_instance.id)

    # Validate the user's role
    user_role = getattr(current_user.role_id, "roles", None)
    if user_role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{user_role}' is not authorized.")

    # Extract parameters from the request body
    username = request.data.get('username')
    score = request.data.get('score')
    game_id = request.data.get('game_id')

    # Validate required fields
    if not all([username, score, game_id]):
        return APIResponse.HTTP_400_BAD_REQUEST(
            message="Missing required fields: 'username', 'score', or 'game_id'."
        )

    try:
        # Add or update the user score
        admin_panel = AdminGamePanel()
        result = async_to_sync(admin_panel.redeem_user_score)(
            username=username,
            score=int(score),
            game_id=game_id
        )

        # Handle response based on result
        player_data = result.get("player")
        if player_data is None:
            return APIResponse.HTTP_400_BAD_REQUEST(message=result["message"])

        return APIResponse.HTTP_200_OK(message=result["message"], data=player_data)

    except Exception as e:
        logging.error(f"Error in redeem_score_from_game API: {str(e)}")
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_all_games_accounts(request):
    """
    API endpoint to fetch all game accounts, excluding players with no creator.

    Returns:
        JsonResponse: List of game accounts with their details.
    """
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")
    print(f"user_instance: {user_instance}")
    # Allowed roles
    allowed_roles = ["Admin","Agent","User"]
    print(f"user_instance.role_id: {user_instance.id}")
    current_user = User.objects.get(user_id=user_instance.id)
    # Validate the user's role
    user_role = getattr(current_user.role_id, "roles", None)
    if user_role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{user_role}' is not authorized.")
    print(f"Authenticated user's role: {user_role}")
    try:
        # Initialize admin panel and fetch data
        admin_panel = AdminGamePanel()
        result = async_to_sync(admin_panel.get_all_games_accounts)()

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
    user_instance = AuthService.get_user_from_token(request)
    user = AuthService.validate_user_role(user_instance, "Admin")

    # Get page, page_size, and search query from request query params
    page = int(request.query_params.get('page', 1))
    page_size = int(request.query_params.get('page_size', 10))
    search = request.query_params.get('search', '').strip().lower()

    try:
        # Fetch all players asynchronously
        admin_panel = AdminGamePanel()
        players = async_to_sync(admin_panel.get_all_my_created_players)(user.id)

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
        except InvalidPage:
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

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_all_my_created_games_by_admin(request):
    """
    API to retrieve all players created by a specific user with the Admin role,
    including search and pagination functionality.
    """
    user_instance = AuthService.get_user_from_token(request)
    user = AuthService.validate_user_role(user_instance, "Admin")

    # Get page, page_size, and search query from request query params
    page = int(request.query_params.get('page', 1))
    page_size = int(request.query_params.get('page_size', 10))
    search = request.query_params.get('search', '').strip().lower()

    try:
        # Fetch all players asynchronously
        admin_panel = AdminGamePanel()
        games = async_to_sync(admin_panel.get_all_my_created_games)(user.id)


        if games is None:  # Check if the list is empty or None
            return APIResponse.HTTP_404_NOT_FOUND(message="No games found.")

        # Apply search filter if the search parameter is provided
        if search:
            games = [
                game for game in games
                if search in game.get('game_name', '').lower() or
                   search in game.get('game_id', {}).lower() or
                   search in game.get('game_price', {}).lower()
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
            "games": paginated_games.object_list,  # Use object_list for the paginated games
            "pagination": {
                "current_page": paginated_games.number,
                "total_pages": paginator.num_pages,
                "page_size": page_size,
                "has_next": paginated_games.has_next(),
                "has_previous": paginated_games.has_previous(),
                "next_page": paginated_games.next_page_number() if paginated_games.has_next() else None,
                "previous_page": paginated_games.previous_page_number() if paginated_games.has_previous() else None,
                "pages": list(range(1, paginator.num_pages + 1)),  # Create list of page numbers
            },
        }

        return APIResponse.HTTP_200_OK(message=f"Games retrieved successfully for '{user.user_id.username}'.", data=response_data)

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
        print(f"user_instance: {user_instance}")

        # Allowed roles
        allowed_roles = ["Admin", "Agent", "User"]

        print(f"user_instance.role_id: {user_instance.id}")
        current_user = User.objects.get(user_id=user_instance.id)

        # Validate the user's role
        user_role = getattr(current_user.role_id, "roles", None)
        if user_role not in allowed_roles:
            return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{user_role}' is not authorized.")
        print(f"Authenticated user's role: {user_role}")

        ##
        if not username:
            data =  {
                "username": username,
                "datetime": datetime.now(tz=UTC).__str__(),
            }
            return APIResponse.HTTP_400_BAD_REQUEST(message="Missing required fields: 'username'.", data=data)

        # Fetch data from AdminGamePanel
        admin_panel = AdminGamePanel()
        data = admin_panel.get_player_score(username=username)

        if not data:
            data =  {
                "username": username,
                "datetime": datetime.now(tz=UTC).__str__(),
            }
            return APIResponse.HTTP_422_UNPROCESSABLE_ENTITY(message="Unable to find user. Please create user first.",data=data)

        else:
            if data.get("errors"):
                return APIResponse.HTTP_400_BAD_REQUEST(message=data.get("errors"), data={
                    "username": username,
                    "datetime": datetime.now(tz=UTC).__str__(),
                })

            data= {
                "username": username,
                "score": data.get("score"),
                "datetime": datetime.now(tz=UTC).__str__(),
            }
            return APIResponse.HTTP_200_OK(message="Score successfully fetch from the game.", data=data)

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
    print(f"user_instance: {user_instance}")
    # Allowed roles
    allowed_roles = ["Admin"]
    print(f"user_instance.role_id: {user_instance.id}")
    current_user = User.objects.get(user_id=user_instance.id)
    # Validate the user's role
    user_role = getattr(current_user.role_id, "roles", None)
    if user_role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{user_role}' is not authorized.")
    print(f"Authenticated user's role: {user_role}")
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
    auth_user = AuthService.validate_user_role(user_instance, "Admin")

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
    auth_user = AuthService.validate_user_role(user_instance, "Admin")

    game_id = request.data.get('game_id')
    game = Game.objects.filter(game_id=game_id).first()

    if game is None:
        return APIResponse.HTTP_404_NOT_FOUND(message=f"Please provide correct game id or Game not found. Try again to provide correct game id.")

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
    auth_user = AuthService.validate_user_role(user_instance, "Admin")

    game_id = request.data.get('game_id')
    game = Game.objects.filter(game_id=game_id).first()

    if game is None:
        return APIResponse.HTTP_404_NOT_FOUND(message=f"Please provide correct game id or Game not found. Try again to provide correct game id.")

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
    auth_user = AuthService.validate_user_role(user_instance, "Admin")

    game_id = request.data.get('game_id')
    game = models.Game.objects.filter(game_id=game_id).first()

    if game is None:
        return APIResponse.HTTP_404_NOT_FOUND(message=f"Please provide correct game id or Game not found. Try again to provide correct game id.")

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
            "upcoming_status": game.upcoming_status,
        }

        upcoming_status = "is set to upcoming status" if game.upcoming_status else "is not set to upcoming status"

        return APIResponse.HTTP_200_OK(message=f"Game '{game.game_name}' {upcoming_status} successfully.", data=data)
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
    auth_user = AuthService.validate_user_role(user_instance, "Admin")

    game_id = request.data.get('game_id')
    game = models.Game.objects.filter(game_id=game_id).first()

    if game is None:
        return APIResponse.HTTP_404_NOT_FOUND(message=f"Please provide correct game id or Game not found. Try again to provide correct game id.")

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
            "is_trending": game.is_trending,
        }

        is_trending = "is set to trending status" if game.is_trending else "is not set to trending status"

        return APIResponse.HTTP_200_OK(message=f"Game '{game.game_name}' {is_trending} successfully.", data=data)
    except Game.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message=f"Game not found.")
    except Exception as e:
        logging.error(f"Error: {str(e)}")
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_player(request):
    ##
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    AuthService.validate_user_role(user_instance, "Admin")

    player_username = request.data.get('player_username')
    player = Player.objects.get(username=player_username)

    try:
        player.delete()

        data = {
            "player_id": str(player.id),
            "username": player.username,
            "nick_name": player.nick_name,
            "score": player.score,
            "is_banned": player.is_banned,
            "status": player.status,
        }

        return APIResponse.HTTP_200_OK(message=f"Player '{player.username}' deleted successfully.", data=data)
    except Player.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message=f"Player {player_username} not found.")
    except Exception as e:
        logging.error(f"Error: {str(e)}")
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")

# @api_view(['DELETE'])
# @permission_classes([IsAuthenticated])
# def delete_game(request):
#     ##
#     # Authenticate and fetch the user
#     user_instance = AuthService.get_user_from_token(request)
#     auth_user = AuthService.validate_user_role(user_instance, "Admin")
#
#     game_id = request.data.get('game_id')
#     game = models.Game.objects.filter(game_id=game_id, created_by_user_id=auth_user.id).first()
#
#     print(f"game delete: {game}")
#
#     if game is None:
#         return APIResponse.HTTP_404_NOT_FOUND(message=f"Please provide correct game id or Game not found. Try again to provide correct game id.")
#
#     try:
#         game.delete()
#
#         data = {
#             "game_id": str(game.id),
#             "game_name": game.game_name,
#             "game_description": game.game_description,
#             "game_image": game.game_image.url if game.game_image else "N/A",
#             "game_video": game.game_video.url if game.game_video else "N/A",
#             "game_price": game.game_price,
#             "is_active": game.is_active,
#         }
#
#         return APIResponse.HTTP_200_OK(message=f"Game '{game.game_name}' deleted successfully.", data=data)
#     except Game.DoesNotExist:
#         return APIResponse.HTTP_404_NOT_FOUND(message=f"Game not found.")
#     except Exception as e:
#         logging.error(f"Error: {str(e)}")
#         return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


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
    user_role = getattr(current_user.role_id, "roles", None)
    if user_role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{user_role}' is not authorized.")

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
    upcoming_status = request.data.get('upcoming_status')
    is_trending = request.data.get('is_trending')
    score = request.data.get('score')
    transfer_score_percentage = request.data.get('transfer_score_percentage')
    redeem_score_percentage = request.data.get('redeem_score_percentage')
    is_free = request.data.get('is_free')

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
        game.upcoming_status = upcoming_status
        game.is_trending = is_trending
        game.score = score
        game.transfer_score_percentage = transfer_score_percentage
        game.redeem_score_percentage = redeem_score_percentage
        game.is_free = is_free

        game.save()

        # Prepare the response data
        data = {
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
            "is_trending": game.is_trending,
            "score": game.score,
            "transfer_score_percentage": game.transfer_score_percentage,
            "redeem_score_percentage": game.redeem_score_percentage,
            "is_free": game.is_free,
        }

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
def all_agent_user_chats(request):
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    try:
        current_user = User.objects.get(user_id=user_instance.id)
    except ObjectDoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")

    # Validate the user's role
    allowed_roles = ["Admin"]
    user_role = getattr(current_user.role_id, "roles", None)
    if user_role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{user_role}' is not authorized.")

    # Fetch all records from AgentChat in descending order of agent_chat_created_at
    all_chats = AgentChat.objects.all().order_by('-agent_chat_created_at')

    if not all_chats.exists():
        return APIResponse.HTTP_404_NOT_FOUND(message="No agent user chats found.")

    try:
        # Construct the response data
        data = []
        for chat in all_chats:
            user_data = {
                "profile_image": chat.user_id.profile_image.url if chat.user_id and chat.user_id.profile_image else None,
                "email": chat.user_id.email if chat.user_id else None,
                "user_reply_messages": {
                    "profile_image": chat.user_id.profile_image.url if chat.user_id and chat.user_id.profile_image else None,
                    "email": chat.user_id.email if chat.user_id else None,
                    "message_content": chat.message_content,
                    "message_time": chat.agent_chat_created_at.isoformat(),
                },
            }

            agent_data = {
                "profile_image": chat.agent_id.profile_image.url if chat.agent_id and chat.agent_id.profile_image else None,
                "email": chat.agent_id.email if chat.agent_id else None,
                "message_content": chat.message_content,
            }

            data.append({
                "agent_messages": {
                    **agent_data,
                    "user_messages": user_data,
                }
            })

        # Return the successful response
        return APIResponse.HTTP_200_OK(
            message="All agent user chats fetched successfully.",
            data=data
        )
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")



## Admin Game Panel Management System

############################################################################################################

## Spin Wheel Management System
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_spin_wheel(request):
    ##
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")
    print(f"user_instance: {user_instance}")
    # Allowed roles
    allowed_roles = ["Admin"]
    print(f"user_instance.role_id: {user_instance.id}")
    current_user = User.objects.get(user_id=user_instance.id)

    # Validate the user's role
    user_role = getattr(current_user.role_id, "roles", None)
    if user_role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{user_role}' is not authorized.")
    print(f"Authenticated user's role: {user_role}")
    ##
    try:
        # Fetch all records from Spin, Prize, and SpinHistory
        spins = Spin.objects.all()

        # Check if no spins exist
        if not spins:
            return APIResponse.HTTP_404_NOT_FOUND(message="Spin wheel not found.")

        # Prepare the data for each spin
        data = []
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

        # Respond with data
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
    ##
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")
    print(f"user_instance: {user_instance}")
    # Allowed roles
    allowed_roles = ["Admin"]
    print(f"user_instance.role_id: {user_instance.id}")
    current_user = models.User.objects.get(user_id=user_instance.id)

    # Validate the user's role
    user_role = getattr(current_user.role_id, "roles", None)
    if user_role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{user_role}' is not authorized.")
    print(f"Authenticated user's role: {user_role}")
    ##
    try:
        # Fetch all records from SpinHistory
        spins_history = models.SpinHistory.objects.all()

        # Check if no spin history records exist
        if not spins_history:
            return APIResponse.HTTP_404_NOT_FOUND(message="Spin history not found.")

        # Prepare the data for each spin history
        data = []
        for spin in spins_history:
            spin_data = {
                "id": str(spin.id),
                "prize": {  # prize is a ForeignKey, so access it directly
                    "prize_id": spin.prize_id.prize_id,  # Accessing prize_id from related Prize model
                    "name": spin.prize_id.name,
                    "quantity": spin.prize_id.quantity,
                    "image": spin.prize_id.image.url if spin.prize_id.image else None,
                    "probability": spin.prize_id.probability,
                    "is_active": spin.prize_id.is_active
                },
                "created_at": spin.created_at  # Include the creation timestamp
            }
            data.append(spin_data)

        # Respond with data
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
    ##
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")
    print(f"user_instance: {user_instance}")
    # Allowed roles
    allowed_roles = ["Admin","Agent"]
    print(f"user_instance.role_id: {user_instance.id}")
    current_user = User.objects.get(user_id=user_instance.id)

    # Validate the user's role
    user_role = getattr(current_user.role_id, "roles", None)
    if user_role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{user_role}' is not authorized.")
    print(f"Authenticated user's role: {user_role}")
    ##

    try:
        # Get prizes, limited to 10 items
        prizes = Prize.objects.all()[:10]

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
    ##
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")
    print(f"user_instance: {user_instance}")
    # Allowed roles
    allowed_roles = ["Admin", "Agent"]
    print(f"user_instance.role_id: {user_instance.id}")
    current_user = User.objects.get(user_id=user_instance.id)

    # Validate the user's role
    user_role = getattr(current_user.role_id, "roles", None)
    if user_role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{user_role}' is not authorized.")
    print(f"Authenticated user's role: {user_role}")
    ##
    try:
        prize_id = request.data.get('prize_id')

        # Fetch the prize by ID
        prize = Prize.objects.filter(id=prize_id).first()

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
    print(f"user_instance: {user_instance}")
    # Allowed roles
    allowed_roles = ["Admin", "Agent"]
    print(f"user_instance.role_id: {user_instance.id}")
    current_user = User.objects.get(user_id=user_instance.id)

    # Validate the user's role
    user_role = getattr(current_user.role_id, "roles", None)
    if user_role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{user_role}' is not authorized.")
    print(f"Authenticated user's role: {user_role}")
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
            return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid data", errors=form.errors)

    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def get_prize_by_id(request):
    ##
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")
    print(f"user_instance: {user_instance}")
    # Allowed roles
    allowed_roles = ["Admin", "Agent"]
    print(f"user_instance.role_id: {user_instance.id}")
    current_user = User.objects.get(user_id=user_instance.id)

    # Validate the user's role
    user_role = getattr(current_user.role_id, "roles", None)
    if user_role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{user_role}' is not authorized.")
    print(f"Authenticated user's role: {user_role}")
    ##
    try:
        prize_id = request.data.get('prize_id')

        # Fetch the prize by ID
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
    ##
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid or missing authentication token.")

    # Allowed roles
    allowed_roles = ["Admin", "Agent"]
    current_user = User.objects.get(user_id=user_instance.id)

    # Validate the user's role
    user_role = getattr(current_user.role_id, "roles", None)
    if user_role not in allowed_roles:
        return APIResponse.HTTP_403_FORBIDDEN(message=f"User role '{user_role}' is not authorized.")
    ##

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


# Prize Management URLs

############################################################################################################

# Promo Code Management System

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_promo_codes(request):
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    user = AuthService.validate_user_role(user_instance, "User")

    limit = int(request.GET.get('limit', 10))

    # Fetch promo codes with or without a receiver, limited by the provided limit
    promos = PromoCode.objects.filter(sender_user_id=user.id).all().order_by('-promo_code_created_at')[:limit]

    if not promos.exists():
        return APIResponse.HTTP_404_NOT_FOUND(message="No promo codes found.")

    try:

        data = []
        for promo in promos:
            # Get receiver user details if available
            receiver_obj = promo.receiver_user_id
            sender_obj = promo.sender_user_id

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
                        "profile_image": receiver_obj.profile_image.url if receiver_obj and receiver_obj.profile_image else None,
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
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    user = AuthService.validate_user_role(user_instance, "User")

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
                    "profile_image": promo.sender_user_id.profile_image.url if promo.sender_user_id.profile_image else None,
                } if promo.sender_user_id else None,
                "receiver": {
                    "id": str(promo.receiver_user_id.id) if promo.receiver_user_id else None,
                    "username": promo.receiver_user_id.user_id.username if promo.receiver_user_id else None,
                    "first_name": promo.receiver_user_id.first_name if promo.receiver_user_id else None,
                    "last_name": promo.receiver_user_id.last_name if promo.receiver_user_id else None,
                    "email": promo.receiver_user_id.email if promo.receiver_user_id else None,
                    "phone_number": promo.receiver_user_id.phone if promo.receiver_user_id else None,
                    "profile_image": promo.receiver_user_id.profile_image.url if promo.receiver_user_id and promo.receiver_user_id.profile_image else None,
                    } if promo.receiver_user_id else None
            }
        }
        return APIResponse.HTTP_200_OK(message="Promo code retrieved successfully.", data=data)

    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_promo_code(request):
    ##
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    auth_user = AuthService.validate_user_role(user_instance, "User")

    form = PromoCodeForm(request.data)
    if not form.is_valid():
        return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid data", data=form.errors)

    # Check if the sender already has a promo code
    if PromoCode.objects.filter(sender_user_id=auth_user.id).exists():
        return APIResponse.HTTP_400_BAD_REQUEST(message="User already has a promo code.")

    try:
        if form.is_valid():
            uuid_gen = str(uuid.uuid4().hex).upper()
            promo = form.save(commit=False)
            promo.promo_code = uuid_gen
            promo.sender_user_id = auth_user  # Assign the sender to the promo code
            promo.save()

            # Generate a verification link
            verification_url = f"http://127.0.0.1:8000/api/v1/promo-code/verify-promo-code/?promo_code={promo.promo_code}"

            # Generate QR code for the verification link
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(verification_url)
            qr.make(fit=True)

            # Render the QR code as an image
            qr_image = qr.make_image(fill_color="black", back_color="white")

            # Ensure the directory exists in the media root
            qr_folder = os.path.join(settings.MEDIA_ROOT, 'qrcode')
            os.makedirs(qr_folder, exist_ok=True)

            # Save the QR code to the 'qrcode' directory
            qr_file_path = os.path.join(qr_folder, f"qr_{promo.promo_code}.png")
            qr_image.save(qr_file_path)

            # Generate the QR code URL
            qr_code_url = f"{settings.MEDIA_URL}qrcode/qr_{promo.promo_code}.png"

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
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    auth_user = AuthService.validate_user_role(user_instance, "User")   # receiver user

    # Retrieve promo_code from query parameters or request body
    promo_code = request.query_params.get('promo_code') or request.data.get('promo_code')

    # Fetch the promo code from the PromoCode model
    promo = PromoCode.objects.filter(promo_code=promo_code).first()

    if not promo:
        return APIResponse.HTTP_404_NOT_FOUND(message="Promo code not found.")

    if not promo.is_expired:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Promo code has expired.")

    # Check that sender and receiver are not the same
    if auth_user.id == promo.sender_user_id.id:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Sender and receiver cannot be the same.")

    # Check if the promo code already has a receiver (it should not)
    if promo.receiver_user_id:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Promo code has already been used.")

    try:

        # Assign the receiver user to the promo code and mark it as expired
        promo.receiver_user_id = auth_user
        promo.is_expired = True
        promo.save()

        # Prepare response data
        data = {
            "id": str(promo.id),
            "promo_code": promo.promo_code,
            "bonus_percentage": promo.bonus_percentage,
            "promo_code_created_at": promo.promo_code_created_at,
            "users": {
                "creator": promo.sender_user_id.user_id.username,
                "receiver": auth_user.user_id.username
            }
        }

        return APIResponse.HTTP_200_OK(message=f"Promo code verified successfully by {auth_user.user_id.username}.", data=data)

    except User.DoesNotExist:
        return APIResponse.HTTP_404_NOT_FOUND(message="Sender or receiver user not found.")
    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_promo_code(request):
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    user = AuthService.validate_user_role(user_instance, "User")

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

        return APIResponse.HTTP_200_OK(message=f"Promo code deleted successfully by {user.user_id.username}.", data=data)

    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An unexpected error occurred: {str(e)}")

@api_view(['PUT'])
def update_promo_code(request):
    try:
        promo_id = request.data.get('promo_id')

        promo = get_object_or_404(PromoCode, id=promo_id)
        form = PromoCodeForm(request.data, instance=promo)
        if form.is_valid():
            updated_promo = form.save()
            return APIResponse.HTTP_200_OK(
                message="Promo code updated successfully.", data=model_to_dict(updated_promo)
            )
        else:
            return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid data", data=form.errors)

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
        This function generates a unique Spin key for the user and returns it.
        it takes the user token as input and returns the referral key.
    Args:
        request:
            request object containing the user token.
    Returns:
        1.
            {
                "status": 200,
                "message": "Referralkey has been generated successfully.",
                "data": {
                    "referral_key": "33CCF33FC29343D9A61FEFEE1904292F",
                    "created_by": "AmmarHussain",
                    "quantity": 95
                }
            }
        2.
            {
                "status": 400,
                "message": "Use token to authenticate."
            }
        3.
            {
                "status": 401,
                "message": "Invalid token."
            }


    """
    user_instance = AuthService.get_user_from_token(request)          # Authenticate and fetch the user
    # ------------------------------------------ Validating Parameters -----------------
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Use token to authenticate.")
    user = AuthService.validate_user_role(user_instance, "User")
    if not user:
         return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid token.")
    referral_key = str(uuid.uuid4().hex).upper()                      # Generate a unique Referral key
    random_quantity_between_80_100 = random.randint(80, 100)
    # ----------------------------------------------- Validating Completed   -----------
    referral = models.Referral.objects.create(
         user_id=user,
         quantity=int(random_quantity_between_80_100),
         referral_key=referral_key
     )
    data = {
        "referral_key":referral.referral_key,
        "created_by":referral.user_id.user_id.username,
        "quantity":referral.quantity
    }
    return APIResponse.HTTP_200_OK(message="Referral key has been generated successfully.", data=data)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def get_referral_codes(request):
    """
        This function returns all the referral codes of the user.
        it takes the user token as input and returns the referral codes.
        Args:
            request:
                request object containing the user token.
        Returns:
            1.
                {
                    "status": 200,
                    "message": "Referral code retrieved successfully.",
                    "data": {
                        "id": "645e55c2-ee73-41aa-9029-4318c5ad7737",
                        "user_id": "9b03dcbb-e3a3-454f-93b6-15096801bb56",
                        "quantity": 95,
                        "referral_key": "33CCF33FC29343D9A61FEFEE1904292F",
                        "referral_created_at": "2024-12-26T11:39:44.526562Z",
                        "referral_expires_in": "2025-02-24",
                        "users": {
                            "sender": [
                                {
                                    "id": "9b03dcbb-e3a3-454f-93b6-15096801bb56",
                                    "username": "AmmarHussain",
                                    "email": "amaar@gmail.com"
                                },
                                {
                                    "id": "9b03dcbb-e3a3-454f-93b6-15096801bb56",
                                    "username": "AmmarHussain",
                                    "email": "amaar@gmail.com"
                                }
                            ],
                            "receivers": []
                        }
                    }
                }
            2.
                {
                    "status": 400,
                    "message": "Use token to authenticate."
                }
            3.
                {
                    "status": 401,
                    "message": "Invalid token."
                }
            4.
                {
                    "status": 404,
                    "message": "User not found."
                }
            5.
                {
                    "status": 404,
                    "message": "Referral code not found."

    """
    #                                                               # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    # --------------------------------------------------- Validating Parameters ---------------------------
    if not user_instance:                                           # print(f"user_instance: {user_instance}")
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Use token to authenticate.")
    user = AuthService.validate_user_role(user_instance, "User")     # Validate user'sRole
    if not user:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid token.")
    sender_id = user.id
    user = models.User.objects.filter(id=sender_id).first()
    if not user:
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
    ref =  models.Referral.objects.filter(user_id=user).first()
    if not ref:
        return APIResponse.HTTP_404_NOT_FOUND(message="Referral code not found.")
    # --------------------------------------------------- Validating Completed -------------------------
    data = {
        "id": ref.id,
        "user_id": ref.user_id.id,
        "quantity": ref.quantity,
        "referral_key": ref.referral_key,
        "referral_created_at": ref.referral_created_at,
        "referral_expires_in": (ref.referral_created_at + timedelta(days=60)).strftime("%Y-%m-%d"),
        "users": {
            "sender": [
                {
                    "id": ref.user_id.id,
                    "username": ref.user_id.user_id.username,
                    "email": ref.user_id.email,
                } for ref in models.Referral.objects.filter(user_id=user)
            ],
            "receivers": [
                {
                    "id": ref.receiver_user_id.id,
                    "username": ref.receiver_user_id.user_id.username,
                    "email": ref.receiver_user_id.email,
                } for ref in models.Referral.objects.filter(receiver_user_id=user)
            ]
        },
    }
    return APIResponse.HTTP_200_OK(message="Referral code retrieved successfully.", data=data)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def verify_referral_code(request):
    """
        This function verifies a referral code for a user. It checks if the provided referral
        key is valid, ensures the receiver and sender are different, and processes the
        associated rewards for both parties.

        Args:
            request:
                request object containing the referral key and user token.

        Returns:
            1.
                {
                    "status": 200,
                    "message": "Referral key verified and amounts added to wallets.",
                    "data": {
                        "id": "645e55c2-ee73-41aa-9029-4318c5ad7737",
                        "sender_user": {
                            "id": "9b03dcbb-e3a3-454f-93b6-15096801bb56",
                            "username": "AmmarHussain",
                            "email": "amaar@gmail.com",
                            "amount_added": "20.00"
                        },
                        "quantity": 100,
                        "referral_key": "33CCF33FC29343D9A61FEFEE1904292F",
                        "receiver_user": {
                            "id": "9b03dcbb-e3a3-454f-93b6-15096801bb56",
                            "username": "JohnDoe",
                            "email": "john@example.com",
                            "amount_added": "80.00"
                        },
                        "referral_created_at": "2024-12-26T11:39:44.526562Z",
                        "referral_expiry_date": "2025-02-24"
                    }
                }
            2.
                {
                    "status": 400,
                    "message": "Referral key is required."
                }
            3.
                {
                    "status": 400,
                    "message": "Sender and receiver cannot be the same."
                }
            4.
                {
                    "status": 400,
                    "message": "User has already used this Referral key."
                }
            5.
                {
                    "status": 400,
                    "message": "Receiver user does not have a wallet."
                }
            6.
                {
                    "status": 400,
                    "message": "Sender user does not have a wallet."
                }
            7.
                {
                    "status": 401,
                    "message": "Use token to authenticate."
                }
            8.
                {
                    "status": 401,
                    "message": "Invalid token."
                }
            9.
                {
                    "status": 404,
                    "message": "Referral key not found."
                }
            10.
                {
                    "status": 404,
                    "message": "User not found."
                }
    """
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    # ------------------------------------------ Validating Parameters ---------------------------
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Use token to authenticate.")
    receiver_user = AuthService.validate_user_role(user_instance, "User")
    if not receiver_user:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid token.")
    referral_key = request.data.get('referral_key')
    if not referral_key:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Referral key is required.")
    ref =models.Referral.objects.filter(referral_key=referral_key).first()
    if not ref:
        return APIResponse.HTTP_404_NOT_FOUND(message="Referral key not found.")
    user = models.User.objects.filter(id=receiver_user.id).first()
    if not user:                                              # print(f"user 2:> {user}")
        return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
    if ref.user_id.id == user.id:                            # Ensure sender and receiver are not the same
        return APIResponse.HTTP_400_BAD_REQUEST(message="Sender and receiver cannot be the same.")
    if ref.receiver_user_id.filter(id=receiver_user.id).exists(): # if the receiver has already used this Referral key
        return APIResponse.HTTP_400_BAD_REQUEST(message="User has already used this Referral key.")
    # ---------------------------------------------- Validating Completed ---------------------------
    ref.receiver_user_id.add(receiver_user)
    ref.save()
    total_quantity = ref.quantity                              # Assume this is 100 for example
    receiver_amount = total_quantity * Decimal('0.8')          # 80%
    sender_amount = total_quantity * Decimal('0.2')            # 20%
    if hasattr(receiver_user, 'wallet_id'):
        receiver_wallet = receiver_user.wallet_id
        receiver_wallet.current_balance += receiver_amount
        receiver_wallet.total_amount += receiver_amount
        receiver_wallet.save()
    else:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Receiver user does not have a wallet.")
    sender_user = ref.user_id                                   # Update the sender's wallet
    if hasattr(sender_user, 'wallet_id'):
        sender_wallet = sender_user.wallet_id
        sender_wallet.current_balance += sender_amount
        sender_wallet.total_amount += sender_amount
        sender_wallet.save()
    else:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Sender user does not have a wallet.")
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




@api_view(['POST'])
@permission_classes([IsAuthenticated])
def verify_referral_key_by_link(request):
    """
        This function verifies a referral key provided via a link for a user. It checks if the
        referral key is valid, ensures the sender and receiver are not the same, and processes
        the associated rewards for both parties.

        Args:
            request:
                request object containing the referral key as a query parameter and user token.

        Returns:
            1.
                {
                    "status": 200,
                    "message": "Referral key verified and amounts added to wallets.",
                    "data": {
                        "id": "645e55c2-ee73-41aa-9029-4318c5ad7737",
                        "sender_user": {
                            "id": "9b03dcbb-e3a3-454f-93b6-15096801bb56",
                            "username": "AmmarHussain",
                            "email": "amaar@gmail.com",
                            "amount_added": "20.00"
                        },
                        "quantity": 100,
                        "referral_key": "33CCF33FC29343D9A61FEFEE1904292F",
                        "receiver_user": {
                            "id": "9b03dcbb-e3a3-454f-93b6-15096801bb56",
                            "username": "JohnDoe",
                            "email": "john@example.com",
                            "amount_added": "80.00"
                        },
                        "referral_created_at": "2024-12-26T11:39:44.526562Z",
                        "referral_expiry_date": "2025-02-24"
                    }
                }
            2.
                {
                    "status": 400,
                    "message": "Referral key is required."
                }
            3.
                {
                    "status": 400,
                    "message": "Sender and receiver cannot be the same."
                }
            4.
                {
                    "status": 400,
                    "message": "User has already used this referral key."
                }
            5.
                {
                    "status": 400,
                    "message": "Receiver user does not have a wallet."
                }
            6.
                {
                    "status": 400,
                    "message": "Sender user does not have a wallet."
                }
            7.
                {
                    "status": 401,
                    "message": "Use token to authenticate."
                }
            8.
                {
                    "status": 401,
                    "message": "Invalid token."
                }
            9.
                {
                    "status": 404,
                    "message": "Referral key not found."
                }
            10.
                {
                    "status": 500,
                    "message": "An error occurred: <error_details>"
                }
    """
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    receiver_user = AuthService.validate_user_role(user_instance, "User")
    referral_key = request.query_params.get('referral_key')
    if not referral_key:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Referral key is required.")
    ref = models.Referral.objects.filter(referral_key=referral_key).first()
    if not ref:
        return APIResponse.HTTP_404_NOT_FOUND(message="Referral key not found.")
    user = models.User.objects.filter(id=receiver_user.id).first()
    if ref.user_id.id == user.id:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Sender and receiver cannot be the same.")
    if ref.receiver_user_id.filter(id=receiver_user.id).exists():
        return APIResponse.HTTP_400_BAD_REQUEST(message="User has already used this referral key.")

    ref.receiver_user_id.add(receiver_user)
    ref.save()
    total_quantity = ref.quantity
    receiver_amount = total_quantity * Decimal('0.8')
    sender_amount = total_quantity * Decimal('0.2')
    if hasattr(receiver_user, 'wallet_id'):
        receiver_wallet = receiver_user.wallet_id
        receiver_wallet.current_balance += receiver_amount
        receiver_wallet.total_amount += receiver_amount
        receiver_wallet.save()
    else:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Receiver user does not have a wallet.")
    sender_user = ref.user_id
    if hasattr(sender_user, 'wallet_id'):
        sender_wallet = sender_user.wallet_id
        sender_wallet.current_balance += sender_amount
        sender_wallet.total_amount += sender_amount
        sender_wallet.save()
    else:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Sender user does not have a wallet.")
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
    Delete all referrals associated with the authenticated user.

    Args:
        request: The HTTP request object containing the user token.

    Returns:
        - 200 OK: Returns the count and details of deleted referrals.
        - 404 NOT FOUND: If no referrals are found for the user.
        - 401 UNAUTHORIZED: If the user token is invalid or missing.
        - 404 NOT FOUND: If no referrals are found to delete.
    """
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Use token to authenticate.")
    sender_user = AuthService.validate_user_role(user_instance, "User")
    if not sender_user:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid token.")
    user_id = sender_user.id
    all_referrals = models.Referral.objects.filter(user_id=user_id).all()
    total_referrals = all_referrals.count()
    if total_referrals == 0:
        return APIResponse.HTTP_404_NOT_FOUND(message="No referrals found to delete.")
    data = [
        {
            "user": {
                "id": str(ref.user_id.id),
                "username": ref.user_id.user_id.username,
                "first_name": ref.user_id.first_name,
                "last_name": ref.user_id.last_name,
                "email": ref.user_id.email,
                "referrals": [
                    {
                        "id": str(ref.id),
                        "referral_key": ref.referral_key,
                        "quantity": ref.quantity,
                        "referral_created_at": ref.referral_created_at.strftime('%Y-%m-%d %H:%M:%S'),
                    }
                ]
            }
        }
        for ref in all_referrals
    ]
    all_referrals.delete()
    return APIResponse.HTTP_200_OK(
        message=f"All {total_referrals} referrals have been deleted successfully.",
        data=data
    )

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_referral_by_key(request):
    """
    This function is used to delete a referral record based on the referral key. Provide the token of the logged-in user.

    Args:
        request: The HTTP request object containing the user token and referral key.

    Returns:
        1.
            {
                "status": 200,
                "message": "Referral with key 'some_referral_key' has been deleted successfully.",
                "data": {
                    "sender_user_id": {
                        "id": "e974d9ee-8f41-4f24-ab9f-c76707e38236",
                        "username": "Irshad",
                        "first_name": "Irshad",
                        "last_name": "Hussain",
                        "email": "irshad@gmail.com"
                    },
                    "receiver_user_id": [
                        {
                            "id": "a5c2d1f5-1234-5678-9abc-def012345678",
                            "username": "JohnDoe",
                            "email": "john.doe@example.com"
                        }
                    ],
                    "referral": {
                        "id": "49d07b88-7f67-4fdc-9238-30fc3d1689e2",
                        "referral_key": "some_referral_key",
                        "quantity": 5,
                        "referral_created_at": "2024-12-27 10:44:41"
                    }
                }
            }
        2.
            {
                "status": 401,
                "message": "Use token to authenticate."
            }
        3.
            {
                "status": 401,
                "message": "Invalid token."
            }
        4.
            {
                "status": 400,
                "message": "Referral key is required."
            }
        5.
            {
                "status": 404,
                "message": "No referral found with key 'some_referral_key'."
            }
    """
    user_instance = AuthService.get_user_from_token(request)  # Authenticate and fetch the user
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Use token to authenticate.")
    sender_user = AuthService.validate_user_role(user_instance, "User")
    if not sender_user:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid token.")
    referral_key = request.data.get('referral_key')  # Get referral key from request
    if not referral_key:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Referral key is required.")
    referral = models.Referral.objects.filter(referral_key=referral_key, user_id=sender_user.id).first()
    if not referral:
        return APIResponse.HTTP_404_NOT_FOUND(message=f"No referral found with key '{referral_key}'.")
    user = referral.user_id  # Extract sender user details
    data = {
        "sender_user_id": {
            "id": str(user.id),
            "username": user.user_id.username,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "email": user.email,
        },
        "receiver_user_id": [
            {
                "id": receiver.id,
                "username": receiver.user_id.username,
                "email": receiver.email,
            }
            for receiver in referral.receiver_user_id.all()
        ],
        "referral": {
            "id": str(referral.id),
            "referral_key": referral.referral_key,
            "quantity": referral.quantity,
            "referral_created_at": referral.referral_created_at.strftime('%Y-%m-%d %H:%M:%S'),
        },
    }
    referral.delete()  # Delete the referral
    return APIResponse.HTTP_200_OK(
        message=f"Referral with key '{referral_key}' has been deleted successfully.",
        data=data
    )

# Referral Management System
############################################################################################################

# Wallet Management System

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_account_wallet(request):
    """
        Retrieve the details of the user's wallet.

    Args:
        request: The HTTP request object containing the user token.
    Payload:
            {
                "username": "AmmarHussain"
            }
    Returns:
        - 200 OK:
            {
                "status": 200,
                "message": "Wallet retrieved successfully.",
                "data": {
                    "wallet_id": "123e4567-e89b-12d3-a456-426614174000",
                    "current_balance": 500.00,
                    "last_transaction_date": "2024-12-26 11:45:00",
                    "withdrawal_percentage_tax": 5.0,
                    "order_id": "ORD12345678"
                }
            }
        - 400 BAD REQUEST:
            {
                "status": 400,
                "message": "User ID or username is invalid."
            }
        - 404 NOT FOUND:
            {
                "status": 404,
                "message": "Wallet not found."
            }
        - 401 UNAUTHORIZED:
            {
                "status": 401,
                "message": "Use token to authenticate."
            }
        - 401 UNAUTHORIZED:
            {
                "status": 401,
                "message": "Invalid token."
            }
    """
    user_instance = AuthService.get_user_from_token(request)
    # -------------------------------------- Validate Parameters -----------------------------------
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Use token to authenticate.")
    auth_user = AuthService.validate_user_role(user_instance, "User")
    if not auth_user:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid token.")
    user_id = auth_user.id
    username = request.GET.get('username')    # get the username from the request
    user = models.User.objects.filter(id=user_id).first()
    if username:
        user_by_username = models.User.objects.filter(user_id__username=username).first()
        user = user or user_by_username
    if not user:
        return APIResponse.HTTP_400_BAD_REQUEST(message="User ID or username is invalid.")

    # Fetch the wallet details
    wallet = user.wallet_id
    if not wallet:
        return APIResponse.HTTP_404_NOT_FOUND(message="Wallet not found.")

    # Prepare response data
    data = {
        "wallet_id": str(wallet.id),
        "current_balance": wallet.current_balance,
        "total_balance": wallet.total_amount,
        "last_transaction_date": wallet.last_transaction_date.strftime(
            '%Y-%m-%d %H:%M:%S') if wallet.last_transaction_date else None,
        "withdrawal_percentage_tax": wallet.withdrawal_percentage_tax,
        "order_id": wallet.order_id,
    }

    return APIResponse.HTTP_200_OK(message="Wallet retrieved successfully.", data=data)


# @api_view(['GET'])
# @permission_classes([IsAuthenticated])
# def get_transaction_history(request):
#     """
#       This function is used to Retrieve the transaction history of the user's wallet. Provide the token
#       of login user and wallet ID and then fetch the transaction history of the wallet.
# 
#     Args:
#         request: The HTTP request object containing the user token and optional query parameter `limit`.
# 
#     Query Parameters:
#         - limit (int, optional): The maximum number of transactions to retrieve. Defaults to 10.
# 
#     Returns:
#         - 200 OK:
#             {
#                 "status": 200,
#                 "message": "Transaction history retrieved successfully.",
#                 "data": [
#                     {
#                         "wallet_id": "123e4567-e89b-12d3-a456-426614174000",
#                         "current_balance": 500.00,
#                         "total_amount": 1000.00,
#                         "last_transaction_date": "2024-12-26 11:45:00",
#                         "withdrawal_percentage_tax": 5.0,
#                         "order_id": "ORD12345678",
#                         "wallet_transaction_history": [
#                             {
#                                 "id": "456e7890-e89b-12d3-a456-426614174001",
#                                 "payment_method": "Credit Card",
#                                 "transaction_amount": 100.00,
#                                 "payment_status": "Completed",
#                                 "payment": "Ref12345",
#                                 "transaction_date": "2024-12-25 10:00:00"
#                             },
#                             ...
#                         ]
#                     }
#                 ]
#             }
#         - 400 BAD REQUEST:
#             {
#                 "status": 400,
#                 "message": "Wallet not found."
#             }
#         - 401 UNAUTHORIZED:
#             {
#                 "status": 401,
#                 "message": "Use token to authenticate."
#             }
#         - 401 UNAUTHORIZED:
#             {
#                 "status": 401,
#                 "message": "Invalid token."
#             }
#         - 404 NOT FOUND:
#             {
#                 "status": 404,
#                 "message": "Transaction history not found."
#             }
#     """
#     # Authenticate and validate the user
#     print(f"get transaction history request: {request.data}")
#     user_instance = AuthService.get_user_from_token(request)
#     # ----------------------------------------------- Validating Parameters ----------------------
#     if not user_instance:
#         return APIResponse.HTTP_401_UNAUTHORIZED(message="Use token to authenticate.")
#     auth_user = AuthService.validate_user_role(user_instance, "User")
#     if not auth_user:
#         return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid token.")
#     wallet = models.Wallet.objects.filter(id=auth_user.wallet_id.id).first()  # get the wallet of the user by token
#     if not wallet:
#         return APIResponse.HTTP_400_BAD_REQUEST(message="Wallet not found.")
#     limit = int(request.GET.get('limit', 10))  # get the limit from the request
#     transactions = wallet.wallet_transaction_history_id.all()[:limit]
#     if not transactions:
#         return APIResponse.HTTP_404_NOT_FOUND(message="Transaction history not found.")
# 
#     data = [
#         {
#             "wallet_id": str(wallet.id),
#             "current_balance": wallet.current_balance,
#             "total_amount": wallet.total_amount,
#             "last_transaction_date": wallet.last_transaction_date.strftime('%Y-%m-%d %H:%M:%S') if
#             wallet.last_transaction_date else None,
#             "withdrawal_percentage_tax": wallet.withdrawal_percentage_tax,
#             "order_id": wallet.order_id,
#             "wallet_transaction_history": [
#                 {
#                     "id": str(tx.id),
#                     "payment_method": tx.payment_method,
#                     "transaction_amount": tx.transaction_amount,
#                     "payment_status": tx.payment_status,
#                     "payment": tx.payment,
#                     "transaction_date": tx.transaction_date.strftime('%Y-%m-%d %H:%M:%S')
#                 } for tx in transactions
#             ]
#         }
#     ]
#     return APIResponse.HTTP_200_OK(message="Transaction history retrieved successfully.", data=data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_transaction_history(request):
    """
      This function is used to Retrieve the transaction history of the user's wallet. Provide the token
      of login user and wallet ID and then fetch the transaction history of the wallet.

    Args:
        request: The HTTP request object containing the user token and optional query parameter `limit`.

    Query Parameters:
        - limit (int, optional): The maximum number of transactions to retrieve. Defaults to 10.

    Returns:
        - 200 OK:
            {
                "status": 200,
                "message": "Transaction history retrieved successfully.",
                "data": [
                    {
                        "wallet_id": "123e4567-e89b-12d3-a456-426614174000",
                        "current_balance": 500.00,
                        "total_amount": 1000.00,
                        "last_transaction_date": "2024-12-26 11:45:00",
                        "withdrawal_percentage_tax": 5.0,
                        "order_id": "ORD12345678",
                        "wallet_transaction_history": [
                            {
                                "id": "456e7890-e89b-12d3-a456-426614174001",
                                "payment_method": "Credit Card",
                                "transaction_amount": 100.00,
                                "payment_status": "Completed",
                                "payment": "Ref12345",
                                "transaction_date": "2024-12-25 10:00:00"
                            },
                            ...
                        ]
                    }
                ]
            }
        - 400 BAD REQUEST:
            {
                "status": 400,
                "message": "Wallet not found."
            }
        - 401 UNAUTHORIZED:
            {
                "status": 401,
                "message": "Use token to authenticate."
            }
        - 401 UNAUTHORIZED:
            {
                "status": 401,
                "message": "Invalid token."
            }
        - 404 NOT FOUND:
            {
                "status": 404,
                "message": "Transaction history not found."
            }
    """
    # Authenticate and validate the user
    print(f"get transaction history request: {request.data}")
    user_instance = AuthService.get_user_from_token(request)
    # ----------------------------------------------- Validating Parameters ----------------------
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Use token to authenticate.")
    auth_user = AuthService.validate_user_role(user_instance, "User")
    if not auth_user:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid token.")
    wallet = models.Wallet.objects.filter(id=auth_user.wallet_id.id).first()  # get the wallet of the user by token
    if not wallet:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Wallet not found.")
    limit = int(request.GET.get('limit', 10))  # get the limit from the request
    selected_range = request.GET.get('range', '12 Month')
    print(f"selected_range:{selected_range}")
    # Filter transactions based on the selected time range
    now = timezone.now()
    if selected_range == '12 Month':
        start_date = now - timedelta(days=365)
    elif selected_range == '30 Days':
        start_date = now - timedelta(days=30)
    elif selected_range == '7 Days':
        start_date = now - timedelta(days=7)
    elif selected_range == '24 hours':
        start_date = now - timedelta(days=1)
    else:
        start_date = now - timedelta(days=365)  # Default to 12 Month if no valid range is selected

    transactions = wallet.wallet_transaction_history_id.filter(transaction_date__gte=start_date)[:limit]

    if not transactions:
        return APIResponse.HTTP_404_NOT_FOUND(message="Transaction history not found.")

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
                    "payment_method": tx.payment_method.title(),  # Capitalize first letter of each word
                    "transaction_amount": tx.transaction_amount,
                    "payment_status": tx.payment_status,
                    "payment": tx.payment,
                    "transaction_date": tx.transaction_date.strftime('%Y-%m-%d'),  # Extract only date
                    "transaction_time": tx.transaction_date.strftime('%I:%M:%S %p')  # Extract time with AM/PM
                } for tx in transactions
            ]
        }
    ]
    return APIResponse.HTTP_200_OK(message="Transaction history retrieved successfully.", data=data)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def pay_by_link(request):
    """
        This functioin is used to Generate a payment link and a corresponding QR code for a transaction.
        on the base of user token and wallet ID.
    Args:
        request: The HTTP request object containing the wallet ID, transaction amount, and payment method.

    Request Body:
        - wallet_id (str): The ID of the wallet.
        - transaction_amount (float): The amount to be transacted.
        - payment_method (str): The method of payment (e.g., "Credit Card", "PayPal").
    Payload:
        {
            "wallet_id": "123e4567-e89b-12d3-a456-426614174000",
            "transaction_amount": 100.00,
            "payment_method": "Credit Card"
        }

    Returns:
        - 200 OK:
            {
                "status": 200,
                "message": "Payment link and QR code generated successfully.",
                "data": {
                    "order_id": "ORDER12345",
                    "transaction_history_id": "TRANSACTION12345",
                    "payment_link": "https://payment.example.com/?order-id=ORDER12345",
                    "qr_code_url": "https://example.com/media/qrcode/qr_ORDER12345.png"
                }
            }
        - 400 BAD REQUEST:
            {
                "status": 400,
                "message": "All fields (wallet_id, transaction_amount, payment_method) are required."
            }
        - 400 BAD REQUEST:
            {
                "status": 400,
                "message": "User has no wallet, please create the wallet first."
            }
        - 400 BAD REQUEST:
            {
                "status": 400,
                "message": "Invalid data for transaction."
            }
        - 401 UNAUTHORIZED:
            {
                "status": 401,
                "message": "Use token to authenticate."
            }

    """
    user_instance = AuthService.get_user_from_token(request)
    # ----------------------------------------------- Validating Parameters -------------------------
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Use token to authenticate.")
    auth_user = AuthService.validate_user_role(user_instance, "User")
    if not auth_user:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid token.")
    wallet_id = request.data.get('wallet_id')                            # Get the wallet ID from the request
    transaction_amount = request.data.get('transaction_amount')          # Get the transaction amount from the request
    payment_method = request.data.get('payment_method')                  # Get the payment method from the request
    if not all([wallet_id, transaction_amount, payment_method]):
        return APIResponse.HTTP_400_BAD_REQUEST(
            message="All fields (wallet_id, transaction_amount, payment_method) are required."
        )
    wallet = get_object_or_404(models.Wallet, id=wallet_id)
    user = models.User.objects.filter(id=auth_user.id, wallet_id=wallet).first()
    if not user:
        return APIResponse.HTTP_400_BAD_REQUEST(
            message="User has no wallet, please create the wallet first."
        )
    # -------------------------------------------------------- Validating Completed -----------------
    order_id = str(uuid.uuid4().hex).upper()
    data = {
        'payment_method': payment_method,
        'payment_status': 'Pending',
        'transaction_amount': transaction_amount,
        'payment': 'Debit',
        'order_id': order_id,
    }
    form = forms.WalletTransactionHistoryForm(data)
    if not form.is_valid():
        return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid data for transaction.")
    transaction_form = form.save()
    wallet.wallet_transaction_history_id.add(transaction_form)
    wallet.last_transaction_date = transaction_form.transaction_date
    payment_link = f"{settings.PAYMENT_BASE_URL_LINK}/?order-id={transaction_form.order_id}"
    qr = qrcode.QRCode(                             # Generate QR code for the payment link
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(payment_link)
    qr.make(fit=True)
    qr_image = qr.make_image(fill_color="black", back_color="white")
    qr_folder = os.path.join(settings.MEDIA_ROOT, 'qrcode')                    # Save QR code image
    os.makedirs(qr_folder, exist_ok=True)
    qr_file_path = os.path.join(qr_folder, f"qr_{transaction_form.order_id}.png")
    qr_image.save(qr_file_path)
    qr_code_url = f"{settings.MEDIA_URL}qrcode/qr_{transaction_form.order_id}.png"  # Get the QR code URL
    ##
    wallet.order_id = transaction_form.order_id                     ## add order_id to wallet save code by hafiz
    ##
    wallet.save()
    response_data = {
        "order_id": transaction_form.order_id,
        "transaction_history_id": str(transaction_form.id),
        "payment_link": payment_link,
        "qr_code_url": qr_code_url,
    }
    return APIResponse.HTTP_200_OK(message="Payment link and QR code generated successfully.", data=response_data)



@api_view(['POST'])
@permission_classes([IsAuthenticated])
def verify_payment_by_order_id(request):
    """
     This function is used to Verify the payment for a given order ID and retrieve the related transaction history.
         on the base of user token and order ID.

    Args:
        request: The HTTP request object containing the user token and `order_id`.
    Payload:
        {
            "order_id": "ORD12345678"
        }

    Returns:
        - 200 OK:
            {
                "status": 200,
                "message": "Transaction history retrieved successfully.",
                "data": {
                    "wallet_id": "123e4567-e89b-12d3-a456-426614174000",
                    "current_balance": 500.00,
                    "total_amount": 1000.00,
                    "last_transaction_date": "2024-12-26 11:45:00",
                    "withdrawal_percentage_tax": 5.0,
                    "order_id": "ORD12345678",
                    "user": {
                        "id": "456e7890-e89b-12d3-a456-426614174001",
                        "username": "user123",
                        "first_name": "John",
                        "last_name": "Doe"
                    },
                    "wallet_transaction_history": [
                        {
                            "id": "789e1234-e89b-12d3-a456-426614174002",
                            "payment_method": "Credit Card",
                            "transaction_amount": 100.00,
                            "payment_status": "Completed",
                            "payment": "Ref12345",
                            "transaction_date": "2024-12-25 10:00:00"
                        },
                        ...
                    ]
                }
            }
        - 400 BAD REQUEST:
            {
                "status": 400,
                "message": "Payment ID is invalid."
            }
        - 404 NOT FOUND:
            {
                "status": 404,
                "message": "Wallet not found. Please check the order ID or create a wallet account first."
            }
        - 404 NOT FOUND:
            {
                "status": 404,
                "message": "No transaction history found for this order ID."
            }
        - 401 UNAUTHORIZED:
            {
                "status": 401,
                "message": "Use token to authenticate."
            }
        - 401 UNAUTHORIZED:
            {
                "status": 401,
                "message": "Invalid token."
            }
    """

    user_instance = AuthService.get_user_from_token(request)
    # ------------------------------------------------ Validating Parameters ---------------------
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Use token to authenticate.")
    user = AuthService.validate_user_role(user_instance, "User")
    if not user:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid token.")
    order_id = request.data.get('order_id')
    if not order_id:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Payment ID is invalid.")
    #
    wallet = models.Wallet.objects.filter(id=user.wallet_id.id, order_id=order_id).first()
    if not wallet:
        return APIResponse.HTTP_404_NOT_FOUND(
            message="Wallet not found. Please check the order ID or create a wallet account first."
        )
    transaction_history = wallet.wallet_transaction_history_id.all()
    if not transaction_history.exists():
        return APIResponse.HTTP_404_NOT_FOUND(message="No transaction history found for this order ID.")
    # ------------------------------------------------------ Validating Completed --------------------
    transactions = [
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
    data = {
        "wallet_id": str(wallet.id),
        "current_balance": wallet.current_balance,
        "total_amount": wallet.total_amount,
        "last_transaction_date": wallet.last_transaction_date.strftime('%Y-%m-%d %H:%M:%S') if
        wallet.last_transaction_date else None,
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


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def withdraw_money_from_user_account_wallet(request):
    """
        This function is used to Withdraw money from a user's wallet.Provide the token of login user

    Args:
        request: The HTTP request object containing the user token and withdrawal details
         (transaction amount and payment method).

    Returns:
        - 200 OK: If the withdrawal is successful.
        - 400 BAD REQUEST: If the data is invalid or missing required fields.
        - 400 BAD REQUEST: If there is insufficient wallet balance.
        - 400 BAD REQUEST: If the withdrawal amount exceeds the maximum allowed.
        - 404 NOT FOUND: If the wallet is not found.
    """
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    # --------------------------------------------- Validating Parameters -----------------------
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Use token to authenticate.")
    user = AuthService.validate_user_role(user_instance, "User")
    if not user:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid token.")
    form = forms.WalletTransactionHistoryFormUpdated(request.data)
    if not form.is_valid():
        return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid data", data=form.errors)
    wallet_id = user.wallet_id.id
    transaction_amount = form.cleaned_data['transaction_amount']
    payment_method = form.cleaned_data['payment_method']
    if not transaction_amount or not payment_method:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Missing required fields.")
    wallet = models.Wallet.objects.filter(id=wallet_id).first()
    if not wallet:
        return APIResponse.HTTP_404_NOT_FOUND(message="Wallet not found.")
    if wallet.total_amount <= 0:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Wallet balance is empty.")
    current_balance = wallet.current_balance
    max_withdrawal_amount = current_balance * 5
    if transaction_amount > max_withdrawal_amount:
        return APIResponse.HTTP_400_BAD_REQUEST(
            message=f"Transaction amount must be less than or equal to {max_withdrawal_amount} "
                    f"(5 times the current balance)."
        )
    withdrawal_tax = transaction_amount * (wallet.withdrawal_percentage_tax / 100)
    # Check if there is enough balance to cover the withdrawal amount and tax
    if (transaction_amount + withdrawal_tax) > wallet.total_amount:
        return APIResponse.HTTP_400_BAD_REQUEST(
            message="Insufficient wallet balance. Total and current amount must cover the "
                    "withdrawal amount and the tax.",
            data={
                "transaction_amount": transaction_amount,
                "withdrawal_tax": withdrawal_tax,
                "wallet": {
                    "id": wallet.id,
                    "total_amount": wallet.total_amount,
                    "current_balance": wallet.current_balance,
                },
            }
        )
    wallet.total_amount -= (transaction_amount + withdrawal_tax)
    wallet.current_balance -= (transaction_amount + withdrawal_tax)
    wallet.last_transaction_date = datetime.now()
    order_id = str(uuid.uuid4().hex).upper()
    transaction_obj = models.WalletTransactionHistory.objects.create(
        payment_method=payment_method,
        payment_status="Approved",
        transaction_amount=transaction_amount,
        payment="Debit",
        order_id=order_id,
        withdrawal_percentage_tax=wallet.withdrawal_percentage_tax,
    )
    wallet.wallet_transaction_history_id.add(transaction_obj)
    wallet.order_id = transaction_obj.order_id
    wallet.save()
    data = {
        "transaction_amount": transaction_amount,
        "withdrawal_tax": withdrawal_tax,
        "wallet_id": wallet_id,
        "payment_method": payment_method,
        "last_transaction_date": wallet.last_transaction_date.strftime('%Y-%m-%d %H:%M:%S'),
        "previous_balance": current_balance,
        "current_balance": wallet.current_balance,
        "user": {
            "id": user.id,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
        },
    }
    return APIResponse.HTTP_200_OK(
        message=f"Withdrew money from user wallet successfully by {user.user_id.username}.",
        data=data
    )


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def deposit_money_to_user_account_wallet(request):
    """
        This function is used to Deposit money to a user's wallet. Provide the token of login user
    Args:
        request: The HTTP request object containing the deposit details.

    Returns:
        1.
            {
                "status": 200,
                "message": "Withdrew money from user wallet successfully by IrshadHussain.",
                "data": {
                    "transaction_amount": 200,
                    "withdrawal_tax": 0.0,
                    "wallet_id": "49d07b88-7f67-4fdc-9238-30fc3d1689e2",
                    "payment_method": "stripe",
                    "last_transaction_date": "2024-12-27 10:57:45",
                    "previous_balance": 2006600,
                    "current_balance": 2006400.0,
                    "user": {
                        "id": "e974d9ee-8f41-4f24-ab9f-c76707e38236",
                        "email": "irsad@gmail.com",
                        "first_name": "Irshad",
                        "last_name": "Hussain"
                    }
                }
            }
        2.
            {
                    "status": 401,
                    "message": "Use token to authenticate." }
        3.
            {
                    "status": 401,
                    "message": "Invalid token."
            }
        3.
            {
                "status": 400,
                "message": "Invalid data",
                "data": {
                    "transaction_amount": ["This field is required."],
                }
            }
        4.
            {
                "status": 400,
                "message": "Missing required fields."
            }
    """
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Use token to authenticate.")
    user = AuthService.validate_user_role(user_instance, "User")
    if not user:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid token.")
    form = forms.WalletTransactionHistoryFormUpdated(request.data)
    if not form.is_valid():
        return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid data", data=form.errors)
    transaction_amount = form.cleaned_data['transaction_amount']
    payment_method = form.cleaned_data['payment_method']
    payment = request.data.get('payment')
    if not transaction_amount or not payment_method:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Missing required fields.")
    if transaction_amount <= 5:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Transaction amount must be greater than 5 dollars.")
    wallet = models.Wallet.objects.filter(id=user.wallet_id.id).first()
    if not wallet:
        return APIResponse.HTTP_404_NOT_FOUND(message="Wallet not found.")
    if payment == "Card":
        if not user.driving_license_front_image or not user.driving_license_back_image or not user.is_verified_license:
            return APIResponse.HTTP_400_BAD_REQUEST(
                message="User is not verified. Please verify your driving license or other relevant documents."
            )
    previous_balance = wallet.current_balance
    wallet.current_balance += transaction_amount
    wallet.total_amount += transaction_amount
    wallet.last_transaction_date = datetime.now()
    order_id = str(uuid.uuid4().hex).upper()
    transaction_obj = models.WalletTransactionHistory.objects.create(
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
        "last_transaction_date": wallet.last_transaction_date.strftime('%Y-%m-%d %H:%M:%S'),
        "previous_balance": previous_balance,
        "current_balance": wallet.current_balance,
        "payment": transaction_obj.payment,
        "user": {
            "id": user.id,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
        },
    }

    return APIResponse.HTTP_200_OK(
        message=f"Deposited money to {user.user_id.username}'s wallet successfully.",
        data=data
    )


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def deposit_money_to_user_account_wallet(request):
    """
         This function is used to Deposit money to a user's wallet. Provide the token of login user
    Args:
        request: The HTTP request object containing the deposit details.

    Returns:
        1.
            {
                "status": 200,
                "message": "Withdrew money from user wallet successfully by IrshadHussain.",
                "data": {
                    "transaction_amount": 200,
                    "withdrawal_tax": 0.0,
                    "wallet_id": "49d07b88-7f67-4fdc-9238-30fc3d1689e2",
                    "payment_method": "stripe",
                    "last_transaction_date": "2024-12-27 10:44:41",
                    "previous_balance": 2005800,
                    "current_balance": 2005600.0,
                    "user": {
                        "id": "e974d9ee-8f41-4f24-ab9f-c76707e38236",
                        "email": "irsad@gmail.com",
                        "first_name": "Irshad",
                        "last_name": "Hussain"
                    }
                }
            }
        2.
            {
                    "status": 401,
                    "message": "Use token to authenticate."
            }
        3.
            {
                    "status": 401,
                    "message": "Invalid token."
            }
        4.
            {
                "status": 400,
                "message": "Invalid data",
                "data": {
                    "transaction_amount": ["This field is required."],
                }
            }
        5.
            {
                "status": 400,
                "message": "Missing required fields."
            }
        6.
            {
                "status": 400,
                "message": "Transaction amount must be greater than 5 dollars."
            }
        7.
            {
                "status": 400,
                "message": "User is not verified. Please verify your driving license or other relevant documents."
            }
        8.
            {
                "status": 404,
                "message": "Wallet not found."
            }
        9.
            {
                "status": 400,
                "message": "Insufficient wallet balance. Total and current amount must cover the
                     withdrawal amount and the tax.",
            }

    """
    user_instance = AuthService.get_user_from_token(request)         # Authenticate and fetch the user
    # ------------------------------------- Validating Parameters -----------------------------
    if not user_instance:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Use token to authenticate.")
    user = AuthService.validate_user_role(user_instance, "User")
    if not user:
        return APIResponse.HTTP_401_UNAUTHORIZED(message="Invalid token.")
    form = forms.WalletTransactionHistoryFormUpdated(request.data)     # Validate the form data
    if not form.is_valid():
        return APIResponse.HTTP_400_BAD_REQUEST(message="Invalid data", data=form.errors)
    transaction_amount = form.cleaned_data['transaction_amount']     # Extract data from the form
    payment_method = form.cleaned_data['payment_method']
    payment = request.data.get('payment')                           # ["Debit", "Credit", "Card"]
    if not transaction_amount or not payment_method:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Missing required fields.")
    # Ensure transaction amount is greater than the minimum required
    if transaction_amount <= 5:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Transaction amount must be greater than 5 dollars.")
    wallet = models.Wallet.objects.filter(id=user.wallet_id.id).first()    # Fetch the user's wallet
    if not wallet:
        return APIResponse.HTTP_404_NOT_FOUND(message="Wallet not found.")
    # Validate additional conditions for "Card" payment
    if payment == "Card":
        if not user.driving_license_front_image or not user.driving_license_back_image or not user.is_verified_license:
            return APIResponse.HTTP_400_BAD_REQUEST(
                message="User is not verified. Please verify your driving license or other relevant documents."
            )
    # ----------------------------------------------------------- Validating Completed ----------
    previous_balance = wallet.current_balance                       # Update wallet balances
    wallet.current_balance += transaction_amount
    wallet.total_amount += transaction_amount
    wallet.last_transaction_date = datetime.now()
    order_id = str(uuid.uuid4().hex).upper()                       # Generate a unique order ID
    transaction_obj = models.WalletTransactionHistory.objects.create(
        payment_method=payment_method,
        payment_status="Approved",
        transaction_amount=transaction_amount,
        payment=payment,
        order_id=order_id,
        withdrawal_percentage_tax=wallet.withdrawal_percentage_tax,
    )
    wallet.wallet_transaction_history_id.add(transaction_obj)        # Update wallet with the new transaction
    wallet.order_id = transaction_obj.order_id
    wallet.save()
    data = {
        "transaction_amount": transaction_amount,
        "wallet_id": wallet.id,
        "payment_method": payment_method,
        "last_transaction_date": wallet.last_transaction_date.strftime('%Y-%m-%d %H:%M:%S'),
        "previous_balance": previous_balance,
        "current_balance": wallet.current_balance,
        "payment": transaction_obj.payment,
        "user": {
            "id": user.id,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
        },
    }
    return APIResponse.HTTP_200_OK(
        message=f"Deposited money to {user.user_id.username}'s wallet successfully.",
        data=data
    )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
# Wallet Management System


############################################################################################################

## Agent Panel Management System
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_player_by_agent(request):
    """
    API to create a new player by an agent.
    """
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)

    # Validate user's role
    auth_user = AuthService.validate_user_role(user_instance, "Agent")

    # Extract data from the request
    user_id = request.data.get('user_id')
    username = request.data.get('username')
    nickname = request.data.get('nickname')
    password = request.data.get('password')
    game_id = request.data.get('game_id')
    player_created_by = auth_user.id
    score = 0
    status = 'active'
    is_banned = False

    # Validate required fields
    if not (user_id and username and password and game_id and player_created_by):
        return APIResponse.HTTP_400_BAD_REQUEST(
            message="Missing required fields: user_id, username, password, player_created_by, and game_id are mandatory."
        )

    # Validate user's role
    user = AuthService.validate_user_uuid_role(user_id, "User")

    try:
        # Call the create_player method
        panel = AgentGamePanel()
        response_data = async_to_sync(panel.create_player)(
            user_id=user.id,
            username=username,
            nick_name=nickname,
            password=password,
            score=score,
            status=status,
            is_banned=is_banned,
            game_id=game_id,
            created_by=player_created_by,
        )

        # Return the successful response
        return APIResponse.HTTP_200_OK(
            message="Player created successfully.",
            data=response_data
        )

    except User.DoesNotExist:
        return APIResponse.HTTP_400_BAD_REQUEST(message="User with the given UUID does not exist.")
    except Player.DoesNotExist:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Player with the given UUID does not exist.")
    except Game.DoesNotExist:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Game with the given UUID does not exist.")
    except Exception as e:
        # Handle unexpected errors
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(
            message=f"User not created. Please try again after a few minutes. {str(e)}",
            data={
                "username": username,
                "datetime": datetime.now(tz=UTC).__str__(),
                "nickname": nickname,
                "score": 0
            }
        )


@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def get_all_my_created_players(request):
    """
    API to retrieve all players created by a specific user with the Agent role.

    Query Parameters:
        player_created_by (str): The ID of the user who created the players.

    Returns:
        JSON response with a list of players or an appropriate error message.
    """
    # Authenticate and fetch the user
    user_instance = AuthService.get_user_from_token(request)
    print(f"user_instance: {user_instance}")

    # Validate user's role
    user = AuthService.validate_user_role(user_instance, "Agent")
    print(f"User: {user}")

    # Get the creator's ID from the query parameters
    player_created_by = user.id
    if not player_created_by:
        return APIResponse.HTTP_400_BAD_REQUEST(message="Missing required parameter: player_created_by.")

    try:

        # Fetch all players asynchronously
        agent_panel = AgentGamePanel()
        players = async_to_sync(agent_panel.get_all_my_created_players)(player_created_by)

        # Return the list of players if found
        if players:
            return APIResponse.HTTP_200_OK(message="Players retrieved successfully.", data=players)
        else:
            return APIResponse.HTTP_404_NOT_FOUND(message="No created by user found or not an agent.")

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

@api_view(['GET'])
def landing_page_data(request):
    try:

        # Fetch all games
        games = models.Game.objects.all()
        # print("all games")
        # print(games)
        top_rated_games_obj = games.filter(is_trending=True)
        upcoming_games_obj = games.filter(upcoming_status=True)

        # Fetch all players and match with users
        user = models.User.objects.all()
        player_games = models.Player.objects.all()
        matching_user_players = player_games.filter(user_id__in=user)
        ##
        all_games = []
        all_games_obj = models.Game.objects.all()

        for game in all_games_obj:
            all_games.append({
                        "id": game.id,
                        "game_name": game.game_name,
                        "game_image": request.build_absolute_uri(game.game_image.url) if game.game_image else None,
                        "game_video": request.build_absolute_uri(game.game_video.url) if game.game_video else None,
                        "gradient_style": game.gradient_style, ##
                        "game_description": game.game_description,
                        "game_created_at": game.game_created_at.date(),
                        "game_price": game.game_price,
                        "android_game_url": game.android_game_url,
                        "ios_game_url": game.ios_game_url,
                        "browser_game_url": game.browser_game_url,
                        "score": game.score,
            })
        ##
        # Group the games by their players
        popular_games_obj = matching_user_players

        if not top_rated_games_obj:
            return APIResponse.HTTP_404_NOT_FOUND(message="Top-rated games not found.")

        top_rated = []
        # Populate top-rated games
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

        # Group players by game and populate popular games
        game_ids = popular_games_obj.values_list('game_id', flat=True).distinct()  # Get unique game ids

        game_players = []

        for game_id in game_ids:
            game = models.Game.objects.get(id=game_id)  # Get game details
            players = models.Player.objects.filter(game_id=game_id)
            print(game)
            game_players = {
                "id": game.id,
                "game_name": game.game_name,
                "game_description": game.game_description,
                "game_image": request.build_absolute_uri(game.game_image.url) if game.game_image else None,
                "game_video": request.build_absolute_uri(game.game_video.url) if game.game_video else None,
                "game_price": game.game_price,
                "android_game_url": game.android_game_url,
                "gradient_style": game.gradient_style,   ##
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

        #1. get all the games-reviews
        reviews = models.GameReview.objects.all()

        #2. match the game reviews id with the games-reviews
        game_reviews = games.all()

        game_reviews_list = []

        for game in game_reviews:
            # 
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

        # Response data structure
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

############################################################################################################
from rest_framework.response import Response
from rest_framework import status

## User Management System
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_player_by_user(request):
    logger.info(f"Request received: {request.data}")

    user_instance = AuthService.get_user_from_token(request)
    if not user_instance:
        logger.error("Invalid token")
        return Response({"message": "Invalid token"}, status=404)

    user = AuthService.validate_user_role(user_instance, "User")
    if not user:
        logger.error("User not authorized")
        return Response({"message": "User not authorized to create player."}, status=401)

    username = request.data.get('username')
    nickname = request.data.get('nickname')
    password = request.data.get('password')
    confirm_password = request.data.get("confirm_password")
    game_name = request.data.get('game_name')

    if not (username and password and confirm_password and game_name):
        logger.error("Missing required fields")
        return Response(
            {"message": "Missing required fields: username, nickname, password, and game_name are mandatory."},
            status=400
        )

    if password != confirm_password:
        logger.error("Passwords do not match")
        return Response({"message": "Password and Confirm Password do not match."}, status=400)

    game = models.Game.objects.filter(game_name=game_name).first()
    if not game:
        logger.error(f"Game with name '{game_name}' does not exist")
        return Response({"message": f"Game with name '{game_name}' does not exist."}, status=404)

    if not username:
        logger.error("Username is required")
        return Response({"message": "Username is required."}, status=400)

    if ' ' in username:
        logger.error("Username contains spaces")
        return Response({"message": "Username must not contain spaces."}, status=400)

    if not username.isalnum() and not all(char in ['_', '-'] for char in username):
        logger.error("Invalid characters in username")
        return Response({"message": "Username can only contain letters, numbers, underscores, or hyphens."}, status=400)

    if len(username) < 3 or len(username) > 20:
        logger.error("Username length invalid")
        return Response({"message": "Username must be between 3 and 20 characters."}, status=400)

    logger.info("Before model username checking")
    player = models.Player.objects.filter(username=username, game_id=game.id).first()
    if player:
        logger.error("Username already exists")
        return Response({"message": "Username already exists."}, status=503)

    models.Player.objects.create(
        username=username,
        nick_name=nickname,
        password=make_password(password),
        user_id=user,
        game_id=game,
        created_by=user,
    )

    res = {
        'status': 200,
        'message': f"Player created for user '{user_instance.first_name} {user_instance.last_name}' successfully",
        "data": {
            "username": username,
            "datetime": datetime.now(tz=UTC).__str__(),
            "nickname": nickname,
            "score": 0
        }
    }

    logger.info("Player created successfully")
    return Response(res, status=res['status'])


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
        user = AuthService.validate_user_role(user_instance, "User")

        # Fetch all players asynchronously
        panel = UserGamePanel()
        players = async_to_sync(panel.get_all_my_accounts)(user.id)  # Pass user ID to the method

        # Return the list of players if found
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
    # Authenticate user and validate role
    user_instance = AuthService.get_user_from_token(request)
    user = AuthService.validate_user_role(user_instance, "User")

    try:
        # Get the data from the request body
        username = request.data.get('username')
        score = float(request.data.get('score'))
        game_id = request.data.get('game_id')

        if not username or not score or not game_id:
            return APIResponse.HTTP_400_BAD_REQUEST(message="Missing required parameters.")

        # Call the update_score method to update the player's score
        result = UserGamePanel.update_score(username, score, game_id, user.id)

        # If result contains player data, return a success response
        if isinstance(result, dict) and "id" in result:
            return APIResponse.HTTP_200_OK(message="Player score updated successfully.", data=result)
        else:
            # If the result contains an error message
            return APIResponse.HTTP_404_NOT_FOUND(message=result.get("message"))

    except Exception as e:
        logging.error(f"Unexpected error in API: {str(e)}")
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message="An unexpected error occurred.")

# api for show the admin chat response and agent chat response
# @api_view(['GET'])
# @permission_classes([IsAuthenticated])
# def get_chat_response(request):
#     try:
#         # Authenticate user and validate role
#         user_instance = AuthService.get_user_from_token(request)
#         user = AuthService.validate_user_role(user_instance, "User")
#
#         # Get the data from the request body
#         game_id = request.query_params.get('game_id')
#         agent_id = request.query_params.get('agent_id')
#         admin_id = request.query_params.get('admin_id')
#         if not game_id or not agent_id or not admin_id:
#             return APIResponse.HTTP_400_BAD_REQUEST(message="Missing required parameters.")
#
#
#
#         return APIResponse.HTTP_200_OK(message="Chat response retrieved successfully.", )


# from rest_framework.decorators import api_view, permission_classes
# from rest_framework.permissions import IsAuthenticated
# from rest_framework.response import Response
# from .models import AdminReply, AgentChat
# from .services import AuthService
# from .responses import APIResponse
from django.db.models import Q

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_admin_and_agent_chat_history(request):
    try:
        # Authenticate user and validate role
        user_instance = AuthService.get_user_from_token(request)
        user = AuthService.validate_user_role(user_instance, "User")

        # Get the game_id, agent_id, and user_id from the request parameters
        game_id = request.data.get('game_id')
        admin_id = request.data.get('admin_id')
        agent_id = request.data.get('agent_id')
        print(game_id, admin_id, agent_id)

        if not game_id or not admin_id or not agent_id:
            return APIResponse.HTTP_400_BAD_REQUEST(message="Missing required parameters.")

        # Retrieve chat history from AdminReply
        admin_replies = models.AdminReply.objects.filter(
            game_review_id__game_id=game_id,
            rated_by_user_id=admin_id
        ).values(
            'message_content', 'reply_posted_at', 'admin_id'
        )

        # Retrieve chat history from AgentChat
        agent_chats = models.AgentChat.objects.filter(
            Q(user_id=admin_id) | Q(agent_id=agent_id),
            Q(status='active')  # Optional: can include only active chats or remove this filter
        ).values(
            'message_content', 'agent_chat_created_at', 'agent_id'
        )

        # Combine both lists of chats
        combined_chats = list(admin_replies) + list(agent_chats)

        # Merge and order by timestamp (reply_posted_at or agent_chat_created_at)
        for chat in combined_chats:
            if 'reply_posted_at' in chat:
                chat['timestamp'] = chat['reply_posted_at']
                chat['sender_type'] = 'admin'
            else:
                chat['timestamp'] = chat['agent_chat_created_at']
                chat['sender_type'] = 'agent'  # Can also include the user if necessary

        # Sort by timestamp (oldest first)
        combined_chats.sort(key=lambda x: x['timestamp'])

        # Return the combined chat history
        chat_messages = [
            {
                "sender": chat['sender_type'],
                "message": chat['message_content'],
                "timestamp": chat['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                "sender_id": chat['admin_id'] if chat['sender_type'] == 'admin' else chat['agent_id']
            }
            for chat in combined_chats
        ]

        return APIResponse.HTTP_200_OK(message="Combined chat history retrieved successfully.", data=chat_messages)

    except Exception as e:
        # Handle any errors
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An error occurred: {str(e)}")


# from rest_framework.decorators import api_view
# from django.db.models import Q
# from . import models
# from .services import AuthService  # Assuming AuthService handles user authentication and validation
# from .response import APIResponse  # Assuming APIResponse handles HTTP responses


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def get_agent_and_user_chat_history(request):
    """
    Retrieve all chat history between a user and an agent with timestamps and days.
    Payload:
        {
            "user_id": "9b03dcbb-e3a3-454f-93b6-15096801bb56",
            "agent_id": "adc1f1de-caba-4616-9058-ee53bfb14e47"
        }
    Returns:
        {
            "status": 200,
            "message": "Chat history retrieved successfully.",
            "data": [
                {
                    "message_content": "Hello, how can I help you?",
                    "timestamp": "2025-01-21T14:32:00Z",
                    "day": "Monday",
                    "role": "user"
                },
                {
                    "message_content": "I need assistance with my account.",
                    "timestamp": "2025-01-21T14:34:00Z",
                    "day": "Monday",
                    "role": "agent"
                },
                ...
            ]
        }
    """
    try:
        # Authenticate the user from the token
        user_instance = AuthService.get_user_from_token(request)

        # Retrieve the user_id and agent_id from the payload
        user_id = request.data.get('user_id')
        agent_id = request.data.get('agent_id')

        if not user_id or not agent_id:
            return APIResponse.HTTP_400_BAD_REQUEST(message="User ID and Agent ID are required.")

        # Validate user and agent existence
        user = models.User.objects.filter(id=user_id).first()
        agent = models.User.objects.filter(id=agent_id).first()

        if not user:
            return APIResponse.HTTP_404_NOT_FOUND(message="User not found.")
        if not agent:
            return APIResponse.HTTP_404_NOT_FOUND(message="Agent not found.")

        # Retrieve chat history from AgentChat
        agent_chats = models.AgentChat.objects.filter(
            Q(user_id=user_id, agent_id=agent_id) | Q(user_id=agent_id, agent_id=user_id)
        ).values(
            'message_content', 'agent_chat_created_at', 'user_id', 'agent_id'
        )

        # Retrieve chat history from GlobalChat
        user_chats = models.GlobalChat.objects.filter(
            Q(user_id=user_id) | Q(user_id=agent_id)
        ).values(
            'message_content', 'global_chat_created_at', 'user_id'
        )

        # Combine both agent and user chat histories
        combined_chats = []

        for chat in agent_chats:
            combined_chats.append({
                'message_content': chat['message_content'],
                'timestamp': chat['agent_chat_created_at'],
                'day': chat['agent_chat_created_at'].strftime('%A'),
                'role': 'agent' if chat['agent_id'] == agent_id else 'user',
                'user_id': chat['user_id'],
                'agent_id': chat['agent_id']
            })

        for chat in user_chats:
            combined_chats.append({
                'message_content': chat['message_content'],
                'timestamp': chat['global_chat_created_at'],
                'day': chat['global_chat_created_at'].strftime('%A'),
                'role': 'user',
                'user_id': chat['user_id'],
                'agent_id': agent_id  # Assuming all GlobalChat messages are from the user to the agent
            })

        # Sort the combined chats by timestamp in ascending order
        combined_chats = sorted(combined_chats, key=lambda x: x['timestamp'])

        # Return the chat history response
        return APIResponse.HTTP_200_OK(
            message="Chat history retrieved successfully.",
            data=combined_chats
        )

    except Exception as e:
        return APIResponse.HTTP_500_INTERNAL_SERVER_ERROR(message=f"An error occurred: {str(e)}")


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

    serializer = PaymentSerializer(data=data)
    if serializer.is_valid():
        serializer.save()
        return Response({"message": "Payment handled successfully."}, status=200)
    return Response(serializer.errors, status=400)