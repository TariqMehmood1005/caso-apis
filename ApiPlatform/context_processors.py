import requests
from CoinsSellingPlatformProject import settings


def user_profile_context(request):
    # Initialize an empty profile context
    profile_context = {}

    # Check if the user is logged in by looking for the 'is_logged_in' cookie
    token = request.COOKIES.get('token')
    is_logged_in = request.COOKIES.get('is_logged_in')

    if is_logged_in == 'true' and token:
        headers = {
            "Authorization": f"Token {token}",  # Correct format for token-based auth
        }

        try:
            # Call the profile API endpoint
            response = requests.post(f"{settings.BASE_API_URL}/profile/", headers=headers)

            if response.status_code == 200:
                # Populate profile context with data
                profile_context = response.json().get('data', {})
            else:
                print(f"Error: {response.status_code}, {response.text}")
        except requests.RequestException as e:
            print(f"Request failed: {e}")

    return {
        "user_profile": profile_context
    }


def player_creation_notifications_context(request):
    # Initialize an empty profile context
    context = {}

    # Check if the user is logged in by looking for the 'is_logged_in' cookie
    token = request.COOKIES.get('token')
    is_logged_in = request.COOKIES.get('is_logged_in')

    if is_logged_in == 'true' and token:
        headers = {
            "Authorization": f"Token {token}",  # Correct format for token-based auth
        }

        try:
            # Remove the trailing slash after 'limit=10'
            player_creation_notifications_response = requests.get(
                f"{settings.BASE_API_URL}/admin-game-panel/player-creation-notifications/?page=1&limit=10",
                headers=headers
            )

            if player_creation_notifications_response.status_code == 200:
                context = player_creation_notifications_response.json().get('data', {})
            else:
                print(
                    f"Error: {player_creation_notifications_response.status_code}, "
                    f"{player_creation_notifications_response.text}")
        except requests.RequestException as e:
            print(f"Request failed: {e}")

    return {
        "player_creation_notifications_context": context
    }


def game_creation_notifications_context(request):
    # Initialize an empty profile context
    context = {}

    # Check if the user is logged in by looking for the 'is_logged_in' cookie
    token = request.COOKIES.get('token')
    is_logged_in = request.COOKIES.get('is_logged_in')

    if is_logged_in == 'true' and token:
        headers = {
            "Authorization": f"Token {token}",  # Correct format for token-based auth
        }

        try:
            # Remove the trailing slash after 'limit=10'
            game_creation_notifications_response = requests.get(
                f"{settings.BASE_API_URL}/admin-game-panel/game-creation-notifications/?page=1&limit=10",
                headers=headers
            )

            if game_creation_notifications_response.status_code == 200:
                context = game_creation_notifications_response.json().get('data', {})
            else:
                print(f"Error: {game_creation_notifications_response.status_code}, "
                      f"{game_creation_notifications_response.text}")
        except requests.RequestException as e:
            print(f"Request failed: {e}")

    return {
        "games": context
    }

def dynamic_host(request):
    host = request.get_host()
    protocol = "https" if request.is_secure() else "http"
    base_url = f"{protocol}://{host}"
    
    settings.HOST = base_url
    settings.BASE_API_URL = f"{base_url}/api/v1"
    
    return {
        "HOST": base_url,
        "BASE_API_URL": f"{base_url}/api/v1"
    }

