import logging
import asyncio
from datetime import UTC, datetime
from typing import Tuple, Any
from asgiref.sync import sync_to_async
from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.core.paginator import Paginator
from django.utils.timesince import timesince
from django.utils.timezone import now
from ApiPlatform.models import AdminReply, Player, Game, User, Role, FreePlay, WalletTransactionHistory, Bonus
from django.db.models import Avg, Sum

from ApiPlatform.signals import player_password_reset_signal


class AdminGamePanel:

    def __init__(self, number_of_browsers: int = 2, total_browsers: int = 10):
        self.number_of_browsers = number_of_browsers
        self.total_browsers = total_browsers
        self.current_browsers = number_of_browsers
        self.scheduler_running = False

    async def scale_browsers(self, user_load: int):
        """
        Adjusts the number of active browsers based on user load.

        Args:
            user_load (int): Current load or number of active users accessing the panel.
        """
        if user_load > self.current_browsers and self.current_browsers < self.total_browsers:
            additional_browsers = min(user_load - self.current_browsers, self.total_browsers - self.current_browsers)
            self.current_browsers += additional_browsers
            print(f"Scaled up to {self.current_browsers} browsers")
        elif user_load < self.current_browsers and self.current_browsers > self.number_of_browsers:
            reduce_browsers = min(self.current_browsers - user_load, self.current_browsers - self.number_of_browsers)
            self.current_browsers -= reduce_browsers
            print(f"Scaled down to {self.current_browsers} browsers")

    @sync_to_async
    def get_all_games_accounts(self, search: str) -> dict:
        """
        Fetch all game accounts with details, excluding players with no creator.

        Returns:
            list[dict]: A list of dictionaries containing game and player details.
        """
        try:
            # search: username, game_name
            if search:
                players = Player.objects.select_related('game_id', 'user_id').filter(user_id__isnull=False).filter(
                    username__icontains=search)
            else:
                players = Player.objects.select_related('game_id', 'user_id').filter(user_id__isnull=False)

            # Prepare structured response data
            accounts = {
                "datetime": datetime.now(tz=UTC).__str__(),
                "players": [players.to_dict() for players in players]
            }
            return accounts

        except Exception as e:
            logging.error(f"Error in get_all_games_accounts: {str(e)}")
            return {}

    @staticmethod
    @sync_to_async
    def get_all_my_created_players(created_by: str) -> list[dict]:
        """
        Fetches all players created by the specified user with the Agent role.

        Args:
            created_by (str): The ID of the user who created the players (must be an Agent).

        Returns:
            list[dict]: A list of player details.
        """
        try:
            # Fetch players created by the specified user
            players = Player.objects.filter(created_by=created_by).all()
            print(f"Players: {players}")

            if not players.exists():
                logging.info(f"No players found for user: {created_by}")
                return []

            # Prepare structured response
            return [
                {
                    "game_id": str(player.game_id.id),
                    "game_name": getattr(player.game_id, "game_name", "N/A"),
                    "game_description": getattr(player.game_id, "game_description", "N/A"),
                    "game_image": f"{settings.HOST}{player.game_id.game_image.url}"
                    if player.game_id.game_image else "N/A",
                    "player": {
                        "player_id": str(player.id),
                        "username": player.username,
                        "nick_name": player.nick_name,
                        "score": player.score,
                        "status": player.status,
                        "is_banned": player.is_banned,
                        "user": {
                            "id": str(player.user_id.id),
                            "email": player.user_id.email,
                            "username": player.user_id.user_id.username,
                            "role": player.user_id.role_id.roles,
                            "phone": player.user_id.phone,
                            "profile": f"{settings.HOST}{player.user_id.profile_image.url}"
                            if player.user_id.profile_image else "N/A",
                            "joined_at": player.user_id.user_id.date_joined.strftime("%Y-%m-%d %H:%M:%S"),
                            "is_last_active": player.user_id.is_last_active
                        }
                    },
                    "created_by": {
                        "id": str(player.created_by.id),
                        "email": player.created_by.email,
                        "username": player.created_by.user_id.username,
                        "role": player.created_by.role_id.roles,
                        "phone": player.created_by.phone,
                        "profile": player.created_by.profile_image.url if player.created_by.profile_image else "N/A",
                        "joined_at": player.created_by.user_id.date_joined.strftime("%Y-%m-%d %H:%M:%S"),
                        "is_last_active": player.created_by.is_last_active
                    }
                } for player in players

            ]

        except ValueError as ve:
            logging.warning(f"Validation error: {str(ve)}")
            return []
        except Exception as e:
            logging.error(f"Unexpected error in fetching players: {str(e)}")
            return []

    @staticmethod
    def get_all_my_created_games(created_by: str) -> list[dict]:
        try:
            games = Game.objects.filter(created_by_user_id=created_by).order_by('-game_created_at')

            if not games.exists():
                logging.info(f"No games found for user: {created_by}")
                return []

            return [
                {
                    # Fetch reviews for the current game
                    "total_reviews": game.game_reviews.count() + AdminReply.objects.filter(
                        game_review_id__game_id=game).count(),

                    "game_ratings_count": game.game_ratings.count(),
                    "average_rating": round(game.game_ratings.aggregate(Avg('rating'))['rating__avg'] or 0, 2),
                    "total_ratings": round(game.game_ratings.aggregate(Sum('rating'))['rating__sum'] or 0, 2),

                    # Game Ratings
                    "game_ratings_average": round(game.game_ratings.aggregate(Avg('rating'))['rating__avg'] or 0, 2),
                    "game_ratings_total": round(game.game_ratings.aggregate(Sum('rating'))['rating__sum'] or 0, 2),
                    "game_ratings": [
                        {
                            "id": str(rating.id),
                            "rating": rating.rating,
                            "total_ratings": rating.total_ratings,
                            "users": [rating.user_id.to_dict() for rating in game.game_ratings.all()],
                        } for rating in game.game_ratings.all()
                    ],

                    # Game Details
                    "id": str(game.id),
                    "game_id": str(game.game_id),
                    "game_name": game.game_name,
                    "game_description": game.game_description,
                    "game_image": f"{settings.HOST}{game.game_image.url}",
                    "game_video": f"{settings.HOST}{game.game_video.url}",
                    "game_price": game.game_price,
                    "android_game_url": game.android_game_url,
                    "ios_game_url": game.ios_game_url,
                    "browser_game_url": game.browser_game_url,
                    "upcoming_status": game.upcoming_status,
                    "is_trending": game.is_trending,
                    "game_created_at": game.game_created_at.strftime("%Y-%m-%d %H:%M:%S"),
                    "game_updated_at": game.game_updated_at.strftime("%Y-%m-%d %H:%M:%S"),
                    "transfer_score_percentage": game.transfer_score_percentage,
                    "redeem_score_percentage": game.redeem_score_percentage,
                    "is_free": game.is_free,
                    "is_active": game.is_active,

                    "game_reviews": [
                        {
                            "id": str(review.id),
                            "message_content": str(review.message_content),
                            "rated_by_users": [
                                {
                                    "user_id": str(rating.user.id),
                                    "email": rating.user.email,
                                    "username": rating.user.user_id.username,
                                    "role": rating.user.role_id.roles,
                                    "phone": rating.user.phone,
                                    "profile": rating.user.profile_image.url if rating.user.profile_image else "N/A",
                                    "rating": rating.rating,
                                    "is_yes": rating.is_yes,
                                }
                                for rating in review.ratings_data.all()  # Fetch users who rated this review
                            ],
                            "email": review.user_id.email,
                            "username": review.user_id.user_id.username,
                            "role": review.user_id.role_id.roles,
                            "phone": review.user_id.phone,
                            "profile": review.user_id.profile_image.url if review.user_id.profile_image else "N/A",
                            "joined_at": review.user_id.user_id.date_joined.strftime("%Y-%m-%d %H:%M:%S"),
                            "is_last_active": review.user_id.is_last_active,
                            "review_posted_at": review.review_posted_at.strftime("%Y-%m-%d %H:%M:%S"),
                            "total_reviews": review.game_id.game_reviews.count(),
                            "average_rating": review.game_id.game_reviews.aggregate(
                                Avg('ratings'))['ratings__avg'] or 0,
                            "total_ratings": review.game_id.game_reviews.aggregate(
                                Sum('ratings'))['ratings__sum'] or 0,
                        } for review in game.game_reviews.all()
                    ],
                    "created_by": game.created_by_user_id.to_dict()
                } for game in games
            ]

        except Exception as e:
            logging.error(f"Unexpected error in fetching games: {str(e)}")
            return []

    @staticmethod
    def get_player_score(username: str) -> dict | None:

        try:
            # Fetch the player matching the username and game ID

            player = Player.objects.filter(username=username).first()

            if player is None:
                return {
                    "errors": f"Invalid username or unable to find user. Please create user first."
                }
            else:
                # Prepare structured response
                if player.is_banned:
                    return {
                        "errors": f"User is banned"
                    }
                else:
                    return {
                        "player_id": str(player.id),
                        "username": player.username,
                        "nick_name": player.nick_name,
                        "game": player.game_id.to_dict(),
                        "score": player.score,
                        "status": player.status,
                    }

        except Exception as e:
            logging.error(f"Error in get_game_score: {str(e)}")
            return None

    @staticmethod
    @sync_to_async
    def create_player(user_id: str, username: str, nick_name: str, password: str, score: int, status: str,
                      is_banned: bool, game_id: str, created_by: str):
        """
        Create a player associated with the given game and user.
        """
        try:
            # Validate the game
            game = Game.objects.filter(game_id=game_id).first()
            if not game:
                raise ValueError(f"Game with ID '{game_id}' does not exist.")

            # Check for an existing player with the same username for the game
            player = Player.objects.filter(username=username, game_id=game).exists()
            if player:
                raise ValueError(f"Player with username '{username}' already exists for this game.")

            # Validate the user
            user = User.objects.filter(id=user_id).first()
            if not user:
                raise ValueError(f"User with ID '{user_id}' does not exist.")

            wallet = user.wallet_id
            if not wallet:
                raise ValueError("User's wallet is not available.")

            game_price = game.game_price

            # 1️⃣ Check FreePlays
            free_play = FreePlay.objects.filter(user=user).first()
            free_plays_available = free_play.free_plays if free_play else 0

            # 2️⃣ Check Bonus
            bonus = Bonus.objects.filter(user_id=user).first()
            bonus_amount = bonus.amount if bonus else 0
            print(f"bonus_amount :{bonus_amount}")

            # # 3️⃣ Check Wallet
            wallet_balance = wallet.total_amount
            print(f"wallet_balance: {wallet_balance}")

            # ❌ If all are zero, prompt deposit message
            if free_plays_available == 0 and bonus_amount == 0 and wallet_balance == 0:
                raise ValueError("Please deposit payment to the wallet. Because you don't have sufficient balance.")

            payment_source = []
            remaining_price = game_price

            # 🌟 **Step 1: Deduct from FreePlays**
            if free_plays_available > 0:
                deduction = min(remaining_price, free_plays_available)
                free_play.free_plays -= deduction
                free_play.save()
                remaining_price -= deduction
                payment_source.append("Free Play")

            # 🌟 **Step 2: Deduct from Bonus**
            if bonus_amount > 0 and remaining_price > 0:
                deduction = min(remaining_price, bonus_amount)

                bonus.amount -= deduction
                print(f"bonus.amount: {bonus.amount}")

                bonus.save()
                remaining_price -= deduction
                print(f"Bonus :> remaining_price: {remaining_price}")
                payment_source.append("Bonus")

            # 🌟 **Step 3: Deduct from Wallet (only if necessary)**
            if remaining_price > 0:
                if wallet.total_amount < remaining_price:
                    raise ValueError("Insufficient wallet balance.")
                wallet.total_amount -= remaining_price
                wallet.save()
                payment_source.append("Wallet")

            # Join sources properly
            payment_source_str = " + ".join(payment_source)

            print(f"Game price deducted from: {payment_source_str}")

            # 🌟 **Only record a wallet transaction if wallet was used**
            if "Wallet" in payment_source_str:
                wallet_history = WalletTransactionHistory.objects.create(
                    payment_method=payment_source_str,
                    payment_status='Approved',
                    transaction_amount=game_price,
                )
                wallet.wallet_transaction_history_id.add(wallet_history)

            created_by_user = User.objects.filter(id=created_by).first()
            if not created_by_user:
                raise ValueError("Creator user not found.")

            # Create the player
            player = Player.objects.create(
                username=username,
                nick_name=nick_name or username,
                password=make_password(password),
                score=score,
                status=status,
                is_banned=is_banned,
                user_id=user,
                game_id=game,
                created_by=created_by_user,
                is_notified_read=True,
            )

            logging.info(f"Player '{player.username}' successfully created for game '{game.game_name}'.")

            # Prepare response data
            return {
                "player": {
                    "id": player.id,
                    "username": player.username,
                    "nick_name": player.nick_name,
                    "email": user.email,
                    "score": player.score,
                    "status": player.status,
                    "is_banned": player.is_banned,
                    "game": game.game_name,
                    "created_by": created_by_user.user_id.username,
                    "is_notified_read": player.is_notified_read,
                },
                "wallet": wallet.to_dict(),
                "free_play": free_play.free_plays if free_play else 0,
                "bonus": bonus.amount if bonus else 0,
                "payment_source": payment_source_str,
            }

        except ValueError as ve:
            logging.error(f"Validation error: {ve}")
            raise
        except Exception as e:
            logging.error(f"Unexpected error while creating player: {e}")
            raise


    @staticmethod
    @sync_to_async
    def player_creation_notifications(page=1, per_page=10, created_by: str = None):
        try:
            # Fetch players with is_notified_read = True
            players = Player.objects.filter(is_notified_read=True, created_by=created_by).all()

            # Paginate the queryset
            paginator = Paginator(players, per_page)
            page_obj = paginator.get_page(page)

            # Log the pagination information
            logging.info(f"Fetched page {page} of players with is_notified_read=True.")

            # Prepare response data for the current page of players
            players_data = []
            for player in page_obj.object_list:
                # Calculate the time difference between current time and created_at
                created_ago = None
                if player.account_created_at:
                    time_diff = now() - player.account_created_at
                    # Convert time_diff to days, hours, and minutes
                    days = time_diff.days
                    hours, remainder = divmod(time_diff.seconds, 3600)
                    minutes, seconds = divmod(remainder, 60)
                    created_ago = f"{days} days, {hours} hours, {minutes} minutes ago" \
                        if days > 0 else f"{hours} hours, {minutes} minutes ago"

                players_data.append({
                    "player": {
                        "id": player.id,
                        "username": player.username,
                        "nick_name": player.nick_name,
                        "score": player.score,
                        "status": player.status,
                        "is_banned": player.is_banned,
                        "game": player.game_id.game_name if player.game_id else None,
                        "created_by": player.created_by.user_id.username if player.created_by else None,
                        "is_notified_read": player.is_notified_read,
                        "created_ago": created_ago,  # Show the created_ago time
                    },
                    "wallet": {
                        "total_amount": player.user_id.wallet.total_amount if hasattr(player.user_id, 'wallet') else 0,
                    },
                    "free_play": {
                        "remaining_free_plays": player.user_id.free_play.free_plays if hasattr(player.user_id,
                                                                                               'free_play') else 0,
                    }
                })

            # Return pagination data along with players data
            return {
                "players_data": players_data,
                "pagination": {
                    "current_page": page_obj.number,
                    "total_pages": paginator.num_pages,
                    "total_items": paginator.count,
                    "has_next": page_obj.has_next(),
                    "has_previous": page_obj.has_previous(),
                }
            }
        except ValueError as ve:
            logging.error(f"Validation error: {ve}")
            raise
        except Exception as e:
            logging.error(f"Unexpected error while fetching players: {e}")
            raise

    @staticmethod
    @sync_to_async
    def game_creation_notifications(page=1, per_page=10, created_by_user_id=str):
        try:
            # Fetch games with is_notified_read = True
            games = Game.objects.filter(is_notified_read=False, created_by_user_id=created_by_user_id).all()

            print(f"Games: {games}")

            # Paginate the queryset
            paginator = Paginator(games, per_page)
            page_obj = paginator.get_page(page)

            # Log the pagination information
            print(f"Fetched page {page} of games with is_notified_read=True.")

            # Prepare response data for the current page of games
            games_data = []
            for game in page_obj.object_list:
                # Use Django's timesince to get the time difference
                created_ago = timesince(game.game_created_at) if game.game_created_at else None

                games_data.append({
                    "game": {
                        "id": game.id,
                        "game_id": game.game_id,
                        "game_name": game.game_name,
                        "is_notified_read": game.is_notified_read,
                        "created_ago": created_ago,
                    }
                })

            print(f"Games data: {games_data}")

            # Return pagination data along with games data
            return {
                "games_data": games_data,
                "pagination": {
                    "current_page": page_obj.number,
                    "total_pages": paginator.num_pages,
                    "total_items": paginator.count,
                    "has_next": page_obj.has_next(),
                    "has_previous": page_obj.has_previous(),
                }
            }
        except ValueError as ve:
            logging.error(f"Validation error: {ve}")
            raise
        except Exception as e:
            logging.error(f"Unexpected error while fetching games: {e}")
            raise

    @staticmethod
    @sync_to_async
    def reset_game_password(current_user: any, username: str, new_password: str, game_id: str) -> tuple[bool, Any] | bool:
        """
        Asynchronously reset the game password in the database, ensuring it's hashed.
        """
        try:
            player = Player.objects.filter(username=username, game_id=game_id).first()
            if not player:
                raise Player.DoesNotExist(f"Player with username '{username}' does not exist.")

            player.password = make_password(new_password)
            player.save()

            # Trigger the notification signal
            player_password_reset_signal.send(sender=Player, player=player, user=current_user)

            return True
        except Exception as e:
            print(f"Failed to reset game password: {e}")
            return False

    @staticmethod
    @sync_to_async
    def get_panel_scores_by_role(role_name: str, limit: int = 10) -> dict:
        """
        Fetches scores for users with the given role, including game and player account details.

        Args:
        role_name (str): The role name to filter users by.
        limit (int): The maximum number of results to return.

        Returns:
        list[dict]: A list of user scores with their game and account details.
        """
        try:
            # Fetch the role
            role = Role.objects.filter(roles=role_name).first()
            if not role:
                logging.warning(f"Role '{role_name}' not found.")
                return {}

            # Fetch top players for users having the given role
            players = (
                Player.objects.filter(user_id__role_id=role)
                .select_related('user_id', 'game_id')
                .order_by('-score')[:limit]
            )

            # Convert players to dictionary format
            data = {
                "datetime": datetime.now(tz=UTC).__str__(),
                "players": [player.to_dict() for player in players]
            }
            return data

        except Exception as e:
            logging.error(f"Unexpected error in get_panel_scores_by_role: {str(e)}")
            return {}

    @staticmethod
    @sync_to_async
    def add_score_to_player_account(username: str, score: float, game_id: str) -> dict:
        try:
            players = Player.objects.filter(username=username, game_id=game_id).order_by('-score').first()
            if not players:
                logging.warning(f"Player '{username}' not found for game ID '{game_id}'")
                return {"error": "Player not found"}

            # Ensure score is a float
            old_score = float(players.score) if players.score is not None else 0.0
            new_score = old_score + float(score)  # Explicitly convert `score` to float

            # Update player's score
            players.score = new_score
            players.save()

            # Convert player to dictionary format
            to_dict = players.to_dict()
            print(f"TO DICT: {to_dict}")

            data = {
                "datetime": datetime.now(tz=UTC).__str__(),
                "old_score": old_score,
                "new_score": new_score,
                "player": to_dict,
            }

            return data
        except ValueError as ve:
            logging.error(f"ValueError in add_score_to_player_account: {str(ve)}")
            return {"error": "Invalid score value"}
        except Exception as e:
            logging.error(f"Unexpected error in add_score_to_player_account: {str(e)}")
            return {"error": "An unexpected error occurred"}

    @staticmethod
    @sync_to_async
    def redeem_score_from_player_account(username: str, score: float, game_id: str) -> dict:
        try:
            players = Player.objects.filter(username=username, game_id=game_id).order_by('-score').first()
            if not players:
                logging.warning(f"Player '{username}' not found for game ID '{game_id}'")
                return {"error": "Player not found"}

            # Ensure score is a float
            old_score = float(players.score) if players.score is not None else 0.0
            new_score = old_score - float(score)  # Explicitly convert `score` to float

            # Update player's score
            players.score = new_score
            players.save()

            # Convert player to dictionary format
            to_dict = players.to_dict()
            print(f"TO DICT: {to_dict}")

            data = {
                "datetime": datetime.now(tz=UTC).__str__(),
                "old_score": old_score,
                "new_score": new_score,
                "player": to_dict,
            }

            return data
        except ValueError as ve:
            logging.error(f"ValueError in redeem_score_from_player_account: {str(ve)}")
            return {"error": "Invalid score value"}
        except Exception as e:
            logging.error(f"Unexpected error in redeem_score_from_player_account: {str(e)}")
            return {"error": "An unexpected error occurred"}

    @staticmethod
    def add_user_score(username: str, score: int, game_id: str) -> dict:
        """
        Add or update the user score in the database.
        If the user does not exist, create a new record with the given score.

        Args:
            username (str): The username of the player.
            score (int): The score to be added or updated.
            game_id (str): The ID of the game.

        Returns:
            dict: A dictionary containing success or error information.
        """
        try:
            # Check if the player exists
            game = Game.objects.get(id=game_id)

            if not game:
                raise ValueError(f"Game with ID '{game_id}' does not exist.")

            player = Player.objects.filter(username=username, game_id=game).first()
            if not player:
                raise ValueError(f"Player with username '{username}' does not exist for game '{game.game_name}'.")

            if game.is_free:
                # Update score if player exists
                player.free_scores = score
                player.save()
                return {
                    "message": "Score updated successfully.",
                    "player": {
                        "username": player.username,
                        "game_id": player.game_id.id,
                        "new_score": player.free_scores,
                    },
                }
            else:
                # Update score if player exists
                player.score = score
                player.save()
                return {
                    "message": "Score updated successfully.",
                    "player": {
                        "username": player.username,
                        "game_id": player.game_id.id,
                        "new_score": player.score,
                    },
                }

        except Exception as e:
            logging.error(f"Error adding/updating user score: {str(e)}")
            return {"message": f"An error occurred: {str(e)}"}

    @staticmethod
    @sync_to_async
    def redeem_user_score(username: str, score: int, game_id: str) -> dict:
        """
        Add or update the user score in the database.
        If the user does not exist, create a new record with the given score.

        Args:
            username (str): The username of the player.
            score (int): The score to be added or updated.
            game_id (str): The ID of the game.

        Returns:
            dict: A dictionary containing success or error information.
        """
        try:
            # Check if the player exists
            player = Player.objects.filter(username=username, game_id=game_id).first()

            if player.score < score:
                return {
                    "message": "Insufficient score to redeem.",
                    "player": None,  # Ensure the `player` key is present in error cases
                }

            if player is None:
                return {
                    "message": "Player not found.",
                    "player": None,  # Ensure the `player` key is always present
                }

            # Update score if player exists
            player.score -= score
            player.save()
            return {
                "message": "Score redeemed successfully.",
                "player": {
                    "username": player.username,
                    "game_id": player.game_id.id,
                    "new_score": player.score,
                },
            }

        except Exception as e:
            logging.error(f"Error adding/updating user score: {str(e)}")
            return {
                "message": f"An error occurred: {str(e)}",
                "player": None,  # Ensure the `player` key is present in error cases
            }

    async def start_scheduler_function(self) -> bool:
        """
        Asynchronously start the scheduler function.
        """
        if not self.scheduler_running:
            self.scheduler_running = True
            await asyncio.sleep(3)  # Placeholder for async start operation
            print("Scheduler started.")
            return True
        else:
            print("Scheduler is already running.")
            return False

    async def stop_scheduler_function(self) -> bool:
        """
        Asynchronously stop the scheduler function.
        """
        if self.scheduler_running:
            self.scheduler_running = False
            await asyncio.sleep(3)  # Placeholder for async stop operation
            print("Scheduler stopped.")
            return True
        else:
            print("Scheduler is not running.")
            return False

    async def browser_pool_destroy_pool(self) -> bool:
        """
        Asynchronously destroy the browser pool.
        """
        if self.current_browsers > 0:
            self.current_browsers = 0
            await asyncio.sleep(0.1)  # Placeholder for async destruction operation
            print("Browser pool destroyed.")
            return True
        else:
            print("Browser pool is already empty.")
            return False
