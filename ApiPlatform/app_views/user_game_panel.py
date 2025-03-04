import logging
import asyncio
from typing import Any

from asgiref.sync import sync_to_async
from django.contrib.auth.hashers import make_password
from ApiPlatform.forms import AddScoreToPlayerForm
from ApiPlatform.models import Player, Game, User, Role, FreePlay
from ApiPlatform.signals import player_update_score_signal


class UserGamePanel:
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
        if (
            user_load > self.current_browsers
            and self.current_browsers < self.total_browsers
        ):
            additional_browsers = min(
                user_load - self.current_browsers,
                self.total_browsers - self.current_browsers,
            )
            self.current_browsers += additional_browsers
            print(f"Scaled up to {self.current_browsers} browsers")
        elif (
            user_load < self.current_browsers
            and self.current_browsers > self.number_of_browsers
        ):
            reduce_browsers = min(
                self.current_browsers - user_load,
                self.current_browsers - self.number_of_browsers,
            )
            self.current_browsers -= reduce_browsers
            print(f"Scaled down to {self.current_browsers} browsers")

    @sync_to_async
    def get_all_games_accounts(self) -> list[dict]:
        """
        Fetch all game accounts with details.

        Returns:
            list[dict]: A list of dictionaries containing game and player details.
        """
        try:
            # Query all players
            players = Player.objects.select_related("game_id", "user_id").all()

            # Prepare structured response data
            accounts = []
            for player in players:
                accounts.append(
                    {
                        "player_id": str(player.id),
                        "username": player.username,
                        "nick_name": player.nick_name,
                        "score": player.score,
                        "status": player.status,
                        "is_banned": player.is_banned,
                        "account_created_at": player.account_created_at,
                        "game": {
                            "game_id": str(player.game_id.id),
                            "game_name": (
                                player.game_id.game_name
                                if hasattr(player.game_id, "game_name")
                                else "N/A"
                            ),
                        },
                        "user": {
                            "user_id": str(player.user_id.id),
                            "email": (
                                player.user_id.email
                                if hasattr(player.user_id, "email")
                                else "N/A"
                            ),
                        },
                    }
                )
            return accounts

        except Exception as e:
            logging.error(f"Error in get_all_games_accounts: {str(e)}")
            return []

    @staticmethod
    def get_game_score(username: str, game_id: int) -> dict | None:
        """
        Fetch the game score for a specific player and game.

        Args:
            username (str): The username of the player.
            game_id (int): The ID of the game.

        Returns:
            dict | None: A dictionary with game and player details, or None if not found.
        """
        try:
            # Fetch the player matching the username and game ID
            player = (
                Player.objects.select_related("game_id")
                .filter(username=username, game_id=game_id)
                .first()
            )

            if not player:
                return None  # No matching record found

            # Prepare structured response
            return {
                "player_id": str(player.id),
                "username": player.username,
                "nick_name": player.nick_name,
                "game": {
                    "game_id": str(player.game_id.id),
                    "game_name": (
                        player.game_id.game_name
                        if hasattr(player.game_id, "game_name")
                        else "N/A"
                    ),
                },
                "score": player.score,
            }

        except Exception as e:
            logging.error(f"Error in get_game_score: {str(e)}")
            return None

    @staticmethod
    @sync_to_async
    def create_player(
        user_id: int, username: str, nickname: str, password: str, game_id: str
    ) -> Any | None:
        """
        Create a player associated with the given game, user, and username.
        Validates all required fields, checks for existing players, and ensures
        the creator has the correct role.
        """
        try:
            game = Game.objects.filter(id=game_id).first()
            if not game:
                raise ValueError(f"Game with name '{game.game_name}' does not exist.")

            # Validate the user
            user = User.objects.filter(id=user_id).first()

            if not user:
                raise ValueError(f"{user.user_id.username} does not exist.")

            # $500 >= $6
            # 500 - 6 = $494
            if (
                user.wallet_id.total_amount >= game.game_price
                and user.wallet_id.current_balance - game.game_price >= game.game_price
            ):

                free_play = FreePlay.objects.filter(user=user).first()
                # deduct money from wallet
                user.wallet_id.total_amount -= game.game_price
                free_play.free_plays -= game.game_price
                free_play.save()
                user.wallet_id.save()

            else:
                raise ValueError(
                    f"User {user.user_id.username} does not have enough money to "
                    f"play this game. Your current balance is "
                    f"{user.wallet_id.total_amount} and the game price is {game.game_price}"
                )

            # Validate the creator's role
            role = Role.objects.filter(roles="User").first()

            if not role:
                raise ValueError("User role does not exist.")

            created_by_user = User.objects.filter(id=user.id, role_id=role).first()

            if not created_by_user:
                raise ValueError(
                    f"Invalid role: {user.user_id.username} has an invalid role."
                )

            # Check for an existing player with the same username for the given game
            existing_player = Player.objects.filter(
                username=username, game_id=game
            ).first()
            if existing_player:
                raise ValueError(
                    f"Player with username '{username}' "
                    f"already exists for game '{game.game_name}'."
                )

            # Create the player
            player = Player.objects.create(
                username=username,
                nick_name=nickname,  # Nickname defaults to the username
                password=make_password(password),
                user_id=user,
                game_id=game,
                created_by=created_by_user,
            )

            logging.info(
                f"Player '{player.username}' successfully created for game '{game.game_name}'."
            )
            return player

        except ValueError as ve:
            logging.error(f"Validation error: {ve}")
            raise  # Let the caller handle validation errors
        except Exception as e:
            logging.error(f"Unexpected error while creating player: {e}")
            return None

    @staticmethod
    @sync_to_async
    def get_all_my_accounts(created_by) -> list[dict]:
        """
        Fetches all players created by the specified user with the Agent role.

        Args:
            created_by (str): The ID of the user who created the players (must be an Agent).

        Returns:
            list[dict]: A list of player details.
        """
        # Fetch players created by the specified user
        players = Player.objects.filter(created_by=created_by).all()
        print(f"players: {players}")
        if not players.exists():
            logging.info(f"No players found for user with ID '{created_by}'.")
            return []

        try:
            # Prepare structured response
            return [
                {
                    "game": {
                        "game_id": str(player.game_id.id),
                        "game_name": getattr(player.game_id, "game_name", "N/A"),
                        "game_description": getattr(
                            player.game_id, "game_description", "N/A"
                        ),
                        "game_image": (
                            player.game_id.game_image.url
                            if player.game_id.game_image
                            else "N/A"
                        ),
                    },
                    "player": {
                        "player_id": str(player.id),
                        "username": player.username,
                        "nick_name": player.nick_name,
                        "score": player.score,
                        "status": player.status,
                        "is_banned": player.is_banned,
                    },
                    "created_by": {
                        "user_id": str(player.created_by.id),
                        "email": player.created_by.email,
                        "username": player.created_by.user_id.username,
                        "role": player.created_by.role_id.roles,
                    },
                }
                for player in players
            ]
        except Exception as e:
            logging.error(f"Unexpected error in fetching players: {str(e)}")
            return []

    @staticmethod
    @sync_to_async
    def reset_game_password(username: str, new_password: str, game_id: str) -> bool | tuple[bool, Any]:
        """
        Asynchronously reset the game password in the database, ensuring it's hashed.
        """
        try:
            player = Player.objects.filter(username=username, game_id=game_id).first()
            if not player:
                raise Player.DoesNotExist(
                    f"Player with username '{username}' does not exist."
                )

            player.password = make_password(new_password)
            player.save()

            return True, player
        except Exception as e:
            print(f"Failed to reset game password: {e}")
            return False

    @staticmethod
    @sync_to_async
    def get_panel_scores_by_role(role_name: str, limit: int = 10) -> list[dict]:
        """
        Fetches scores for users with the given role, including game and player account details.

        Args:
        role_name (str): The role name to filter users by.
        limit (int): The maximum number of results to return.

        Returns:
        list[dict]: A list of user scores with their game and account details.
        """
        try:
            # Get the role
            role = Role.objects.filter(roles=role_name).first()
            if not role:
                raise Role.DoesNotExist(f"Role with name '{role_name}' does not exist.")

            # Get all users with the role
            users = User.objects.filter(role_id=role).prefetch_related("players")
            if not users.exists():
                raise User.DoesNotExist(f"No users found with role '{role_name}'.")

            # Fetch scores for each player associated with the users
            players = (
                Player.objects.filter(user_id__in=users)
                .select_related("user_id", "game_id")
                .order_by("-score")[:limit]
            )

            # Prepare the response
            result = []
            for player in players:
                result.append(
                    {
                        "player_username": player.username,
                        "score": player.score,
                        "game_name": player.game_id.game_name,
                        "account_created_at": player.account_created_at,
                        "user_email": player.user_id.email,
                    }
                )

            return result

        except Role.DoesNotExist as e:
            logging.error(f"Role error: {str(e)}")
            return []
        except User.DoesNotExist as e:
            logging.error(f"User error: {str(e)}")
            return []
        except Exception as e:
            logging.error(f"Unexpected error in get_panel_scores_by_role: {str(e)}")
            return []

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
            player = Player.objects.filter(username=username, game_id=game_id).first()

            if player:
                # Update score if player exists
                player.score += score
                player.save()
                return {
                    "message": "Score updated successfully.",
                    "player": {
                        "username": player.username,
                        "game_id": player.game_id.id,
                        "new_score": player.score,
                    },
                }
            else:
                # Create a new player entry if it doesn't exist
                form = AddScoreToPlayerForm(
                    {"username": username, "score": score, "game_id": game_id}
                )

                if form.is_valid():
                    new_player = form.save()
                    return {
                        "message": "Player created and score added successfully.",
                        "player": {
                            "username": new_player.username,
                            "game_id": new_player.game_id.id,
                            "new_score": new_player.score,
                        },
                    }
                else:
                    return {
                        "message": "Invalid data provided.",
                        "errors": form.errors,
                    }
        except Exception as e:
            logging.error(f"Error adding/updating user score: {str(e)}")
            return {"message": f"An error occurred: {str(e)}"}

    @staticmethod
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

            if player:
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
            else:
                # Create a new player entry if it doesn't exist
                form = AddScoreToPlayerForm(
                    {"username": username, "score": score, "game_id": game_id}
                )

                if form.is_valid():
                    new_player = form.save()
                    return {
                        "message": "Player created and score added successfully.",
                        "player": {
                            "username": new_player.username,
                            "game_id": new_player.game_id.id,
                            "new_score": new_player.score,
                        },
                    }
                else:
                    return {
                        "message": "Invalid data provided.",
                        "errors": form.errors,
                    }
        except Exception as e:
            logging.error(f"Error adding/updating user score: {str(e)}")
            return {"message": f"An error occurred: {str(e)}"}

    @staticmethod
    def get_user_score(username: str, game_id: str) -> dict:
        try:
            player = Player.objects.filter(username=username, game_id=game_id).first()
            if player:
                return {
                    "username": player.username,
                    "game_id": player.game_id.id,
                    "score": player.score,
                }
            else:
                return {"message": "Player not found."}
        except Exception as e:
            logging.error(f"Error getting user score: {str(e)}")
            return {"message": f"An error occurred: {str(e)}"}

    @staticmethod
    def update_score(current_user:any, username: str, score: int, game_id: str, user) -> dict:
        try:
            game = Game.objects.get(id=game_id)
            # Fetch the player object associated with the username and game_id
            player = Player.objects.filter(
                username=username, game_id=game.id, user_id=user
            ).first()
            if not player:
                return {"message": f"Player with username {username} not found."}
            if game.is_free:
                player.free_scores += score
            else:
                player.score += score
            player.save()

            # Trigger the notification signal
            player_update_score_signal.send(sender=Player, instance=player, player=player, user=current_user)

            return {
                "id": str(player.id),
                "username": player.username,
                "game": player.game_id.game_name,
                "score": player.score,
                "free_scores": player.free_scores,
            }
        except Game.DoesNotExist:
            return {"message": "Game not found."}
        except Exception as e:
            logging.error(f"Error updating user score: {str(e)}")
            return {"message": f"An error occurred: {str(e)}"}

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
