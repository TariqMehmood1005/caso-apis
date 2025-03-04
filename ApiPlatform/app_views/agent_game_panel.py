import logging
import asyncio
from asgiref.sync import sync_to_async
from django.contrib.auth.hashers import make_password
from django.conf import settings
from ApiPlatform.forms import AddScoreToPlayerForm
from ApiPlatform.models import Player, Game, User, Role, WalletTransactionHistory, Bonus, FreePlay
from ApiPlatform.signals import player_password_reset_signal
from typing import Any

class AgentGamePanel:
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
    def get_all_games_accounts(self) -> list[dict]:
        """
        Fetch all game accounts with details.

        Returns:
            list[dict]: A list of dictionaries containing game and player details.
        """
        try:
            # Query all players
            players = Player.objects.select_related('game_id', 'user_id').all()

            # Prepare structured response data
            accounts = []
            for player in players:
                accounts.append({
                    "player_id": str(player.id),
                    "username": player.username,
                    "nick_name": player.nick_name,
                    "score": player.score,
                    "status": player.status,
                    "is_banned": player.is_banned,
                    "account_created_at": player.account_created_at,
                    "game": {
                        "game_id": str(player.game_id.id),
                        "game_name": player.game_id.game_name if hasattr(player.game_id, 'game_name') else "N/A"
                    },
                    "user": {
                        "user_id": str(player.user_id.id),
                        "email": player.user_id.email if hasattr(player.user_id, 'email') else "N/A"
                    }
                })
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
            player = Player.objects.select_related('game_id').filter(username=username, game_id=game_id).first()

            if not player:
                return None  # No matching record found

            # Prepare structured response
            return {
                "player_id": str(player.id),
                "username": player.username,
                "nick_name": player.nick_name,
                "game": {
                    "game_id": str(player.game_id.id),
                    "game_name": player.game_id.game_name if hasattr(player.game_id, 'game_name') else "N/A"
                },
                "score": player.score,
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
                        "profile": player.created_by.profile_image.url
                        if player.created_by.profile_image else "N/A",
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
    @sync_to_async
    def reset_game_password(current_user: any, username: str, new_password: str, game_id: str) -> (
            tuple[bool, Any] | bool):
        """
        Asynchronously reset the game password in the database, ensuring it's hashed.
        """
        try:
            player = Player.objects.filter(username=username, game_id=game_id).first()
            if not player:
                raise ValueError(f"Player with username '{username}' does not exist.")

            player.password = make_password(new_password)
            player.save()

            # Trigger the notification signal
            player_password_reset_signal.send(instance=player, sender=Player, player=player, user=current_user)

            return True
        except Exception as e:
            raise ValueError(f"Failed to reset game password: {e}")

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
            users = User.objects.filter(role_id=role).prefetch_related('players')
            if not users.exists():
                raise User.DoesNotExist(f"No users found with role '{role_name}'.")

            # Fetch scores for each player associated with the users
            players = (
                Player.objects.filter(user_id__in=users)
                .select_related('user_id', 'game_id')
                .order_by('-score')[:limit]
            )

            # Prepare the response
            result = []
            for player in players:
                result.append({
                    "player_username": player.username,
                    "score": player.score,
                    "game_name": player.game_id.game_name,
                    "account_created_at": player.account_created_at,
                    "user_email": player.user_id.email,
                })

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
                form = AddScoreToPlayerForm({'username': username, 'score': score, 'game_id': game_id})

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
                form = AddScoreToPlayerForm({'username': username, 'score': score, 'game_id': game_id})

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
