import uuid
from django.db.models.signals import post_migrate
from .models import Country, Level, SubscriptionPlan, SpinHistory, Prize, Spin, Role
from .utils import delete_all_referrals_after_given_time
import datetime
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.dispatch import Signal
from .models import Notification, Player
from django.contrib.auth import get_user_model

User = get_user_model()

# @receiver(post_migrate)
# def create_initial_data(sender, **kwargs):  # Add sender and **kwargs
#     # Data for insertion
#     country_data = ['United States', 'United Kingdom', 'Canada']
#     level_data = [('Level 0', 'L0', 100), ('Level 1', 'L1', 200), ('Level 2', 'L2', 500),
#                   ('Level 3', 'L3', 800), ('Level 4', 'L4', 5000)]
#     subscription_plan_data = [('Free', 0, 0), ('Premium', 50, 10), ('Elite', 100, 20)]
#     prize_data = [('Prize 1', 10, 0.1), ('Prize 2', 5, 0.2), ('Prize 3', 3, 0.3),
#                   ('Prize 4', 2, 0.4), ('Prize 5', 1, 0.5)]
#     ROLES_DATA = [
#         ('User', 'User role: Regular user with basic access to the application.'),
#         ('Agent', 'User Agent role: Can manage users and their permissions.'),
#         ('Admin', 'Administrator role: Has full access to all system features and settings.'),
#     ]

#     for role, description in ROLES_DATA:
#         Role.objects.get_or_create(roles=role, description=description)

#     for country in country_data:
#         Country.objects.get_or_create(country=country)

#     for level, code, score in level_data:
#         Level.objects.get_or_create(level=level, level_code=code, redemption_score_on_level=score)

#     for status, redemption, amount in subscription_plan_data:
#         SubscriptionPlan.objects.get_or_create(pro_status=status, redemption_on_free_subscription=redemption,
#                                                subscription_plan_amount=amount)

#     for name, quantity, probability in prize_data:
#         _, created = Prize.objects.get_or_create(
#             prize_id=str(uuid.uuid4()), name=name, defaults={'quantity': quantity, 'probability': probability})

#     for prize in Prize.objects.all():
#         for _ in range(5):
#             _, created = SpinHistory.objects.get_or_create(prize_id=prize)

#     spin_history_records = SpinHistory.objects.all()
#     for _ in range(5):
#         spin, created = Spin.objects.get_or_create(last_spin_checked=datetime.datetime.now())
#         spin.spin_history_id.set([*spin_history_records[:3]])

# @receiver(post_migrate)
# def delete_all_referrals(sender, **kwargs):  # Add sender and **kwargs
#     delete_all_referrals_after_given_time()

# Define customs signal
player_update_score_signal = Signal()
@receiver(player_update_score_signal)
def player_update_score_handler(instance, player, **kwargs):
    """
    Signal handler to create a notification when a player's score is updated.
    """
    Notification.objects.create(
        user=instance.user_id,
        notification_type="Player Update",
        message=f"Score has been updated by {player.username}."
    )

player_created_signal = Signal()
@receiver(player_created_signal)
def player_created_handler(sender, instance, user, **kwargs):
    """
    Signal handler to create a notification when a new player is created.
    """
    Notification.objects.create(
        user=instance.user_id,  # The owner of the player account
        notification_type="Player Create",
        message=f"Player '{instance.username}' has been created by {user.user_id.username}."
    )

player_password_reset_signal = Signal()
@receiver(player_password_reset_signal)
def player_password_reset_handler(sender, instance, user, **kwargs):
    """
    Signal handler to create a notification when a player's password is reset.
    """
    Notification.objects.create(
        user=instance.user_id,  # The owner of the player account
        notification_type="Player Update",
        message=f"Password has been reset by {user.user_id.username}."
    )

payment_signal = Signal()
@receiver(payment_signal)
def payment_handler(
        sender,
        user,
        notification_type:str = "Wallet Notification",
        message:str = "Your wallet notification goes here...",
        **kwargs):
    """
    Signal handler to create a notification when a player's password is reset.
    """
    Notification.objects.create(
        user=user,
        notification_type=notification_type,
        message=message
    )



