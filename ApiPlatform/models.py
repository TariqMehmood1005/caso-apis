import datetime
import os
from random import random
import uuid
from django.contrib.auth.models import User as DjangoUser
from django.db import models
from django.db.models import ManyToManyField
from django.utils import timezone
from django.utils.timezone import now
from datetime import timedelta
import humanize
from CoinsSellingPlatformProject import settings


# TODO: This is done
def upload_to_agent_user_chats(instance: any = None, filename: str = None):
    """
    Custom upload path and filename for attachment images.
    Saves files as agent-user-chats/<sender_username>_<random_string>.<extension>.
    """
    # Extract the file extension
    file_extension = os.path.splitext(filename)[-1].lower()

    # Generate a new filename
    random_string = uuid.uuid4().hex[:8]  # Short random string
    if instance == instance.user_id:
        new_filename = f"{instance.user_id.user_id.username}_{random_string}{file_extension}"
    else:
        new_filename = f"{instance.agent_id.user_id.id}_{random_string}{file_extension}"

    # Return the full upload path
    return os.path.join("agent-user-chats/", new_filename)


# TODO: This is done
class BannedIP(models.Model):
    DoesNotExist = None
    objects = None

    ip_address = models.GenericIPAddressField(unique=True)
    ban_expiry = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    def is_active(self):
        return self.ban_expiry > now()

    def __str__(self):
        return f"{self.ip_address} banned until {self.ban_expiry}"


# TODO: This is done
class Role(models.Model):
    objects = None
    DoesNotExist = None

    ROLE_CHOICES = [
        ('User', 'User'),
        ('Agent', 'Agent'),
        ('Admin', 'Admin'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    roles = models.CharField(max_length=50, choices=ROLE_CHOICES, default='User')
    description = models.CharField(max_length=200, blank=True, null=True)
    role_created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name_plural = "Roles"
        ordering = ['role_created_at']

    def __str__(self):
        return f"ID: {self.id} - {self.roles}"

    def to_dict(self):
        return {
            'id': self.id,
            'roles': self.roles,
            'description': self.description,
            'role_created_at': self.role_created_at,
        }

# TODO: This is done
class Country(models.Model):
    objects = None
    DoesNotExist = None
    COUNTRY_CHOICES = [
        ('United States', 'United States'),
        ('United Kingdom', 'United Kingdom'),
        ('Canada', 'Canada'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    country = models.CharField(max_length=50, choices=COUNTRY_CHOICES, default='US', unique=True)
    country_created_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name_plural = "Countries"
        ordering = ['country_created_at']

    def __str__(self):
        return f"ID: {self.id} - {self.country}"


# TODO: This is done
class Level(models.Model):
    objects = None
    DoesNotExist = None
    level_choices = [
        ('Level 0', 'Level 0'),
        ('Level 1', 'Level 1'),
        ('Level 2', 'Level 2'),
        ('Level 3', 'Level 3'),
        ('Level 4', 'Level 4'),
    ]

    level_code_choices = [
        ('L0', 'L0'),
        ('L1', 'L1'),
        ('L2', 'L2'),
        ('L3', 'L3'),
        ('L4', 'L4'),
    ]

    Level_score = [
        (100, 100),  ## '100' from this to 100
        (200, 200),
        (500, 500),
        (800, 800),
        (5000, 5000),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    level = models.CharField(max_length=50, unique=True, null=True, blank=True, choices=level_choices)
    level_code = models.CharField(max_length=50, unique=True, null=True, blank=True, choices=level_code_choices)
    redemption_score_on_level = models.IntegerField(default=0, null=True, blank=True, choices=Level_score)
    level_created_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name_plural = "Levels"
        ordering = ['level_created_at']

    def __str__(self):
        return f"ID: {self.id} - {self.level} - {self.redemption_score_on_level}"


# TODO: This is done
class SubscriptionPlan(models.Model):
    objects = None
    DoesNotExist = None
    PRO_STATUS_CHOICES = [
        ('Free', 'Free'),
        ('Premium', 'Premium (Pro)'),
        ('Elite', 'Elite'),
    ]

    REDEMPTION_ON_FREE_SUBSCRIPTION = [
        (0, 0),  ## '0' from this to 0
        (50, 50),
        (100, 100),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    pro_status = models.CharField(max_length=50, choices=PRO_STATUS_CHOICES, default='Free')
    redemption_on_free_subscription = models.IntegerField(choices=REDEMPTION_ON_FREE_SUBSCRIPTION, default=None,
                                                          null=True, blank=True)
    subscription_plan_amount = models.PositiveIntegerField(default=0)
    subscription_plan_created_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name_plural = "Subscription Plans"
        ordering = ['subscription_plan_created_at']

    def __str__(self):
        return f"ID: {self.id} - {self.pro_status} - {self.redemption_on_free_subscription}"


# TODO: This is done
class OTPVerification(models.Model):
    objects = None
    DoesNotExist = None
    VERIFICATION_TYPE_CHOICES = [
        ('OTP', 'OTP'),
        ('password_reset', 'Password Reset'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    otp = models.CharField(max_length=6)
    otp_created_at = models.DateTimeField(auto_now_add=True)
    expire_at = models.DateTimeField(blank=True, null=True)
    verification_type = models.CharField(max_length=20, choices=VERIFICATION_TYPE_CHOICES, default='OTP')

    class Meta:
        verbose_name_plural = "OTP Verifications"
        ordering = ['otp_created_at']

    def __str__(self):
        return f"ID: {self.id} - {self.otp}"


# TODO: This is done
class Prize(models.Model):
    objects = None
    DoesNotExist = None
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    prize_id = models.CharField(max_length=100)
    name = models.CharField(max_length=100)  # e.g., "Better Luck Next Time"
    quantity = models.IntegerField()
    image = models.ImageField(default=None, upload_to="prizes/", blank=True, null=True)
    probability = models.FloatField()
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name_plural = "Prizes"
        ordering = ['created_at']

    def __str__(self):
        return f"ID: {self.id} - {self.name}"


# TODO: This is done
class SpinHistory(models.Model):
    objects = None
    DoesNotExist = None
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    prize_id = models.ForeignKey(Prize, on_delete=models.CASCADE, related_name='spin_histories')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name_plural = "Spin Histories"
        ordering = ['created_at']

    def __str__(self):
        return f"ID: {self.id} - {self.prize_id} - {self.created_at}"


# TODO: This is done
class Spin(models.Model):
    objects = None
    DoesNotExist = None
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    prizes_id = models.ManyToManyField(Prize, related_name='spins')
    last_spin_checked = models.DateTimeField(null=True, blank=True)
    spin_history_id = models.ManyToManyField(SpinHistory,
                                             related_name='spin_histories')  # Assuming the history is tracked for users

    class Meta:
        verbose_name_plural = "Spins"
        ordering = ['id']

    def __str__(self):
        return f"ID: {self.id} - {self.last_spin_checked}"


# TODO: This is done
class WalletTransactionHistory(models.Model):
    objects = None
    DoesNotExist = None
    PAYMENT_STATUS_CHOICES = [
        ('Pending', 'Pending'),
        ('Cancelled', 'Cancelled'),
        ('Approved', 'Approved'),
    ]

    PAYMENT_CHOICES = [
        ('Debit', 'Debit'),
        ('Credit', 'Credit'),
        ('Card', 'Card'),
        ('Crypto', 'Crypto'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    payment_method = models.CharField(max_length=50)
    payment_status = models.CharField(max_length=10, choices=PAYMENT_STATUS_CHOICES, default='Pending')
    transaction_amount = models.IntegerField()
    transaction_date = models.DateTimeField(auto_now=True)
    payment = models.CharField(max_length=10, choices=PAYMENT_CHOICES, default=None, blank=True, null=True)
    order_id = models.CharField(max_length=100, blank=True, null=True, default=None)
    withdrawal_percentage_tax = models.IntegerField(default=0)
    is_crypto_payment = models.BooleanField(default=False)

    class Meta:
        verbose_name_plural = "Wallet Transaction Histories"
        ordering = ['transaction_date']

    def __str__(self):
        return f"ID: {self.id} - {self.payment_method} - {self.payment_status} - {self.payment}"

    def apply_crypto_bonus(self):
        if self.is_crypto_payment:
            # Apply 5% bonus for crypto payments
            self.transaction_amount += int(self.transaction_amount * 0.05)

    def to_dict(self):
        return {
            'id': str(self.id),
            'payment_method': self.payment_method,
            'payment_status': self.payment_status,
            'transaction_amount': self.transaction_amount,
            'transaction_date': self.transaction_date,
            'payment': self.payment,
            'order_id': self.order_id,
            'withdrawal_percentage_tax': self.withdrawal_percentage_tax,
            'is_crypto_payment': self.is_crypto_payment,
        }

# TODO: This is done
class Wallet(models.Model):
    objects = None
    DoesNotExist = None
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    current_balance = models.IntegerField(default=0)
    total_amount = models.IntegerField(default=0)  # To store the total after multiplying by 2
    wallet_transaction_history_id = models.ManyToManyField(WalletTransactionHistory, related_name='wallets')
    order_id = models.CharField(max_length=100, blank=True, null=True, default=None)
    withdrawal_percentage_tax = models.IntegerField(default=0)
    last_transaction_date = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name_plural = "Wallets"
        ordering = ['id']

    def __str__(self):
        # user = User.objects.get(wallet_id=self.id)  - {user.user_id.username}
        return f"ID: {self.id}  - {self.current_balance} at {self.last_transaction_date.date()}"

    # update the last_transaction_date when a transaction is made
    def update(self):
        self.last_transaction_date = timezone.now()
        self.update()

    def to_dict(self):
        """ Returns a dictionary representation of the Wallet, including only the latest transaction """
        latest_transaction = self.wallet_transaction_history_id.order_by('-transaction_date').first()

        return {
            'id': str(self.id),
            'current_balance': self.current_balance,
            'total_amount': self.total_amount,
            'order_id': self.order_id,
            'withdrawal_percentage_tax': self.withdrawal_percentage_tax,
            'last_transaction': latest_transaction.to_dict() if latest_transaction else None,
        }


# TODO: This is done
class Game(models.Model):
    objects = None
    DoesNotExist = None
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    country = models.ManyToManyField(Country, related_name='games', blank=True, null=True)
    game_id = models.CharField(max_length=100, unique=True, null=True)
    game_name = models.CharField(max_length=255)
    game_description = models.TextField()
    game_image = models.ImageField(max_length=255, default="default-game.jpg", null=True,
                                   upload_to="game_images/")  # Path to game image
    game_video = models.FileField(max_length=255, null=True, default=None, upload_to="game_videos/")
    game_price = models.IntegerField()
    android_game_url = models.CharField(max_length=255, null=True)
    ios_game_url = models.CharField(max_length=255, null=True)
    browser_game_url = models.CharField(max_length=255, null=True)
    upcoming_status = models.BooleanField(default=False)
    is_trending = models.BooleanField(default=False)
    game_created_at = models.DateTimeField(auto_now_add=True)
    game_updated_at = models.DateTimeField(auto_now_add=True)
    game_reviews_id = models.ManyToManyField('GameReview', related_name='games', blank=True)
    score = models.PositiveIntegerField(default=0, null=True, blank=True)
    transfer_score_percentage = models.IntegerField(default=0)
    redeem_score_percentage = models.IntegerField(default=0)  # Withdrawal Percentage
    created_by_user_id = models.ForeignKey('User', on_delete=models.SET_NULL, null=True, blank=True,
                                           related_name='games')
    # free plays
    free_scores = models.PositiveIntegerField(default=0, null=True, blank=True)
    is_free = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    is_notified_read = models.BooleanField(default=False)
    is_promotional = models.BooleanField(default=False)
    gradient_style = models.CharField(max_length=255, default="#000000", null=True, blank=True)

    class Meta:
        verbose_name_plural = "Games"
        ordering = ['game_created_at']

    def save(self, *args, **kwargs):
        """Assign a dynamic gradient if not set"""
        if not self.gradient_style:
            self.gradient_style = generate_gradient()
        super().save(*args, **kwargs)

    def to_dict(self):
        return {
            'id': str(self.id),
            'game_id': self.game_id,
            'game_name': self.game_name,
            'game_description': self.game_description,
            'game_image': f"{settings.HOST}{self.game_image.url}" if self.game_image else None,
            'game_video': f"{settings.HOST}{self.game_video.url}" if self.game_video else None,
            'game_price': self.game_price,
            'android_game_url': self.android_game_url,
            'ios_game_url': self.ios_game_url,
            'browser_game_url': self.browser_game_url,
            'upcoming_status': self.upcoming_status,
            'is_trending': self.is_trending,
            'is_active': self.is_active,
            'is_free': self.is_free,
            'free_scores': self.free_scores,
            'transfer_score_percentage': self.transfer_score_percentage,
            'redeem_score_percentage': self.redeem_score_percentage,
            'created_by_user_id': str(self.created_by_user_id.id),
            'game_created_at': self.game_created_at,
            'game_updated_at': self.game_updated_at,
            'game_reviews_id': [str(review.id) for review in self.game_reviews_id.all()],
            'country': [country.country for country in self.country.all()],
            'score': self.score,
            'is_promotional': self.is_promotional,
            'gradient_style': self.gradient_style,
        }

    def __str__(self):
        return (f"ID: {self.id} | "
                f"Game Id: {self.game_id} | "
                f"Game Name: {self.game_name} - "
                f"is_free: {self.is_free} - "
                f"free score: {self.free_scores}")


def generate_gradient():
    """Generate a random gradient color for the game"""
    gradients = [
        "linear-gradient(45deg, #ff9a9e, #fad0c4)",
        "linear-gradient(45deg, #a18cd1, #fbc2eb)",
        "linear-gradient(45deg, #fad0c4, #ff9a9e)",
        "linear-gradient(45deg, #ffdde1, #ee9ca7)",
        "linear-gradient(45deg, #cfd9df, #e2ebf0)",
        "linear-gradient(45deg, #b2fefa, #0ed2f7)",
        "linear-gradient(45deg, #89f7fe, #66a6ff)",
    ]
    return random.choice(gradients)


# TODO: This is done
class GameTransactionHistory(models.Model):
    objects = None
    DoesNotExist = None
    PAYMENT_CHOICES = [
        ('debit', 'Debit'),
        ('credit', 'Credit'),
    ]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    game_id = models.ForeignKey(Game, on_delete=models.CASCADE, related_name='transaction_history', null=True,
                                blank=True)
    payment = models.CharField(max_length=10, choices=PAYMENT_CHOICES, default='debit')
    transaction_amount = models.IntegerField()
    transaction_date = models.DateTimeField(auto_now_add=True)
    order_id = models.CharField(max_length=100, blank=True, null=True, default=None)  # random order id
    withdrawal_percentage_tax = models.IntegerField(default=0)

    class Meta:
        verbose_name_plural = "Game Transaction History"
        ordering = ['transaction_date']

    def __str__(self):
        return f"ID: {self.id} - {self.game_id}"


# TODO: This is done
class GameRating(models.Model):
    objects = None
    DoesNotExist = None
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    game_id = models.ForeignKey(Game, on_delete=models.CASCADE, related_name='game_ratings')
    rating = models.DecimalField(max_digits=3, decimal_places=1, default=0)
    total_ratings = models.IntegerField(default=0)
    user_id = models.ForeignKey('User', on_delete=models.CASCADE, related_name='game_ratings')

    class Meta:
        verbose_name_plural = "Game Ratings"
        ordering = ['rating']

    def __str__(self):
        return f"ID: {self.id} - {self.game_id}"

    def to_dict(self):
        total_ratings = (self.total_ratings + self.rating) if self.total_ratings else 0
        return {
            'id': str(self.id),
            'game_id': str(self.game_id.id),
            'rating': self.rating,
            'total_ratings': total_ratings,
            'user_id': str(self.user_id.id),
        }


class Bonus(models.Model):
    objects = None
    DoesNotExist = None
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_id = models.ForeignKey('User', on_delete=models.CASCADE, related_name='bonuses')
    amount = models.IntegerField() # if user has deposited $100. It will be $200 means $100*2=$200
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name_plural = "Bonuses"
        ordering = ['created_at']

    def __str__(self):
        return f"ID: {self.id} - {self.user_id} - AMOUNT: {self.amount}"

    def to_dict(self):
        return {
            'id': str(self.id),
            'user_id': str(self.user_id.id),
            'amount': self.amount,  # Correct usage
            'created_at': self.created_at,
        }

# TODO: This is done
class User(models.Model):
    objects = None
    DoesNotExist = None
    GENDER_CHOICES = [
        ('M', 'Male'),
        ('F', 'Female'),
        ('O', 'Other'),
    ]
    select_documents = [
        ('driving_license', 'Driving License'),
        ('passport', 'Passport'),
        ('id_card', 'ID Card'),
    ]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    email = models.EmailField(max_length=100, unique=True)

    driving_license_front_image = models.ImageField(default=None, upload_to="user_profiles/license/",
                                                    blank=True, null=True)
    driving_license_back_image = models.ImageField(default=None, upload_to="user_profiles/license/",
                                                   blank=True, null=True)
    is_verified_license = models.BooleanField(default=False)

    gender = models.CharField(max_length=1, choices=GENDER_CHOICES, default='M')
    date_of_birth = models.DateField(blank=True, null=True)
    subscription_plan = models.ForeignKey(SubscriptionPlan, on_delete=models.SET_NULL, blank=True, null=True,
                                          related_name='users_subscription_plan', default=None)

    waiting_list = models.BooleanField(default=False)
    experience_points = models.FloatField(default=0, null=True, blank=True,
                                          help_text="Total experience points of the user. Used for level up.")

    profile_image = models.ImageField(default="default-user.jpg", upload_to="user_profiles/", blank=True, null=True)
    banner_image = models.ImageField(default="default-banner.jpg", upload_to="user_profiles/banners/",
                                     blank=True, null=True)

    # Front and Back images for ["CNIC", "Driving License", "Passport"]
    front_images = models.ImageField(default=None, upload_to="user_profiles/documents/", blank=True, null=True)
    back_images = models.ImageField(default=None, upload_to="user_profiles/documents/", blank=True, null=True)
    selected_documents = models.CharField(max_length=20, choices=select_documents, default=None, null=True, blank=True)

    referral = models.BooleanField(default=False)
    referral_key = models.CharField(max_length=100, blank=True, null=True)
    profile_created_at = models.DateTimeField(auto_now_add=True)
    profile_updated_at = models.DateTimeField(auto_now=True)

    # Custom Fields
    is_banned_from_global_chat = models.BooleanField(default=False)
    is_banned_from_agent_chat = models.BooleanField(default=False)

    phone = models.PositiveIntegerField(blank=True, null=True)  ### max_lenght=20 code missing
    is_phone_verified = models.BooleanField(default=False)

    # Foreign Keys
    user_id = models.OneToOneField(DjangoUser, on_delete=models.CASCADE, related_name='custom_user')
    user_level = models.ForeignKey(Level, on_delete=models.CASCADE, blank=True, null=True, related_name='user_levels')
    otp_verification_id = models.ForeignKey(OTPVerification, on_delete=models.CASCADE, blank=True, null=True,
                                            related_name='user_otp_verifications')
    country_id = models.ForeignKey(Country, on_delete=models.CASCADE, blank=True, related_name='user_countries')
    spin_id = models.ForeignKey(Spin, on_delete=models.CASCADE, blank=True, null=True, related_name='user_spins')
    wallet_id = models.OneToOneField(Wallet, on_delete=models.CASCADE, blank=False, null=False,
                                     related_name='user_wallets', unique=True)
    role_id = models.ForeignKey(Role, on_delete=models.CASCADE, blank=True, null=True, related_name='user_roles')

    last_active = models.DateTimeField(default=now)
    last_login = models.DateTimeField(default=now)
    is_last_active = models.BooleanField(default=False)

    failed_attempts = models.IntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey('self', on_delete=models.CASCADE, blank=True, null=True,
                                   related_name='created_users')

    def is_locked(self):
        if self.locked_until and self.locked_until > timezone.now():
            return True
        return False

    def reset_failed_attempts(self):
        self.failed_attempts = 0
        self.locked_until = None
        self.save()

    def update_experience_points(self, experience_points):
        self.experience_points += experience_points
        self.save()

    def update_last_active(self):
        self.last_active = now()
        self.is_last_active = True
        self.is_verified_license = True
        self.save()

    def to_dict(self):
        return {
            'id': str(self.id),
            'first_name': self.first_name,
            'last_name': self.last_name,
            'username': str(self.user_id.username) if self.user_id else None,
            'email': self.email,
            'driving_license_front_image': f"{settings.HOST}{self.driving_license_front_image.url}"
            if self.driving_license_front_image else None,
            'driving_license_back_image': f"{settings.HOST}{self.driving_license_back_image.url}"
            if self.driving_license_back_image else None,
            'is_verified_license': self.is_verified_license,
            'gender': self.gender,
            'date_of_birth': self.date_of_birth.isoformat() if self.date_of_birth else None,
            'subscription_plan': self.subscription_plan.pro_status if self.subscription_plan else None,
            'waiting_list': self.waiting_list,
            'experience_points': self.experience_points,
            'profile_image': f"{settings.HOST}{self.profile_image.url}" if self.profile_image else None,
            'banner_image': f"{settings.HOST}{self.banner_image.url}" if self.banner_image else None,
            'front_images': f"{settings.HOST}{self.front_images.url}" if self.front_images else None,
            'back_images': f"{settings.HOST}{self.back_images.url}" if self.back_images else None,
            'selected_documents': self.selected_documents,
            'referral': self.referral,
            'referral_key': self.referral_key,
            'profile_created_at': self.profile_created_at.isoformat(),
            'profile_updated_at': self.profile_updated_at.isoformat(),
            'is_banned_from_global_chat': self.is_banned_from_global_chat,
            'is_banned_from_agent_chat': self.is_banned_from_agent_chat,
            'phone': self.phone,
            'is_phone_verified': self.is_phone_verified,
            'user_id': str(self.user_id.id) if self.user_id else None,
            'user_level': self.user_level.level if self.user_level else None,
            'otp_verification_id': str(self.otp_verification_id.id) if self.otp_verification_id else None,
            'country_name': self.country_id.country if self.country_id else None,

            'spin_id': str(self.spin_id.id) if self.spin_id else None,
            'wallet_id': self.wallet_id.to_dict() if self.wallet_id else None,
            'role_id': self.role_id.roles if self.role_id else None,
            'last_active': self.last_active.isoformat(),
            'is_last_active': self.is_last_active,
            'failed_attempts': self.failed_attempts,
            'locked_until': self.locked_until.isoformat() if self.locked_until else None,
            'is_banned': self.user_id.is_active,
            'created_by': self.created_by.email if self.created_by else None,
            'is_active': self.user_id.is_active,
        }

    class Meta:
        verbose_name_plural = "Users"
        ordering = ['profile_created_at']

    def __str__(self):
        return (f""
                f"ID: {self.id} - "
                f"{self.user_id.username} - "
                f"({self.role_id.roles}) - "
                f"{self.subscription_plan.pro_status}")

    def update(self):
        self.save()


# TODO: This is done
class FreePlay(models.Model):
    objects = None
    DoesNotExist = None
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='free_plays')
    free_plays = models.PositiveIntegerField(default=0)  # it can be dollars
    spins_left = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = self.created_at + timedelta(days=30)
        super().save(*args, **kwargs)

    def use_free_play(self):
        if self.spins_left > 0:
            self.spins_left -= 1
            self.save()

    def __str__(self):
        return f"ID: {self.id} - {self.user.user_id.username} - {self.free_plays} Free Plays"

    class Meta:
        ordering = ['-created_at']


# TODO: This is done
class AgentChat(models.Model):
    objects = None
    DoesNotExist = None
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_id = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_agent_chats', null=True,
                                blank=True, default=None)
    agent_id = models.ForeignKey(User, on_delete=models.CASCADE, related_name='agent_agent_chats', null=True,
                                 blank=True, default=None)
    message_content = models.TextField()
    attachment_image = models.ImageField(blank=True, null=True, default=None, upload_to=upload_to_agent_user_chats)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='active')
    is_agent_send = models.BooleanField(default=False)
    agent_chat_created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name_plural = "Agent Chats"
        ordering = ['agent_chat_created_at']

    def __str__(self):
        return (f"User: {self.user_id}"
                f"- Agent: {self.agent_id}"
                f"- Status: {self.status}"
                f"- Created at: {self.agent_chat_created_at}"
                )


# TODO: This is done
class GlobalChat(models.Model):
    objects = None
    DoesNotExist = None
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_id = models.ForeignKey(User, on_delete=models.CASCADE, related_name='global_chats')
    message_content = models.TextField(null=False)
    global_chat_created_at = models.DateTimeField(auto_now_add=True)
    is_pinned = models.BooleanField(default=False)

    class Meta:
        verbose_name_plural = "Global Chats"
        ordering = ['global_chat_created_at']

    def __str__(self):
        return f"ID: {self.id} - {self.user_id} - {self.message_content}"


# TODO: This is done
class Referral(models.Model):
    objects = None
    DoesNotExist = None
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_id = models.ForeignKey(User, on_delete=models.CASCADE, related_name='referrals')
    receiver_user_id = models.ManyToManyField(User, related_name='received_referrals', blank=True)
    referral_key = models.CharField(max_length=255, unique=True)
    quantity = models.IntegerField()
    referral_created_at = models.DateTimeField(auto_now_add=True)
    referral_expiry_date = models.DateField(default=datetime.date.today() + datetime.timedelta(days=60),
                                            null=True, blank=True)

    class Meta:
        verbose_name_plural = "Referrals"
        ordering = ['referral_created_at']

    def __str__(self):
        return f"ID: {self.id} - User {self.user_id}"

    def to_dict(self):
        return {
            'id': str(self.id),
            'user_id': self.user_id.to_dict() if hasattr(self.user_id, "to_dict") else str(self.user_id.id),
            'receiver_user_id': [
                user.to_dict() if hasattr(user, "to_dict") else str(user.id) for user in self.receiver_user_id.all()
            ],
            'referral_key': self.referral_key,
            'quantity': self.quantity,
            'referral_created_at': self.referral_created_at.isoformat(),
            'referral_expiry_date': self.referral_expiry_date.isoformat() if self.referral_expiry_date else None,
        }


# TODO: This is done
class Player(models.Model):
    objects = None
    DoesNotExist = None
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = models.CharField(max_length=255)
    nick_name = models.CharField(max_length=255)
    password = models.CharField(max_length=255)

    score = models.FloatField(default=0, null=True, blank=True)
    free_scores = models.FloatField(default=0, null=True, blank=True)

    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='active')
    is_banned = models.BooleanField(default=False)
    account_created_at = models.DateTimeField(auto_now_add=True)
    account_updated_at = models.DateTimeField(auto_now=True)

    user_id = models.ForeignKey(User, on_delete=models.CASCADE, related_name='players')
    game_id = models.ForeignKey(Game, on_delete=models.CASCADE, related_name='players')

    game_transaction_history_id = models.ManyToManyField(GameTransactionHistory, related_name='players', blank=True)

    is_notified_read = models.BooleanField(default=False)

    # created_by with role - Admin, and Agent
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, blank=True, null=True,
                                   related_name='created_players')

    class Meta:
        verbose_name_plural = "Players"
        ordering = ['account_created_at']

    def __str__(self):
        return f"ID: {self.id} - {self.username}"

    def to_dict(self):
        return {
            'id': str(self.id),  # Convert UUID to string for serialization
            'username': self.username,
            'nick_name': self.nick_name,
            'score': self.score,
            'free_scores': self.free_scores,
            'status': self.status,
            'is_banned': self.is_banned,
            'account_created_at': self.account_created_at.isoformat(),  # Convert datetime to string
            'account_updated_at': self.account_updated_at.isoformat(),  # Convert datetime to string
            'user_id': self.user_id.to_dict() if self.user_id else None,  # Avoid serializing whole object
            'game_id': self.game_id.to_dict() if self.game_id else None,  # Avoid serializing whole object
            'game_transaction_history_id': [str(tx.id) for tx in self.game_transaction_history_id.all()],
            # Convert ManyToManyField to a list of IDs
            'is_notified_read': self.is_notified_read,
            'created_by': str(self.created_by.id) if self.created_by else None,  # Avoid serializing whole object
        }


# TODO: This is done
class AdminReply(models.Model):
    objects = None
    DoesNotExist = None
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    admin_id = models.ForeignKey('User', on_delete=models.CASCADE, related_name='admin_replies',
                                 null=True, blank=True)
    message_content = models.CharField(max_length=100)
    reply_help_full_id = models.ManyToManyField('ReplyHelpFull', related_name='admin_replies', blank=True)
    reply_not_help_full_id = models.ManyToManyField('ReplyNotHelpFull', related_name='admin_replies', blank=True)
    helpful_counter = models.IntegerField(default=0)
    is_yes = models.BooleanField(default=False)
    reply_posted_at = models.DateTimeField(auto_now_add=True)
    game_review_id = models.ForeignKey('GameReview', on_delete=models.CASCADE, related_name='admin_replies',
                                       null=True, blank=True)
    rated_by_user_id = ManyToManyField('User', related_name='rated_admin_replies')

    class Meta:
        verbose_name_plural = "Admin Replies"
        ordering = ['reply_posted_at']

    def to_dict(self):
        return {
            'id': str(self.id),
            'message_content': self.message_content,
            'helpful_counter': self.helpful_counter,
            'is_yes': self.is_yes,
            'reply_posted_at': humanize.naturaltime(self.reply_posted_at),
            "admin": self.admin_id.to_dict(),
        }

    def __str__(self):
        return f"ID: {self.id} - {self.message_content}"


# TODO: not found in  my code
class GameReviewRating(models.Model):
    objects = None
    DoesNotExist = None
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey('User', on_delete=models.CASCADE)
    review = models.ForeignKey('GameReview', on_delete=models.CASCADE, related_name="ratings_data")
    rating = models.DecimalField(max_digits=2, decimal_places=1, default=0)
    is_yes = models.BooleanField(default=False)  # For satisfied users

    class Meta:
        unique_together = ('user', 'review')  # Ensure one rating per user


# TODO: This is done
class GameReview(models.Model):
    objects = None
    DoesNotExist = None
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    message_content = models.CharField(max_length=100)
    user_id = models.ForeignKey('User', on_delete=models.CASCADE, related_name='game_reviews')
    ratings = models.DecimalField(max_digits=2, decimal_places=1, default=0)
    helpful_counter = models.IntegerField(default=0)  # For satisfied users
    review_help_full_id = models.ManyToManyField('ReviewHelpFull', related_name='game_reviews', blank=True)
    review_not_help_full_id = models.ManyToManyField('ReviewNotHelpFull', related_name='game_reviews',
                                                     blank=True)  # not found
    review_posted_at = models.DateTimeField(auto_now_add=True)
    admin_replies_id = models.OneToOneField('AdminReply', on_delete=models.SET_NULL, null=True, blank=True)
    game_id = models.ForeignKey('Game', on_delete=models.CASCADE, related_name='game_reviews', null=True, blank=True)

    class Meta:
        verbose_name_plural = "Game Reviews"
        ordering = ['review_posted_at']

    def __str__(self):
        return f"ID: {self.id} - {self.message_content}"

    # not found
    def to_dict(self):
        return {
            'id': str(self.id),
            'message_content': self.message_content,
            'user_id': self.user_id.to_dict(),
            'ratings': self.ratings,
        }


# TODO: not found
class ReviewHelpFull(models.Model):
    objects = None
    DoesNotExist = None
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_id = models.ForeignKey(User, on_delete=models.SET_NULL, related_name='review_help_full',
                                null=True, blank=True)
    review_id = models.ForeignKey(GameReview, on_delete=models.SET_NULL, related_name='review_help_full',
                                  null=True, blank=True)
    is_liked = models.BooleanField(default=False)

    class Meta:
        verbose_name_plural = "Review Help Full"
        ordering = ['is_liked']

    def __str__(self):
        return f"ID: {self.id} - {self.user_id} - {self.review_id}"

    def to_dict(self):
        return {
            'id': str(self.id),
            'user_id': self.user_id.to_dict(),
            'review_id': self.review_id.to_dict(),
            'is_liked': self.is_liked,
        }


# TODO: not found
class ReviewNotHelpFull(models.Model):
    objects = None
    DoesNotExist = None
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_id = models.ForeignKey(User, on_delete=models.SET_NULL, related_name='review_not_help_full',
                                null=True, blank=True)
    review_id = models.ForeignKey(GameReview, on_delete=models.SET_NULL, related_name='review_not_help_full',
                                  null=True, blank=True)
    is_liked = models.BooleanField(default=False)

    class Meta:
        verbose_name_plural = "Review Not Help Full"
        ordering = ['is_liked']

    def __str__(self):
        return f"ID: {self.id} - {self.user_id} - {self.review_id}"

    def to_dict(self):
        return {
            'id': str(self.id),
            'user_id': self.user_id.to_dict(),
            'review_id': self.review_id.to_dict(),
            'is_liked': self.is_liked,
        }


# TODO: not found
class ReplyHelpFull(models.Model):
    objects = None
    DoesNotExist = None
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_id = models.ForeignKey(User, on_delete=models.SET_NULL, related_name='reply_help_full',
                                null=True, blank=True)
    reply_id = models.ForeignKey(AdminReply, on_delete=models.SET_NULL, related_name='reply_help_full',
                                 null=True, blank=True)
    is_liked = models.BooleanField(default=False)

    class Meta:
        verbose_name_plural = "Reply Help Full"
        ordering = ['is_liked']

    def __str__(self):
        return f"reply id: {self.id} - user id: {self.user_id} - reply id: {self.reply_id}"

    def to_dict(self):
        return {
            'id': str(self.id),
            'user_id': self.user_id.to_dict(),
            'reply_id': self.reply_id.to_dict(),
            'is_liked': self.is_liked,
        }


# TODO: not found
class ReplyNotHelpFull(models.Model):
    objects = None
    DoesNotExist = None
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_id = models.ForeignKey(User, on_delete=models.SET_NULL, related_name='reply_not_help_full',
                                null=True, blank=True)
    reply_id = models.ForeignKey(AdminReply, on_delete=models.SET_NULL, related_name='reply_not_help_full',
                                 null=True, blank=True)
    is_liked = models.BooleanField(default=False)

    class Meta:
        verbose_name_plural = "Reply Not Help Full"
        ordering = ['is_liked']

    def __str__(self):
        return f"ID: {self.id} - {self.user_id} - {self.reply_id}"

    def to_dict(self):
        return {
            'id': str(self.id),
            'user_id': self.user_id.to_dict(),
            'reply_id': self.reply_id.to_dict(),
            'is_liked': self.is_liked,
        }


# TODO: This is done
class PromoCode(models.Model):
    objects = None
    DoesNotExist = None
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    promo_code = models.CharField(max_length=50, unique=True)
    bonus_percentage = models.IntegerField(default=0)
    promo_code_created_at = models.DateTimeField(auto_now_add=True)
    sender_user_id = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_promo_codes',
                                       blank=True, null=True)
    receiver_user_id = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_promo_codes',
                                         blank=True, null=True)
    is_expired = models.BooleanField(default=False)

    class Meta:
        verbose_name_plural = "Promo Codes"
        ordering = ['promo_code_created_at']

    def __str__(self):
        return f"ID: {self.id} - {self.promo_code}"


class Message(models.Model):
    objects = None
    DoesNotExist = None
    STATUS_CHOICES = [
        ('sent', 'Sent'),
        ('read', 'Read'),
        ('pending', 'Pending'),
    ]
    MESSAGE_TYPE_CHOICES = [
        ('text', 'Text'),
        ('image', 'Image'),
        ('file', 'File'),
    ]
    message_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    sender = models.ForeignKey(User, related_name='sent_messages', on_delete=models.CASCADE)
    receiver = models.ForeignKey(User, related_name='received_messages', on_delete=models.CASCADE)
    message_content = models.TextField()
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='sent')
    timestamp = models.DateTimeField(auto_now_add=True)
    message_type = models.CharField(max_length=10, choices=MESSAGE_TYPE_CHOICES, default='text')
    is_send_by_agent = models.BooleanField(default=False)
    is_seen = models.BooleanField(default=False)

    class Meta:
        ordering = ['-timestamp']
        verbose_name_plural = "Messages"

    def __str__(self):
        return (f"ID: {self.message_id} Message from {self.sender.user_id.username} to "
                f"{self.receiver.user_id.username}")

    def to_dict(self):
        return {
            'message_id': str(self.message_id),
            'sender': self.sender.to_dict(),
            'receiver': self.receiver.to_dict(),
            'message_content': self.message_content,
            'status': self.status,
            'timestamp': self.timestamp,
            'message_type': self.message_type,
            'is_send_by_agent': self.is_send_by_agent,
            'is_seen': self.is_seen,
        }


class MessageConversation(models.Model):
    objects = None
    DoesNotExist = None
    conversation_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, related_name='user_conversations', on_delete=models.CASCADE)
    agent = models.ForeignKey(User, related_name='agent_conversations', on_delete=models.CASCADE)
    started_at = models.DateTimeField(auto_now_add=True)
    last_message_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return (f"ID: {self.conversation_id} Conversation between {self.user.user_id.username} and "
                f"{self.agent.user_id.username}")


class Notification(models.Model):
    objects = None
    DoesNotExist = None

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    message = models.TextField()
    notification_type = models.CharField(max_length=50, blank=True, null=True)
    is_read = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)

    # created by user
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')

    class Meta:
        ordering = ['-created_at']
        verbose_name_plural = "Notifications"

    def __str__(self):
        return f"ID: {self.id} - {self.user.user_id.username} - {self.message} - {self.created_at}"

# TODO: not found in sir code
class GamePlay(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="game_plays")
    game = models.ForeignKey(Game, on_delete=models.CASCADE, related_name="game_plays")
    played_at = models.DateTimeField(auto_now_add=True)
    profit = models.FloatField(default=0)

    def __str__(self):
        return f"{self.user.user_id.username} played {self.game.game_name} on {self.played_at}"

    class Meta:
        ordering = ['-played_at']  # You can adjust this if you need to display latest plays firsts


# TODO: not found in sir code
class Payment(models.Model):

    COIN_CHOICES = [
        ("BTC", "Bitcoin"),
        ("ETH", "Ethereum"),
        ("USDT", "Tether"),
        ("LTC", "Litecoin"),
    ]

    NETWORK_CHOICES = {
        "BTC": [("Bitcoin", "Bitcoin"), ("Lightening", "Lightening")],
        "ETH": [("ERC20", "ERC20"), ("BEP20", "BEP20")],
        "USDT": [("TRC20", "TRC20"), ("ERC20", "ERC20")],
        "LTC": [("Lightcoin", "Lightcoin")],
    }

    STATUS_CHOICES = [
        ("Pending", "Pending"),
        ("Approved", "Approved"),
        ("Cancelled", "Cancelled"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    payment_method = models.CharField(max_length=50)

    # Cash app, ...
    amount = models.DecimalField(max_digits=10, decimal_places=2)

    coin = models.CharField(max_length=50, choices=COIN_CHOICES, blank=True, null=True)

    network = models.CharField(max_length=50, choices=NETWORK_CHOICES, blank=True, null=True)

    wallet_address = models.CharField(max_length=255, blank=True, null=True)
    card_number = models.CharField(max_length=16, blank=True, null=True)
    card_name = models.CharField(max_length=100, blank=True, null=True)
    card_expiry_date = models.CharField(max_length=5, blank=True, null=True)
    card_cvv = models.CharField(max_length=3, blank=True, null=True)

    upload_proof = models.ImageField(upload_to='payment_screenshots/', blank=True, null=True)

    account_title = models.CharField(max_length=255, blank=True, null=True)
    cash_tag = models.CharField(max_length=255, blank=True, null=True)
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='Pending')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.payment_method}"
