from django import forms
from .models import GameRating, User, Country, Wallet, Role, AgentChat, GlobalChat, GameReview, \
    AdminReply, Game, GameTransactionHistory, Player, Prize, PromoCode, Level, FreePlay, WalletTransactionHistory, \
    Referral, Message, Bonus, Payment


class MessageForm(forms.ModelForm):
    class Meta:
        model = Message
        fields = ['message_content', 'receiver', 'message_type', 'is_send_by_agent']

    def save(self, sender=None, commit=True):
        """
        Override the save method to accept sender explicitly.
        """
        message = super().save(commit=False)
        if sender:
            message.sender = sender  # Set the sender here
        if commit:
            message.save()
        return message


class RoleForm(forms.ModelForm):
    class Meta:
        model = Role
        fields = ['roles', 'description']

    def __init__(self, *args, **kwargs):
        super(RoleForm, self).__init__(*args, **kwargs)
        self.fields['roles'].widget.attrs.update({'class': 'form-control'})
        self.fields['description'].widget.attrs.update({'class': 'form-control'})

    def clean_roles(self):
        roles = self.cleaned_data.get('roles')
        if not roles:
            raise forms.ValidationError("Please select a role.")
        return roles

    def clean_description(self):
        description = self.cleaned_data.get('description')
        if not description:
            raise forms.ValidationError("Please enter a description.")
        return description

    def save(self, commit=True):
        role = super(RoleForm, self).save(commit=False)
        if commit:
            role.save()
        return role

    def update(self):
        self.instance.update()
        return self.instance

    def create(self):
        self.instance.create()
        return self.instance

    def delete(self):
        """
        When we delete an instance then delete all its related data like wallets, spins, etc.
        """
        self.instance.delete()
        return self.instance


class UserForm(forms.ModelForm):
    class Meta:
        model = User
        exclude = ['user_id']  # Exclude fields assigned programmatically
        fields = [
            'first_name',
            'last_name',
            'driving_license_front_image',
            'driving_license_back_image',
            'is_verified_license',
            'gender',
            'date_of_birth',
            'waiting_list',
            'experience_points',
            'profile_image',
            'banner_image',
            'referral',
            'referral_key',
            'is_banned_from_global_chat',
            'is_banned_from_agent_chat',
            'otp_verification_id',
            'country_id',
            'spin_id',
            'user_level',
            'role_id',
        ]

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("Email already exists.")
        return email

    def clean_username(self):
        username = self.cleaned_data.get('username')
        if User.objects.filter(username=username).exists():
            raise forms.ValidationError("Username already exists.")
        return username

    def delete(self):
        """
        When we delete an instance then delete all its related data like wallets, spins, etc.
        """
        self.instance.delete()
        return self.instance

    def update(self):
        self.instance.update()
        return self.instance

    def create(self):
        self.instance.create()
        return self.instance


class UpdateUserLicenseForm(forms.ModelForm):
    class Meta:
        model = User
        fields = [
            "driving_license_front_image",
            "driving_license_back_image",
            "experience_points",
        ]

    def save(self, commit=True, *args, **kwargs):
        """
        Automatically manage license verification and level upgrades based on experience points.
        Enforce the same validation logic as the UserForm.
        """
        # Ensure we are updating the existing user instance
        user_instance = self.instance
        user = User.objects.get(id=user_instance.id)

        if not user:
            raise ValueError("User not found.")

        # Get the cleaned data from the form
        cleaned_data = self.cleaned_data

        # Extract experience points from the cleaned data
        new_experience_points = cleaned_data.get("experience_points", 0)
        user.is_verified_license = True

        # Check if the user has enough experience points
        if new_experience_points > user.experience_points:
            raise ValueError("You cannot increase your level because you don't have enough experience points.")

        # Ensure driving license images are provided if experience points are used
        if new_experience_points > 0:
            if not (cleaned_data.get("driving_license_front_image") and
                    cleaned_data.get("driving_license_back_image")):
                raise ValueError(
                    "Please upload both the front and back images of the driving "
                    "license when increasing experience points."
                )

            # Update driving license images if they are provided
            user.driving_license_front_image = cleaned_data.get("driving_license_front_image",
                                                                user.driving_license_front_image)
            user.driving_license_back_image = cleaned_data.get("driving_license_back_image",
                                                               user.driving_license_back_image)

        # Ensure that license verification is enforced
        if not user.driving_license_front_image or not user.driving_license_back_image:
            raise ValueError("License image verification is required to move to the next level.")

        # Automatically upgrade level based on experience points
        self._upgrade_user_level(user)

        # Save the user instance if commit is True
        if commit:
            user.save()

        return user

    @staticmethod
    def _upgrade_user_level(user_instance):
        """
        Determine the appropriate level based on remaining experience points and sequential progression.
        """
        # Level thresholds
        LEVEL_THRESHOLDS = {
            "L0": 1000,
            "L1": 5000,
            "L2": 10000,
            "L3": 50000,
            "L4": float("inf"),  # Max level
        }
        levels = list(LEVEL_THRESHOLDS.keys())
        current_level_index = levels.index(user_instance.user_level.level_code)

        # Check for sequential level progression
        next_level_index = current_level_index + 1
        if next_level_index >= len(levels):
            raise ValueError("You have already reached the maximum level.")

        next_level_code = levels[next_level_index]
        required_xp = LEVEL_THRESHOLDS[next_level_code]

        if user_instance.experience_points < required_xp:
            raise ValueError(
                f"You do not have enough experience points to move to Level {next_level_code}. "
                f"You need {user_instance.experience_points - required_xp} more points."
            )

        # Deduct XP for the level upgrade
        print(f"user_instance.experience_points: {user_instance.experience_points}")

        xp_to_deduct = user_instance.experience_points - required_xp
        print(f"xp_to_deduct: {xp_to_deduct}")

        # Upgrade to the next level
        next_level = Level.objects.get(level_code=next_level_code)
        if user_instance.is_verified_license:
            user_instance.user_level = next_level
            user_instance.experience_points = xp_to_deduct
            print(f"user_instance.experience_points: {user_instance.experience_points}")
        else:
            raise ValueError("Profile verification is required to move to the next level.")


class UpdateUserPhoneAndGetFreeXPForm(forms.ModelForm):
    class Meta:
        model = User
        fields = [
            "phone",
        ]

    def save(self, commit=True, *args, **kwargs):
        user_instance = self.instance
        user = User.objects.get(id=user_instance.id)

        if not user:
            raise ValueError("User not found.")

        # Get the cleaned data from the form
        cleaned_data = self.cleaned_data

        # Extract phone number from the cleaned data
        new_phone = cleaned_data.get("phone")

        user.phone = new_phone
        if not user.is_phone_verified:
            user.is_phone_verified = True
        else:
            raise ValueError("Phone number is already verified.")

        user.experience_points += 200

        if commit:
            user.save()
        else:
            user.save(update_fields=["phone", "is_phone_verified"])
        return user


class UpdateUserDocumentForm(forms.ModelForm):
    class Meta:
        model = User
        fields = [
            "front_images",
            "back_images",
            "selected_documents"
        ]


class AgentChatForm(forms.ModelForm):
    class Meta:
        model = AgentChat
        fields = ['user_id', 'agent_id', 'message_content', 'attachment_image', 'status']

    def save(self, commit=True):
        agent_chat = super(AgentChatForm, self).save(commit=False)
        if commit:
            agent_chat.save()
        return agent_chat

    def delete(self):
        """
        When we delete an instance, delete all its related data like wallets, spins, etc.
        """
        self.instance.delete()
        return self.instance

    def update(self):
        self.instance.update()
        return self.instance


class GlobalChatForm(forms.ModelForm):
    class Meta:
        model = GlobalChat
        exclude = ['user_id']
        fields = ['user_id', 'message_content', 'is_pinned', ]


class AdminReplyForm(forms.ModelForm):
    class Meta:
        model = AdminReply
        exclude = ['admin_id']
        fields = [
            'admin_id',
            'message_content',
            "game_review_id",
        ]


class GameReviewForm(forms.ModelForm):
    class Meta:
        model = GameReview
        exclude = ['user_id']
        fields = [
            'message_content',
            'game_id',
        ]


class GameForm(forms.ModelForm):
    class Meta:
        model = Game
        exclude = ['created_by_user_id']
        fields = [
            'country',
            'game_id',
            'game_name',
            'game_description',
            'game_image',
            'game_video',
            'game_price',
            'android_game_url',
            'ios_game_url',
            'browser_game_url',
            'upcoming_status',
            'is_trending',
            'game_reviews_id',
            'score',
            'transfer_score_percentage',
            'redeem_score_percentage',
            'is_free',
            'is_promotional',
            'gradient_style',
        ]

    def __init__(self, *args, **kwargs):
        super(GameForm, self).__init__(*args, **kwargs)
        self.fields['country'].queryset = Country.objects.all()

        # Explicitly mark game_video as not required
        self.fields['game_video'].required = False
        self.fields['game_reviews_id'].required = False

    def save(self, commit=True):
        game = super(GameForm, self).save(commit=False)
        if commit:
            game.save()
        return game

    def delete(self):
        """
        When we delete an instance then delete all its related data like wallets, spins, etc.
        """
        self.instance.delete()
        return self.instance

    def update(self):
        self.instance.update()
        return self.instance


class GameRatingForm(forms.ModelForm):
    class Meta:
        model = GameRating
        fields = ['game_id', 'rating']

    # if the user is rating the game from 1.0 - 5.0 then add the rating to the game, and check if 
    # the game is already rated by the user then update the rating
    def save(self, commit=True):
        game_rating = super(GameRatingForm, self).save(commit=False)
        if commit:
            game_rating.save()
        return game_rating


class GameRatingShowForm(forms.ModelForm):
    class Meta:
        model = GameRating
        fields = ['game_id', 'rating', 'total_ratings', 'user_id']


class GameTransactionHistoryForm(forms.ModelForm):
    class Meta:
        model = GameTransactionHistory
        fields = [
            'game_id',
            'payment',
            'transaction_amount',
            'order_id',
            'withdrawal_percentage_tax',
        ]

    def __init__(self, *args, **kwargs):
        super(GameTransactionHistoryForm, self).__init__(*args, **kwargs)
        self.fields['game_id'].queryset = Game.objects.all()

    def save(self, commit=True):
        game_transaction_history = super(GameTransactionHistoryForm, self).save(commit=False)
        if commit:
            game_transaction_history.save()
        return game_transaction_history

    def delete(self):
        """
        When we delete an instance then delete all its related data like wallets, spins, etc.
        """
        self.instance.delete()
        return self.instance

    def update(self):
        self.instance.update()
        return self.instance


class PlayerForm(forms.ModelForm):
    class Meta:
        model = Player
        fields = [
            'username',
            # 'nick_name',
            'password',
            'score',
            'status',
            'is_banned',
            'user_id',
            'game_id',
            'game_transaction_history_id',
        ]

    def __init__(self, *args, **kwargs):
        super(PlayerForm, self).__init__(*args, **kwargs)
        self.fields['user_id'].queryset = User.objects.all()
        self.fields['game_id'].queryset = Game.objects.all()
        self.fields['game_transaction_history_id'].queryset = GameTransactionHistory.objects.all()

    def clean_username(self):
        """
        Validate if the username is unique for the given game.
        """
        username = self.cleaned_data.get('username')
        game = self.cleaned_data.get('game_id')
        if Player.objects.filter(username=username, game_id=game).exists():
            raise forms.ValidationError(f"Player with username '{username}' already exists for the selected game.")
        return username

    def clean_user_id(self):
        """
        Ensure the provided user_id exists.
        """
        user = self.cleaned_data.get('user_id')
        if not user:
            raise forms.ValidationError("A valid user must be selected.")
        return user

    def clean_game_id(self):
        """
        Ensure the provided game_id exists.
        """
        game = self.cleaned_data.get('game_id')
        if not game:
            raise forms.ValidationError("A valid game must be selected.")
        return game

    def save(self, commit=True):
        player = super(PlayerForm, self).save(commit=False)
        if commit:
            player.save()
            # Add logic for transaction history if needed
            self.save_m2m()
        return player


class AddScoreToPlayerForm(forms.ModelForm):
    class Meta:
        model = Player
        fields = [
            'username',
            'score',
            'game_id',
        ]


class CreatePrizeForm(forms.ModelForm):
    class Meta:
        model = Prize
        fields = ['prize_id', 'name', 'quantity', 'image', 'probability']


class UpdatePrizeForm(forms.ModelForm):
    class Meta:
        model = Prize
        fields = ['name', 'quantity', 'image', 'probability', 'is_active']


class PromoCodeForm(forms.ModelForm):
    class Meta:
        model = PromoCode
        fields = ['bonus_percentage', 'is_expired']


class LevelForm(forms.ModelForm):
    class Meta:
        model = Level
        fields = ['level', 'level_code']


class ReferralForm(forms.ModelForm):
    class Meta:
        model = Referral
        fields = [
            'user_id',
            'quantity',
        ]

    def save(self, commit=True):
        referral = super(ReferralForm, self).save(commit=False)
        if commit:
            referral.save()
        return referral

    def delete(self):
        """
        When we delete an instance then delete all its related data like wallets, spins, etc.
        """
        self.instance.delete()
        return self.instance

    def update(self):
        self.instance.update()
        return self.instance


class WalletForm(forms.ModelForm):
    class Meta:
        model = Wallet
        fields = ['current_balance', 'withdrawal_percentage_tax']

    def save(self, commit=True):
        wallet = super(WalletForm, self).save(commit=False)

        # check to add current balance in the wallet
        # at least greater than 5 dollars
        if wallet.current_balance < 5:
            raise ValueError("balance must be at least 5 dollars.")

        if commit:
            wallet.save()
        return wallet


class WalletTransactionHistoryForm(forms.ModelForm):
    class Meta:
        model = WalletTransactionHistory
        fields = ['payment_method', 'transaction_amount', 'payment', 'order_id', ]


class WalletTransactionHistoryFormUpdated(forms.ModelForm):
    class Meta:
        model = WalletTransactionHistory
        exclude = ['wallet_id']
        fields = ['payment_method', 'transaction_amount', 'wallet_id']

    def clean_wallet_id(self):
        wallet_id = self.cleaned_data.get('wallet_id')
        # Check if the wallet exists
        if not Wallet.objects.filter(id=wallet_id).exists():
            raise forms.ValidationError("Wallet not found.")
        return wallet_id

    def clean_transaction_amount(self):
        transaction_amount = self.cleaned_data.get('transaction_amount')
        if transaction_amount <= 0:
            raise forms.ValidationError("Transaction amount must be greater than 0.")
        return transaction_amount

    def save(self, commit=True):
        """
        If the user is redeeming an amount for the first time,
        apply the formula: total_amount = original_amount * 3 (For the first time only).
        """
        instance = super().save(commit=False)

        # Fetch wallet ID from the cleaned data
        wallet_id = self.cleaned_data.get('wallet_id')
        wallet = Wallet.objects.get(id=wallet_id)

        # Check if this is the first redemption
        if not WalletTransactionHistory.objects.filter(wallet=wallet).exists():
            # Apply the first-time formula
            instance.transaction_amount *= 3
            wallet.total_amount += instance.transaction_amount
        else:
            # Add the transaction amount to the wallet as usual
            wallet.total_amount += instance.transaction_amount

        # Save the wallet updates
        wallet.save()

        if commit:
            # Save the transaction history instance
            instance.wallet = wallet
            instance.save()

        return instance


class FreePlayForm(forms.ModelForm):
    class Meta:
        model = FreePlay
        fields = ['user', 'free_plays', 'spins_left', 'expires_at']


class AddBonusForm(forms.ModelForm):
    class Meta:
        model = Bonus
        fields = [
            "user_id",
            "amount",
        ]
        widgets = {
            'user_id': forms.Select(attrs={'class': 'form-control'}),
            'amount': forms.NumberInput(attrs={'class': 'form-control'}),
        }

    def save(self, commit=True):
        bonus = super(AddBonusForm, self).save(commit=False)
        if commit:
            bonus.user_id.update_balance_for_first_time_multiple_2(bonus.amount)
        return bonus


class PaymentAdminForm(forms.ModelForm):
    class Meta:
        model = Payment
        fields = '__all__'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['network'].widget.attrs['disabled'] = True  # Disable initially
