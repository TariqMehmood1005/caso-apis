from django.contrib import admin
from ApiPlatform import models
from unfold.admin import ModelAdmin
from .models import Payment
from .forms import PaymentAdminForm


# Register your models here.
admin.site.register(models.Role, ModelAdmin)
admin.site.register(models.Country, ModelAdmin)
admin.site.register(models.OTPVerification, ModelAdmin)
admin.site.register(models.Prize, ModelAdmin)
admin.site.register(models.SpinHistory, ModelAdmin)
admin.site.register(models.Spin, ModelAdmin)
admin.site.register(models.WalletTransactionHistory, ModelAdmin)
admin.site.register(models.Wallet, ModelAdmin)
admin.site.register(models.AdminReply, ModelAdmin)
admin.site.register(models.GameReview, ModelAdmin)
admin.site.register(models.Game, ModelAdmin)
admin.site.register(models.GameRating, ModelAdmin)
admin.site.register(models.GameTransactionHistory, ModelAdmin)
admin.site.register(models.User, ModelAdmin)
admin.site.register(models.AgentChat, ModelAdmin)
admin.site.register(models.GlobalChat, ModelAdmin)
admin.site.register(models.Referral, ModelAdmin)
admin.site.register(models.Player, ModelAdmin)
admin.site.register(models.PromoCode, ModelAdmin)
admin.site.register(models.Level, ModelAdmin)
admin.site.register(models.FreePlay, ModelAdmin)
admin.site.register(models.SubscriptionPlan, ModelAdmin)
admin.site.register(models.BannedIP, ModelAdmin)
admin.site.register(models.MessageConversation, ModelAdmin)
admin.site.register(models.Message, ModelAdmin)
admin.site.register(models.Notification, ModelAdmin)
admin.site.register(models.GameReviewRating, ModelAdmin)
admin.site.register(models.ReviewHelpFull, ModelAdmin)
admin.site.register(models.ReviewNotHelpFull, ModelAdmin)
admin.site.register(models.ReplyHelpFull, ModelAdmin)
admin.site.register(models.ReplyNotHelpFull, ModelAdmin)
admin.site.register(models.Bonus, ModelAdmin)


class PaymentAdmin(ModelAdmin):
    form = PaymentAdminForm
    list_display = ('user', 'payment_method', 'coin', 'network', 'amount', 'status', 'created_at')

    class Media:
        js = ('js/payment_admin.js',)  # Include custom JavaScript file

admin.site.register(Payment, PaymentAdmin)
