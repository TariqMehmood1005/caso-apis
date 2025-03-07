# Generated by Django 5.1.1 on 2025-02-27 07:33

import datetime
import django.db.models.deletion
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        (
            "ApiPlatform",
            "0002_alter_referral_referral_expiry_date_replyhelpfull_and_more",
        ),
    ]

    operations = [
        migrations.AlterField(
            model_name="adminreply",
            name="rated_by_user_id",
            field=models.ManyToManyField(
                related_name="rated_admin_replies", to="ApiPlatform.user"
            ),
        ),
        migrations.AlterField(
            model_name="referral",
            name="referral_expiry_date",
            field=models.DateField(
                blank=True, default=datetime.date(2025, 4, 28), null=True
            ),
        ),
        migrations.AlterField(
            model_name="user",
            name="phone",
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
        migrations.CreateModel(
            name="GamePlay",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("played_at", models.DateTimeField(auto_now_add=True)),
                ("profit", models.FloatField(default=0)),
                (
                    "game",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="game_plays",
                        to="ApiPlatform.game",
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="game_plays",
                        to="ApiPlatform.user",
                    ),
                ),
            ],
            options={
                "ordering": ["-played_at"],
            },
        ),
        migrations.CreateModel(
            name="Payment",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("payment_method", models.CharField(max_length=50)),
                ("amount", models.DecimalField(decimal_places=2, max_digits=10)),
                ("coin", models.CharField(blank=True, max_length=50, null=True)),
                ("network", models.CharField(blank=True, max_length=50, null=True)),
                (
                    "wallet_address",
                    models.CharField(blank=True, max_length=255, null=True),
                ),
                ("card_number", models.CharField(blank=True, max_length=16, null=True)),
                ("card_name", models.CharField(blank=True, max_length=100, null=True)),
                (
                    "card_expiry_date",
                    models.CharField(blank=True, max_length=5, null=True),
                ),
                ("card_cvv", models.CharField(blank=True, max_length=3, null=True)),
                (
                    "screenshot",
                    models.ImageField(
                        blank=True, null=True, upload_to="payment_screenshots/"
                    ),
                ),
                (
                    "account_title",
                    models.CharField(blank=True, max_length=255, null=True),
                ),
                ("cash_tag", models.CharField(blank=True, max_length=255, null=True)),
                ("status", models.CharField(default="pending", max_length=50)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="ApiPlatform.user",
                    ),
                ),
            ],
        ),
    ]
