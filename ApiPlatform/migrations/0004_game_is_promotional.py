# Generated by Django 5.1.1 on 2025-02-27 12:37

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("ApiPlatform", "0003_alter_adminreply_rated_by_user_id_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="game",
            name="is_promotional",
            field=models.BooleanField(default=False),
        ),
    ]
