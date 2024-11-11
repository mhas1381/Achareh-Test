# Generated by Django 4.2.16 on 2024-11-11 10:49

import accounts.models.users
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0006_user_blocked_until_user_login_attempts_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='phone_number',
            field=models.CharField(max_length=15, unique=True, validators=[accounts.models.users.validate_phone_number]),
        ),
    ]
