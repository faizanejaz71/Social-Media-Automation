# Generated by Django 5.1.5 on 2025-02-13 11:14

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("accountManager", "0002_twitteraccount_account_type"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="twitteraccount",
            name="access_token_secret",
        ),
    ]
