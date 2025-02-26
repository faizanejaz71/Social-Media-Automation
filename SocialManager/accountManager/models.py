from django.db import models

# Create your models here.
class TwitterAccount(models.Model):
    username = models.CharField(max_length=255, unique=True)
    access_token = models.TextField(blank=True, null=True)  # Longer tokens
    refresh_token = models.TextField(blank=True, null=True)  # Add refresh token
    twitter_user_id = models.CharField(max_length=50, blank=True, null=True)
    expires_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    account_type = models.CharField(max_length=255, null=True)

    def __str__(self):
        return self.username
