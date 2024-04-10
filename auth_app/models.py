'''Function printing python version.'''
from django.db import models
# from django.contrib.auth.models import AbstractUser
from django.contrib.auth.models import User

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    email_token = models.CharField(max_length=200)
    is_verified = models.BooleanField(default=False)
    
class Notification(models.Model):
    message = models.CharField(max_length=100)
    
    def __str__(self):
        return self.message