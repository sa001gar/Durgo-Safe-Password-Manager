from django.db import models
from django.contrib.auth.models import AbstractUser

class CustomUser(AbstractUser):
    # Additional fields for CustomUser
    is_regular_user = models.BooleanField(default=True)  # Indicates if the user is a normal user
    is_admin_user = models.BooleanField(default=False)  # Indicates if the user is an admin user
    is_staff_user = models.BooleanField(default=False)  # Indicates if the user is a staff user
    
    master_key = models.CharField(max_length=255)

    def __str__(self):
        return self.username

class PasswordManager(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)  # Use CustomUser instead of User
    domain = models.CharField(max_length=100)
    username = models.CharField(max_length=100)
    password = models.CharField(max_length=100)
    date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.domain} - {self.username}"
