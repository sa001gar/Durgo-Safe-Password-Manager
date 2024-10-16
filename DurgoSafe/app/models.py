from django.db import models
from django.contrib.auth.models import User


# Create your models here.
class password_manager(models.Model):
    user=models.ForeignKey(User, on_delete=models.CASCADE)
    domain = models.CharField(max_length=100)
    username = models.CharField(max_length=100)
    password = models.CharField(max_length=100)
    confirm_password = models.CharField(max_length=100)

    date = models.DateTimeField(auto_now_add=True)
    def __str__(self):
        return f"{self.domain} -{self.username}"




