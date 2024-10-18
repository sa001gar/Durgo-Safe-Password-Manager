from django.contrib import admin
from .models import CustomUser, PasswordManager

admin.site.register(CustomUser)
admin.site.register(PasswordManager)
