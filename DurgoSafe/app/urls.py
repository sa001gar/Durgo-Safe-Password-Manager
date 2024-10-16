from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register, name='register'),
    path('login/', views.login_user, name='login'),
    path('profile/', views.profile, name='profile'),
    path('logout/', views.logout_user, name='logout'),
    path('add_password/', views.add_password, name='add_password'),
    path('view_passwords/', views.view_passwords, name='view_passwords'),
    path('delete_password/<int:pk>/', views.delete_password, name='delete_password'),

]